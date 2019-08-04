/*******************************************************************************
 *
 * Difference Bound Matrix domain based on the paper "Exploiting
 * Sparsity in Difference-Bound Matrices" by Gange, Navas, Schachte,
 * Sondergaard, and Stuckey published in SAS'16.

 * A re-engineered implementation of the Difference Bound Matrix
 * domain, which maintains bounds and relations separately.
 *
 * Closure operations based on the paper "Fast and Flexible Difference
 * Constraint Propagation for DPLL(T)" by Cotton and Maler.
 *
 * Author: Graeme Gange (gkgange@unimelb.edu.au)
 *
 * Contributors: Jorge A. Navas (jorge.navas@sri.com)
 ******************************************************************************/

#pragma once

#include <optional>
#include <type_traits>
#include <unordered_set>

#include <boost/container/flat_map.hpp>

#include "crab/abstract_domain.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/adapt_sgraph.hpp"
#include "crab/bignums.hpp"
#include "crab/debug.hpp"
#include "crab/graph_ops.hpp"
#include "crab/interval.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/safeint.hpp"
#include "crab/sparse_graph.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

//#define CHECK_POTENTIAL
//#define SDBM_NO_NORMALIZE

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"

namespace crab {

namespace domains {

/** DBM weights (Wt) can be represented using one of the following
 * types:
 *
 * 1) basic integer type: e.g., long
 * 2) safei64
 * 3) z_number
 *
 * 1) is the fastest but things can go wrong if some DBM
 * operation overflows. 2) is slower than 1) but it checks for
 * overflow before any DBM operation. 3) is the slowest and it
 * represents weights using unbounded mathematical integers so
 * overflow is not a concern but it might not be what you need
 * when reasoning about programs with wraparound semantics.
 **/

struct SafeInt64DefaultParams {
    using Wt = safe_i64;
    using graph_t = AdaptGraph<Wt>;
};

/**
 * Helper to translate from Number to DBM Wt (graph weights).  Number
 * is the template parameter of the DBM-based abstract domain to
 * represent a number. Number might not fit into Wt type.
 **/
inline safe_i64 convert_NtoW(const z_number& n, bool& overflow) {
    overflow = false;
    if (!n.fits_slong()) {
        overflow = true;
        return 0;
    }
    return safe_i64(n);
}

class SplitDBM final : public writeable {
  public:
    using constraint_kind_t = typename linear_constraint_t::constraint_kind_t;

  private:
    using variable_vector_t = std::vector<variable_t>;

    using Params = SafeInt64DefaultParams;
    using Wt = typename Params::Wt;
    using graph_t = typename Params::graph_t;
    using vert_id = typename graph_t::vert_id;
    using vert_map_t = boost::container::flat_map<variable_t, vert_id>;
    using vmap_elt_t = typename vert_map_t::value_type;
    using rev_map_t = std::vector<std::optional<variable_t>>;
    using GrOps = GraphOps<graph_t>;
    using GrPerm = GraphPerm<graph_t>;
    using edge_vector = typename GrOps::edge_vector;
    // < <x, y>, k> == x - y <= k.
    using diffcst_t = std::pair<std::pair<variable_t, variable_t>, Wt>;
    using vert_set_t = std::unordered_set<vert_id>;

  private:
    //================
    // Domain data
    //================
    // GKG: ranges are now maintained in the graph
    vert_map_t vert_map; // Mapping from variables to vertices
    rev_map_t rev_map;
    graph_t g;                 // The underlying relation graph
    std::vector<Wt> potential; // Stored potential for the vertex
    vert_set_t unstable;
    bool _is_bottom;

    class Wt_max {
      public:
        Wt_max() {}
        Wt apply(const Wt& x, const Wt& y) { return std::max(x, y); }
        bool default_is_absorbing() { return true; }
    };

    class Wt_min {
      public:
        Wt_min() {}
        Wt apply(const Wt& x, const Wt& y) { return std::min(x, y); }
        bool default_is_absorbing() { return false; }
    };

    vert_id get_vert(variable_t v);

    vert_id get_vert(graph_t& g, vert_map_t& vmap, rev_map_t& rmap, std::vector<Wt>& pot, variable_t v);

    template <class G, class P>
    inline void check_potential(G& g, P& p, unsigned line) {}

    class vert_set_wrap_t {
      public:
        vert_set_wrap_t(const vert_set_t& _vs) : vs(_vs) {}

        bool operator[](vert_id v) const { return vs.find(v) != vs.end(); }
        const vert_set_t& vs;
    };

    // Evaluate the potential value of a variable.
    Wt pot_value(variable_t v) {
        auto it = vert_map.find(v);
        if (it != vert_map.end())
            return potential[(*it).second];
        return ((Wt)0);
    }

    Wt pot_value(variable_t v, std::vector<Wt>& potential) {
        auto it = vert_map.find(v);
        if (it != vert_map.end())
            return potential[(*it).second];
        return ((Wt)0);
    }

    // Evaluate an expression under the chosen potentials
    Wt eval_expression(linear_expression_t e, bool overflow) {
        Wt v(convert_NtoW(e.constant(), overflow));
        if (overflow) {
            return Wt(0);
        }

        for (auto [n, v] : e) {
            Wt coef = convert_NtoW(v, overflow);
            if (overflow) {
                return Wt(0);
            }
            v += (pot_value(n) - potential[0]) * coef;
        }
        return v;
    }

    interval_t compute_residual(linear_expression_t e, variable_t pivot) {
        interval_t residual(-e.constant());
        for (auto [v, n] : e) {
            if (v.index() != pivot.index()) {
                residual = residual - (interval_t(n) * this->operator[](v));
            }
        }
        return residual;
    }

    /**
     *  Turn an assignment into a set of difference constraints.
     *
     *  Given v := a*x + b*y + k, where a,b >= 0, we generate the
     *  difference constraints:
     *
     *  if extract_upper_bounds
     *     v - x <= ub((a-1)*x + b*y + k)
     *     v - y <= ub(a*x + (b-1)*y + k)
     *  else
     *     x - v <= lb((a-1)*x + b*y + k)
     *     y - v <= lb(a*x + (b-1)*y + k)
     **/
    void diffcsts_of_assign(variable_t x, linear_expression_t exp,
                            /* if true then process the upper
                               bounds, else the lower bounds */
                            bool extract_upper_bounds,
                            /* foreach {v, k} \in diff_csts we have
                               the difference constraint v - k <= k */
                            std::vector<std::pair<variable_t, Wt>>& diff_csts);

    // Turn an assignment into a set of difference constraints.
    void diffcsts_of_assign(variable_t x, linear_expression_t exp, std::vector<std::pair<variable_t, Wt>>& lb,
                            std::vector<std::pair<variable_t, Wt>>& ub) {
        diffcsts_of_assign(x, exp, true, ub);
        diffcsts_of_assign(x, exp, false, lb);
    }

    /**
     * Turn a linear inequality into a set of difference
     * constraints.
     **/
    void diffcsts_of_lin_leq(const linear_expression_t& exp,
                             /* difference contraints */
                             std::vector<diffcst_t>& csts,
                             /* x >= lb for each {x,lb} in lbs */
                             std::vector<std::pair<variable_t, Wt>>& lbs,
                             /* x <= ub for each {x,ub} in ubs */
                             std::vector<std::pair<variable_t, Wt>>& ubs);

    bool add_linear_leq(const linear_expression_t& exp);

    // x != n
    void add_univar_disequation(variable_t x, number_t n);

    void add_disequation(linear_expression_t e) {
        // XXX: similar precision as the interval domain
        for (auto [pivot, n] : e) {
            interval_t i = compute_residual(e, pivot) / interval_t(n);
            if (auto k = i.singleton()) {
                add_univar_disequation(pivot, *k);
            }
        }
        return;
    }

    interval_t get_interval(variable_t x) { return get_interval(vert_map, g, x); }

    interval_t get_interval(vert_map_t& m, graph_t& r, variable_t x) {
        auto it = m.find(x);
        if (it == m.end()) {
            return interval_t::top();
        }
        vert_id v = (*it).second;
        interval_t x_out = interval_t(r.elem(v, 0) ? -number_t(r.edge_val(v, 0)) : bound_t::minus_infinity(),
                                      r.elem(0, v) ? number_t(r.edge_val(0, v)) : bound_t::plus_infinity());
        return x_out;
    }

    // Resore potential after an edge addition
    bool repair_potential(vert_id src, vert_id dest) { return GrOps::repair_potential(g, potential, src, dest); }

    // Restore closure after a single edge addition
    void close_over_edge(vert_id ii, vert_id jj);

    // return true if edge from x to y with weight k is unsatisfiable
    bool is_unsat_edge(vert_id x, vert_id y, Wt k);

    // return true iff cst is unsatisfiable without modifying the DBM
    bool is_unsat(linear_constraint_t cst);

  public:
    SplitDBM(bool is_bottom = false) : _is_bottom(is_bottom) {
        g.growTo(1); // Allocate the zero vector
        potential.push_back(Wt(0));
        rev_map.push_back(std::nullopt);
    }

    // FIXME: Rewrite to avoid copying if o is _|_
    SplitDBM(vert_map_t&& _vert_map, rev_map_t&& _rev_map, graph_t&& _g, std::vector<Wt>&& _potential,
             vert_set_t&& _unstable)
        : vert_map(std::move(_vert_map)), rev_map(std::move(_rev_map)), g(std::move(_g)),
          potential(std::move(_potential)), unstable(std::move(_unstable)), _is_bottom(false) {

        CrabStats::count("SplitDBM.count.copy");
        ScopedCrabStats __st__("SplitDBM.copy");

        CRAB_LOG("zones-split-size", auto p = size();
                 std::cout << "#nodes = " << p.first << " #edges=" << p.second << "\n";);

        assert(g.size() > 0);
    }

    SplitDBM(const SplitDBM& o) = default;
    SplitDBM(SplitDBM&& o) = default;

    SplitDBM& operator=(const SplitDBM& o) = default;
    SplitDBM& operator=(SplitDBM&& o) = default;

    void set_to_top() {
        this->~SplitDBM();
        new(this) SplitDBM(false);
    }

    void set_to_bottom() {
        this->~SplitDBM();
        new(this) SplitDBM(true);
    }

    bool is_bottom() const { return _is_bottom; }

    static SplitDBM top() {
        return SplitDBM(false);
    }

    static SplitDBM bottom() {
        return SplitDBM(true);
    }

    bool is_top() const {
        if (_is_bottom)
            return false;
        return g.is_empty();
    }

    bool operator<=(SplitDBM o);

    // FIXME: can be done more efficient
    void operator|=(SplitDBM o) { *this = *this | o; }
    void operator|=(SplitDBM&& o) {
        if (is_bottom()) {
            std::swap(*this, o);
        } else {
            *this = *this | o;
        }
    }

    SplitDBM operator|(const SplitDBM& o) &;
    SplitDBM operator|(const SplitDBM& o) && {
        if (o.is_bottom()) return *this;
        return static_cast<SplitDBM&>(*this) | o;
    }

    SplitDBM widen(SplitDBM o);

    SplitDBM widening_thresholds(SplitDBM o, const iterators::thresholds_t& ts) {
        // TODO: use thresholds
        return ((*this).widen(o));
    }

    SplitDBM operator&(SplitDBM o);

    SplitDBM narrow(SplitDBM o);

    void normalize();

    void operator-=(variable_t v);

    void assign(variable_t x, linear_expression_t e);

    void apply(arith_binop_t op, variable_t x, variable_t y, variable_t z);

    void apply(arith_binop_t op, variable_t x, variable_t y, number_t k);

    // bitwise_operators_api
    void apply(bitwise_binop_t op, variable_t x, variable_t y, variable_t z);

    void apply(bitwise_binop_t op, variable_t x, variable_t y, number_t k);

    template <typename NumOrVar>
    void apply(binop_t op, variable_t x, variable_t y, NumOrVar z) {
        std::visit([&](auto top) { apply(top, x, y, z); }, op);
    }

    void operator+=(linear_constraint_t cst);

    interval_t eval_interval(linear_expression_t e) {
        interval_t r = e.constant();
        for (auto [v, n] : e)
            r += n * operator[](v);
        return r;
    }

    interval_t operator[](variable_t x) {
        CrabStats::count("SplitDBM.count.to_intervals");
        ScopedCrabStats __st__("SplitDBM.to_intervals");

        // if (is_top())    return interval_t::top();

        if (is_bottom()) {
            return interval_t::bottom();
        } else {
            return get_interval(vert_map, g, x);
        }
    }

    void set(variable_t x, interval_t intv);

    void forget(const variable_vector_t& variables);

    void rename(const variable_vector_t& from, const variable_vector_t& to);

    // -- begin array_sgraph_domain_helper_traits

    // -- end array_sgraph_domain_helper_traits

    // Output function
    void write(std::ostream& o);

    // return number of vertices and edges
    std::pair<std::size_t, std::size_t> size() const { return {g.size(), g.num_edges()}; }

    static std::string getDomainName() { return "SplitDBM"; }

}; // class SplitDBM

} // namespace domains
} // namespace crab

#pragma GCC diagnostic pop
