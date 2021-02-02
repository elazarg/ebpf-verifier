// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/
#include <cinttypes>

#include <ctime>
#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"

#include "asm_syntax.hpp"
#include "crab_verifier.hpp"

using std::string;

using crab::linear_constraint_t;

program_info global_program_info;

// Numerical domains over integers
//using sdbm_domain_t = crab::domains::SplitDBM;
using crab::domains::ebpf_domain_t;

// Toy database to store invariants.
struct checks_db final {
    std::map<label_t, std::vector<std::string>> m_db;
    int total_warnings{};
    int total_unreachable{};
    std::set<label_t> maybe_nonterminating;

    void add(const label_t& label, const std::string& msg) {
        m_db[label].emplace_back(msg);
    }

    void add_warning(const label_t& label, const std::string& msg) {
        add(label, msg);
        total_warnings++;
    }

    void add_unreachable(const label_t& label, const std::string& msg) {
        add(label, msg);
        total_unreachable++;
    }

    void add_nontermination(const label_t& label) {
        maybe_nonterminating.insert(label);
        total_warnings++;
    }

    checks_db() = default;
};

static checks_db generate_report(std::ostream& s,
                                 cfg_t& cfg,
                                 crab::invariant_table_t& preconditions,
                                 crab::invariant_table_t& postconditions,
                                 ebpf_verifier_options_t options) {
    checks_db m_db;
    for (const label_t& label : cfg.sorted_labels()) {
        basic_block_t& bb = cfg.get_node(label);

        if (options.print_invariants) {
            s << "\n" << preconditions.at(label) << "\n";
            s << bb;
            s << "\n" << postconditions.at(label) << "\n";
        }

        ebpf_domain_t from_inv(preconditions.at(label));
        from_inv.set_require_check([&m_db, label](auto& inv, const linear_constraint_t& cst, const std::string& s) {
            if (inv.is_bottom())
                return;
            if (cst.is_contradiction()) {
                m_db.add_warning(label, std::string("Contradiction: ") + s);
                return;
            }

            if (inv.entail(cst)) {
                // add_redundant(s);
            } else if (inv.intersect(cst)) {
                // TODO: add_error() if imply negation
                m_db.add_warning(label, s);
            } else {
                m_db.add_warning(label, s);
            }
        });

        if (options.check_termination) {
            bool pre_join_terminates = false;
            for (const label_t& prev_label : bb.prev_blocks_set())
                pre_join_terminates |= preconditions.at(prev_label).terminates();

            if (pre_join_terminates && !from_inv.terminates())
                m_db.add_nontermination(label);
        }

        bool pre_bot = from_inv.is_bottom();

        from_inv(bb, options.check_termination);

        if (!pre_bot && from_inv.is_bottom()) {
            m_db.add_unreachable(label, std::string("Invariant became _|_ after ") + to_string(bb.label()));
        }
    }
    return m_db;
}

static void print_report(std::ostream& s, const checks_db& db) {
    s << "\n";
    for (auto [label, messages] : db.m_db) {
        s << label << ":\n";
        for (const auto& msg : messages)
            s << "  " << msg << "\n";
    }
    s << "\n";
    if (!db.maybe_nonterminating.empty()) {
        s << "Could not prove termination on join into: ";
        for (const label_t& label : db.maybe_nonterminating) {
            s << label << ", ";
        }
        s << "\n";
    }
    s << db.total_warnings << " warnings\n";
}

/// Returned value is true if the program passes verification.
bool run_ebpf_analysis(std::ostream& s, cfg_t& cfg, program_info info, const ebpf_verifier_options_t* options) {
    if (options == nullptr)
        options = &ebpf_verifier_default_options;

    global_program_info = std::move(info);
    crab::domains::clear_global_state();

    // Get dictionaries of preconditions and postconditions for each
    // basic block.
    auto [preconditions, postconditions] = crab::run_forward_analyzer(cfg, options->check_termination);

    checks_db report = generate_report(s, cfg, preconditions, postconditions, *options);

    if (options->print_failures) {
        print_report(s, report);
    }
    return (report.total_warnings == 0);
}
