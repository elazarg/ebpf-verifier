// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <algorithm>
#include <bitset>
#include <functional>
#include <optional>
#include <set>
#include <map>
#include <utility>
#include <vector>

#include "boost/range/algorithm/set_algorithm.hpp"

#include "crab/variable.hpp"
#include "crab_utils/debug.hpp"
#include "crab_utils/stats.hpp"

#include "crab/interval.hpp"
#include "crab/split_dbm.hpp"

#include "asm_ostream.hpp"
#include "crab_verifier.hpp"
#include "dsl_syntax.hpp"
#include "helpers.hpp"
#include "platform.hpp"

#include "crab/array_domain.hpp"

extern thread_local ebpf_verifier_options_t thread_local_options;

namespace crab::domains {

struct reg_pack_t {
    variable_t value, offset, type;
};

inline reg_pack_t reg_pack(int i) {
    return {
       variable_t::reg(data_kind_t::values, i),
       variable_t::reg(data_kind_t::offsets, i),
       variable_t::reg(data_kind_t::types, i),
    };
}
inline reg_pack_t reg_pack(Reg r) { return reg_pack(r.v); }

inline linear_constraint_t eq(variable_t a, variable_t b) {
    using namespace dsl_syntax;
    return {a - b, constraint_kind_t::EQUALS_ZERO};
}

inline linear_constraint_t neq(variable_t a, variable_t b) {
    using namespace dsl_syntax;
    return {a - b, constraint_kind_t::NOT_ZERO};
}

constexpr int MAX_PACKET_OFF = 0xffff;
constexpr int64_t MY_INT_MAX = INT_MAX;
constexpr int64_t PTR_MAX = MY_INT_MAX - MAX_PACKET_OFF;

/** Linear constraint for a pointer comparison.
 */
inline linear_constraint_t jmp_to_cst_offsets_reg(Condition::Op op, variable_t dst_offset, variable_t src_offset) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return eq(dst_offset, src_offset);
    case Op::NE: return neq(dst_offset, src_offset);
    case Op::GE: return dst_offset >= src_offset;
    case Op::SGE: return dst_offset >= src_offset; // pointer comparison is unsigned
    case Op::LE: return dst_offset <= src_offset;
    case Op::SLE: return dst_offset <= src_offset; // pointer comparison is unsigned
    case Op::GT: return dst_offset > src_offset;
    case Op::SGT: return dst_offset > src_offset; // pointer comparison is unsigned
    case Op::SLT: return src_offset > dst_offset;
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return src_offset > dst_offset; // FIX unsigned
    default: return dst_offset - dst_offset == 0;
    }
}

/** Linear constraints for a comparison with a constant.
 */
inline std::vector<linear_constraint_t> jmp_to_cst_imm(Condition::Op op, variable_t dst_value, int imm) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {dst_value == imm};
    case Op::NE: return {dst_value != imm};
    case Op::GE: return {dst_value >= (unsigned)imm}; // FIX unsigned
    case Op::SGE: return {dst_value >= imm};
    case Op::LE: return {dst_value <= imm, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= imm};
    case Op::GT: return {dst_value > (unsigned)imm}; // FIX unsigned
    case Op::SGT: return {dst_value > imm};
    case Op::LT: return {dst_value < (unsigned)imm}; // FIX unsigned
    case Op::SLT: return {dst_value < imm};
    case Op::SET: throw std::exception();
    case Op::NSET: return {};
    }
    return {};
}

/** Linear constraint for a numerical comparison between registers.
 */
inline std::vector<linear_constraint_t> jmp_to_cst_reg(Condition::Op op, variable_t dst_value, variable_t src_value) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {eq(dst_value, src_value)};
    case Op::NE: return {neq(dst_value, src_value)};
    case Op::GE: return {dst_value >= src_value}; // FIX unsigned
    case Op::SGE: return {dst_value >= src_value};
    case Op::LE: return {dst_value <= src_value, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= src_value};
    case Op::GT: return {dst_value > src_value}; // FIX unsigned
    case Op::SGT: return {dst_value > src_value};
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return {src_value > dst_value}; // FIX unsigned
    case Op::SLT: return {src_value > dst_value};
    case Op::SET: throw std::exception();
    case Op::NSET: return {};
    }
    return {};
}

inline bool is_unsigned_cmp(Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
    case Op::GE:
    case Op::LE:
    case Op::GT:
    case Op::LT: return true;
    default: return false;
    }
    return {};
}

class ebpf_domain_t final {
  public:
    using variable_vector_t = std::vector<variable_t>;
    typedef void check_require_func_t(NumAbsDomain&, const linear_constraint_t&, std::string);

  private:
    /// Mapping from variables (including registers, types, offsets,
    /// memory locations, etc.) to numeric intervals or relationships
    /// to other variables.
    NumAbsDomain m_inv;

    /// Represents the stack as a memory region, i.e., an array of bytes,
    /// allowing mapping to variable in the m_inv numeric domains
    /// while dealing with overlapping byte ranges.
    array_domain_t stack;

    std::function<check_require_func_t> check_require{};

  public:
    void set_require_check(std::function<check_require_func_t> f) { check_require = std::move(f); }

    static ebpf_domain_t top() {
        ebpf_domain_t abs;
        abs.set_to_top();
        return abs;
    }

    static ebpf_domain_t bottom() {
        ebpf_domain_t abs;
        abs.set_to_bottom();
        return abs;
    }

  public:
    ebpf_domain_t() : m_inv(NumAbsDomain::top()) {}

    ebpf_domain_t(NumAbsDomain inv, array_domain_t stack) : m_inv(std::move(inv)), stack(stack) {}

    void set_to_top() {
        m_inv.set_to_top();
        stack.set_to_top();
    }

    void set_to_bottom() { m_inv.set_to_bottom(); }

    bool is_bottom() const { return m_inv.is_bottom(); }

    bool is_top() const { return m_inv.is_top() && stack.is_top(); }

    bool operator<=(const ebpf_domain_t& other) {
        return m_inv <= other.m_inv && stack <= other.stack;
    }

    bool operator==(ebpf_domain_t other) {
        return stack == other.stack && m_inv <= other.m_inv && other.m_inv <= m_inv;
    }

    void operator|=(ebpf_domain_t&& other) {
        if (is_bottom()) {
            *this = other;
            return;
        }
        m_inv |= other.m_inv;
        stack |= other.stack;
    }

    void operator|=(const ebpf_domain_t& other) {
        ebpf_domain_t tmp{other};
        operator|=(std::move(tmp));
    }

    ebpf_domain_t operator|(ebpf_domain_t&& other) {
        return ebpf_domain_t(m_inv | other.m_inv, stack | other.stack);
    }

    ebpf_domain_t operator|(const ebpf_domain_t& other) & {
        return ebpf_domain_t(m_inv | other.m_inv, stack | other.stack);
    }

    ebpf_domain_t operator|(const ebpf_domain_t& other) && {
        return ebpf_domain_t(m_inv | other.m_inv, stack | other.stack);
    }

    ebpf_domain_t operator&(ebpf_domain_t other) {
        return ebpf_domain_t(m_inv & std::move(other.m_inv), stack & other.stack);
    }

    ebpf_domain_t widen(const ebpf_domain_t& other) {
        return ebpf_domain_t(m_inv.widen(other.m_inv), stack | other.stack);
    }

    ebpf_domain_t widening_thresholds(const ebpf_domain_t& other, const iterators::thresholds_t& ts) {
        return ebpf_domain_t(m_inv.widening_thresholds(other.m_inv, ts), stack | other.stack);
    }

    ebpf_domain_t narrow(const ebpf_domain_t& other) {
        return ebpf_domain_t(m_inv.narrow(other.m_inv), stack & other.stack);
    }

    interval_t operator[](variable_t x) { return m_inv[x]; }

    void forget(const variable_vector_t& variables) {
        // TODO: forget numerical values
        if (is_bottom() || is_top()) {
            return;
        }

        m_inv.forget(variables);
    }

    void operator+=(const linear_constraint_t& cst) { m_inv += cst; }

    void operator-=(variable_t var) { m_inv -= var; }

    void assign(variable_t x, const linear_expression_t& e) { m_inv.assign(x, e); }
    void assign(variable_t x, int e) { m_inv.set(x, interval_t(number_t(e))); }

    void apply(arith_binop_t op, variable_t x, variable_t y, const number_t& z) { m_inv.apply(op, x, y, z); }

    void apply(arith_binop_t op, variable_t x, variable_t y, variable_t z) { m_inv.apply(op, x, y, z); }

    void apply(bitwise_binop_t op, variable_t x, variable_t y, variable_t z) { m_inv.apply(op, x, y, z); }

    void apply(bitwise_binop_t op, variable_t x, variable_t y, const number_t& k) { m_inv.apply(op, x, y, k); }

    void apply(binop_t op, variable_t x, variable_t y, const number_t& z) {
        std::visit([&](auto top) { apply(top, x, y, z); }, op);
    }

    void apply(binop_t op, variable_t x, variable_t y, variable_t z) {
        std::visit([&](auto top) { apply(top, x, y, z); }, op);
    }

  private:
    static NumAbsDomain when(NumAbsDomain inv, const linear_constraint_t& cond) {
        inv += cond;
        return inv;
    }

    void scratch_caller_saved_registers() {
        for (int i = R1_ARG; i <= R5_ARG; i++) {
            auto reg = reg_pack(i);
            havoc(reg.value);
            havoc(reg.offset);
            havoc(reg.type);
        }
    }

    void forget_packet_pointers() {
        using namespace dsl_syntax;
        for (variable_t v : variable_t::get_type_variables()) {
            // TODO: this is sufficient, but for clarity it may be useful to forget the offset and value too.
           if (m_inv.intersect(v == T_PACKET))
               m_inv -= v;
        }
    }

    void apply(NumAbsDomain& inv, binop_t op, variable_t x, variable_t y, const number_t& z, bool finite_width = false) {
        inv.apply(op, x, y, z);
        if (finite_width)
            overflow(x);
    }

    void apply(NumAbsDomain& inv, binop_t op, variable_t x, variable_t y, variable_t z, bool finite_width = false) {
        inv.apply(op, x, y, z);
        if (finite_width)
            overflow(x);
    }

    void add(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2); }
    void add(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2); }
    void sub(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2); }
    void sub(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2); }
    void add_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2, true); }
    void add_overflow(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2, true); }
    void sub_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2, true); }
    void sub_overflow(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2, true); }
    void neg(variable_t lhs) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, (number_t)-1, true); }
    void mul(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, op2, true); }
    void mul(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, op2, true); }
    void div(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SDIV, lhs, lhs, op2, true); }
    void div(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::SDIV, lhs, lhs, op2, true); }
    void udiv(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::UDIV, lhs, lhs, op2, true); }
    void udiv(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::UDIV, lhs, lhs, op2, true); }
    void rem(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SREM, lhs, lhs, op2, true); }
    void rem(variable_t lhs, const number_t& op2, bool mod = true) {
        apply(m_inv, crab::arith_binop_t::SREM, lhs, lhs, op2, mod);
    }
    void urem(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::UREM, lhs, lhs, op2, true); }
    void urem(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::UREM, lhs, lhs, op2, true); }

    void bitwise_and(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::AND, lhs, lhs, op2); }
    void bitwise_and(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::AND, lhs, lhs, op2); }
    void bitwise_or(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::OR, lhs, lhs, op2); }
    void bitwise_or(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::OR, lhs, lhs, op2); }
    void bitwise_xor(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::XOR, lhs, lhs, op2); }
    void bitwise_xor(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::XOR, lhs, lhs, op2); }
    void shl_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::SHL, lhs, lhs, op2, true); }
    void shl_overflow(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::SHL, lhs, lhs, op2, true); }
    void lshr(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
    void lshr(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
    void ashr(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }
    void ashr(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }

    void assume(const linear_constraint_t& cst) { assume(m_inv, cst); }
    static void assume(NumAbsDomain& inv, const linear_constraint_t& cst) { inv += cst; }

    void require(NumAbsDomain& inv, const linear_constraint_t& cst, std::string s) {
        if (check_require)
            check_require(inv, cst, std::move(s));
        assume(inv, cst);
    }

    void require_false(NumAbsDomain& inv, std::string s) {
        using namespace dsl_syntax;
        require(m_inv, linear_expression_t(0) != 0, s);
    }

    /// Forget everything we know about the value of a variable.
    void havoc(variable_t v) { m_inv -= v; }

    void assign(variable_t lhs, variable_t rhs) { m_inv.assign(lhs, rhs); }

    void assert_no_pointer(reg_pack_t reg) {
        using namespace dsl_syntax;
        require(m_inv, reg.type == T_NUM, "invalid operation on a non-numerical value");
        havoc(reg.offset);
    }

    static linear_constraint_t is_shared(variable_t v) {
        using namespace dsl_syntax;
        return v > T_SHARED;
    }

    static linear_constraint_t is_pointer(reg_pack_t r) {
        using namespace dsl_syntax;
        return r.type >= T_CTX;
    }

    void overflow(variable_t lhs) {
        using namespace dsl_syntax;
        auto interval = m_inv[lhs];
        // handle overflow, assuming 64 bit
        number_t max(std::numeric_limits<int64_t>::max() / 2);
        number_t min(std::numeric_limits<int64_t>::min() / 2);
        if (interval.lb() <= min || interval.ub() >= max)
            havoc(lhs);
    }

  public:
    // All transfer functions are operations on this abstract domain.
    // It provides the basic operations of setting a variable or adding
    // a constraint, so all of them would be converted to some kind of
    // constraint that is added to the domain.

    void operator()(const basic_block_t& bb, bool check_termination) {
        for (const Instruction& statement : bb) {
            std::visit(*this, statement);
        }
        if (check_termination) {
            // +1 to avoid being tricked by empty loops
            add(variable_t::instruction_count(), z_number((unsigned)bb.size() + 1));
        }
    }

    int get_instruction_count_upper_bound() {
        const auto& ub = m_inv[variable_t::instruction_count()].ub();
        return (ub.is_finite() && ub.number().value().fits_sint()) ? (int)ub.number().value() : INT_MAX;
    }

    void operator()(Assume const& s) {
        using namespace dsl_syntax;
        Condition cond = s.cond;
        auto dst = reg_pack(cond.left);
        if (std::holds_alternative<Reg>(cond.right)) {
            auto src = reg_pack(std::get<Reg>(cond.right));
            int stype = get_type(src.type);
            int dtype = get_type(dst.type);
            if (stype == dtype) {
                switch (stype) {
                    case T_MAP: break;
                    case T_UNINIT: break;
                    case T_NUM: {
                        if (!is_unsigned_cmp(cond.op))
                            for (const linear_constraint_t& cst : jmp_to_cst_reg(cond.op, dst.value, src.value))
                                m_inv += cst;
                        return;
                    }
                    default: {
                        m_inv += jmp_to_cst_offsets_reg(cond.op, dst.offset, src.offset);
                        return;
                    }
                }
            }
            NumAbsDomain different{m_inv};
            different += neq(dst.type, src.type);

            NumAbsDomain null_src{different};
            null_src += is_pointer(dst);
            NumAbsDomain null_dst{different};
            null_dst += is_pointer(src);

            m_inv += eq(dst.type, src.type);

            NumAbsDomain numbers{m_inv};
            numbers += dst.type == T_NUM;
            if (!is_unsigned_cmp(cond.op))
                for (const linear_constraint_t& cst : jmp_to_cst_reg(cond.op, dst.value, src.value))
                    numbers += cst;

            m_inv += is_pointer(dst);
            m_inv += jmp_to_cst_offsets_reg(cond.op, dst.offset, src.offset);

            m_inv |= std::move(numbers);

            m_inv |= std::move(null_src);
            m_inv |= std::move(null_dst);
        } else {
            int imm = static_cast<int>(std::get<Imm>(cond.right).v);
            for (const linear_constraint_t& cst : jmp_to_cst_imm(cond.op, dst.value, imm))
                assume(cst);
        }
    }

    void operator()(Undefined const& a) {}
    void operator()(Un const& stmt) {
        auto dst = reg_pack(stmt.dst);
        switch (stmt.op) {
        case Un::Op::LE16:
        case Un::Op::LE32:
        case Un::Op::LE64:
            havoc(dst.value);
            assert_no_pointer(dst);
            break;
        case Un::Op::NEG:
            neg(dst.value);
            assert_no_pointer(dst);
            break;
        }
    }
    void operator()(Exit const& a) {}
    void operator()(Jmp const& a) {}

    void operator()(const Comparable& s) { require(m_inv, eq(reg_pack(s.r1).type, reg_pack(s.r2).type), to_string(s)); }

    void operator()(const Addable& s) {
        using namespace dsl_syntax;
        linear_constraint_t cond = reg_pack(s.ptr).type > T_NUM;
        NumAbsDomain is_ptr{m_inv};
        is_ptr += cond;
        require(is_ptr, reg_pack(s.num).type == T_NUM, "only numbers can be added to pointers (" + to_string(s) + ")");

        m_inv += cond.negate();
        m_inv |= std::move(is_ptr);
    }

    void operator()(const ValidSize& s) {
        using namespace dsl_syntax;
        auto r = reg_pack(s.reg);
        require(m_inv, s.can_be_zero ? r.value >= 0 : r.value > 0, to_string(s));
    }

    void operator()(const ValidMapKeyValue& s) {
        using namespace dsl_syntax;

        // Get the actual map_fd value to look up the key size and value size.
        auto fd_reg = reg_pack(s.map_fd_reg);
        interval_t fd_interval = operator[](fd_reg.value);
        std::optional<EbpfMapType> map_type;
        uint32_t max_entries = 0;
        if (fd_interval.is_bottom()) {
            m_inv.set(variable_t::map_value_size(), interval_t::bottom());
            m_inv.set(variable_t::map_key_size(), interval_t::bottom());
        } else {
            std::optional<number_t> fd_opt = fd_interval.singleton();
            if (fd_opt.has_value()) {
                number_t map_fd = *fd_opt;
                EbpfMapDescriptor& map_descriptor = global_program_info.platform->get_map_descriptor((int)map_fd);
                m_inv.assign(variable_t::map_value_size(), (int)map_descriptor.value_size);
                m_inv.assign(variable_t::map_key_size(), (int)map_descriptor.key_size);
                map_type = global_program_info.platform->get_map_type(map_descriptor.type);
                max_entries = map_descriptor.max_entries;
            } else {
                m_inv.set(variable_t::map_value_size(), interval_t::top());
                m_inv.set(variable_t::map_key_size(), interval_t::top());
            }
        }

        auto access_reg = reg_pack(s.access_reg);

        variable_t lb = access_reg.offset;
        variable_t width = s.key ? variable_t::map_key_size() : variable_t::map_value_size();
        linear_expression_t ub = lb + width;
        std::string m = std::string(" (") + to_string(s) + ")";
        require(m_inv, access_reg.type >= T_STACK, "Only stack or packet can be used as a parameter" + m);
        require(m_inv, access_reg.type <= T_PACKET, "Only stack or packet can be used as a parameter" + m);

        auto when_stack = when(m_inv, access_reg.type == T_STACK);
        if (!when_stack.is_bottom()) {
            if (!stack.all_num(when_stack, lb, ub)) {
                require(when_stack, access_reg.type != T_STACK, "Illegal map update with a non-numerical value.");
            } else if (thread_local_options.strict && map_type.has_value() && map_type->is_array) {
                // Get offset value.
                variable_t key_ptr = access_reg.offset;
                std::optional<number_t> offset = m_inv[key_ptr].singleton();
                if (!offset.has_value()) {
                    require_false(m_inv, "Pointer must be a singleton");
                } else if (s.key) {
                    // Look up the value pointed to by the key pointer.
                    variable_t key_value =
                        variable_t::cell_var(data_kind_t::values, (uint64_t)offset.value(), sizeof(uint32_t));

                    require(m_inv, key_value < max_entries, "Array index overflow");
                    require(m_inv, key_value >= 0, "Array index underflow");
                }
            }
        }

        m_inv = check_access_packet(when(m_inv, access_reg.type == T_PACKET), lb, ub, m, false) |
                check_access_stack(when(m_inv, access_reg.type == T_STACK), lb, ub, m);
    }

    void operator()(const ValidAccess& s) {
        using namespace dsl_syntax;

        bool is_comparison_check = s.width == (Value)Imm{0};

        auto reg = reg_pack(s.reg);
        linear_expression_t lb = reg.offset + s.offset;
        linear_expression_t ub = std::holds_alternative<Imm>(s.width)
            ? lb + std::get<Imm>(s.width).v
            : lb + reg_pack(std::get<Reg>(s.width)).value;
        std::string m = std::string(" (") + to_string(s) + ")";

        NumAbsDomain assume_ptr =
            check_access_packet(when(m_inv, reg.type == T_PACKET), lb, ub, m, is_comparison_check) |
            check_access_stack(when(m_inv, reg.type == T_STACK), lb, ub, m) |
            check_access_shared(when(m_inv, is_shared(reg.type)), lb, ub, m, reg.type) |
            check_access_context(when(m_inv, reg.type == T_CTX), lb, ub, m);
        if (is_comparison_check) {
            assume(m_inv, reg.type <= T_NUM);
            m_inv |= std::move(assume_ptr);
            return;
        } else {
            if (s.or_null) {
                require(m_inv, reg.type >= T_NUM, "Must be a pointer or null");
                assume(m_inv, reg.type == T_NUM);
                require(m_inv, reg.value == 0, "Pointers may be compared only to the number 0");
                m_inv |= std::move(assume_ptr);
                return;
            } else {
                require(m_inv, reg.type > T_NUM, "Only pointers can be dereferenced");
                require(m_inv, reg.value > 0, "Possible null access");
                m_inv = std::move(assume_ptr);
                return;
            }
        }
    }

    NumAbsDomain check_access_packet(NumAbsDomain inv, const linear_expression_t& lb, const linear_expression_t& ub, const std::string& s,
                                     bool is_comparison_check) {
        using namespace dsl_syntax;
        require(inv, lb >= variable_t::meta_offset(), std::string("Lower bound must be at least meta_offset") + s);
        if (is_comparison_check)
            require(inv, ub <= MAX_PACKET_OFF,
                    std::string("Upper bound must be at most ") + std::to_string(MAX_PACKET_OFF) + s);
        else
            require(inv, ub <= variable_t::packet_size(),
                    std::string("Upper bound must be at most packet_size") + s);
        return inv;
    }

    NumAbsDomain check_access_stack(NumAbsDomain inv, const linear_expression_t& lb, const linear_expression_t& ub, const std::string& s) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be at least 0") + s);
        require(inv, ub <= EBPF_STACK_SIZE, std::string("Upper bound must be at most EBPF_STACK_SIZE") + s + std::string(", make sure to bounds check any pointer access"));
        return inv;
    }

    NumAbsDomain check_access_shared(NumAbsDomain inv, const linear_expression_t& lb, const linear_expression_t& ub, const std::string& s,
                                     variable_t reg_type) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be at least 0") + s);
        require(inv, ub <= reg_type, std::string("Upper bound must be at most ") + reg_type.name() + s);
        return inv;
    }

    NumAbsDomain check_access_context(NumAbsDomain inv, const linear_expression_t& lb, const linear_expression_t& ub, const std::string& s) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be at least 0") + s);
        require(inv, ub <= global_program_info.type.context_descriptor->size,
                std::string("Upper bound must be at most ") + std::to_string(global_program_info.type.context_descriptor->size) +
                    s);
        return inv;
    }

    void operator()(const ValidStore& s) {
        using namespace dsl_syntax;
        linear_constraint_t cond = reg_pack(s.mem).type != T_STACK;

        NumAbsDomain non_stack{m_inv};
        non_stack += cond;
        require(non_stack, reg_pack(s.val).type == T_NUM, "Only numbers can be stored to externally-visible regions");

        m_inv += cond.negate();
        m_inv |= std::move(non_stack);
    }

    void operator()(const TypeConstraint& s) {
        using namespace dsl_syntax;
        variable_t t = reg_pack(s.reg).type;
        std::string str = to_string(s);
        switch (s.types) {
        case TypeGroup::number: require(m_inv, t == T_NUM, str); break;
        case TypeGroup::map_fd: require(m_inv, t == T_MAP, str); break;
        case TypeGroup::ctx: require(m_inv, t == T_CTX, str); break;
        case TypeGroup::packet: require(m_inv, t == T_PACKET, str); break;
        case TypeGroup::stack: require(m_inv, t == T_STACK, str); break;
        case TypeGroup::shared: require(m_inv, t > T_SHARED, str); break;
        case TypeGroup::non_map_fd: require(m_inv, t >= T_NUM, str); break;
        case TypeGroup::mem: require(m_inv, t >= T_STACK, str); break;
        case TypeGroup::mem_or_num:
            require(m_inv, t >= T_NUM, str);
            require(m_inv, t != T_CTX, str);
            break;
        case TypeGroup::pointer: require(m_inv, t >= T_CTX, str); break;
        case TypeGroup::ptr_or_num: require(m_inv, t >= T_NUM, str); break;
        case TypeGroup::stack_or_packet:
            require(m_inv, t >= T_STACK, str);
            require(m_inv, t <= T_PACKET, str);
            break;
        }
    }

    void operator()(const ZeroOffset& s) {
        using namespace dsl_syntax;
        auto reg = reg_pack(s.reg);
        require(m_inv, reg.offset == 0, to_string(s));
    }

    void operator()(Assert const& stmt) { std::visit(*this, stmt.cst); };

    void operator()(Packet const& a) {
        auto reg = reg_pack(R0_RETURN_VALUE);
        assign(reg.type, T_NUM);
        havoc(reg.offset);
        havoc(reg.value);
        scratch_caller_saved_registers();
    }

    static NumAbsDomain do_load_packet_or_shared(NumAbsDomain inv, reg_pack_t target, const linear_expression_t& addr, int width) {
        if (inv.is_bottom())
            return inv;

        inv.assign(target.type, T_NUM);
        inv -= target.offset;

        // A 1 or 2 byte copy results in a limited range of values that may be used as array indices.
        if (width == 1) {
            inv.set(target.value, interval_t(0, UINT8_MAX));
        } else if (width == 2) {
            inv.set(target.value, interval_t(0, UINT16_MAX));
        } else {
            inv -= target.value;
        }
        return inv;
    }

    static NumAbsDomain do_load_ctx(NumAbsDomain inv, reg_pack_t target, const linear_expression_t& addr_vague, int width) {
        using namespace dsl_syntax;
        if (inv.is_bottom())
            return inv;

        const ebpf_context_descriptor_t* desc = global_program_info.type.context_descriptor;

        inv -= target.value;

        if (desc->end < 0) {
            inv -= target.offset;
            inv.assign(target.type, T_NUM);
            return inv;
        }

        interval_t interval = inv.eval_interval(addr_vague);
        std::optional<number_t> maybe_addr = interval.singleton();

        bool may_touch_ptr = interval[desc->data] || interval[desc->end] || interval[desc->end];

        if (!maybe_addr) {
            inv -= target.offset;
            if (may_touch_ptr)
                inv -= target.type;
            else
                inv.assign(target.type, T_NUM);
            return inv;
        }

        number_t addr = *maybe_addr;

        if (addr == desc->data) {
            inv.assign(target.offset, 0);
        } else if (addr == desc->end) {
            inv.assign(target.offset, variable_t::packet_size());
        } else if (addr == desc->meta) {
            inv.assign(target.offset, variable_t::meta_offset());
        } else {
            inv -= target.offset;
            if (may_touch_ptr)
                inv -= target.type;
            else
                inv.assign(target.type, T_NUM);
            return inv;
        }
        inv.assign(target.type, T_PACKET);
        inv += 4098 <= target.value;
        inv += target.value <= PTR_MAX;
        return inv;
    }

    NumAbsDomain do_load_stack(NumAbsDomain inv, reg_pack_t target, const linear_expression_t& addr, int width) {
        if (width == 1 || width == 2 || width == 4 || width == 8) {
            inv.assign(target.type, stack.load(inv, data_kind_t::types, addr, width));
            inv.assign(target.value, stack.load(inv,  data_kind_t::values, addr, width));
            inv.assign(target.offset, stack.load(inv, data_kind_t::offsets, addr, width));
        } else {
            inv.assign(target.type, stack.load(inv, data_kind_t::types, addr, width));
            inv -= target.value;
            inv -= target.offset;
        }
        return inv;
    }

    void do_load(Mem const& b, reg_pack_t target) {
        if (m_inv.is_bottom())
            return;
        using namespace dsl_syntax;
        auto mem_reg = reg_pack(b.access.basereg);
        int width = b.access.width;
        int offset = b.access.offset;
        linear_expression_t addr = mem_reg.offset + (number_t)offset;

        if (b.access.basereg.v == R10_STACK_POINTER) {
            m_inv = do_load_stack(std::move(m_inv), target, addr, width);
            return;
        }

        int type = get_type(mem_reg.type);
        if (type == T_UNINIT) {
            return;
        }

        switch (type) {
            case T_UNINIT: {
                m_inv = do_load_ctx(when(m_inv, mem_reg.type == T_CTX), target, addr, width) |
                        do_load_packet_or_shared(when(m_inv, mem_reg.type >= T_PACKET), target, addr, width) |
                        do_load_stack(when(m_inv, mem_reg.type == T_STACK), target, addr, width);
                return;
            }
            case T_MAP: return;
            case T_NUM: return;
            case T_CTX: m_inv = do_load_ctx(std::move(m_inv), target, addr, width); break;
            case T_STACK: m_inv = do_load_stack(std::move(m_inv), target, addr, width); break;
            default: m_inv = do_load_packet_or_shared(std::move(m_inv), target, addr, width); break;
        }
    }

    int get_type(variable_t v) {
        auto res = m_inv[v].singleton();
        if (!res)
            return T_UNINIT;
        return (int)*res;
    }

    static int get_type(int t) { return t; }

    template <typename A, typename X, typename Y, typename Z>
    void do_store_stack(NumAbsDomain& inv, int width, A addr, X val_type, Y val_value,
                        std::optional<Z> opt_val_offset) {
        inv.assign(stack.store(inv, data_kind_t::types, addr, width, val_type), val_type);
        if (width == 8) {
            inv.assign(stack.store(inv, data_kind_t::values, addr, width, val_value), val_value);
            if (opt_val_offset && get_type(val_type) != T_NUM)
                inv.assign(stack.store(inv, data_kind_t::offsets, addr, width, *opt_val_offset), *opt_val_offset);
            else
                stack.havoc(inv, data_kind_t::offsets, addr, width);
        } else if ((width == 1 || width == 2 || width == 4) && get_type(val_type) == T_NUM) {
            // Keep track of numbers on the stack that might be used as array indices.
            inv.assign(stack.store(inv, data_kind_t::values, addr, width, val_value), val_value);
            stack.havoc(inv, data_kind_t::offsets, addr, width);
        } else {
            stack.havoc(inv, data_kind_t::values, addr, width);
            stack.havoc(inv, data_kind_t::offsets, addr, width);
        }
    }

    void operator()(Mem const& b) {
        if (std::holds_alternative<Reg>(b.value)) {
            auto data_reg = reg_pack(std::get<Reg>(b.value));
            if (b.is_load) {
                do_load(b, data_reg);
            } else {
                do_mem_store(b, data_reg.type, data_reg.value, data_reg.offset);
            }
        } else {
            do_mem_store(b, T_NUM, std::get<Imm>(b.value).v, {});
        }
    }

    template <typename Type, typename Value>
    void do_mem_store(Mem const& b, Type val_type, Value val_value, std::optional<variable_t> opt_val_offset) {
        if (m_inv.is_bottom())
            return;
        using namespace dsl_syntax;
        auto mem_reg = reg_pack(b.access.basereg);
        int width = b.access.width;
        int offset = b.access.offset;
        if (b.access.basereg.v == R10_STACK_POINTER) {
            int addr = EBPF_STACK_SIZE + offset;
            do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
            return;
        }
        linear_expression_t addr = linear_expression_t(mem_reg.offset) + offset;
        switch (get_type(mem_reg.type)) {
            case T_STACK: do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset); return;
            case T_UNINIT: { //maybe stack
                NumAbsDomain assume_not_stack(m_inv);
#ifdef _MSC_VER
                // MSVC seems to have a harder time coercing the right things, so force
                // the correct interpretations.
                assume_not_stack += (linear_constraint_t)(mem_reg.type != T_STACK);
                m_inv += crab::dsl_syntax::operator==(mem_reg.type, T_STACK);
#else
                assume_not_stack += mem_reg.type != T_STACK;
                m_inv += mem_reg.type == T_STACK;
#endif
                if (!m_inv.is_bottom()) {
                    do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
                }
                m_inv |= std::move(assume_not_stack);
            }
            default: break;
        }
    }

    void operator()(LockAdd const& a) {
        // nothing to do here
    }

    void operator()(Call const& call) {
        using namespace dsl_syntax;
        if (m_inv.is_bottom())
            return;
        for (ArgSingle param : call.singles) {
            switch (param.kind) {
            case ArgSingle::Kind::ANYTHING:
            case ArgSingle::Kind::MAP_FD:
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
            case ArgSingle::Kind::PTR_TO_CTX:
                // Do nothing. We don't track the content of relevant memory regions
                break;
            }
        }
        for (ArgPair param : call.pairs) {
            switch (param.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
            case ArgPair::Kind::PTR_TO_MEM:
                // Do nothing. No side effect allowed.
                break;

            case ArgPair::Kind::PTR_TO_UNINIT_MEM: {
                // Pointer to a memory region that the called function may change,
                // so we must havoc.
                interval_t t = m_inv[reg_pack(param.mem).type];
                if (t[T_STACK]) {
                    variable_t addr = reg_pack(param.mem).offset;
                    variable_t width = reg_pack(param.size).value;
                    stack.havoc(m_inv, data_kind_t::types, addr, width);
                    stack.havoc(m_inv, data_kind_t::values, addr, width);
                    stack.havoc(m_inv, data_kind_t::offsets, addr, width);
                    if (t.singleton()) {
                        // Functions are not allowed to write sensitive data,
                        // and initialization is guaranteed
                        stack.store_numbers(m_inv, addr, width);
                    }
                }
            }
            }
        }

        if (call.func == call.reallocate_packet) {
            forget_packet_pointers();
        }

        scratch_caller_saved_registers();
        auto r0 = reg_pack(R0_RETURN_VALUE);
        havoc(r0.value);
        if (call.returns_map) {
            // no support for map-in-map yet:
            //   if (machine.info.map_defs.at(map_type).type == MapType::ARRAY_OF_MAPS
            //    || machine.info.map_defs.at(map_type).type == MapType::HASH_OF_MAPS) { }
            // This is the only way to get a null pointer - note the `<=`:
            m_inv += 0 <= r0.value;
            m_inv += r0.value <= PTR_MAX;
            assign(r0.offset, 0);
            assign(r0.type, variable_t::map_value_size());
        } else {
            havoc(r0.offset);
            assign(r0.type, T_NUM);
            // assume(r0.value < 0); for VOID, which is actually "no return if succeed".
        }
    }

    void operator()(LoadMapFd const& ins) {
        auto dst = reg_pack(ins.dst);
        assign(dst.type, T_MAP);
        assign(dst.value, ins.mapfd);
        havoc(dst.offset);
    }

    void operator()(Bin const& bin) {
        using namespace dsl_syntax;

        auto dst = reg_pack(bin.dst);

        if (std::holds_alternative<Imm>(bin.v)) {
            // dst += K
            int imm = static_cast<int>(std::get<Imm>(bin.v).v);
            switch (bin.op) {
            case Bin::Op::MOV:
                assign(dst.value, imm);
                assign(dst.type, T_NUM);
                havoc(dst.offset);
                break;
            case Bin::Op::ADD:
                if (imm == 0)
                    return;
                add_overflow(dst.value, imm);
                add(dst.offset, imm);
                break;
            case Bin::Op::SUB:
                if (imm == 0)
                    return;
                sub_overflow(dst.value, imm);
                sub(dst.offset, imm);
                break;
            case Bin::Op::MUL:
                mul(dst.value, imm);
                assert_no_pointer(dst);
                break;
            case Bin::Op::DIV:
                div(dst.value, imm);
                assert_no_pointer(dst);
                break;
            case Bin::Op::MOD:
                rem(dst.value, imm);
                assert_no_pointer(dst);
                break;
            case Bin::Op::OR:
                bitwise_or(dst.value, imm);
                assert_no_pointer(dst);
                break;
            case Bin::Op::AND:
                // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
                bitwise_and(dst.value, imm);
                if ((int32_t)imm > 0) {
                    assume(dst.value <= imm);
                    assume(0 <= dst.value);
                }
                assert_no_pointer(dst);
                break;
            case Bin::Op::LSH:
                // avoid signedness and overflow issues in shl_overflow(dst.value, imm);
                shl_overflow(dst.value, imm);
                assert_no_pointer(dst);
                break;
            case Bin::Op::RSH:
                // avoid signedness and overflow issues in lshr(dst.value, imm);
                havoc(dst.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::ARSH:
                // avoid signedness and overflow issues in ashr(dst.value, imm);
                // = (int64_t)dst >> imm;
                havoc(dst.value);
                // assume(dst.value <= (1 << (64 - imm)));
                // assume(dst.value >= -(1 << (64 - imm)));
                assert_no_pointer(dst);
                break;
            case Bin::Op::XOR:
                bitwise_xor(dst.value, imm);
                assert_no_pointer(dst);
                break;
            }
        } else {
            // dst op= src
            auto src = reg_pack(std::get<Reg>(bin.v));
            switch (bin.op) {
            case Bin::Op::ADD: {
                auto stype = get_type(src.type);
                auto dtype = get_type(dst.type);
                if (stype == T_NUM && dtype == T_NUM) {
                    add_overflow(dst.value, src.value);
                } else if (dtype == T_NUM) {
                    apply(m_inv, crab::arith_binop_t::ADD, dst.value, src.value, dst.value, true);
                    apply(m_inv, crab::arith_binop_t::ADD, dst.offset, src.offset, dst.value, false);
                    m_inv.assign(dst.type, src.type);
                } else if (stype == T_NUM) {
                    add_overflow(dst.value, src.value);
                    add(dst.offset, src.value);
                } else {
                    havoc(dst.type);
                    havoc(dst.value);
                    havoc(dst.offset);
                }
                break;
            }
            case Bin::Op::SUB: {
                auto stype = get_type(src.type);
                auto dtype = get_type(dst.type);
                if (dtype == T_NUM && stype == T_NUM) {
                    sub_overflow(dst.value, src.value);
                } else if (stype == T_NUM) {
                    sub_overflow(dst.value, src.value);
                    sub(dst.offset, src.value);
                } else if (stype == dtype && stype < 0) { // subtracting non-shared pointers
                    apply(m_inv, crab::arith_binop_t::SUB, dst.value, dst.offset, src.offset, true);
                    havoc(dst.offset);
                    assign(dst.type, T_NUM);
                } else {
                    havoc(dst.type);
                    havoc(dst.value);
                    havoc(dst.offset);
                }
                break;
            }
            case Bin::Op::MUL:
                mul(dst.value, src.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::DIV:
                // DIV is not checked for zerodiv
                div(dst.value, src.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::MOD:
                // See DIV comment
                rem(dst.value, src.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::OR:
                bitwise_or(dst.value, src.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::AND:
                bitwise_and(dst.value, src.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::LSH:
                shl_overflow(dst.value, src.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::RSH:
                havoc(dst.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::ARSH:
                havoc(dst.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::XOR:
                bitwise_xor(dst.value, src.value);
                assert_no_pointer(dst);
                break;
            case Bin::Op::MOV:
                assign(dst.value, src.value);
                assign(dst.offset, src.offset);
                assign(dst.type, src.type);
                break;
            }
        }
        if (!bin.is64) {
            bitwise_and(dst.value, UINT32_MAX);
        }
    }

    friend std::ostream& operator<<(std::ostream& o, ebpf_domain_t dom) {
        if (dom.is_bottom()) {
            o << "_|_";
        } else {
            o << dom.m_inv << "\nStack: " << dom.stack;
        }
        return o;
    }

    static ebpf_domain_t setup_entry(bool check_termination) {
        using namespace dsl_syntax;

        ebpf_domain_t inv;
        auto r10 = reg_pack(R10_STACK_POINTER);
        inv += EBPF_STACK_SIZE <= r10.value;
        inv += r10.value <= PTR_MAX;
        inv.assign(r10.offset, EBPF_STACK_SIZE);
        inv.assign(r10.type, T_STACK);

        auto r1 = reg_pack(R1_ARG);
        inv += 1 <= r1.value;
        inv += r1.value <= PTR_MAX;
        inv.assign(r1.offset, 0);
        inv.assign(r1.type, T_CTX);

        inv += 0 <= variable_t::packet_size();
        inv += variable_t::packet_size() < MAX_PACKET_OFF;
        if (global_program_info.type.context_descriptor->meta >= 0) {
            inv += variable_t::meta_offset() <= 0;
            inv += variable_t::meta_offset() >= -4098;
        } else {
            inv.assign(variable_t::meta_offset(), 0);
        }
        if (check_termination) {
            inv.assign(variable_t::instruction_count(), 0);
        }
        return inv;
    }
}; // end ebpf_domain_t

} // namespace crab
