#pragma once

/*
   Implementation of the abstract transfer functions by reducing them
   to abstract domain operations.
*/
#include <iostream>
#include <limits>
#include <variant>

#include "crab/abstract_domain_operators.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

#include "config.hpp"
#include "dsl_syntax.hpp"
#include "spec_prototypes.hpp"
#include "spec_type_descriptors.hpp"

namespace crab {
/**
 * Abstract forward transformer for all statements.
 **/
variable_t reg_value(int i) { return variable_t::reg(data_kind_t::values, i); }
variable_t reg_offset(int i) { return variable_t::reg(data_kind_t::offsets, i); }
variable_t reg_type(int i) { return variable_t::reg(data_kind_t::types, i); }

variable_t reg_value(Reg i) { return reg_value(i.v); }
variable_t reg_offset(Reg i) { return reg_offset(i.v); }
variable_t reg_type(Reg i) { return reg_type(i.v); }

inline linear_constraint_t eq(variable_t a, variable_t b) {
    using namespace dsl_syntax;
    return {a - b, linear_constraint_t::EQUALITY};
}

inline linear_constraint_t neq(variable_t a, variable_t b) {
    using namespace dsl_syntax;
    return {a - b, linear_constraint_t::DISEQUATION};
};

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
    case Op::GT: return dst_offset >= src_offset + 1;
    case Op::SGT: return dst_offset >= src_offset + 1; // pointer comparison is unsigned
    case Op::SLT: return src_offset >= dst_offset + 1;
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return src_offset >= dst_offset + 1; // FIX unsigned
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
    case Op::GT: return {dst_value >= (unsigned)imm + 1}; // FIX unsigned
    case Op::SGT: return {dst_value >= imm + 1};
    case Op::LT: return {dst_value <= (unsigned)imm - 1}; // FIX unsigned
    case Op::SLT: return {dst_value <= imm - 1};
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
    case Op::GT: return {dst_value >= src_value + 1}; // FIX unsigned
    case Op::SGT: return {dst_value >= src_value + 1};
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return {src_value >= dst_value + 1}; // FIX unsigned
    case Op::SLT: return {src_value >= dst_value + 1};
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

template <typename AbsDomain>
class intra_abs_transformer {
  public:
    AbsDomain m_inv;

  private:
    static AbsDomain when(AbsDomain inv, linear_constraint_t cond) {
        inv += cond;
        return inv;
    }

    void scratch_caller_saved_registers() {
        for (int i = 1; i <= 5; i++) {
            havoc(reg_value(i));
            havoc(reg_offset(i));
            havoc(reg_type(i));
        }
    }

    template <typename NumOrVar>
    void apply(AbsDomain& inv, binop_t op, variable_t x, variable_t y, NumOrVar z, bool finite_width = false) {
        inv.apply(op, x, y, z);
        if (finite_width)
            overflow(x);
    }

    void add(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2); }
    void add(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2); }
    void sub(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2); }
    void sub(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2); }
    void add_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2, true); }
    void add_overflow(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2, true); }
    void sub_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2, true); }
    void sub_overflow(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2, true); }
    void neg(variable_t lhs) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, (number_t)-1, true); }
    void mul(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, op2, true); }
    void mul(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, op2, true); }
    void div(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SDIV, lhs, lhs, op2, true); }
    void div(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::SDIV, lhs, lhs, op2, true); }
    void udiv(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::UDIV, lhs, lhs, op2, true); }
    void udiv(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::UDIV, lhs, lhs, op2, true); }
    void rem(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SREM, lhs, lhs, op2, true); }
    void rem(variable_t lhs, number_t op2, bool mod = true) {
        apply(m_inv, crab::arith_binop_t::SREM, lhs, lhs, op2, mod);
    }
    void urem(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::UREM, lhs, lhs, op2, true); }
    void urem(variable_t lhs, number_t op2) { apply(m_inv, crab::arith_binop_t::UREM, lhs, lhs, op2, true); }

    void bitwise_and(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::AND, lhs, lhs, op2); }
    void bitwise_and(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::AND, lhs, lhs, op2); }
    void bitwise_or(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::OR, lhs, lhs, op2); }
    void bitwise_or(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::OR, lhs, lhs, op2); }
    void bitwise_xor(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::XOR, lhs, lhs, op2); }
    void bitwise_xor(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::XOR, lhs, lhs, op2); }
    void shl_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::SHL, lhs, lhs, op2, true); }
    void shl_overflow(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::SHL, lhs, lhs, op2, true); }
    void lshr(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
    void lshr(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
    void ashr(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }
    void ashr(variable_t lhs, number_t op2) { apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }

  protected:
    void assume(const linear_constraint_t& cst) { assume(m_inv, cst); }
    void assume(AbsDomain& inv, const linear_constraint_t& cst) { inv += cst; }

    void require(const linear_constraint_t& cst, std::string s) { require(this->m_inv, cst, s); }
    virtual void require(AbsDomain& inv, const linear_constraint_t& cst, std::string s) { assume(inv, cst); }

    void havoc(variable_t v) { m_inv -= v; }
    void assign(variable_t lhs, variable_t rhs) { m_inv.assign(lhs, rhs); }
    void assign(variable_t lhs, number_t rhs) { m_inv.assign(lhs, rhs); }

    void no_pointer(int i) {
        assign(reg_type(i), T_NUM);
        havoc(reg_offset(i));
    };
    void no_pointer(Reg r) { no_pointer(r.v); }

    static linear_constraint_t is_shared(variable_t v) {
        using namespace dsl_syntax;
        return v > T_SHARED;
    }

    static linear_constraint_t is_pointer(Reg v) {
        using namespace dsl_syntax;
        return reg_type(v) >= T_CTX;
    }
    static linear_constraint_t is_init(Reg v) {
        using namespace dsl_syntax;
        return reg_type(v) > T_UNINIT;
    }
    static linear_constraint_t is_shared(Reg v) { return is_shared(reg_type(v)); }
    static linear_constraint_t is_not_num(Reg v) {
        using namespace dsl_syntax;
        return reg_type(v) > T_NUM;
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
    intra_abs_transformer(const AbsDomain& inv) : m_inv(inv) {}

    void operator()(Assume const& s) {
        using namespace dsl_syntax;
        Condition cond = s.cond;
        Reg dst = cond.left;
        variable_t dst_value = reg_value(dst);
        variable_t dst_offset = reg_offset(dst);
        variable_t dst_type = reg_type(dst);
        if (std::holds_alternative<Reg>(cond.right)) {
            Reg src = std::get<Reg>(cond.right);
            variable_t src_value = reg_value(src);
            variable_t src_offset = reg_offset(src);
            variable_t src_type = reg_type(src);
            AbsDomain different{m_inv};
            different += neq(dst_type, src_type);

            AbsDomain null_src{different};
            null_src += is_pointer(dst);
            AbsDomain null_dst{different};
            null_dst += is_pointer(src);

            m_inv += eq(dst_type, src_type);

            AbsDomain numbers{m_inv};
            numbers += dst_type == T_NUM;
            if (!is_unsigned_cmp(cond.op))
                for (const linear_constraint_t& cst : jmp_to_cst_reg(cond.op, dst_value, src_value))
                    numbers += cst;

            m_inv += is_pointer(dst);
            m_inv += jmp_to_cst_offsets_reg(cond.op, dst_offset, src_offset);

            m_inv |= std::move(numbers);

            m_inv |= std::move(null_src);
            m_inv |= std::move(null_dst);
        } else {
            int imm = static_cast<int>(std::get<Imm>(cond.right).v);
            for (const linear_constraint_t& cst : jmp_to_cst_imm(cond.op, dst_value, imm))
                assume(cst);
        }
    }

    void operator()(Undefined const& a) {}
    void operator()(Un const& stmt) {
        switch (stmt.op) {
        case Un::Op::LE16:
        case Un::Op::LE32:
        case Un::Op::LE64:
            havoc(reg_value(stmt.dst));
            no_pointer(stmt.dst);
            break;
        case Un::Op::NEG:
            neg(reg_value(stmt.dst));
            no_pointer(stmt.dst);
            break;
        }
    }
    void operator()(Exit const& a) {}
    void operator()(Jmp const& a) {}

    void operator()(const Comparable& s) { require(m_inv, eq(reg_type(s.r1), reg_type(s.r2)), to_string(s)); }

    void operator()(const Addable& s) {
        using namespace dsl_syntax;
        linear_constraint_t cond = reg_type(s.ptr) > T_NUM;
        AbsDomain is_ptr{m_inv};
        is_ptr += cond;
        require(is_ptr, reg_type(s.num) == T_NUM, "only numbers can be added to pointers (" + to_string(s) + ")");

        m_inv += cond.negate();
        m_inv |= std::move(is_ptr);
    }

    void operator()(const ValidSize& s) {
        using namespace dsl_syntax;
        variable_t r = reg_value(s.reg);
        require(s.can_be_zero ? r >= 0 : r > 0, to_string(s));
    }

    void operator()(const ValidMapKeyValue& s) {
        using namespace dsl_syntax;

        variable_t v = reg_value(s.map_fd_reg);
        apply(m_inv, crab::bitwise_binop_t::LSHR, variable_t::map_value_size(), v, (number_t)14);
        variable_t mk = variable_t::map_key_size();
        apply(m_inv, crab::arith_binop_t::UREM, mk, v, (number_t)(1 << 14));
        lshr(mk, 6);

        variable_t lb = reg_offset(s.access_reg);
        variable_t width = s.key ? variable_t::map_key_size() : variable_t::map_value_size();
        linear_expression_t ub = lb + width;
        std::string m = std::string(" (") + to_string(s) + ")";
        require(m_inv, reg_type(s.access_reg) >= T_STACK, "Only stack or packet can be used as a parameter" + m);
        require(m_inv, reg_type(s.access_reg) <= T_PACKET, "Only stack or packet can be used as a parameter" + m);
        m_inv = check_access_packet(when(m_inv, reg_type(s.access_reg) == T_PACKET), lb, ub, m, false) |
                check_access_stack(when(m_inv, reg_type(s.access_reg) == T_STACK), lb, ub, m);
    }

    void operator()(const ValidAccess& s) {
        using namespace dsl_syntax;

        bool is_comparison_check = s.width == (Value)Imm{0};

        linear_expression_t lb = reg_offset(s.reg) + s.offset;
        linear_expression_t ub;
        if (std::holds_alternative<Imm>(s.width))
            ub = lb + std::get<Imm>(s.width).v;
        else
            ub = lb + reg_value(std::get<Reg>(s.width));
        std::string m = std::string(" (") + to_string(s) + ")";

        AbsDomain assume_ptr =
            check_access_packet(when(m_inv, reg_type(s.reg) == T_PACKET), lb, ub, m, is_comparison_check) |
            check_access_stack(when(m_inv, reg_type(s.reg) == T_STACK), lb, ub, m) |
            check_access_shared(when(m_inv, is_shared(reg_type(s.reg))), lb, ub, m, reg_type(s.reg)) |
            check_access_context(when(m_inv, reg_type(s.reg) == T_CTX), lb, ub, m);
        if (is_comparison_check) {
            m_inv |= std::move(assume_ptr);
            return;
        } else if (s.or_null) {
            assume(m_inv, reg_type(s.reg) == T_NUM);
            require(m_inv, reg_value(s.reg) == 0, "Pointers may be compared only to the number 0");
            m_inv |= std::move(assume_ptr);
            return;
        } else {
            require(m_inv, reg_type(s.reg) > T_NUM, "Only pointers can be dereferenced");
        }
        m_inv = std::move(assume_ptr);
    }

    AbsDomain check_access_packet(AbsDomain inv, linear_expression_t lb, linear_expression_t ub, std::string s,
                                  bool is_comparison_check) {
        using namespace dsl_syntax;
        require(inv, lb >= variable_t::meta_offset(), std::string("Lower bound must be higher than meta_offset") + s);
        if (is_comparison_check)
            require(inv, ub <= MAX_PACKET_OFF,
                    std::string("Upper bound must be lower than ") + std::to_string(MAX_PACKET_OFF) + s);
        else
            require(inv, ub <= variable_t::packet_size(),
                    std::string("Upper bound must be lower than meta_offset") + s);
        return inv;
    }

    AbsDomain check_access_stack(AbsDomain inv, linear_expression_t lb, linear_expression_t ub, std::string s) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be higher than 0") + s);
        require(inv, ub <= STACK_SIZE, std::string("Upper bound must be lower than STACK_SIZE") + s);
        return inv;
    }

    AbsDomain check_access_shared(AbsDomain inv, linear_expression_t lb, linear_expression_t ub, std::string s,
                                  variable_t reg_type) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be higher than 0") + s);
        require(inv, ub <= reg_type, std::string("Upper bound must be lower than ") + reg_type.name() + s);
        return inv;
    }

    AbsDomain check_access_context(AbsDomain inv, linear_expression_t lb, linear_expression_t ub, std::string s) {
        using namespace dsl_syntax;
        require(inv, lb >= 0, std::string("Lower bound must be higher than 0") + s);
        require(inv, ub <= global_program_info.descriptor.size,
                std::string("Upper bound must be lower than ") + std::to_string(global_program_info.descriptor.size) +
                    s);
        return inv;
    }

    void operator()(const ValidStore& s) {
        using namespace dsl_syntax;
        linear_constraint_t cond = reg_type(s.mem) != T_STACK;

        AbsDomain non_stack{m_inv};
        non_stack += cond;
        require(non_stack, reg_type(s.val) == T_NUM, "Only numbers can be stored to externally-visible regions");

        m_inv += cond.negate();
        m_inv |= std::move(non_stack);
    }

    void operator()(const TypeConstraint& s) {
        using namespace dsl_syntax;
        variable_t t = reg_type(s.reg);
        std::string str = to_string(s);
        switch (s.types) {
        case TypeGroup::num: require(t == T_NUM, str); break;
        case TypeGroup::map_fd: require(t == T_MAP, str); break;
        case TypeGroup::ctx: require(t == T_CTX, str); break;
        case TypeGroup::packet: require(t == T_PACKET, str); break;
        case TypeGroup::stack: require(t == T_STACK, str); break;
        case TypeGroup::shared: require(t > T_SHARED, str); break;
        case TypeGroup::non_map_fd: require(t >= T_NUM, str); break;
        case TypeGroup::mem: require(t >= T_STACK, str); break;
        case TypeGroup::mem_or_num:
            require(t >= T_NUM, str);
            require(t != T_CTX, str);
            break;
        case TypeGroup::ptr: require(t >= T_CTX, str); break;
        case TypeGroup::ptr_or_num: require(t >= T_NUM, str); break;
        case TypeGroup::stack_or_packet:
            require(t >= T_STACK, str);
            require(t <= T_PACKET, str);
            break;
        }
    }

    void operator()(Assert const& stmt) { std::visit(*this, stmt.cst); };

    void operator()(Packet const& a) {
        assign(reg_type(0), T_NUM);
        havoc(reg_offset(0));
        havoc(reg_value(0));
        scratch_caller_saved_registers();
    }

    static AbsDomain do_load_packet_or_shared(AbsDomain inv, Reg target, linear_expression_t addr, int width) {
        if (inv.is_bottom())
            return inv;

        inv.assign(reg_type(target), T_NUM);
        inv -= reg_offset(target);
        inv -= reg_value(target);
        return inv;
    }

    static AbsDomain do_load_ctx(AbsDomain inv, Reg target, linear_expression_t addr_vague, int width) {
        using namespace dsl_syntax;
        if (inv.is_bottom())
            return inv;

        ptype_descr desc = global_program_info.descriptor;

        variable_t target_value = reg_value(target);
        variable_t target_offset = reg_offset(target);
        variable_t target_type = reg_type(target);

        inv -= target_value;

        if (desc.end < 0) {
            inv -= target_offset;
            inv.assign(target_type, T_NUM);
            return inv;
        }

        interval_t interval = inv.to_interval(addr_vague);
        std::optional<number_t> maybe_addr = interval.singleton();

        bool may_touch_ptr = interval[desc.data] || interval[desc.end] || interval[desc.end];

        if (!maybe_addr) {
            inv -= target_offset;
            if (may_touch_ptr)
                inv -= target_type;
            else
                inv.assign(target_type, T_NUM);
            return inv;
        }

        number_t addr = *maybe_addr;

        if (addr == desc.data) {
            inv.assign(target_offset, 0);
        } else if (addr == desc.end) {
            inv.assign(target_offset, variable_t::packet_size());
        } else if (addr == desc.meta) {
            inv.assign(target_offset, variable_t::meta_offset());
        } else {
            inv -= target_offset;
            if (may_touch_ptr)
                inv -= target_type;
            else
                inv.assign(target_type, T_NUM);
            return inv;
        }
        inv.assign(target_type, T_PACKET);
        inv += 4098 <= target_value;
        inv += target_value <= PTR_MAX;
        return inv;
    }

    static AbsDomain do_load_stack(AbsDomain inv, Reg target, linear_expression_t addr, int width) {
        if (inv.is_bottom())
            return inv;

        if (width == 8) {
            inv.array_load(reg_type(target), data_kind_t::types, addr, width);
            inv.array_load(reg_value(target), data_kind_t::values, addr, width);
            inv.array_load(reg_offset(target), data_kind_t::offsets, addr, width);
        } else {
            // havocing handled in array_expansion
            inv.array_load(reg_type(target), data_kind_t::types, addr, width);
            inv -= reg_value(target);
            inv -= reg_offset(target);
        }
        return inv;
    }

    void do_load(Mem const& b, Reg target) {
        using namespace dsl_syntax;
        Reg mem_reg = b.access.basereg;
        int width = (int)b.access.width;
        int offset = (int)b.access.offset;
        linear_expression_t addr = reg_offset(mem_reg) + (number_t)offset;
        variable_t mem_reg_type = reg_type(mem_reg);

        if (mem_reg.v == 10) {
            m_inv = do_load_stack(std::move(m_inv), target, addr, width);
            return;
        }

        int type = get_type(mem_reg_type);
        if (type != T_UNINIT) {
            switch (type) {
                case T_CTX: m_inv = do_load_ctx(std::move(m_inv), target, addr, width); break;
                case T_STACK: m_inv = do_load_stack(std::move(m_inv), target, addr, width); break;
                default: m_inv = do_load_packet_or_shared(std::move(m_inv), target, addr, width); break;
            }
            return;
        }

        m_inv = do_load_ctx(when(m_inv, mem_reg_type == T_CTX), target, addr, width) |
                do_load_packet_or_shared(when(m_inv, mem_reg_type >= T_PACKET), target, addr, width) |
                do_load_stack(when(m_inv, mem_reg_type == T_STACK), target, addr, width);
    }

    int get_type(variable_t v) {
        auto res = m_inv[v].singleton();
        if (!res)
            return T_UNINIT;
        return (int)*res;
    }

    int get_type(int t) { return t; }

    template <typename A, typename X, typename Y, typename Z>
    void do_store_stack(AbsDomain& inv, int width, A addr, X val_type, Y val_value, std::optional<Z> opt_val_offset) {
        inv.array_store(data_kind_t::types, addr, width, val_type);
        if (width == 8) {
            inv.array_store(data_kind_t::values, addr, width, val_value);
            if (opt_val_offset && get_type(val_type) != T_NUM)
                inv.array_store(data_kind_t::offsets, addr, width, *opt_val_offset);
            else
                inv.array_havoc(data_kind_t::offsets, addr, width);
        } else {
            inv.array_havoc(data_kind_t::values, addr, width);
            inv.array_havoc(data_kind_t::offsets, addr, width);
        }
    }

    void operator()(Mem const& b) {
        if (std::holds_alternative<Reg>(b.value)) {
            Reg data_reg = std::get<Reg>(b.value);
            if (b.is_load) {
                do_load(b, data_reg);
            } else {
                do_mem_store(b, reg_type(data_reg), reg_value(data_reg), reg_offset(data_reg));
            }
        } else {
            do_mem_store(b, T_NUM, std::get<Imm>(b.value).v, {});
        }
    }

    template <typename Type, typename Value>
    void do_mem_store(Mem const& b, Type val_type, Value val_value, std::optional<variable_t> opt_val_offset) {
        using namespace dsl_syntax;
        Reg mem_reg = b.access.basereg;
        int width = (int)b.access.width;
        int offset = (int)b.access.offset;
        if (mem_reg.v == 10) {
            int addr = STACK_SIZE + offset;
            do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
            return;
        }
        variable_t mem_reg_type = reg_type(mem_reg);
        linear_expression_t addr = reg_offset(mem_reg) + (number_t)offset;
        if (get_type(mem_reg_type) == T_STACK) {
            do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
            return;
        }
        AbsDomain assume_not_stack(m_inv);
        assume_not_stack += mem_reg_type != T_STACK;
        m_inv += mem_reg_type == T_STACK;
        if (!m_inv.is_bottom()) {
            do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
        }
        m_inv |= std::move(assume_not_stack);
    }

    void operator()(LockAdd const& a) {
        // nothing to do here
    }

    void operator()(Call const& call) {
        using namespace dsl_syntax;
        for (ArgSingle param : call.singles) {
            switch (param.kind) {
            case ArgSingle::Kind::ANYTHING: break;
            // should have been done in the assertion
            case ArgSingle::Kind::MAP_FD: break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY: break;
            case ArgSingle::Kind::PTR_TO_MAP_VALUE: break;
            case ArgSingle::Kind::PTR_TO_CTX: break;
            }
        }
        for (ArgPair param : call.pairs) {
            switch (param.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
            case ArgPair::Kind::PTR_TO_MEM:
                // TODO: check that initialzied
                break;

            case ArgPair::Kind::PTR_TO_UNINIT_MEM: {
                AbsDomain stack{m_inv};
                stack += reg_type(param.mem) == T_STACK;
                if (!stack.is_bottom()) {
                    variable_t addr = reg_offset(param.mem);
                    variable_t width = reg_value(param.size);
                    stack.array_store_numbers(addr, width);
                    stack.array_havoc(data_kind_t::values, addr, width);
                    stack.array_havoc(data_kind_t::offsets, addr, width);
                }
                m_inv += reg_type(param.mem) == T_PACKET;
                m_inv |= std::move(stack);
            }
            }
        }
        scratch_caller_saved_registers();
        variable_t r0 = reg_value(0);
        havoc(r0);
        if (call.returns_map) {
            // no support for map-in-map yet:
            //   if (machine.info.map_defs.at(map_type).type == MapType::ARRAY_OF_MAPS
            //    || machine.info.map_defs.at(map_type).type == MapType::HASH_OF_MAPS) { }
            // This is the only way to get a null pointer - note the `<=`:
            m_inv += 0 <= r0;
            m_inv += r0 <= PTR_MAX;
            assign(reg_offset(0), 0);
            assign(reg_type(0), variable_t::map_value_size());
        } else {
            havoc(reg_offset(0));
            assign(reg_type(0), T_NUM);
            // assume(r0 < 0); for VOID, which is actually "no return if succeed".
        }
    }

    void operator()(LoadMapFd const& ins) {
        Reg dst = ins.dst;
        assign(reg_type(dst), T_MAP);
        assign(reg_value(dst), ins.mapfd);
        havoc(reg_offset(dst));
    }

    void operator()(Bin const& bin) {
        using namespace dsl_syntax;

        Reg dst = bin.dst;
        variable_t dst_value = reg_value(dst);
        variable_t dst_offset = reg_offset(dst);
        variable_t dst_type = reg_type(dst);

        if (std::holds_alternative<Imm>(bin.v)) {
            // dst += K
            int imm = static_cast<int>(std::get<Imm>(bin.v).v);
            switch (bin.op) {
            case Bin::Op::MOV:
                assign(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::ADD:
                if (imm == 0)
                    return;
                add_overflow(dst_value, imm);
                add(dst_offset, imm);
                break;
            case Bin::Op::SUB:
                if (imm == 0)
                    return;
                sub_overflow(dst_value, imm);
                sub(dst_offset, imm);
                break;
            case Bin::Op::MUL:
                mul(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::DIV:
                div(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::MOD:
                rem(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::OR:
                bitwise_or(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::AND:
                // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
                bitwise_and(dst_value, imm);
                if ((int32_t)imm > 0) {
                    assume(dst_value <= imm);
                    assume(0 <= dst_value);
                }
                no_pointer(dst);
                break;
            case Bin::Op::LSH: {
                shl_overflow(dst_value, imm); // avoid signedness and overflow issues in shl_overflow(dst_value, imm);
                no_pointer(dst);
                break;
            }
            case Bin::Op::RSH:
                havoc(dst_value); // avoid signedness and overflow issues in lshr(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::ARSH:
                havoc(dst_value); // avoid signedness and overflow issues in ashr(dst_value, imm); // = (int64_t)dst >>
                                  // imm;
                // assume(dst_value <= (1 << (64 - imm)));
                // assume(dst_value >= -(1 << (64 - imm)));
                no_pointer(dst);
                break;
            case Bin::Op::XOR:
                bitwise_xor(dst_value, imm);
                no_pointer(dst);
                break;
            }
        } else {
            // dst op= src
            Reg src = std::get<Reg>(bin.v);
            variable_t src_value = reg_value(src);
            variable_t src_offset = reg_offset(src);
            variable_t src_type = reg_type(src);
            switch (bin.op) {
            case Bin::Op::ADD: {
                AbsDomain ptr_dst{m_inv};
                ptr_dst += is_pointer(dst);
                apply(ptr_dst, crab::arith_binop_t::ADD, dst_value, dst_value, src_value, true);
                apply(ptr_dst, crab::arith_binop_t::ADD, dst_offset, dst_offset, src_value, false);

                AbsDomain ptr_src{m_inv};
                ptr_src += is_pointer(src);
                apply(ptr_src, crab::arith_binop_t::ADD, dst_value, src_value, dst_value, true);
                apply(ptr_src, crab::arith_binop_t::ADD, dst_offset, src_offset, dst_value, false);
                ptr_src.assign(dst_type, src_type);

                m_inv += dst_type == T_NUM;
                m_inv += src_type == T_NUM;
                add_overflow(dst_value, src_value);

                m_inv |= std::move(ptr_dst);
                m_inv |= std::move(ptr_src);
                break;
            }
            case Bin::Op::SUB: {
                AbsDomain ptr_dst{m_inv};
                ptr_dst += src_type == T_NUM;
                ptr_dst += is_pointer(dst);
                apply(ptr_dst, crab::arith_binop_t::SUB, dst_value, dst_value, src_value, true);
                apply(ptr_dst, crab::arith_binop_t::SUB, dst_offset, dst_offset, src_value, false);

                AbsDomain both_num{m_inv};
                both_num += src_type == T_NUM;
                both_num += dst_type == T_NUM;
                apply(both_num, crab::arith_binop_t::SUB, dst_value, dst_value, src_value, true);

                m_inv += is_pointer(src);
                m_inv += src_type < T_SHARED; // cannot subtract two pointers to shared regions
                m_inv += eq(src_type, dst_type);
                apply(m_inv, crab::arith_binop_t::SUB, dst_value, dst_offset, src_offset);
                m_inv.assign(dst_type, T_NUM);
                m_inv -= dst_offset;

                m_inv |= std::move(both_num);
                m_inv |= std::move(ptr_dst);
                break;
            }
            case Bin::Op::MUL:
                mul(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::DIV:
                // DIV is not checked for zerodiv
                div(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::MOD:
                // See DIV comment
                rem(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::OR:
                bitwise_or(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::AND:
                bitwise_and(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::LSH:
                shl_overflow(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::RSH:
                havoc(dst_value);
                no_pointer(dst);
                break;
            case Bin::Op::ARSH:
                havoc(dst_value);
                no_pointer(dst);
                break;
            case Bin::Op::XOR:
                bitwise_xor(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::MOV:
                assign(dst_value, src_value);
                assign(dst_offset, src_offset);
                assign(dst_type, src_type);
                break;
            }
        }
        if (!bin.is64) {
            bitwise_and(dst_value, UINT32_MAX);
        }
    }
};

enum class check_kind_t { Error, Warning, Redundant, Unreachable };

// Toy database to store invariants.
class checks_db final {
    std::map<label_t, std::vector<std::pair<std::string, check_kind_t>>> m_db;
    std::map<check_kind_t, int> total{
        {check_kind_t::Error, {}},
        {check_kind_t::Warning, {}},
        {check_kind_t::Redundant, {}},
        {check_kind_t::Unreachable, {}},
    };

  public:
    void merge_db(checks_db&& other) {
        for (auto [label, vec] : other.m_db)
            for (auto p : vec)
                m_db[label].push_back(p);
        for (auto [k, v] : other.total)
            total[k] += v;
        other.m_db.clear();
        other.total.clear();
    }

    void add(label_t label, check_kind_t status, std::string msg) {
        m_db[label].emplace_back(msg, status);
        total[status]++;
    }

    int total_error() const { return total.at(check_kind_t::Error); }
    int total_warning() const { return total.at(check_kind_t::Warning); }
    int total_redundant() const { return total.at(check_kind_t::Unreachable); }
    int total_unreachable() const { return total.at(check_kind_t::Unreachable); }
    checks_db() = default;

    void write(std::ostream& o) const {
        for (auto [label, reports] : m_db) {
            o << label << ":\n";
            for (auto [k, t] : reports)
                o << "  " << k << "\n";
        }

        std::vector<int> cnts = {total_error(), total_warning(), total_redundant(), total_unreachable()};
        int maxvlen = 0;
        for (auto c : cnts) {
            maxvlen = std::max(maxvlen, (int)std::to_string(c).size());
        }

        o << std::string((int)maxvlen - std::to_string(total_error()).size(), ' ') << total_error()
          << std::string(2, ' ') << "Number of total error checks\n";
        o << std::string((int)maxvlen - std::to_string(total_warning()).size(), ' ') << total_warning()
          << std::string(2, ' ') << "Number of total warning checks\n";
        o << std::string((int)maxvlen - std::to_string(total_redundant()).size(), ' ') << total_redundant()
          << std::string(2, ' ') << "Number of total redundant checks\n";
        o << std::string((int)maxvlen - std::to_string(total_unreachable()).size(), ' ') << total_unreachable()
          << std::string(2, ' ') << "Number of block that become unreachable\n";
    }
};

template <typename AbsDomain>
class assert_property_checker final : private intra_abs_transformer<AbsDomain> {

    void add_error(std::string msg) { m_db.add(label, check_kind_t::Error, msg); }
    void add_warning(std::string msg) { m_db.add(label, check_kind_t::Warning, msg); }
    void add_redundant(std::string msg) { m_db.add(label, check_kind_t::Redundant, msg); }
    void add_unreachable(std::string msg) { m_db.add(label, check_kind_t::Unreachable, msg); }

  public:
    label_t label;
    checks_db m_db;
    using parent = intra_abs_transformer<AbsDomain>;

    assert_property_checker(const AbsDomain& inv, label_t label)
        : intra_abs_transformer<AbsDomain>(inv), label(label) {}

    void require(AbsDomain& inv, const linear_constraint_t& cst, std::string s) override {
        s = label + ": " + s;
        if (inv.is_bottom())
            goto out;
        if (cst.is_contradiction()) {
            add_warning(std::string("Contradition: ") + s);
            goto out;
        }

        if (domains::checker_domain_traits<AbsDomain>::entail(inv, cst)) {
            // add_redundant(s);
        } else if (domains::checker_domain_traits<AbsDomain>::intersect(inv, cst)) {
            // TODO: add_error() if imply negation
            add_warning(s);
        } else {
            /* Instead this program:
                x:=0;
                y:=1;
                if (x=34) {
                    assert(y==2);
                }
            Suppose due to some abstraction we have:
                havoc(x);
                y:=1;
                if (x=34) {
                    assert(y==2);
                }
            As a result, we have inv={y=1,x=34}  and cst={y=2}
            Note that inv does not either entail or intersect with cst.
            However, the original program does not violate the assertion.
            */
            add_warning(s);
        }
    out:
        this->assume(inv, cst);
    }

    template <typename T>
    void operator()(const T& s) {
        bool pre_bot = this->m_inv.is_bottom();
        parent::operator()(s);

        if (!pre_bot && this->m_inv.is_bottom()) {
            add_unreachable("inv became bot after " + to_string(s));
        }
    }
};

template <typename AbsDomain>
inline AbsDomain setup_entry() {
    std::cerr << "meta: " << global_program_info.descriptor.meta << "\n";
    std::cerr << "data: " << global_program_info.descriptor.data << "\n";
    std::cerr << "end: " << global_program_info.descriptor.end << "\n";
    std::cerr << "ctx size: " << global_program_info.descriptor.size << "\n";
    using namespace dsl_syntax;

    // intra_abs_transformer<AbsDomain>(inv);
    AbsDomain inv;
    inv += STACK_SIZE <= reg_value(10);
    inv.assign(reg_offset(10), STACK_SIZE);
    inv.assign(reg_type(10), T_STACK);

    inv += 1 <= reg_value(1);
    inv += reg_value(1) <= PTR_MAX;
    inv.assign(reg_offset(1), 0);
    inv.assign(reg_type(1), T_CTX);

    inv += 0 <= variable_t::packet_size();
    inv += variable_t::packet_size() < MAX_PACKET_OFF;
    if (global_program_info.descriptor.meta >= 0) {
        inv += variable_t::meta_offset() <= 0;
        inv += variable_t::meta_offset() >= -4098;
    } else {
        inv.assign(variable_t::meta_offset(), 0);
    }
    return inv;
}

template <typename AbsDomain>
inline AbsDomain transform(const basic_block_t& bb, const AbsDomain& from_inv) {
    intra_abs_transformer<AbsDomain> transformer(from_inv);
    for (const auto& statement : bb) {
        std::visit(transformer, statement);
    }
    return std::move(transformer.m_inv);
}

template <typename AbsDomain>
inline void check_block(const basic_block_t& bb, const AbsDomain& from_inv, checks_db& db) {
    if (std::none_of(bb.begin(), bb.end(), [](const auto& s) { return std::holds_alternative<Assert>(s); }))
        return;
    assert_property_checker<AbsDomain> checker(from_inv, bb.label());
    for (const auto& statement : bb) {
        std::visit(checker, statement);
    }
    db.merge_db(std::move(checker.m_db));
}
} // namespace crab
