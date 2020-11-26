#include <cinttypes>

#include <utility>
#include <vector>

#include "asm_syntax.hpp"
#include "crab/cfg.hpp"
#include "gpl/spec_type_descriptors.hpp"

using std::string;
using std::to_string;
using std::vector;

class AssertExtractor {
    program_info info;
    const bool is_privileged = info.program_type == BpfProgType::KPROBE;

    static Reg reg(Value v) {
        return std::get<Reg>(v);
    }

    static Imm imm(Value v) {
        return std::get<Imm>(v);
    }

  public:
    explicit AssertExtractor(program_info info) : info{std::move(info)} {}

    template <typename T>
    vector<Assert> operator()(T) const {
        return {};
    }

    /// Packet access implicitly uses R6, so verify that R6 still has a pointer to the context.
    vector<Assert> operator()(Packet const& ins) const { return {Assert{TypeConstraint{Reg{6}, TypeGroup::ctx}}}; }

    /// Verify that Exit returns a number.
    vector<Assert> operator()(Exit const& e) const { return {Assert{TypeConstraint{Reg{R0_RETURN_VALUE}, TypeGroup::num}}}; }

    vector<Assert> operator()(Call const& call) const {
        vector<Assert> res;
        std::optional<Reg> map_fd_reg;
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING:
                // avoid pointer leakage:
                if (!is_privileged) {
                    res.emplace_back(TypeConstraint{arg.reg, TypeGroup::num});
                }
                break;
            case ArgSingle::Kind::MAP_FD:
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::map_fd});
                map_fd_reg = arg.reg;
                break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::stack_or_packet});
                res.emplace_back(ValidMapKeyValue{arg.reg, *map_fd_reg,
                                                  arg.kind == ArgSingle::Kind::PTR_TO_MAP_KEY});
                break;
            case ArgSingle::Kind::PTR_TO_CTX:
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::ctx});
                // TODO: the kernel has some other conditions here -
                //       maybe offset == 0
                break;
            }
        }
        for (ArgPair arg : call.pairs) {
            switch (arg.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
                res.emplace_back(TypeConstraint{arg.mem, TypeGroup::mem_or_num});
                // res.emplace_back(OnlyZeroIfNum{arg.mem});
                break;
            case ArgPair::Kind::PTR_TO_MEM:
                /* LINUX: pointer to valid memory (stack, packet, map value) */
                // TODO: check initialization
                res.emplace_back(TypeConstraint{arg.mem, TypeGroup::mem});
                break;
            case ArgPair::Kind::PTR_TO_UNINIT_MEM:
                // memory may be uninitialized, i.e. write only
                res.emplace_back(TypeConstraint{arg.mem, TypeGroup::mem});
                break;
            }
            // TODO: reg is constant (or maybe it's not important)
            res.emplace_back(TypeConstraint{arg.size, TypeGroup::num});
            res.emplace_back(ValidSize{arg.size, arg.can_be_zero});
            res.emplace_back(ValidAccess{arg.mem, 0, arg.size,
                                         arg.kind == ArgPair::Kind::PTR_TO_MEM_OR_NULL});
        }
        return res;
    }

    [[nodiscard]]
    vector<Assert> explicate(Condition cond) const {
        if (is_privileged)
            return {};
        vector<Assert> res;
        res.emplace_back(ValidAccess{cond.left});
        if (std::holds_alternative<Imm>(cond.right)) {
            if (imm(cond.right).v != 0) {
                res.emplace_back(TypeConstraint{cond.left, TypeGroup::num});
            } else {
                // OK - map_fd is just another pointer
                // Anything can be compared to 0
            }
        } else {
            res.emplace_back(ValidAccess{reg(cond.right)});
            if (cond.op != Condition::Op::EQ && cond.op != Condition::Op::NE) {
                res.emplace_back(TypeConstraint{cond.left, TypeGroup::non_map_fd});
            }
            res.emplace_back(Comparable{cond.left, reg(cond.right)});
        }
        return res;
    }

    vector<Assert> operator()(Assume ins) const { return explicate(ins.cond); }

    vector<Assert> operator()(Jmp ins) const {
        if (!ins.cond)
            return {};
        return explicate(*ins.cond);
    }

    vector<Assert> operator()(Mem ins) const {
        vector<Assert> res;
        Reg basereg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        int offset = ins.access.offset;
        if (basereg.v == R10_STACK_POINTER) {
            // We know we are accessing the stack.
            res.emplace_back(ValidAccess{basereg, offset, width, false});
        } else {
            res.emplace_back(TypeConstraint{basereg, TypeGroup::ptr});
            res.emplace_back(ValidAccess{basereg, offset, width, false});
            if (!is_privileged && !ins.is_load && std::holds_alternative<Reg>(ins.value)) {
                if (width.v != 8)
                    res.emplace_back(TypeConstraint{reg(ins.value), TypeGroup::num});
                else
                    res.emplace_back(ValidStore{ins.access.basereg, reg(ins.value)});
            }
        }
        return res;
    }

    vector<Assert> operator()(LockAdd ins) const {
        vector<Assert> res;
        res.emplace_back(TypeConstraint{ins.access.basereg, TypeGroup::shared});
        res.emplace_back(ValidAccess{ins.access.basereg, ins.access.offset,
                                     Imm{static_cast<uint32_t>(ins.access.width)}, false});
        return res;
    }

    vector<Assert> operator()(Bin ins) const {
        switch (ins.op) {
        case Bin::Op::MOV: return {};
        case Bin::Op::ADD:
            if (std::holds_alternative<Reg>(ins.v)) {
                return {
                    Assert{Addable{reg(ins.v), ins.dst}},
                    Assert{Addable{ins.dst, reg(ins.v)}}
                };
            }
            return {};
        case Bin::Op::SUB:
            if (std::holds_alternative<Reg>(ins.v)) {
                vector<Assert> res;
                // disallow map-map since same type does not mean same offset
                // TODO: map identities
                res.emplace_back(TypeConstraint{ins.dst, TypeGroup::ptr_or_num});
                res.emplace_back(Comparable{reg(ins.v), ins.dst});
                return res;
            }
            return {};
        default:
            return { Assert{TypeConstraint{ins.dst, TypeGroup::num}} };
        }
    }
};

/// Annotate the CFG by adding explicit assertions for all the preconditions
/// of any instruction. For example, jump instructions are asserted not to
/// compare numbers and pointers, or pointers to potentially distinct memory
/// regions. The verifier will use these assertions to treat the program as
/// unsafe unless it can prove that the assertions can never fail.
void explicate_assertions(cfg_t& cfg, const program_info& info) {
    for (auto& [label, bb] : cfg) {
        vector<Instruction> insts;
        for (const auto& ins : vector<Instruction>(bb.begin(), bb.end())) {
            for (auto a : std::visit(AssertExtractor{info}, ins))
                insts.emplace_back(a);
            insts.push_back(ins);
        }
        bb.swap_instructions(insts);
    }
}
