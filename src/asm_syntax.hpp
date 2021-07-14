// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include "crab/variable.hpp"

namespace crab {
struct label_t {
    int from; ///< Jump source, or simply index of instruction
    int to; ///< Jump target or -1

    constexpr explicit label_t(int index, int to=-1) noexcept : from(index), to(to) { }

    static constexpr label_t make_jump(const label_t& src_label, const label_t& target_label) {
        return label_t{src_label.from, target_label.from};
    }

    constexpr bool operator==(const label_t& other) const { return from == other.from && to == other.to; }
    constexpr bool operator!=(const label_t& other) const { return !(*this == other); }
    constexpr bool operator<(const label_t& other) const {
        if (this == &other) return false;
        if (*this == label_t::exit) return false;
        if (other == label_t::exit) return true;
        return from < other.from || (from == other.from && to < other.to);
    }

    // no hash; intended for use in ordered containers.

    [[nodiscard]] constexpr bool isjump() const { return to != -1; }

    friend std::ostream& operator<<(std::ostream& os, const label_t& label) {
        if (label == entry)
            return os << "entry";
        if (label == exit)
            return os << "exit";
        if (label.to == -1)
            return os << label.from;
        return os << label.from << ":" << label.to;
    }

    static const label_t entry;
    static const label_t exit;
};

inline const label_t label_t::entry{-1};
inline const label_t label_t::exit{-2};

}
using crab::label_t;

// Assembly syntax.
namespace asm_syntax {

/// Immediate argument.
struct Imm {
    uint64_t v{};
};

/// Register argument.
struct Reg {
    uint8_t v{};
};

using Value = std::variant<Imm, Reg>;

/// Binary operation.
struct Bin {
    enum class Op {
        MOV,
        ADD,
        SUB,
        MUL,
        DIV,
        MOD,
        OR,
        AND,
        LSH,
        RSH,
        ARSH,
        XOR,
    };

    Op op;
    Reg dst;      ///< Destination.
    Value v;
    bool is64{};
    bool lddw{};
};

/// Unary operation.
struct Un {
    enum class Op {
        LE16,
        LE32,
        LE64,
        NEG,
    };

    Op op;
    Reg dst;
};

/// This instruction is encoded similarly to LDDW.
/// See comment in makeLddw() at asm_unmarshal.cpp
struct LoadMapFd {
    Reg dst;
    int mapfd{};
};

struct Condition {
    enum class Op {
        EQ,
        NE,
        SET,
        NSET, // NSET does not exist in ebpf
        LT,
        LE,
        GT,
        GE,
        SLT,
        SLE,
        SGT,
        SGE,
    };

    Op op;
    Reg left;
    Value right;
};

struct Jmp {
    std::optional<Condition> cond;
    label_t target;
};

struct ArgSingle {
    // see comments in spec_prototypes.hpp
    enum class Kind {
        MAP_FD,
        PTR_TO_MAP_KEY,
        PTR_TO_MAP_VALUE,
        PTR_TO_CTX,
        ANYTHING,
    } kind{};
    Reg reg;
};

/// Pair of arguments to a function for pointer and size.
struct ArgPair {
    enum class Kind {
        PTR_TO_MEM,
        PTR_TO_MEM_OR_NULL,
        PTR_TO_UNINIT_MEM,
    } kind{};
    Reg mem;            ///< Pointer.
    Reg size;           ///< Size of space pointed to.
    bool can_be_zero{};
};

struct Call {
    int32_t func{};
    std::string name;
    bool returns_map{};
    bool reallocate_packet{};
    std::vector<ArgSingle> singles;
    std::vector<ArgPair> pairs;
};

struct Exit {};

struct Deref {
    int width{};
    Reg basereg;
    int offset{};
};

/// Load/store instruction.
struct Mem {
    Deref access;
    Value value;
    bool is_load{};
};

/// A special instruction for checked access to packets; it is actually a
/// function call, and analyzed as one, e.g., by scratching caller-saved
/// registers after it is performed.
struct Packet {
    int width{};
    int offset{};
    std::optional<Reg> regoffset;
};

/// Special instruction for incrementing values inside shared memory.
struct LockAdd {
    Deref access;
    Reg valreg;
};

/// Not an instruction, just used for failure cases.
struct Undefined {
    int opcode{};
};

/// When a CFG is translated to its nondeterministic form, Conditional Jump
/// instructions are replaced by two Assume instructions, immediately after
/// the branch and before each jump target.
struct Assume {
    Condition cond;
};

// The exact numbers are taken advantage of, in the abstract domain
enum { T_UNINIT = -6, T_MAP = -5, T_NUM = -4, T_CTX = -3, T_STACK = -2, T_PACKET = -1, T_SHARED = 0 };

enum class TypeGroup {
    number,
    map_fd,
    ctx,            ///< pointer to the special memory region named 'ctx'
    packet,         ///< pointer to the packet
    stack,          ///< pointer to the stack
    shared,         ///< pointer to shared memory
    non_map_fd,     // reg >= T_NUM
    mem,            // shared | packet | stack = reg >= T_STACK
    mem_or_num,     // reg >= T_NUM && reg != T_CTX
    pointer,        // reg >= T_CTX
    ptr_or_num,     // reg >= T_NUM
    stack_or_packet // reg >= T_STACK && reg <= T_PACKET
};

/// Condition check whether something is a valid size.
struct ValidSize {
    Reg reg;
    bool can_be_zero{};
};

/// Condition check whether two registers can be compared with each other.
/// For example, one is not allowed to compare a number with a pointer,
/// or compare pointers to different memory regions.
struct Comparable {
    Reg r1;
    Reg r2;
};

// ptr: ptr -> num : num
struct Addable {
    Reg ptr;
    Reg num;
};

struct ValidAccess {
    Reg reg;
    int offset{};
    Value width{Imm{0}};
    bool or_null{};
};

/// Condition check whether something is a valid key value.
struct ValidMapKeyValue {
    Reg access_reg;
    Reg map_fd_reg;
    bool key{};
};

// "if mem is not stack, val is num"
struct ValidStore {
    Reg mem;
    Reg val;
};

struct TypeConstraint {
    Reg reg;
    TypeGroup types;
};

/// Condition check whether something is a valid size.
struct ZeroOffset {
    Reg reg;
};

using AssertionConstraint =
    std::variant<Comparable, Addable, ValidAccess, ValidStore, ValidSize, ValidMapKeyValue, TypeConstraint, ZeroOffset>;

struct Assert {
    AssertionConstraint cst;
    bool satisfied = false;
    Assert(AssertionConstraint cst, bool satisfied=false): cst(cst), satisfied(satisfied) { }
};

#define DECLARE_EQ4(T, f1, f2, f3, f4)                                       \
    inline bool operator==(T const& a, T const& b) {                         \
        return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3 && a.f4 == b.f4; \
    }
#define DECLARE_EQ3(T, f1, f2, f3) \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3; }
#define DECLARE_EQ2(T, f1, f2) \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1 && a.f2 == b.f2; }
#define DECLARE_EQ1(T, f1) \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1; }

using Instruction = std::variant<Undefined, Bin, Un, LoadMapFd, Call, Exit, Jmp, Mem, Packet, LockAdd, Assume, Assert>;

using LabeledInstruction = std::tuple<label_t, Instruction>;
using InstructionSeq = std::vector<LabeledInstruction>;

using pc_t = uint16_t;

// Helpers:

struct InstructionVisitorPrototype {
    void operator()(Undefined const& a);
    void operator()(LoadMapFd const& a);
    void operator()(Bin const& a);
    void operator()(Un const& a);
    void operator()(Call const& a);
    void operator()(Exit const& a);
    void operator()(Jmp const& a);
    void operator()(Assume const& a);
    void operator()(Assert const& a);
    void operator()(Packet const& a);
    void operator()(Mem const& a);
    void operator()(LockAdd const& a);
};

inline bool operator==(Imm const& a, Imm const& b) { return a.v == b.v; }
inline bool operator==(Reg const& a, Reg const& b) { return a.v == b.v; }
inline bool operator==(Deref const& a, Deref const& b) {
    return a.basereg == b.basereg && a.offset == b.offset && a.width == b.width;
}
inline bool operator==(Condition const& a, Condition const& b) {
    return a.left == b.left && a.op == b.op && a.right == b.right;
}
inline bool operator==(Undefined const& a, Undefined const& b) { return a.opcode == b.opcode; }
inline bool operator==(LoadMapFd const& a, LoadMapFd const& b) { return a.dst == b.dst && a.mapfd == b.mapfd; }
inline bool operator==(Bin const& a, Bin const& b) {
    return a.op == b.op && a.dst == b.dst && a.is64 == b.is64 && a.v == b.v && a.lddw == b.lddw;
}
inline bool operator==(Un const& a, Un const& b) { return a.op == b.op && a.dst == b.dst; }
inline bool operator==(Call const& a, Call const& b) { return a.func == b.func; }
inline bool operator==(Exit const& a, Exit const& b) { return true; }
inline bool operator==(Jmp const& a, Jmp const& b) { return a.cond == b.cond && a.target == b.target; }
inline bool operator==(Packet const& a, Packet const& b) {
    return a.offset == b.offset && a.regoffset == b.regoffset && a.width == b.width;
}
inline bool operator==(Mem const& a, Mem const& b) {
    return a.access == b.access && a.value == b.value && a.is_load == b.is_load;
}
inline bool operator==(LockAdd const& a, LockAdd const& b) { return a.access == b.access && a.valreg == b.valreg; }
inline bool operator==(Assume const& a, Assume const& b) { return a.cond == b.cond; }
bool operator==(Assert const& a, Assert const& b);

DECLARE_EQ2(TypeConstraint, reg, types)
DECLARE_EQ2(ValidSize, reg, can_be_zero)
DECLARE_EQ2(Comparable, r1, r2)
DECLARE_EQ2(Addable, ptr, num)
DECLARE_EQ2(ValidStore, mem, val)
DECLARE_EQ4(ValidAccess, reg, offset, width, or_null)
DECLARE_EQ3(ValidMapKeyValue, access_reg, map_fd_reg, key)
DECLARE_EQ1(ZeroOffset, reg)
DECLARE_EQ1(Assert, cst)

}

using namespace asm_syntax;

template <class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...)->overloaded<Ts...>;
