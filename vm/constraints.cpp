#include <iostream>
#include <vector>
#include <string>
#include <map>

#include "instructions.hpp"
#include "common.hpp"
#include "constraints.hpp"
#include "prototypes.h"

using std::tuple;
using std::string;
using std::vector;
using std::map;

// rough estimates:
static constexpr int perf_max_trace_size = 2048;
static constexpr int ptregs_size = (3 + 63 + 8 + 2) * 8;

static constexpr int cgroup_dev_regions = 3 * 4;
static constexpr int kprobe_regions = ptregs_size;
static constexpr int tracepoint_regions = perf_max_trace_size;
static constexpr int perf_event_regions = 3 * 8 + ptregs_size;
static constexpr int socket_filter_regions = 24 * 4;
static constexpr int sched_regions = 24 * 4;
static constexpr int xdp_regions = 5 * 4;
static constexpr int lwt_regions = 24 * 4;
static constexpr int cgroup_sock_regions = 12 * 4;
static constexpr int sock_ops_regions =  42 * 4 + 2 * 8;
static constexpr int sk_skb_regions = 36 * 4;

static constexpr ptype_descr sk_buff = { sk_skb_regions, 19*4, 20*4, 35*4};
static constexpr ptype_descr xdp_md = { xdp_regions, 0, 1*4, 2*4};
static constexpr ptype_descr sk_msg_md = { 11*4, 0, 1*4, -1};

static constexpr ptype_descr unspec_descr = { 0 };
static constexpr ptype_descr cgroup_dev_descr = {cgroup_dev_regions};
static constexpr ptype_descr kprobe_descr = {kprobe_regions};
static constexpr ptype_descr tracepoint_descr = {tracepoint_regions};
static constexpr ptype_descr perf_event_descr = {perf_event_regions};
static constexpr ptype_descr socket_filter_descr = sk_buff;
static constexpr ptype_descr sched_descr = sk_buff;
static constexpr ptype_descr xdp_descr = xdp_md;
static constexpr ptype_descr lwt_xmit_descr = sk_buff;
static constexpr ptype_descr lwt_inout_descr = sk_buff;
static constexpr ptype_descr cgroup_sock_descr = {cgroup_sock_regions};
static constexpr ptype_descr sock_ops_descr = {sock_ops_regions};
static constexpr ptype_descr sk_skb_descr = sk_buff;

const std::map<ebpf_prog_type, ptype_descr> descriptors {
	{EBPF_PROG_TYPE_UNSPEC, unspec_descr},
	{EBPF_PROG_TYPE_CGROUP_DEVICE, cgroup_dev_descr},
	{EBPF_PROG_TYPE_KPROBE, kprobe_descr},
	{EBPF_PROG_TYPE_TRACEPOINT, tracepoint_descr},
    {EBPF_PROG_TYPE_RAW_TRACEPOINT, tracepoint_descr},
	{EBPF_PROG_TYPE_PERF_EVENT, perf_event_descr},
	{EBPF_PROG_TYPE_SOCKET_FILTER, socket_filter_descr},
	{EBPF_PROG_TYPE_CGROUP_SKB, socket_filter_descr},
	{EBPF_PROG_TYPE_SCHED_ACT, sched_descr},
	{EBPF_PROG_TYPE_SCHED_CLS, sched_descr},
	{EBPF_PROG_TYPE_XDP, xdp_descr},
	{EBPF_PROG_TYPE_LWT_XMIT, lwt_xmit_descr},
	{EBPF_PROG_TYPE_LWT_IN,  lwt_inout_descr},
	{EBPF_PROG_TYPE_LWT_OUT, lwt_inout_descr},
	{EBPF_PROG_TYPE_CGROUP_SOCK, cgroup_sock_descr},
	{EBPF_PROG_TYPE_SOCK_OPS, sock_ops_descr},
	{EBPF_PROG_TYPE_SK_SKB, sk_skb_descr},
    {EBPF_PROG_TYPE_SK_MSG, sk_msg_md},
};


constraints::constraints(ebpf_prog_type prog_type) : ctx_desc{descriptors.at(prog_type)}
{
    for (int i=0; i < 16; i++) {
        regs.emplace_back(vfac, i);
    }
}

void constraints::setup_entry(basic_block_t& entry)
{
    entry.assume(STACK_SIZE <= regs[10].value);
    entry.assign(regs[10].offset, 0); // XXX: Maybe start with T_STACK
    entry.assign(regs[10].region, T_STACK);

    entry.assume(1 <= regs[1].value);
    entry.assign(regs[1].offset, 0);
    entry.assign(regs[1].region, T_CTX);

    for (int i : {0, 2, 3, 4, 5, 6, 7, 8, 9}) {
        entry.assign(regs[i].region, T_UNINIT);
    }

    entry.assume(0 <= total_size);
    if (ctx_desc.meta < 0) {
        entry.assign(meta_size, 0);
    } else {
        entry.assume(0 <= meta_size);
        entry.assume(meta_size <= total_size);
    }
}

static auto eq(var_t& a, var_t& b)
{
    return lin_cst_t(a - b, lin_cst_t::EQUALITY);
}

static lin_cst_t jmp_to_cst_offsets(uint8_t opcode, int imm, var_t& dst_offset, var_t& src_offset)
{
    switch (opcode) {
    case EBPF_OP_JEQ_REG:
        return eq(dst_offset, src_offset);

    case EBPF_OP_JGE_REG:  return dst_offset >= src_offset; // FIX unsigned
    case EBPF_OP_JSGE_REG: return dst_offset >= src_offset;
    case EBPF_OP_JLE_REG:  return dst_offset <= src_offset; // FIX unsigned
    case EBPF_OP_JSLE_REG: return dst_offset <= src_offset;
    case EBPF_OP_JNE_REG:
        return lin_cst_t(dst_offset - src_offset, lin_cst_t::DISEQUATION);
    
    case EBPF_OP_JGT_REG:  return dst_offset > src_offset; // FIX unsigned
    case EBPF_OP_JSGT_REG: return dst_offset > src_offset;

    // Note: reverse the test as a workaround strange lookup:
    case EBPF_OP_JLT_REG:  return src_offset > dst_offset; // FIX unsigned
    case EBPF_OP_JSLT_REG: return src_offset > dst_offset;
    }
    return dst_offset - dst_offset == 0;
}


static lin_cst_t jmp_to_cst(uint8_t opcode, int imm, var_t& dst_value, var_t& src_value)
{
    switch (opcode) {
    case EBPF_OP_JEQ_IMM:  return dst_value == imm;
    case EBPF_OP_JEQ_REG:
        return eq(dst_value, src_value);

    case EBPF_OP_JGE_IMM:  return dst_value >= imm; // FIX unsigned
    case EBPF_OP_JGE_REG:  return dst_value >= src_value; // FIX unsigned

    case EBPF_OP_JSGE_IMM: return dst_value >= imm;
    case EBPF_OP_JSGE_REG: return dst_value >= src_value;
    
    case EBPF_OP_JLE_IMM:  return dst_value <= imm; // FIX unsigned
    case EBPF_OP_JLE_REG:  return dst_value <= src_value; // FIX unsigned
    case EBPF_OP_JSLE_IMM: return dst_value <= imm;
    case EBPF_OP_JSLE_REG: return dst_value <= src_value;

    case EBPF_OP_JNE_IMM:  return dst_value != imm;
    case EBPF_OP_JNE_REG:
        return lin_cst_t(dst_value - src_value, lin_cst_t::DISEQUATION);
    
    case EBPF_OP_JGT_IMM:  return dst_value > imm; // FIX unsigned
    case EBPF_OP_JGT_REG:  return dst_value > src_value; // FIX unsigned
    case EBPF_OP_JSGT_IMM: return dst_value > imm;
    case EBPF_OP_JSGT_REG: return dst_value > src_value;

    case EBPF_OP_JLT_IMM:  return dst_value < imm; // FIX unsigned
    // Note: reverse the test as a workaround strange lookup:
    case EBPF_OP_JLT_REG:  return src_value > dst_value; // FIX unsigned
    case EBPF_OP_JSLT_IMM: return dst_value < imm;
    case EBPF_OP_JSLT_REG: return src_value > dst_value;
    }
    assert(false);
}


void constraints::jump(ebpf_inst inst, basic_block_t& block, bool taken)
{
    uint8_t opcode = taken ? inst.opcode : reverse(inst.opcode);
    lin_cst_t cst = jmp_to_cst(opcode, inst.imm, regs[inst.dst].value, regs[inst.src].value);
    block.assume(cst);

    lin_cst_t offset_cst = jmp_to_cst_offsets(opcode, inst.imm, regs[inst.dst].offset, regs[inst.src].offset);
    if (!offset_cst.is_tautology()) {
        block.assume(offset_cst);
    }
}

static void wrap32(basic_block_t& block, var_t& dst_value)
{
    block.bitwise_and(dst_value, dst_value, UINT32_MAX);
}


void constraints::no_pointer(basic_block_t& block, dom_t& v)
{
    block.havoc(v.offset);
    block.assign(v.region, T_NUM);
}

void constraints::exec(ebpf_inst inst, multiblock_t& block)
{
    if (is_alu(inst.opcode)) {
        exec_alu(inst, block.block());
    } else if (inst.opcode == EBPF_OP_LDDW) {
        block.assign(regs[inst.dst].value, (uint32_t)inst.imm | ((uint64_t)inst.imm << 32));
        no_pointer(block.block(), regs[inst.dst]);
    } else if (is_access(inst.opcode)) {
        exec_mem_access(block, inst);
    } else if (inst.opcode == EBPF_OP_EXIT) {
        // assert_init(block, regs[inst.dst]);
        block.assertion(regs[inst.dst].region == T_NUM);
    } else if (inst.opcode == EBPF_OP_CALL) {
        exec_call(block, inst.imm);
    } else if (is_jump(inst.opcode)) {
        // cfg-related action is handled in build_cfg() and constraints::jump()
        if (inst.opcode != EBPF_OP_JA) {
            if (inst.opcode & EBPF_SRC_REG) {
                assert_init(block, regs[inst.src]);
            }
            assert_init(block, regs[inst.dst]);
        }
    } else {
        std::cout << "bad instruction " << (int)inst.opcode << " at " << block.block().label() << "},n";
        assert(false);
    }
}

static void assert_pointer_or_null(multiblock_t& block, var_t& region, var_t& value, lin_cst_t region_cst)
{
    auto [pointer, null] = block.split("pointer", "null");
    pointer.assume(region_cst);
    null.assume(region == T_NUM);
    null.assertion(value == 0);
}

void constraints::exec_call(multiblock_t& block, int32_t imm)
{
    assert(imm < sizeof(prototypes) / sizeof(prototypes[0]));
    assert(imm > 0);
    auto proto = *prototypes[imm];
    int i = 0;
    for (bpf_arg_type t : {proto.arg1_type, proto.arg2_type, proto.arg3_type, proto.arg4_type, proto.arg5_type}) {
        auto& arg = regs[++i];
        if (t == ARG_DONTCARE)
            break;
        switch (t) {
        case ARG_DONTCARE:
            assert(false);
            break;
        case ARG_ANYTHING:
            // avoid pointer leakage:
            block.assertion(arg.region == T_NUM);
            break;
        case ARG_CONST_SIZE:
            block.assertion(arg.value != 0);
            break;
        case ARG_CONST_SIZE_OR_ZERO:
            block.assertion(arg.region == T_NUM);
            break;
        case ARG_CONST_MAP_PTR:
            assert_pointer_or_null(block, arg.region, arg.value, arg.region == T_MAP);
            break;
        case ARG_PTR_TO_CTX: 
            assert_pointer_or_null(block, arg.region, arg.value, arg.region == T_CTX);
            break;
        case ARG_PTR_TO_MEM_OR_NULL:
            assert_pointer_or_null(block, arg.region, arg.value, arg.region >= T_CTX);
            break;
        case ARG_PTR_TO_MAP_KEY:
            block.assertion(arg.value != 0);
            block.assertion(arg.region == T_STACK);
            break;
        case ARG_PTR_TO_MAP_VALUE:
            block.assertion(arg.value != 0);
            block.assertion(arg.region == T_STACK);
            break;
        case ARG_PTR_TO_MEM:
            block.assertion(arg.value != 0);
            block.assertion(arg.region >= T_STACK);
            break;
        case ARG_PTR_TO_UNINIT_MEM:
            block.assertion(arg.region == T_STACK);
            break;
        }
    }

    for (int i=1; i<=5; i++) {
        block.havoc(regs[i].value);
        block.havoc(regs[i].offset);
        block.assign(regs[i].region, T_UNINIT);
    }
    switch (proto.ret_type) {
    case RET_PTR_TO_MAP_VALUE_OR_NULL:
        block.assign(regs[0].region, T_MAP);
        block.havoc(regs[0].value);
        block.assign(regs[0].offset, 0);
        break;
    case RET_INTEGER:
        block.havoc(regs[0].value);
        block.assign(regs[0].region, T_NUM);
        break;
    case RET_VOID:
        // no havoc r0?
        break;
    }
}

template<typename Dom, typename T>
void load_datapointer(multiblock_t post, Dom& target, lin_cst_t cst, T lower_bound)
{
    post.assume(cst);

    post.assign(target.region, T_DATA);
    post.havoc(target.value);
    post.assume(1 <= target.value);
    post.assign(target.offset, lower_bound);
}

void constraints::exec_mem_access(multiblock_t& block, ebpf_inst inst)
{
    uint8_t mem = is_load(inst.opcode) ? inst.src : inst.dst;
    int width = access_width(inst.opcode);

    if (mem == 10) {
        auto offset = inst.offset;
        // not dynamic
        assert(offset <= -width);
        assert(offset >= -STACK_SIZE);
        if (is_load(inst.opcode)) {
            stack_arr.load(block, regs[inst.dst], offset, width);
        } else {
            stack_arr.store(block, offset, regs[inst.src], width);
        }
        return;
    } else if ((inst.opcode & 0xE0) == 0x20 || (inst.opcode & 0xE0) == 0x40) { // TODO NAME: LDABS, LDIND
        // load only
        auto target = regs[inst.dst];
        ctx_arr.load(block, target, inst.offset, width);
        if (inst.offset == ctx_desc.data) {
            if (ctx_desc.meta > 0)
                block.assign(target.offset, meta_size);
            else 
                block.assign(target.offset, 0);
        } else if (inst.offset == ctx_desc.end) {
            block.assign(target.offset, total_size);
        } else if (inst.offset == ctx_desc.meta) {
            block.assign(target.offset, 0);
        } else {
            block.assign(target.region, T_NUM);
            return;
        }
        block.havoc(target.value);
        block.assertion(target.value != 0);
        block.assign(target.region, T_DATA);
        return;
    } else {
        block.assertion(regs[mem].value != 0);
        block.assertion(regs[mem].region != T_NUM);
        {
            multiblock_t stack = block.branch("assume_stack");
            lin_exp_t addr = regs[mem].offset - inst.offset;
            stack.assume(regs[mem].region == T_STACK);
            stack.assertion(addr <= -width);
            stack.assertion(addr >= -STACK_SIZE);
            if (is_load(inst.opcode)) {
                stack_arr.load(stack, regs[inst.dst], addr, width);
            } else {
                stack_arr.store(stack, addr, regs[inst.src], width);
            }
        }
        {
            multiblock_t ctx = block.branch("assume_ctx");
            lin_exp_t addr = regs[mem].offset + inst.offset;
            ctx.assume(regs[mem].region == T_CTX);
            ctx.assertion(addr >= 0);
            ctx.assertion(addr <= ctx_desc.size - width);
            int width = access_width(inst.opcode);
            if (is_load(inst.opcode)) {
                if (ctx_desc.data >= 0) {
                    multiblock_t normal = ctx.branch("normal");
                    load_datapointer(ctx.branch("data_start"), regs[inst.dst], addr == ctx_desc.data, meta_size);
                    load_datapointer(ctx.branch("data_end"), regs[inst.dst], addr == ctx_desc.end, total_size);
                    if (ctx_desc.meta >= 0) {
                        load_datapointer(ctx.branch("meta"), regs[inst.dst], addr == ctx_desc.meta, 0);
                        normal.assume(addr != ctx_desc.meta);
                    }
                    normal.assume(addr != ctx_desc.data);
                    normal.assume(addr != ctx_desc.end);
                    ctx_arr.load(normal, regs[inst.dst], addr, width);
                    normal.assign(regs[inst.dst].region, T_NUM);
                } else {
                    ctx_arr.load(ctx, regs[inst.dst], addr, width);
                    ctx.assign(regs[inst.dst].region, T_NUM);
                }
            } else {
                ctx_arr.store(ctx, addr, regs[inst.src], width);
            }
        }
        if (ctx_desc.data >= 0) {
            multiblock_t data = block.branch("assume_data");
            lin_exp_t addr = regs[mem].offset + inst.offset;
            data.assume(regs[mem].region == T_DATA);
            data.assertion(addr >= 0);
            data.assertion(addr <= total_size - width);
            if (is_load(inst.opcode)) {
                data_arr.load(data, regs[inst.dst], addr, width);
                data.assign(regs[inst.dst].region, T_NUM);
            } else {
                data_arr.store(data, addr, regs[inst.src], width);
            }
        }
        {
            multiblock_t map = block.branch("assume_map");
            lin_exp_t addr = regs[mem].offset + inst.offset;
            map.assume(regs[mem].region == T_MAP);
            map.assertion(addr >= 0);
            constexpr int MAP_SIZE = 256;
            map.assertion(addr <= MAP_SIZE - width);
            if (is_load(inst.opcode)) {
                data_arr.load(map, regs[inst.dst], addr, width);
                map.assign(regs[inst.dst].region, T_NUM);
            } else {
                data_arr.store(map, addr, regs[inst.src], width);
            }
        }
        return;
    }
}

void constraints::exec_alu(ebpf_inst inst, basic_block_t& block)
{
    assert((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU
         ||(inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64);

    auto& dst = regs[inst.dst];
    auto& src = regs[inst.src];

    int imm = inst.imm;

    // TODO: add assertion for all operators that the arguments are initialized
    /*if (inst.opcode & EBPF_SRC_REG) {
        assert_init(block, regs[inst.src]);
    }
    assert_init(block, regs[inst.dst]);*/
    switch (inst.opcode) {
    case EBPF_OP_LE:
    case EBPF_OP_BE:
        block.havoc(dst.value);
        no_pointer(block, dst);
        break;

    case EBPF_OP_ADD_IMM:
    case EBPF_OP_ADD64_IMM:
        block.add(dst.value, dst.value, imm);
        block.add(dst.offset, dst.offset, imm);
        break;
    case EBPF_OP_ADD_REG:
    case EBPF_OP_ADD64_REG:
        block.add(dst.value, dst.value, src.value);
        block.add(dst.offset, dst.offset, src.value); // XXX note src.value
        break;
    case EBPF_OP_SUB_IMM:
    case EBPF_OP_SUB64_IMM:
        block.sub(dst.value, dst.value, imm);
        block.sub(dst.offset, dst.offset, imm);
        break;
    case EBPF_OP_SUB_REG:
    case EBPF_OP_SUB64_REG:
        block.sub(dst.offset, dst.offset, src.offset);
        block.sub(dst.offset, dst.offset, src.value); // XXX note src.value
        break;
    case EBPF_OP_MUL_IMM:
    case EBPF_OP_MUL64_IMM:
        block.mul(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MUL_REG:
    case EBPF_OP_MUL64_REG:
        block.mul(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_DIV_IMM:
    case EBPF_OP_DIV64_IMM:
        block.div(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_DIV_REG:
    case EBPF_OP_DIV64_REG:
        block.div(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_OR_IMM:
    case EBPF_OP_OR64_IMM:
        block.bitwise_or(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_OR_REG:
    case EBPF_OP_OR64_REG:
        block.bitwise_or(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_AND_IMM:
    case EBPF_OP_AND64_IMM:
        block.bitwise_and(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_AND_REG:
    case EBPF_OP_AND64_REG:
        block.bitwise_and(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_LSH_IMM:
    case EBPF_OP_LSH64_IMM:
        block.lshr(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_LSH_REG:
    case EBPF_OP_LSH64_REG:
        block.lshr(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_RSH_IMM:
    case EBPF_OP_RSH64_IMM:
        block.ashr(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_RSH_REG:
    case EBPF_OP_RSH64_REG:
        block.ashr(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_NEG64:
        block.mul(dst.value, dst.value, -1); // ???
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOD_IMM:
    case EBPF_OP_MOD64_IMM:
        block.rem(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOD_REG:
    case EBPF_OP_MOD64_REG:
        block.rem(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_XOR_IMM:
    case EBPF_OP_XOR64_IMM:
        block.bitwise_xor(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_XOR_REG:
    case EBPF_OP_XOR64_REG:
        block.bitwise_xor(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOV_IMM:
    case EBPF_OP_MOV64_IMM:
        block.assign(dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOV_REG:
    case EBPF_OP_MOV64_REG:
        block.assign(dst.value, src.value);
        block.assign(dst.offset, src.offset);
        block.assign(dst.region, src.region);
        break;
    case EBPF_OP_ARSH_IMM:
    case EBPF_OP_ARSH64_IMM:
        block.ashr(dst.value, dst.value, imm); // = (int64_t)dst >> imm;
        no_pointer(block, dst);
        break;
    case EBPF_OP_ARSH_REG:
    case EBPF_OP_ARSH64_REG:
        block.ashr(dst.value, dst.value, src.value); // = (int64_t)dst >> src;
        no_pointer(block, dst);
        break;
    default:
        assert(false);
        break;
    }
    if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU)
        wrap32(block, dst.value);
}
