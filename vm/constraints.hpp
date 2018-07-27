#pragma once

#include <vector>
#include <string>

#include "instructions.hpp"
#include "common.hpp"
#include "cfg.hpp"
#include "multiblock.hpp"

using crab::cfg_impl::variable_factory_t;
using ikos::z_number;

constexpr int STACK_SIZE=512;

struct ptype_descr {
    int size;
    int data = -1;
    int end = -1;
    int meta = -1; // data to meta is like end to data. i.e. meta <= data <= end
};

enum region_t {
    T_UNINIT,
    T_NUM,
    T_CTX,
    T_STACK,
    T_DATA,
    T_MAP,
};

// hand-crafted mix of absolute values and offsets 
class constraints final
{
    struct dom_t {
        var_t value;
        var_t offset;
        var_t region;
        dom_t(variable_factory_t& vfac, int i) :
            value{vfac[std::string("r") + std::to_string(i)], crab::INT_TYPE, 64}, 
            offset{vfac[std::string("off") + std::to_string(i)], crab::INT_TYPE, 64},
            region{vfac[std::string("t") + std::to_string(i)], crab::INT_TYPE, 8}
        { }
    };

    static void assume_init(multiblock_t& block, dom_t& target)
    {
        block.assume(target.region >= T_NUM);
    }

    static void assert_init(multiblock_t& block, dom_t& target)
    {
        block.assertion(target.region >= T_NUM);
    }

    struct array_dom_t {
        var_t values;
        var_t offsets;
        var_t regions;
        array_dom_t(variable_factory_t& vfac, std::string name) :
            values{vfac[std::string(name + "_vals")], crab::ARR_INT_TYPE, 64}, 
            offsets{vfac[std::string(name + "_offsets")], crab::ARR_INT_TYPE, 64},
            regions{vfac[std::string(name + "_regions")], crab::ARR_INT_TYPE, 8}
        { }
        template<typename T>
        void load(multiblock_t& block, dom_t& target, const T& offset, int width) {
            block.block().array_load(target.value, values, offset, width);
            block.block().array_load(target.offset, offsets, offset, width);
            block.block().array_load(target.region, regions, offset, width);
            // TODO: remove when we have a memory domain ...
            block.havoc(target.value);
            block.havoc(target.offset);
            block.havoc(target.region);
            // ... however for maps this should be kept:
            assume_init(block, target);
        }
        template<typename T>
        void store(multiblock_t& block, T& offset, dom_t& target, int width) {
            assert_init(block, target);
            block.block().array_store(values, offset, target.value, width);
            block.block().array_store(offsets, offset, target.offset, width);
            block.block().array_store(regions, offset, target.region, width);
        }
    };

    ptype_descr ctx_desc;
    variable_factory_t vfac;
    std::vector<dom_t> regs;
    array_dom_t stack_arr{vfac, "stack"};
    array_dom_t ctx_arr{vfac, "ctx"};
    array_dom_t data_arr{vfac, "data"};
    var_t pc{vfac[std::string("pc")], crab::INT_TYPE, 16};
    var_t meta_size{vfac[std::string("meta_size")], crab::INT_TYPE, 64};
    var_t total_size{vfac[std::string("total_data_size")], crab::INT_TYPE, 64};

    static void no_pointer(basic_block_t& block, constraints::dom_t& v);
    void exec_mem_access(multiblock_t& multiblock, ebpf_inst inst);
    void exec_alu(ebpf_inst inst, basic_block_t& block);
    void exec_call(multiblock_t& multiblock, int32_t imm);
public:
    constraints(ebpf_prog_type prog_type);
    void setup_entry(basic_block_t& entry);

    void jump(ebpf_inst inst, basic_block_t& block, bool taken);
    void exec(ebpf_inst inst, multiblock_t& multiblock);
};
