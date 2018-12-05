#pragma once

#include <vector>
#include "linux_ebpf.hpp"
#include "asm_syntax.hpp"

std::vector<ebpf_inst> marshal(Instruction ins, pc_t pc);
std::vector<ebpf_inst> marshal(std::vector<Instruction> insts);
// TODO marshal to ostream?

Instruction parse_instruction(std::string text);
std::vector<std::tuple<Label, Instruction>> parse_program(std::istream& is);

std::ifstream open_asm_file(std::string path);
