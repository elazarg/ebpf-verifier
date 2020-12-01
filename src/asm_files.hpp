// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <fstream>
#include <string>
#include <tuple>
#include <vector>

#include "asm_syntax.hpp"
#include "gpl/spec_type_descriptors.hpp"

using MapFd = auto(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries) -> int;

std::vector<raw_program> read_raw(std::string path, program_info info);
std::vector<raw_program> read_elf(const std::string& path, const std::string& section, MapFd* allocate_fds);

void write_binary_file(std::string path, const char* data, size_t size);

std::ifstream open_asm_file(std::string path);
