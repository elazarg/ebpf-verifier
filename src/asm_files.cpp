// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <sys/stat.h>

#include "asm_files.hpp"
#include "platform.hpp"

#include "elfio/elfio.hpp"

using std::cout;
using std::string;
using std::vector;

template <typename T>
static vector<T> vector_of(ELFIO::section* sec) {
    if (!sec)
        return {};
    auto data = sec->get_data();
    auto size = sec->get_size();
    assert(size % sizeof(T) == 0);
    return {(T*)data, (T*)(data + size)};
}

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options) {
    if (map_type.is_value_map_fd) {
        // Map-in-map is not yet supported.
        return -1;
    }
    if ((map_type.is_array && key_size != 4) || (key_size > (1 << 8)))
        throw std::runtime_error("bad map key size " + std::to_string(key_size));
    if (value_size > (1 << (31 - 8)))
        throw std::runtime_error("bad map value size " + std::to_string(value_size));
    int res = (value_size << 8) + key_size;
    return res;
}

EbpfMapDescriptor* find_map_descriptor(int map_fd) {
    for (EbpfMapDescriptor& map : global_program_info.map_descriptors) {
        if (map.original_fd == map_fd) {
            return &map;
        }
    }
    return nullptr;
}

bool is_map_section(const std::string& name) {
    std::string maps_prefix = "maps/";
    return name == "maps" || (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0);
}

// parse_maps_sections processes all maps sections in the provided ELF file by calling the platform-specific maps
// parser. The section index of each maps section is inserted into section_indices. Maps sections are identified as any
// section called "maps", or matching "maps/<map-name>".
void parse_map_sections(const ebpf_verifier_options_t* options, const ebpf_platform_t* platform, const ELFIO::elfio& reader, std::vector<EbpfMapDescriptor>& map_descriptors, std::set<ELFIO::Elf_Half>& section_indices) {
    for (ELFIO::Elf_Half i = 0; i < reader.sections.size(); ++i) {
        auto s = reader.sections[i];
        if (is_map_section(s->get_name())) {
            platform->parse_maps_section(map_descriptors, s->get_data(), s->get_size(), platform, *options);
            section_indices.insert(s->get_index());
        }
    }
}

vector<raw_program> read_elf(const std::string& path, const std::string& desired_section, const ebpf_verifier_options_t* options, const ebpf_platform_t* platform) {
    if (options == nullptr)
        options = &ebpf_verifier_default_options;
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        struct stat st;
        if (stat(path.c_str(), &st)) {
            throw std::runtime_error(string(strerror(errno)) + " opening " + path);
        }
        throw std::runtime_error(string("Can't process ELF file ") + path);
    }

    program_info info{platform};
    std::set<ELFIO::Elf_Half> map_section_indices;

    parse_map_sections(options, platform, reader, info.map_descriptors, map_section_indices);

    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};
    auto read_reloc_value = [&symbols,platform](int symbol) -> size_t {
        string symbol_name;
        ELFIO::Elf64_Addr value{};
        ELFIO::Elf_Xword size{};
        unsigned char bind{};
        unsigned char type{};
        ELFIO::Elf_Half section_index{};
        unsigned char other{};
        symbols.get_symbol(symbol, symbol_name, value, size, bind, type, section_index, other);

        return value / platform->map_record_size;
    };

    vector<raw_program> res;

    for (const auto section : reader.sections) {
        const string name = section->get_name();
        if (!desired_section.empty() && name != desired_section)
            continue;
        if (name == "license" || name == "version" || name == "maps")
            continue;
        if (name != ".text" && name.find('.') == 0) {
            continue;
        }
        info.type = platform->get_program_type(name, path);
        if (section->get_size() == 0)
            continue;
        raw_program prog{path, name, vector_of<ebpf_inst>(section), info};
        auto prelocs = reader.sections[string(".rel") + name];
        if (!prelocs)
            prelocs = reader.sections[string(".rela") + name];

        if (prelocs) {
            ELFIO::const_relocation_section_accessor reloc{reader, prelocs};
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol{};
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword addend;

            // Below, only relocations of symbols located in the map sections are allowed,
            // so if there are relocations there needs to be a maps section.
            if (reloc.get_entries_num() && !map_section_indices.size()) {
                throw std::runtime_error(string("Can't find any maps sections in file ") + path);
            }

            for (ELFIO::Elf_Xword i = 0; i < reloc.get_entries_num(); i++) {
                if (reloc.get_entry(i, offset, symbol, type, addend)) {
                    ebpf_inst& inst = prog.prog[offset / sizeof(ebpf_inst)];

                    string symbol_name;
                    ELFIO::Elf64_Addr symbol_value{};
                    unsigned char symbol_bind{};
                    unsigned char symbol_type{};
                    ELFIO::Elf_Half symbol_section_index{};
                    unsigned char symbol_other{};
                    ELFIO::Elf_Xword symbol_size{};

                    symbols.get_symbol(symbol, symbol_name, symbol_value, symbol_size, symbol_bind, symbol_type,
                                       symbol_section_index, symbol_other);

                    // Only perform relocation for symbols located in the maps section.
                    if (map_section_indices.find(symbol_section_index) == map_section_indices.end()) {
                        throw std::runtime_error(string("Unresolved external symbol " + symbol_name +
                                                        " at location " + std::to_string(offset / sizeof(ebpf_inst))));
                    }

                    // Only permit loading the address of the map.
                    if ((inst.opcode & INST_CLS_MASK) != INST_CLS_LD)
                    {
                        throw std::runtime_error(string("Illegal operation on symbol " + symbol_name +
                                                        " at location " + std::to_string(offset / sizeof(ebpf_inst))));
                    }
                    inst.src = 1; // magic number for LoadFd

                    size_t reloc_value = read_reloc_value(symbol);
                    if (reloc_value >= info.map_descriptors.size()) {
                        throw std::runtime_error(string("Bad reloc value (") + std::to_string(reloc_value) + "). "
                                                 + "Make sure to compile with -O2.");
                    }
                    inst.imm = info.map_descriptors.at(reloc_value).original_fd;
                }
            }
        }
        res.push_back(prog);
    }
    if (res.empty()) {
        if (desired_section.empty()) {
            throw std::runtime_error(string("Can't find any non-empty TEXT sections in file ") + path);
        }
        throw std::runtime_error(string("Can't find section ") + desired_section + " in file " + path);
    }
    return res;
}
