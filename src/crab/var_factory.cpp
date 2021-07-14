// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/*
 * Factories for variable names.
 */

#include "crab/variable.hpp"

namespace crab {

variable_t variable_t::make(const std::string& name) {
    auto it = std::find(names.begin(), names.end(), name);
    if (it == names.end()) {
        names.emplace_back(name);
        return variable_t(names.size() - 1);
    } else {
        return variable_t(std::distance(names.begin(), it));
    }
}

thread_local std::vector<std::string> variable_t::names;

void variable_t::clear_thread_local_state() {
    names = std::vector<std::string>{
        "r0.value",  "r0.offset",  "r0.type",
        "r1.value",  "r1.offset",  "r1.type",
        "r2.value",  "r2.offset",  "r2.type",
        "r3.value",  "r3.offset",  "r3.type",
        "r4.value",  "r4.offset",  "r4.type",
        "r5.value",  "r5.offset",  "r5.type",
        "r6.value",  "r6.offset",  "r6.type",
        "r7.value",  "r7.offset",  "r7.type",
        "r8.value",  "r8.offset",  "r8.type",
        "r9.value",  "r9.offset",  "r9.type",
        "r10.value", "r10.offset", "r10.type",
        "S.value",   "S.offset",   "S.type",
        "data_size", "meta_size",  "map_value_size",
        "map_key_size"};
}

static std::string name_of(data_kind_t kind) {
    switch (kind) {
    case data_kind_t::offsets: return "offset";
    case data_kind_t::values: return "value";
    case data_kind_t::types: return "type";
    }
    return {};
}

variable_t variable_t::reg(data_kind_t kind, int i) {
    return make("r" + std::to_string(i) + "." + name_of(kind)); }

std::ostream& operator<<(std::ostream& o, const data_kind_t& s) {
    return o << name_of(s);
}

static std::string mk_scalar_name(data_kind_t kind, int o, int size) {
    std::stringstream os;
    os << "S." << name_of(kind) << "[" << o;
    if (size != 1) {
        os << "..." << o + size - 1;
    }
    os << "]";
    return os.str();
}

variable_t variable_t::cell_var(data_kind_t array, index_t offset, unsigned size) {
    return make(mk_scalar_name(array, - (512 - (int)offset), (int)size));
}

variable_t variable_t::map_value_size() { return make("map_value_size"); }
variable_t variable_t::map_key_size() { return make("map_key_size"); }
variable_t variable_t::meta_offset() { return make("meta_offset"); }
variable_t variable_t::packet_size() { return make("packet_size"); }
variable_t variable_t::instruction_count() { return make("instruction_count"); }

static bool ends_with(const std::string& str, const std::string& suffix)
{
    return str.size() >= suffix.size() && 0 == str.compare(str.size()-suffix.size(), suffix.size(), suffix);
}

std::vector<variable_t> variable_t::get_type_variables() {
    std::vector<variable_t> res;
    for (const std::string& name: names) {
        if (ends_with(name, ".type"))
            res.push_back(make(name));
    }
    return res;
}
} // end namespace crab
