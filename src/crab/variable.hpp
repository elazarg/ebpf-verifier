// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <iosfwd>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

#include "crab_utils/bignums.hpp"
#include "crab_utils/debug.hpp"
#include "radix_tree/radix_tree.hpp"
using index_t = uint64_t;

/* Basic type definitions */

namespace crab {

// XXX: this is eBPF-specific.
enum class data_kind_t { types, values, offsets };
std::ostream& operator<<(std::ostream& o, const data_kind_t& s);

// Wrapper for typed variables used by the crab abstract domains and linear_constraints.
// Being a class (instead of a type alias) enables overloading in dsl_syntax
class variable_t final {
    index_t _id;

    explicit variable_t(index_t id) : _id(id) {}

  public:
    [[nodiscard]] std::size_t hash() const { return (size_t)_id; }

    bool operator==(variable_t o) const { return _id == o._id; }

    bool operator!=(variable_t o) const { return (!(operator==(o))); }

    // for flat_map
    bool operator<(variable_t o) const { return _id < o._id; }


    [[nodiscard]] std::string name() const { return names.at(_id); }

    bool is_type() { return names.at(_id).find(".type") != std::string::npos; }

    friend std::ostream& operator<<(std::ostream& o, variable_t v)  { return o << names.at(v._id); }

    // var_factory portion.
    // This singleton is eBPF-specific, to avoid life time issues and/or passing factory explicitly everywhere:
  private:
    static variable_t make(const std::string& name);
    static thread_local std::vector<std::string> names;

  public:
    static void clear_thread_local_state();

    static std::vector<variable_t> get_type_variables();
    static variable_t reg(data_kind_t, int);
    static variable_t cell_var(data_kind_t array, index_t offset, unsigned size);
    static variable_t map_value_size();
    static variable_t map_key_size();
    static variable_t meta_offset();
    static variable_t packet_size();
    static variable_t instruction_count();
}; // class variable_t

inline size_t hash_value(variable_t v) { return v.hash(); }

} // namespace crab
