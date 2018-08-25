/*
 * Copyright 2018 VMware, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <functional>
#include <map>
#include <ctime>
#include <iostream>

#include <boost/signals2.hpp>

#include <crab/checkers/base_property.hpp>
#include <crab/checkers/div_zero.hpp>
#include <crab/checkers/assertion.hpp>
#include <crab/checkers/checker.hpp>
#include <crab/analysis/dataflow/assumptions.hpp>

#include "crab_dom.hpp"

#include "instructions.hpp"
#include "common.hpp"
#include "cfg.hpp"
#include "verifier.hpp"


using std::string;
using std::vector;
using std::map;

using printer_t = boost::signals2::signal<void(const string&)>;

using namespace crab::cfg;
using namespace crab::checker;
using namespace crab::analyzer;
using namespace crab::domains;
using namespace crab::domain_impl;

static checks_db analyze(string domain_name, cfg_t& cfg, printer_t& pre_printer, printer_t& post_printer);

bool abs_validate(vector<struct ebpf_inst> insts,
                  string domain_name, enum ebpf_prog_type prog_type)
{
    variable_factory_t vfac;
    cfg_t cfg(entry_label(), ARR);
    build_cfg(cfg, vfac, insts, prog_type);

    printer_t pre_printer;
    printer_t post_printer;
    
    checks_db checks = analyze(domain_name, cfg, pre_printer, post_printer);
    int nwarn = checks.get_total_warning() + checks.get_total_error();
    if (global_options.print_invariants) {
        for (string label : sorted_labels(cfg)) {
            pre_printer(label);
            cfg.get_node(label).write(crab::outs());
            post_printer(label);
        }
    }

    if (nwarn > 0) {
        checks.write(crab::outs());
        return false;
    }
    return true;
}

template<typename analyzer_t>
auto extract_pre(analyzer_t& analyzer)
{
    map<string, typename analyzer_t::abs_dom_t> res;
    for (const auto& block : analyzer.get_cfg())
        res.emplace(block.label(), analyzer.get_pre(block.label()));
    return res;
}

template<typename analyzer_t>
auto extract_post(analyzer_t& analyzer)
{
    map<string, typename analyzer_t::abs_dom_t> res;
    for (const auto& block : analyzer.get_cfg())
        res.emplace(block.label(), analyzer.get_post(block.label()));
    return res;
}

template<typename analyzer_t>
static checks_db check(analyzer_t& analyzer)
{
    constexpr int verbose = 2;
    using checker_t = intra_checker<analyzer_t>;
    using prop_checker_ptr = typename checker_t::prop_checker_ptr;
    checker_t checker(analyzer, {
        prop_checker_ptr(new assert_property_checker<analyzer_t>(verbose))
        //,
        //prop_checker_ptr(new div_zero_property_checker<analyzer_t>(verbose))
    });
    checker.run();
    return checker.get_all_checks();
}

static checks_db dont_analyze(cfg_t& cfg, printer_t& printer, printer_t& post_printer)
{
    return {};
}

template<typename dom_t, typename analyzer_t>
void check_semantic_reachability(cfg_t& cfg, analyzer_t& analyzer, checks_db& c)
{
    for (auto& b : cfg) {
        dom_t post = analyzer.get_post(b.label());
        if (post.is_bottom()) {
            if (b.label().find(':') == string::npos)
                c.add(_ERR, {"unreachable", (unsigned int)first_num(b.label()), 0});
        }
    }
}

template<typename dom_t>
static checks_db analyze(cfg_t& cfg, printer_t& pre_printer, printer_t& post_printer)
{
    using analyzer_t = intra_fwd_analyzer<cfg_ref<cfg_t>, dom_t>;
    
    liveness<typename analyzer_t::cfg_t> live(cfg);
    live.exec();

    analyzer_t analyzer(cfg, dom_t::top(), &live);
    analyzer.run();

    pre_printer.connect([pre=extract_pre(analyzer)](const string& label) {
        dom_t inv = pre.at(label);
        crab::outs() << "\n" << inv << "\n";
    });
    post_printer.connect([post=extract_post(analyzer)](const string& label) {
        dom_t inv = post.at(label);
        crab::outs() << "\n" << inv << "\n";
    });
    checks_db c = check(analyzer);
    if (global_options.check_semantic_reachability) {
        check_semantic_reachability<dom_t>(cfg, analyzer, c);
    }
    return c;
}

struct domain_desc {
    std::function<checks_db(cfg_t&, printer_t&, printer_t&)> analyze;
    string description;
};

const map<string, domain_desc> domains{
    { "interval"          , { analyze<z_interval_domain_t>, "simple interval (z_interval_domain_t)" } },
    { "interval-arr"      , { analyze<array_expansion_domain<z_interval_domain_t>>, "mem: simple interval (z_interval_domain_t)" } },
    { "ric"               , { analyze<z_ric_domain_t>, "numerical congruence (z_ric_domain_t)" } },
    { "ric-arr"           , { analyze<array_expansion_domain<z_ric_domain_t>>, "mem: numerical congruence (z_ric_domain_t)" } },
    { "dbm"               , { analyze<z_dbm_domain_t>, "sparse dbm (z_dbm_domain_t)" } },
    { "dbm-arr"           , { analyze<array_expansion_domain<z_dbm_domain_t>>, "mem: sparse dbm (z_dbm_domain_t)" } },
    { "sdbm"              , { analyze<z_sdbm_domain_t>, "split dbm (z_sdbm_domain_t)" } },
    { "sdbm-arr"          , { analyze<array_expansion_domain<z_sdbm_domain_t>>, "mem: split dbm (z_sdbm_domain_t)" } },
    { "boxes"             , { analyze<z_boxes_domain_t>, "boxes (z_boxes_domain_t)" } },
    { "boxes-arr"         , { analyze<array_expansion_domain<z_boxes_domain_t>>, "mem: boxes (z_boxes_domain_t)" } },
    { "disj_interval"     , { analyze<z_dis_interval_domain_t>, "disjoint intervals (z_dis_interval_domain_t)" } },
    { "disj_interval-arr" , { analyze<array_expansion_domain<z_dis_interval_domain_t>>, "mem: disjoint intervals (z_dis_interval_domain_t)" } },
#ifdef APRON
    { "box_apron"         , { analyze<z_box_apron_domain_t>, "boxes x apron (z_box_apron_domain_t)" } },
    { "box_apron-arr"     , { analyze<array_expansion_domain<z_box_apron_domain_t>>, "mem: boxes x apron (z_box_apron_domain_t)" } },
    { "opt_oct_apron"     , { analyze<z_opt_oct_apron_domain_t>, "optional octagon x apron (z_opt_oct_apron_domain_t)" } },
    { "opt_oct_apron-arr" , { analyze<array_expansion_domain<z_opt_oct_apron_domain_t>>, "mem: optional octagon x apron (z_opt_oct_apron_domain_t)" } },
    { "pk_apron"          , { analyze<z_pk_apron_domain_t>, "(z_pk_apron_domain_t)" } },
    { "pk_apron-arr"      , { analyze<array_expansion_domain<z_pk_apron_domain_t>>, "mem: (z_pk_apron_domain_t)" } },
#endif
    { "term"              , { analyze<z_term_domain_t>, "(z_term_domain_t)" } },
    { "term-arr"          , { analyze<array_expansion_domain<z_term_domain_t>>, "mem: (z_term_domain_t)" } },
    { "term_dbm"          , { analyze<z_term_dbm_t>, "(z_term_dbm_t)" } },
    { "term_dbm-arr"      , { analyze<array_expansion_domain<z_term_dbm_t>>, "mem: (z_term_dbm_t)" } },
    { "term_disj_interval", { analyze<z_term_dis_int_t>, "term x disjoint intervals (z_term_dis_int_t)" } },
    { "term_disj_interval-arr", { analyze<array_expansion_domain<z_term_dis_int_t>>, "mem: term x disjoint intervals (z_term_dis_int_t)" } },
    { "num"               , { analyze<z_num_domain_t>, "term x disjoint interval x sparse dbm (z_num_domain_t)" } },
    { "num-arr"           , { analyze<array_expansion_domain<z_num_domain_t>>, "mem: term x disjoint interval x sparse dbm (z_num_domain_t)" } },
    { "num_boxes"         , { analyze<z_num_boxes_domain_t>, "term x boxes x sparse dbm (z_num_domain_t)" } },
    { "num_boxes-arr"     , { analyze<array_expansion_domain<z_num_boxes_domain_t>>, "mem: term x boxes x sparse dbm" } },
    { "wrapped"           , { analyze<z_wrapped_interval_domain_t>, "wrapped interval domain (z_wrapped_interval_domain_t)" } },
    { "wrapped-arr"       , { analyze<array_expansion_domain<z_wrapped_interval_domain_t>>, "mem: wrapped interval domain (z_wrapped_interval_domain_t)" } },
    { "none"              , { dont_analyze, "build CFG only, don't perform analysis" } },
};

global_options_t global_options {
    .simplify = false,
    .stats = false,
    .check_raw_reachability = true,
    .check_semantic_reachability = false,
    .print_invariants = true
};

map<string, string> domain_descriptions()
{
    map<string, string> res;
    for (auto const [name, desc] : domains)
        res.emplace(name, desc.description);
    return res;
}

static checks_db analyze(string domain_name, cfg_t& cfg, printer_t& pre_printer, printer_t& post_printer)
{
    using namespace std;
    clock_t begin = clock();

    checks_db res = domains.at(domain_name).analyze(cfg, pre_printer, post_printer);

    clock_t end = clock();
    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    cout << "seconds:" << elapsed_secs << "\n";
    if (global_options.stats) {
        crab::CrabStats::Print(crab::outs());
        crab::CrabStats::reset();
    }

    return res;
}
