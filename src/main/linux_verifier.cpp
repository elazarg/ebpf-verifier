// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#if __linux__

#include <unistd.h>
#include <linux/bpf.h>
#include <ctime>

#include "config.hpp"
#include "linux_verifier.hpp"
#include "utils.hpp"


static bpf_prog_type to_linuxtype(BpfProgType t) {
    switch (t) {
    case BpfProgType::UNSPEC: return BPF_PROG_TYPE_UNSPEC;
    case BpfProgType::SOCKET_FILTER: return BPF_PROG_TYPE_SOCKET_FILTER;
    case BpfProgType::KPROBE: return BPF_PROG_TYPE_KPROBE;
    case BpfProgType::SCHED_CLS: return BPF_PROG_TYPE_SCHED_CLS;
    case BpfProgType::SCHED_ACT: return BPF_PROG_TYPE_SCHED_ACT;
    case BpfProgType::TRACEPOINT: return BPF_PROG_TYPE_TRACEPOINT;
    case BpfProgType::XDP: return BPF_PROG_TYPE_XDP;
    case BpfProgType::PERF_EVENT: return BPF_PROG_TYPE_PERF_EVENT;
    case BpfProgType::CGROUP_SKB: return BPF_PROG_TYPE_CGROUP_SKB;
    case BpfProgType::CGROUP_SOCK: return BPF_PROG_TYPE_CGROUP_SOCK;
    case BpfProgType::LWT_IN: return BPF_PROG_TYPE_LWT_IN;
    case BpfProgType::LWT_OUT: return BPF_PROG_TYPE_LWT_OUT;
    case BpfProgType::LWT_XMIT: return BPF_PROG_TYPE_LWT_XMIT;
    case BpfProgType::SOCK_OPS: return BPF_PROG_TYPE_SOCK_OPS;
    case BpfProgType::SK_SKB: return BPF_PROG_TYPE_SK_SKB;
    case BpfProgType::CGROUP_DEVICE: return BPF_PROG_TYPE_CGROUP_DEVICE;
    // case BpfProgType::SK_MSG: return BPF_PROG_TYPE_SK_MSG;
    // case BpfProgType::RAW_TRACEPOINT: return BPF_PROG_TYPE_RAW_TRACEPOINT;
    // case BpfProgType::CGROUP_SOCK_ADDR: return BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
    // case BpfProgType::LWT_SEG6LOCAL: return BPF_PROG_TYPE_LWT_SEG6LOCAL;
    // case BpfProgType::LIRC_MODE2: return BPF_PROG_TYPE_LIRC_MODE2;
    default: return BPF_PROG_TYPE_SOCKET_FILTER;
    }
    return BPF_PROG_TYPE_UNSPEC;
}

static int do_bpf(bpf_cmd cmd, union bpf_attr& attr) { return syscall(321, cmd, &attr, sizeof(attr)); }

/** Try to allocate a Linux map.
 *
 *  This function requires admin privileges.
 */
int create_map_linux(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options) {
    union bpf_attr attr{};
    memset(&attr, '\0', sizeof(attr));
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = 20;
    attr.map_flags = map_type == BPF_MAP_TYPE_HASH ? BPF_F_NO_PREALLOC : 0;
    int map_fd = do_bpf(BPF_MAP_CREATE, attr);
    if (map_fd < 0) {
        if (options.print_failures) {
            std::cerr << "Failed to create map, " << strerror(errno) << "\n";
            std::cerr << "Map: \n"
                      << " map_type = " << attr.map_type << "\n"
                      << " key_size = " << attr.key_size << "\n"
                      << " value_size = " << attr.value_size << "\n"
                      << " max_entries = " << attr.max_entries << "\n"
                      << " map_flags = " << attr.map_flags << "\n";
        }
        exit(2);
    }
    return map_fd;
}

/** Run the built-in Linux verifier on a raw eBPF program.
 *
 *  \return A pair (passed, elapsec_secs)
 */

std::tuple<bool, double> bpf_verify_program(BpfProgType type, const std::vector<ebpf_inst>& raw_prog, ebpf_verifier_options_t* options) {
    std::vector<char> buf(options->print_failures ? 1000000 : 10);
    buf[0] = 0;
    memset(buf.data(), '\0', buf.size());

    union bpf_attr attr{};
    memset(&attr, '\0', sizeof(attr));
    attr.prog_type = (__u32)to_linuxtype(type);
    attr.insn_cnt = (__u32)raw_prog.size();
    attr.insns = (__u64)raw_prog.data();
    attr.license = (__u64) "GPL";
    if (options->print_failures) {
        attr.log_buf = (__u64)buf.data();
        attr.log_size = buf.size();
        attr.log_level = 3;
    }
    attr.kern_version = 0x041800;
    attr.prog_flags = 0;

    const auto [res, elapsed_secs] = timed_execution([&] {
        return do_bpf(BPF_PROG_LOAD, attr);
    });
    if (res < 0) {
        if (options->print_failures) {
            std::cerr << "Failed to verify program: " << strerror(errno) << " (" << errno << ")\n";
            std::cerr << "LOG: " << (char*)attr.log_buf;
        }
        return {false, elapsed_secs};
    }
    return {true, elapsed_secs};
}

#endif
