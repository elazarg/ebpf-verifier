#pragma once
#include <cassert>
#include <string>
#include <unordered_map>
#include <vector>

#include "linux_ebpf.hpp"

enum class BpfProgType : int {
    UNSPEC,
    SOCKET_FILTER,
    KPROBE,
    SCHED_CLS,
    SCHED_ACT,
    TRACEPOINT,
    XDP,
    PERF_EVENT,
    CGROUP_SKB,
    CGROUP_SOCK,
    LWT_IN,
    LWT_OUT,
    LWT_XMIT,
    SOCK_OPS,
    SK_SKB,
    CGROUP_DEVICE,
    SK_MSG,
    RAW_TRACEPOINT,
    CGROUP_SOCK_ADDR,
    LWT_SEG6LOCAL,
    LIRC_MODE2
};

// Order is important
enum class MapType : unsigned int {
    UNSPEC,
    HASH,
    ARRAY,
    PROG_ARRAY,
    PERF_EVENT_ARRAY,
    PERCPU_HASH,
    PERCPU_ARRAY,
    STACK_TRACE,
    CGROUP_ARRAY,
    LRU_HASH,
    LRU_PERCPU_HASH,
    LPM_TRIE,
    ARRAY_OF_MAPS,
    HASH_OF_MAPS,
    DEVMAP,
    SOCKMAP,
    CPUMAP,
    XSKMAP,
    SOCKHASH,
    CGROUP_STORAGE,
    REUSEPORT_SOCKARRAY,
    PERCPU_CGROUP_STORAGE,
    QUEUE,
    STACK,
};

constexpr int NMAPS = 64;
constexpr int NONMAPS = 5;
constexpr int ALL_TYPES = NMAPS + NONMAPS;

// rough estimates:
constexpr int perf_max_trace_size = 2048;
constexpr int ptregs_size = (3 + 63 + 8 + 2) * 8;
constexpr int cgroup_dev_regions = 3 * 4;
constexpr int kprobe_regions = ptregs_size;
constexpr int tracepoint_regions = perf_max_trace_size;
constexpr int perf_event_regions = 3 * 8 + ptregs_size;
constexpr int socket_filter_regions = 24 * 4;
constexpr int sched_regions = 24 * 4;
constexpr int xdp_regions = 5 * 4;
constexpr int lwt_regions = 24 * 4;
constexpr int cgroup_sock_regions = 12 * 4;
constexpr int sock_ops_regions = 42 * 4 + 2 * 8;
constexpr int sk_skb_regions = 36 * 4;

struct program_info {
    BpfProgType program_type;
    std::vector<EbpfMapDescriptor> map_descriptors;
    EbpfContextDescriptor context_descriptor;
};

extern program_info global_program_info;

struct raw_program {
    std::string filename;
    std::string section;
    std::vector<ebpf_inst> prog;
    program_info info;
};

constexpr EbpfContextDescriptor sk_buff = {sk_skb_regions, 19 * 4, 20 * 4, 35 * 4};
constexpr EbpfContextDescriptor xdp_md = {xdp_regions, 0, 1 * 4, 2 * 4};
constexpr EbpfContextDescriptor sk_msg_md = {17 * 4, 0, 1 * 8, -1}; // TODO: verify
constexpr EbpfContextDescriptor unspec_descr = {0};
constexpr EbpfContextDescriptor cgroup_dev_descr = {cgroup_dev_regions};
constexpr EbpfContextDescriptor kprobe_descr = {kprobe_regions};
constexpr EbpfContextDescriptor tracepoint_descr = {tracepoint_regions};
constexpr EbpfContextDescriptor perf_event_descr = {perf_event_regions};
constexpr EbpfContextDescriptor socket_filter_descr = sk_buff;
constexpr EbpfContextDescriptor sched_descr = sk_buff;
constexpr EbpfContextDescriptor xdp_descr = xdp_md;
constexpr EbpfContextDescriptor lwt_xmit_descr = sk_buff;
constexpr EbpfContextDescriptor lwt_inout_descr = sk_buff;
constexpr EbpfContextDescriptor cgroup_sock_descr = {cgroup_sock_regions};
constexpr EbpfContextDescriptor sock_ops_descr = {sock_ops_regions};
constexpr EbpfContextDescriptor sk_skb_descr = sk_buff;

inline EbpfContextDescriptor get_context_descriptor(BpfProgType t) {
    switch (t) {
    case BpfProgType::UNSPEC: return unspec_descr;
    case BpfProgType::CGROUP_DEVICE: return cgroup_dev_descr;
    case BpfProgType::CGROUP_SOCK: return cgroup_sock_descr;
    case BpfProgType::CGROUP_SOCK_ADDR: return cgroup_sock_descr;
    case BpfProgType::CGROUP_SKB: return socket_filter_descr;
    case BpfProgType::KPROBE: return kprobe_descr;
    case BpfProgType::TRACEPOINT: return tracepoint_descr;
    case BpfProgType::RAW_TRACEPOINT: return tracepoint_descr;
    case BpfProgType::PERF_EVENT: return perf_event_descr;
    case BpfProgType::SOCKET_FILTER: return socket_filter_descr;
    case BpfProgType::SOCK_OPS: return sock_ops_descr;
    case BpfProgType::SCHED_ACT: return sched_descr;
    case BpfProgType::SCHED_CLS: return sched_descr;
    case BpfProgType::XDP: return xdp_descr;
    case BpfProgType::LWT_XMIT: return lwt_xmit_descr;
    case BpfProgType::LWT_IN: return lwt_inout_descr;
    case BpfProgType::LWT_OUT: return lwt_inout_descr;
    case BpfProgType::SK_SKB: return sk_skb_descr;
    case BpfProgType::SK_MSG: return sk_msg_md;

    case BpfProgType::LWT_SEG6LOCAL: return lwt_xmit_descr;
    case BpfProgType::LIRC_MODE2: return sk_msg_md;
    }
    assert(false);
    return {};
}
