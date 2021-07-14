#include "platform.hpp"
#include "spec_type_descriptors.hpp"

const ebpf_context_descriptor_t g_sk_buff = sk_buff;
const ebpf_context_descriptor_t g_xdp_md = xdp_md;
const ebpf_context_descriptor_t g_sk_msg_md = sk_msg_md;
const ebpf_context_descriptor_t g_unspec_descr = unspec_descr;
const ebpf_context_descriptor_t g_cgroup_dev_descr = cgroup_dev_descr;
const ebpf_context_descriptor_t g_kprobe_descr = kprobe_descr;
const ebpf_context_descriptor_t g_tracepoint_descr = tracepoint_descr;
const ebpf_context_descriptor_t g_perf_event_descr = perf_event_descr;
const ebpf_context_descriptor_t g_cgroup_sock_descr = cgroup_sock_descr;
const ebpf_context_descriptor_t g_sock_ops_descr = sock_ops_descr;

// eBPF helpers are documented at the following links:
// https://github.com/iovisor/bpf-docs/blob/master/bpf_helpers.rst
// https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html

static const struct EbpfHelperPrototype bpf_unspec_proto = {
    .name = "unspec",
};

/* int bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)
 * 	Description
 * 		This special helper is used to trigger a "tail call", or in
 * 		other words, to jump into another eBPF program. The same stack
 * 		frame is used (but values on stack and in registers for the
 * 		caller are not accessible to the callee). This mechanism allows
 * 		for program chaining, either for raising the maximum number of
 * 		available eBPF instructions, or to execute given programs in
 * 		conditional blocks. For security reasons, there is an upper
 * 		limit to the number of successive tail calls that can be
 * 		performed.
 *
 * 		Upon call of this helper, the program attempts to jump into a
 * 		program referenced at index *index* in *prog_array_map*, a
 * 		special map of type **BPF_MAP_TYPE_PROG_ARRAY**, and passes
 * 		*ctx*, a pointer to the context.
 *
 * 		If the call succeeds, the kernel immediately runs the first
 * 		instruction of the new program. This is not a function call,
 * 		and it never returns to the previous program. If the call
 * 		fails, then the helper has no effect, and the caller continues
 * 		to run its subsequent instructions. A call can fail if the
 * 		destination program for the jump does not exist (i.e. *index*
 * 		is superior to the number of entries in *prog_array_map*), or
 * 		if the maximum number of tail calls has been reached for this
 * 		chain of programs. This limit is defined in the kernel by the
 * 		macro **MAX_TAIL_CALL_CNT** (not accessible to user space),
 * 		which is currently set to 32.
 * 	Return
 * 		Negative error in case of failure. No return in case of success
 */
const struct EbpfHelperPrototype bpf_tail_call_proto = {
    .name = "tail_call",
    //.func		= NULL,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_VOID,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

static const struct EbpfHelperPrototype bpf_override_return_proto = {
    .name = "override_return",
    //.func		= bpf_override_return,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

/*
 * int bpf_probe_read(void *dst, u32 size, const void *src)
 * 	Description
 * 		For tracing programs, safely attempt to read *size* bytes from
 * 		address *src* and store the data in *dst*.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_probe_read_proto = {
    .name = "probe_read",
    //.func		= bpf_probe_read,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

/*
 * int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
 *     Copy a NUL terminated string from unsafe address. In case the string
 *     length is smaller than size, the target is not padded with further NUL
 *     bytes. In case the string length is larger than size, just count-1
 *     bytes are copied and the last byte is set to NUL.
 *     @dst: destination address
 *     @size: maximum number of bytes to copy, including the trailing NUL
 *     @unsafe_ptr: unsafe address
 *     Return:
 *       > 0 length of the string including the trailing NUL on success
 *       < 0 error
 */
static const struct EbpfHelperPrototype bpf_probe_read_str_proto = {
    .name = "probe_read_str",
    //.func		= bpf_probe_read_str,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

static const struct EbpfHelperPrototype bpf_probe_write_user_proto = {
    .name = "probe_write_user",
    //.func		= bpf_probe_write_user,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
};

/*
 * int bpf_trace_printk(const char *fmt, int fmt_size, ...)
 *     Return: length of buffer written or negative error
 */
static const struct EbpfHelperPrototype bpf_trace_printk_proto = {
    .name = "trace_printk",
    //.func		= bpf_trace_printk,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
};

static const struct EbpfHelperPrototype bpf_perf_event_read_proto = {
    .name = "perf_event_read",
    //.func		= bpf_perf_event_read,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

/*
 * int bpf_perf_event_read_value(map, flags, buf, buf_size)
 *     read perf event counter value and perf event enabled/running time
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return: 0 on success or negative error code
 */
static const struct EbpfHelperPrototype bpf_perf_event_read_value_proto = {
    .name = "perf_event_read_value",
    //.func		= bpf_perf_event_read_value,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
};

/*
 * int bpf_perf_event_output(struct pt_reg *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)
 * 	Description
 * 		Write raw *data* blob into a special BPF perf event held by
 * 		*map* of type **BPF_MAP_TYPE_PERF_EVENT_ARRAY**. This perf
 * 		event must have the following attributes: **PERF_SAMPLE_RAW**
 * 		as **sample_type**, **PERF_TYPE_SOFTWARE** as **type**, and
 * 		**PERF_COUNT_SW_BPF_OUTPUT** as **config**.
 *
 * 		The *flags* are used to indicate the index in *map* for which
 * 		the value must be put, masked with **BPF_F_INDEX_MASK**.
 * 		Alternatively, *flags* can be set to **BPF_F_CURRENT_CPU**
 * 		to indicate that the index of the current CPU core should be
 * 		used.
 *
 * 		The value to write, of *size*, is passed through eBPF stack and
 * 		pointed by *data*.
 *
 * 		The context of the program *ctx* needs also be passed to the
 * 		helper.
 *
 * 		On user space, a program willing to read the values needs to
 * 		call **perf_event_open**\ () on the perf event (either for
 * 		one or for all CPUs) and to store the file descriptor into the
 * 		*map*. This must be done before the eBPF program can send data
 * 		into it. An example is available in file
 * 		*samples/bpf/trace_output_user.c* in the Linux kernel source
 * 		tree (the eBPF program counterpart is in
 * 		*samples/bpf/trace_output_kern.c*).
 *
 * 		**bpf_perf_event_output**\ () achieves better performance
 * 		than **bpf_trace_printk**\ () for sharing data with user
 * 		space, and is much better suitable for streaming data from eBPF
 * 		programs.
 *
 * 		Note that this helper is not restricted to tracing use cases
 * 		and can be used with programs attached to TC or XDP as well,
 * 		where it allows for passing data to user space listeners. Data
 * 		can be:
 *
 * 		* Only custom structs,
 * 		* Only the packet payload, or
 * 		* A combination of both.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_perf_event_output_proto = {
    .name = "perf_event_output",
    //.func		= bpf_perf_event_output,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
    },
};

/*
 * u64 bpf_get_current_task()
 *     Returns current task_struct
 *     Return: current
 */
static const struct EbpfHelperPrototype bpf_get_current_task_proto = {
    .name = "get_current_task",
    //.func		= bpf_get_current_task,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

/*
 * int bpf_current_task_under_cgroup(map, index)
 *     Check cgroup2 membership of current task
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 current failed the cgroup2 descendant test
 *       == 1 current succeeded the cgroup2 descendant test
 *        < 0 error
 */
static const struct EbpfHelperPrototype bpf_current_task_under_cgroup_proto = {
    .name = "current_task_under_cgroup",
    //.func       = bpf_current_task_under_cgroup,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

// static const struct EbpfHelperPrototype bpf_perf_event_output_proto_tp = {
// 	//.func		= bpf_perf_event_output_tp,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
// 	    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
// 	},
// };

// static const struct EbpfHelperPrototype bpf_get_stackid_proto_tp = {
// 	//.func		= bpf_get_stackid_tp,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
//  },
// };

// // see bpf_get_stack_proto
// static const struct EbpfHelperPrototype bpf_get_stack_proto_tp = {
// 	//.func		= bpf_get_stack_tp,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
// 	    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
//   },
// };

/*
 * int bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, u32 buf_size)
 * 	Description
 * 		For en eBPF program attached to a perf event, retrieve the
 * 		value of the event counter associated to *ctx* and store it in
 * 		the structure pointed by *buf* and of size *buf_size*. Enabled
 * 		and running times are also stored in the structure (see
 * 		description of helper **bpf_perf_event_read_value**\ () for
 * 		more details).
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_perf_prog_read_value_proto = {
    .name = "perf_prog_read_value",
    //.func       = bpf_perf_prog_read_value,
    //.gpl_only   = true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
    .context_descriptor = &g_perf_event_descr
};

// static const struct EbpfHelperPrototype bpf_perf_event_output_proto_raw_tp = {
// 	//.func		= bpf_perf_event_output_raw_tp,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
// 	    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
// 	},
// };

// static const struct EbpfHelperPrototype bpf_get_stackid_proto_raw_tp = {
// 	//.func		= bpf_get_stackid_raw_tp,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
//   },
// };

// static const struct EbpfHelperPrototype bpf_get_stack_proto_raw_tp = {
// 	//.func		= bpf_get_stack_raw_tp,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
// 	    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	},
// };

/* Always built-in helper functions. */

/*
 * void *bpf_map_lookup_elem(&map, &key)
 *     Return: Map value or NULL
 */
static const struct EbpfHelperPrototype bpf_map_lookup_elem_proto = {
    .name = "map_lookup_elem",
    //.func		= bpf_map_lookup_elem,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
        EBPF_ARGUMENT_TYPE_DONTCARE,
        EBPF_ARGUMENT_TYPE_DONTCARE,
        EBPF_ARGUMENT_TYPE_DONTCARE,
    },
};

/*
 * int bpf_map_update_elem(&map, &key, &value, flags)
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_map_update_elem_proto = {
    .name = "map_update_elem",
    //.func		= bpf_map_update_elem,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_DONTCARE,
    },
};

/*
 * int bpf_map_delete_elem(&map, &key)
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_map_delete_elem_proto = {
    .name = "map_delete_elem",
    //.func		= bpf_map_delete_elem,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
        EBPF_ARGUMENT_TYPE_DONTCARE,
        EBPF_ARGUMENT_TYPE_DONTCARE,
        EBPF_ARGUMENT_TYPE_DONTCARE,
    },
};

/*
 * u32 bpf_prandom_u32()
 *     Return: random value
 */
static const struct EbpfHelperPrototype bpf_get_prandom_u32_proto = {
    .name = "get_prandom_u32",
    //.func		= bpf_user_rnd_u32,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static const struct EbpfHelperPrototype bpf_get_smp_processor_id_proto = {
    .name = "get_smp_processor_id",
    //.func		= bpf_get_smp_processor_id,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static const struct EbpfHelperPrototype bpf_get_numa_node_id_proto = {
    .name = "get_numa_node_id",
    //.func		= bpf_get_numa_node_id,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

/*
 * u64 bpf_ktime_get_ns()
 *     Return: current ktime
 */
static const struct EbpfHelperPrototype bpf_ktime_get_ns_proto = {
    .name = "ktime_get_ns",
    //.func		= bpf_ktime_get_ns,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static const struct EbpfHelperPrototype bpf_get_current_pid_tgid_proto = {
    .name = "get_current_pid_tgid",
    //.func		= bpf_get_current_pid_tgid,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

static const struct EbpfHelperPrototype bpf_get_current_uid_gid_proto = {
    .name = "get_current_uid_gid",
    //.func		= bpf_get_current_uid_gid,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

/*
 * int bpf_get_current_comm(char *buf, u32 size_of_buf)
 * 	Description
 * 		Copy the **comm** attribute of the current task into *buf* of
 * 		*size_of_buf*. The **comm** attribute contains the name of
 * 		the executable (excluding the path) for the current task. The
 * 		*size_of_buf* must be strictly positive. On success, the
 * 		helper makes sure that the *buf* is NUL-terminated. On failure,
 * 		it is filled with zeroes.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_get_current_comm_proto = {
    .name = "get_current_comm",
    //.func		= bpf_get_current_comm,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
};

static const struct EbpfHelperPrototype bpf_get_current_cgroup_id_proto = {
    .name = "get_current_cgroup_id",
    //.func		= bpf_get_current_cgroup_id,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
};

/*
 * int bpf_sock_map_update(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags)
 * 	Description
 * 		Add an entry to, or update a *map* referencing sockets. The
 * 		*skops* is used as a new value for the entry associated to
 * 		*key*. *flags* is one of:
 *
 * 		**BPF_NOEXIST**
 * 			The entry for *key* must not exist in the map.
 * 		**BPF_EXIST**
 * 			The entry for *key* must already exist in the map.
 * 		**BPF_ANY**
 * 			No condition on the existence of the entry for *key*.
 *
 * 		If the *map* has eBPF programs (parser and verdict), those will
 * 		be inherited by the socket being added. If the socket is
 * 		already attached to eBPF programs, this results in an error.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_sock_map_update_proto = {
    .name = "sock_map_update",
    //.func		= bpf_sock_map_update,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_DONTCARE,
    },
    .context_descriptor = &g_sock_ops_descr
};

static const struct EbpfHelperPrototype bpf_sock_hash_update_proto = {
    .name = "sock_hash_update",
    //.func		= bpf_sock_hash_update,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_DONTCARE,
    },
    .context_descriptor = &g_sock_ops_descr
};

/*
 * int bpf_get_stackid(ctx, map, flags)
 *     walk user or kernel stack and return id
 *     @ctx: struct pt_regs*
 *     @map: pointer to stack_trace map
 *     @flags: bits 0-7 - numer of stack frames to skip
 *             bit 8 - collect user stack instead of kernel
 *             bit 9 - compare stacks by hash only
 *             bit 10 - if two different stacks hash into the same stackid
 *                      discard old
 *             other bits - reserved
 *     Return: >= 0 stackid on success or negative error
 */
static const struct EbpfHelperPrototype bpf_get_stackid_proto = {
    .name = "get_stackid",
    //.func		= bpf_get_stackid,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

/*
 * int bpf_get_stack(struct pt_regs *regs, void *buf, u32 size, u64 flags)
 * 	Description
 * 		Return a user or a kernel stack in bpf program provided buffer.
 * 		To achieve this, the helper needs *ctx*, which is a pointer
 * 		to the context on which the tracing program is executed.
 * 		To store the stacktrace, the bpf program provides *buf* with
 * 		a nonnegative *size*.
 *
 * 		The last argument, *flags*, holds the number of stack frames to
 * 		skip (from 0 to 255), masked with
 * 		**BPF_F_SKIP_FIELD_MASK**. The next bits can be used to set
 * 		the following flags:
 *
 * 		**BPF_F_USER_STACK**
 * 			Collect a user space stack instead of a kernel stack.
 * 		**BPF_F_USER_BUILD_ID**
 * 			Collect buildid+offset instead of ips for user stack,
 * 			only valid if **BPF_F_USER_STACK** is also specified.
 *
 * 		**bpf_get_stack**\ () can collect up to
 * 		**PERF_MAX_STACK_DEPTH** both kernel and user frames, subject
 * 		to sufficient large buffer size. Note that
 * 		this limit can be controlled with the **sysctl** program, and
 * 		that it should be manually increased in order to profile long
 * 		user stacks (such as stacks for Java programs). To do so, use:
 *
 * 		::
 *
 * 			# sysctl kernel.perf_event_max_stack=<new value>
 * 	Return
 * 		A non-negative value equal to or less than *size* on success,
 * 		or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_get_stack_proto = {
    .name = "get_stack",
    //.func		= bpf_get_stack,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

/*
 * u32 bpf_raw_smp_processor_id()
 *     Return: SMP processor ID
//  */
// static const struct EbpfHelperPrototype bpf_get_raw_smp_processor_id_proto = {
//     .name = "get_raw_smp_processor_id",
// 	//.func		= bpf_get_raw_cpu_id,
// 	//.gpl_only	= false,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// };

/*
 * int bpf_skb_store_bytes(skb, offset, from, len, flags)
 *     store bytes into packet
 *     @skb: pointer to skb
 *     @offset: offset within packet from skb->mac_header
 *     @from: pointer where to copy bytes from
 *     @len: number of bytes to store into packet
 *     @flags: bit 0 - if true, recompute skb->csum
 *             other bits - reserved
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_skb_store_bytes_proto = {
    .name = "skb_store_bytes",
    //.func		= bpf_skb_store_bytes,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_load_bytes(const struct sk_buff *skb, u32 offset, void *to, u32 len)
 * 	Description
 * 		This helper was provided as an easy way to load data from a
 * 		packet. It can be used to load *len* bytes from *offset* from
 * 		the packet associated to *skb*, into the buffer pointed by
 * 		*to*.
 *
 * 		Since Linux 4.7, usage of this helper has mostly been replaced
 * 		by "direct packet access", enabling packet data to be
 * 		manipulated with *skb*\ **->data** and *skb*\ **->data_end**
 * 		pointing respectively to the first byte of packet data and to
 * 		the byte after the last byte of packet data. However, it
 * 		remains useful if one wishes to read large quantities of data
 * 		at once from a packet into the eBPF stack.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_skb_load_bytes_proto = {
    .name = "skb_load_bytes",
    //.func		= bpf_skb_load_bytes,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int skb_load_bytes_relative(const struct sk_buff *skb, u32 offset, void *to, u32 len, u32 start_header)
 * 	Description
 * 		This helper is similar to **bpf_skb_load_bytes**\ () in that
 * 		it provides an easy way to load *len* bytes from *offset*
 * 		from the packet associated to *skb*, into the buffer pointed
 * 		by *to*. The difference to **bpf_skb_load_bytes**\ () is that
 * 		a fifth argument *start_header* exists in order to select a
 * 		base offset to start from. *start_header* can be one of:
 *
 * 		**BPF_HDR_START_MAC**
 * 			Base offset to load data from is *skb*'s mac header.
 * 		**BPF_HDR_START_NET**
 * 			Base offset to load data from is *skb*'s network header.
 *
 * 		In general, "direct packet access" is the preferred method to
 * 		access packet data, however, this helper is in particular useful
 * 		in socket filters where *skb*\ **->data** does not always point
 * 		to the start of the mac header and where "direct packet access"
 * 		is not available.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_skb_load_bytes_relative_proto = {
    .name = "skb_load_bytes_relative",
    //.func		= bpf_skb_load_bytes_relative,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

static const struct EbpfHelperPrototype bpf_skb_pull_data_proto = {
    .name = "skb_pull_data",
    //.func		= bpf_skb_pull_data,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

// static const struct EbpfHelperPrototype sk_skb_pull_data_proto = {
// 	//.func		= sk_skb_pull_data,
// 	//.gpl_only	= false,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	},
// };

/*
 * int bpf_l3_csum_replace(skb, offset, from, to, flags)
 *     recompute IP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where IP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             other bits - reserved
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_l3_csum_replace_proto = {
    .name = "l3_csum_replace",
    //.func		= bpf_l3_csum_replace,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_l4_csum_replace(skb, offset, from, to, flags)
 *     recompute TCP/UDP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where TCP/UDP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             bit 4 - is pseudo header
 *             other bits - reserved
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_l4_csum_replace_proto = {
    .name = "l4_csum_replace",
    //.func		= bpf_l4_csum_replace,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * s64 bpf_csum_diff(from, from_size, to, to_size, seed)
 *     calculate csum diff
 *     @from: raw from buffer
 *     @from_size: length of from buffer
 *     @to: raw to buffer
 *     @to_size: length of to buffer
 *     @seed: optional seed
 *     Return: csum result or negative error code
 */
static const struct EbpfHelperPrototype bpf_csum_diff_proto = {
    .name = "csum_diff",
    //.func		= bpf_csum_diff,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL,
        EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL,
        EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

static const struct EbpfHelperPrototype bpf_csum_update_proto = {
    .name = "csum_update",
    //.func		= bpf_csum_update,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

static const struct EbpfHelperPrototype bpf_clone_redirect_proto = {
    .name = "clone_redirect",
    //.func       = bpf_clone_redirect,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_redirect_proto = {
    .name = "redirect",
    //.func       = bpf_redirect,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};
static const struct EbpfHelperPrototype bpf_sk_redirect_hash_proto = {
    .name = "sk_redirect_hash",
    //.func       = bpf_sk_redirect_hash,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_sk_redirect_map_proto = {
    .name = "sk_redirect_map",
    //.func       = bpf_sk_redirect_map,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_msg_redirect_hash_proto = {
    .name = "msg_redirect_hash",
    //.func       = bpf_msg_redirect_hash,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_msg_md
};
static const struct EbpfHelperPrototype bpf_msg_redirect_map_proto = {
    .name = "msg_redirect_map",
    //.func       = bpf_msg_redirect_map,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_msg_md
};
static const struct EbpfHelperPrototype bpf_msg_apply_bytes_proto = {
    .name = "msg_apply_bytes",
    //.func       = bpf_msg_apply_bytes,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_msg_md
};
static const struct EbpfHelperPrototype bpf_msg_cork_bytes_proto = {
    .name = "msg_cork_bytes",
    //.func       = bpf_msg_cork_bytes,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_msg_md
};
static const struct EbpfHelperPrototype bpf_msg_pull_data_proto = {
    .name = "msg_pull_data",
    //.func		= bpf_msg_pull_data,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_msg_md
};
static const struct EbpfHelperPrototype bpf_get_cgroup_classid_proto = {
    .name = "get_cgroup_classid",
    //.func       = bpf_get_cgroup_classid,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = { EBPF_ARGUMENT_TYPE_PTR_TO_CTX, },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_get_route_realm_proto = {
    .name = "get_route_realm",
    //.func       = bpf_get_route_realm,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = { EBPF_ARGUMENT_TYPE_PTR_TO_CTX, },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_get_hash_recalc_proto = {
    .name = "get_hash_recalc",
    //.func		= bpf_get_hash_recalc,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_set_hash_invalid_proto = {
    .name = "set_hash_invalid",
    //.func		= bpf_set_hash_invalid,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_set_hash_proto = {
    .name = "set_hash",
    //.func		= bpf_set_hash,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_skb_vlan_push_proto = {
    .name = "skb_vlan_push",
    //.func       = bpf_skb_vlan_push,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_skb_vlan_pop_proto = {
    .name = "skb_vlan_pop",
    //.func       = bpf_skb_vlan_pop,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_change_proto(skb, proto, flags)
 *     Change protocol of the skb. Currently supported is v4 -> v6,
 *     v6 -> v4 transitions. The helper will also resize the skb. eBPF
 *     program is expected to fill the new headers via skb_store_bytes
 *     and lX_csum_replace.
 *     @skb: pointer to skb
 *     @proto: new skb->protocol type
 *     @flags: reserved
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_skb_change_proto_proto = {
    .name = "skb_change_proto",
    //.func		= bpf_skb_change_proto,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_change_type(skb, type)
 *     Change packet type of skb.
 *     @skb: pointer to skb
 *     @type: new skb->pkt_type type
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_skb_change_type_proto = {
    .name = "skb_change_type",
    //.func		= bpf_skb_change_type,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_adjust_room(skb, len_diff, mode, flags)
 *     Grow or shrink room in sk_buff.
 *     @skb: pointer to skb
 *     @len_diff: (signed) amount of room to grow/shrink
 *     @mode: operation mode (enum bpf_adj_room_mode)
 *     @flags: reserved for future use
 *     Return: 0 on success or negative error code
 */
static const struct EbpfHelperPrototype bpf_skb_adjust_room_proto = {
    .name = "skb_adjust_room",
    //.func		= bpf_skb_adjust_room,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_change_tail(skb, len, flags)
 *     The helper will resize the skb to the given new size, to be used f.e.
 *     with control messages.
 *     @skb: pointer to skb
 *     @len: new skb length
 *     @flags: reserved
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_skb_change_tail_proto = {
    .name = "skb_change_tail",
    //.func		= bpf_skb_change_tail,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

// static const struct EbpfHelperPrototype sk_skb_change_tail_proto = {
// 	//.func		= sk_skb_change_tail,
// 	//.gpl_only	= false,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	},
// };

/* int bpf_skb_change_head(struct sk_buff *skb, u32 len, u64 flags)
 * 	Description
 * 		Grows headroom of packet associated to *skb* and adjusts the
 * 		offset of the MAC header accordingly, adding *len* bytes of
 * 		space. It automatically extends and reallocates memory as
 * 		required.
 *
 * 		This helper can be used on a layer 3 *skb* to push a MAC header
 * 		for redirection into a layer 2 device.
 *
 * 		All values for *flags* are reserved for future usage, and must
 * 		be left at zero.
 *
 * 		A call to this helper is susceptible to change the underlaying
 * 		packet buffer. Therefore, at load time, all checks on pointers
 * 		previously done by the verifier are invalidated and must be
 * 		performed again, if the helper is used in combination with
 * 		direct packet access.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_skb_change_head_proto = {
    .name = "skb_change_head",
    //.func		= bpf_skb_change_head,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .reallocate_packet = true,
    .context_descriptor = &g_sk_buff
};

// static const struct EbpfHelperPrototype sk_skb_change_head_proto = {
// 	//.func		= sk_skb_change_head,
// 	//.gpl_only	= false,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
//  },
// };

static const struct EbpfHelperPrototype bpf_xdp_adjust_head_proto = {
    .name = "xdp_adjust_head",
    //.func		= bpf_xdp_adjust_head,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .reallocate_packet = true,
    .context_descriptor = &g_xdp_descr
};

static const struct EbpfHelperPrototype bpf_xdp_adjust_tail_proto = {
    .name = "xdp_adjust_tail",
    //.func		= bpf_xdp_adjust_tail,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_xdp_descr
};

static const struct EbpfHelperPrototype bpf_xdp_adjust_meta_proto = {
    .name = "xdp_adjust_meta",
    //.func		= bpf_xdp_adjust_meta,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_xdp_descr
};

// static const struct EbpfHelperPrototype bpf_xdp_redirect_proto = {
//     .name = "xdp_redirect",
// 	//.func       = bpf_xdp_redirect,
// 	//.gpl_only   = false,
// 	.return_type   = EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
//  },
// };

// static const struct EbpfHelperPrototype bpf_xdp_redirect_map_proto = {
//     .name = "xdp_redirect_map",
// 	//.func       = bpf_xdp_redirect_map,
// 	//.gpl_only   = false,
// 	.return_type   = EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	},
// };

// static const struct EbpfHelperPrototype bpf_skb_event_output_proto = {
//     .name = "skb_event_output",
// 	//.func		= bpf_skb_event_output,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
// 	    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
// 	},
// };

/*
 * int bpf_skb_get_tunnel_key(skb, key, size, flags)
 *     retrieve or populate tunnel metadata
 *     @skb: pointer to skb
 *     @key: pointer to 'struct bpf_tunnel_key'
 *     @size: size of 'struct bpf_tunnel_key'
 *     @flags: room for future extensions
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_skb_get_tunnel_key_proto = {
    .name = "skb_get_tunnel_key",
    //.func		= bpf_skb_get_tunnel_key,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_get_tunnel_opt(skb, opt, size)
 *     retrieve tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: option size
 */
static const struct EbpfHelperPrototype bpf_skb_get_tunnel_opt_proto = {
    .name = "skb_get_tunnel_opt",
    //.func		= bpf_skb_get_tunnel_opt,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_set_tunnel_key(skb, key, size, flags)
 *     retrieve or populate tunnel metadata
 *     @skb: pointer to skb
 *     @key: pointer to 'struct bpf_tunnel_key'
 *     @size: size of 'struct bpf_tunnel_key'
 *     @flags: room for future extensions
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_skb_set_tunnel_key_proto = {
    .name = "skb_set_tunnel_key",
    //.func		= bpf_skb_set_tunnel_key,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_set_tunnel_opt(skb, opt, size)
 *     populate tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: 0 on success or negative error
 */
static const struct EbpfHelperPrototype bpf_skb_set_tunnel_opt_proto = {
    .name = "skb_set_tunnel_opt",
    //.func		= bpf_skb_set_tunnel_opt,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
    .context_descriptor = &g_sk_buff
};

/*
 * int bpf_skb_under_cgroup(skb, map, index)
 *     Check cgroup2 membership of skb
 *     @skb: pointer to skb
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 skb failed the cgroup2 descendant test
 *       == 1 skb succeeded the cgroup2 descendant test
 *        < 0 error
 */
static const struct EbpfHelperPrototype bpf_skb_under_cgroup_proto = {
    .name = "skb_under_cgroup",
    //.func		= bpf_skb_under_cgroup,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

static const struct EbpfHelperPrototype bpf_skb_cgroup_id_proto = {
    .name = "skb_cgroup_id",
    //.func       = bpf_skb_cgroup_id,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
    },
    .context_descriptor = &g_sk_buff
};

// static const struct EbpfHelperPrototype bpf_xdp_event_output_proto = {
//     .name = "xdp_event_output",
// 	//.func		= bpf_xdp_event_output,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
// 	    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
// 	},
// };

static const struct EbpfHelperPrototype bpf_get_socket_cookie_proto = {
    .name = "get_socket_cookie",
    //.func       = bpf_get_socket_cookie,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = { EBPF_ARGUMENT_TYPE_PTR_TO_CTX, },
    .context_descriptor = &g_sk_buff
};

static const struct EbpfHelperPrototype bpf_get_socket_uid_proto = {
    .name = "get_socket_uid",
    //.func       = bpf_get_socket_uid,
    //.gpl_only   = false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = { EBPF_ARGUMENT_TYPE_PTR_TO_CTX, },
    .context_descriptor = &g_sk_buff
};

static const struct EbpfHelperPrototype bpf_setsockopt_proto = {
    .name = "setsockopt",
    //.func		= bpf_setsockopt,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
};

/*
 * int bpf_getsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls getsockopt. Not all opts are available.
 *     Supported levels: IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 */
static const struct EbpfHelperPrototype bpf_getsockopt_proto = {
    .name = "getsockopt",
    //.func		= bpf_getsockopt,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
};

static const struct EbpfHelperPrototype bpf_sock_ops_cb_flags_set_proto = {
    .name = "sock_ops_cb_flags_set",
    //.func		= bpf_sock_ops_cb_flags_set,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sock_ops_descr
};
static const struct EbpfHelperPrototype bpf_bind_proto = {
    .name = "bind",
    //.func		= bpf_bind,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
    },
};

/*
 * int bpf_skb_get_xfrm_state(struct sk_buff *skb, u32 index, struct bpf_xfrm_state *xfrm_state, u32 size, u64 flags)
 * 	Description
 * 		Retrieve the XFRM state (IP transform framework, see also
 * 		**ip-xfrm(8)**) at *index* in XFRM "security path" for *skb*.
 *
 * 		The retrieved value is stored in the **struct bpf_xfrm_state**
 * 		pointed by *xfrm_state* and of length *size*.
 *
 * 		All values for *flags* are reserved for future usage, and must
 * 		be left at zero.
 *
 * 		This helper is available only if the kernel was compiled with
 * 		**CONFIG_XFRM** configuration option.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
static const struct EbpfHelperPrototype bpf_skb_get_xfrm_state_proto = {
    .name = "skb_get_xfrm_state",
    //.func		= bpf_skb_get_xfrm_state,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};

static const struct EbpfHelperPrototype bpf_xdp_fib_lookup_proto = {
    .name = "xdp_fib_lookup",
    //.func		= bpf_xdp_fib_lookup,
    //.gpl_only	= true,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

// static const struct EbpfHelperPrototype bpf_skb_fib_lookup_proto = {
//     .name = "skb_fib_lookup",
// 	//.func		= bpf_skb_fib_lookup,
// 	//.gpl_only	= true,
// 	.return_type	= EBPF_RETURN_TYPE_INTEGER,
// 	.argument_type = {
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
// 	    EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
// 	    EBPF_ARGUMENT_TYPE_CONST_SIZE,
// 	    EBPF_ARGUMENT_TYPE_ANYTHING,
// 	},
// };

static const struct EbpfHelperPrototype bpf_lwt_push_encap_proto = {
    .name = "lwt_push_encap",
    //.func		= bpf_lwt_push_encap,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_lwt_seg6_store_bytes_proto = {
    .name = "lwt_seg6_store_bytes",
    //.func		= bpf_lwt_seg6_store_bytes,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_lwt_seg6_action_proto = {
    .name = "lwt_seg6_action",
    //.func		= bpf_lwt_seg6_action,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
        EBPF_ARGUMENT_TYPE_CONST_SIZE
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_lwt_seg6_adjust_srh_proto = {
    .name = "lwt_seg6_adjust_srh",
    //.func		= bpf_lwt_seg6_adjust_srh,
    //.gpl_only	= false,
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
    .context_descriptor = &g_sk_buff
};
static const struct EbpfHelperPrototype bpf_rc_repeat_proto = {
    .name = "rc_repeat", // without bpf_ originally
                         //.func	   = bpf_rc_repeat,
                         //.gpl_only  = true, /* rc_repeat is EXPORT_SYMBOL_GPL */
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
    },
};
static const struct EbpfHelperPrototype bpf_rc_keydown_proto = {
    .name = "rc_keydown", // without bpf_ originally
                          //.func	   = bpf_rc_keydown,
                          //.gpl_only  = true, /* rc_keydown is EXPORT_SYMBOL_GPL */
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

/* BPF helper function descriptions:
 *
 * void *bpf_map_lookup_elem(&map, &key)
 *     Return: Map value or NULL
 *
 * int bpf_map_update_elem(&map, &key, &value, flags)
 *     Return: 0 on success or negative error
 *
 * int bpf_map_delete_elem(&map, &key)
 *     Return: 0 on success or negative error
 *
 * int bpf_probe_read(void *dst, int size, void *src)
 *     read arbitrary kernel memory
 *     Return: 0 on success or negative error
 *
 * u64 bpf_ktime_get_ns()
 *     Return: current ktime
 *
 * int bpf_trace_printk(const char *fmt, int fmt_size, ...)
 *     Return: length of buffer written or negative error
 *
 * u32 bpf_prandom_u32()
 *     Return: random value
 *
 * u32 bpf_raw_smp_processor_id()
 *     Return: SMP processor ID
 *
 * int bpf_l3_csum_replace(skb, offset, from, to, flags)
 *     recompute IP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where IP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_l4_csum_replace(skb, offset, from, to, flags)
 *     recompute TCP/UDP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where TCP/UDP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             bit 4 - is pseudo header
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_tail_call(ctx, prog_array_map, index)
 *     jump into another BPF program
 *     @ctx: context pointer passed to next program
 *     @prog_array_map: pointer to map which type is BPF_MAP_TYPE_PROG_ARRAY
 *     @index: 32-bit index inside array that selects specific program to run
 *     Return: 0 on success or negative error
 *//*
 * int bpf_clone_redirect(skb, ifindex, flags)
 *     redirect to another netdev
 *     @skb: pointer to skb
 *     @ifindex: ifindex of the net device
 *     @flags: bit 0 - if set, redirect to ingress instead of egress
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *//*
 * u64 bpf_get_current_pid_tgid()
 *     Return: current->tgid << 32 | current->pid
 *//*
 * u64 bpf_get_current_uid_gid()
 *     Return: current_gid << 32 | current_uid
 *//*
 * int bpf_get_current_comm(char *buf, int size_of_buf)
 *     stores current->comm into buf
 *     Return: 0 on success or negative error
 *//*
 * u32 bpf_get_cgroup_classid(skb)
 *     retrieve a proc's classid
 *     @skb: pointer to skb
 *     Return: classid if != 0
 *//*
 * int bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
 *     Return: 0 on success or negative error
 *//*
 * int bpf_skb_vlan_pop(skb)
 *     Return: 0 on success or negative error
 *//*
 * int bpf_skb_get_tunnel_key(skb, key, size, flags)
 * int bpf_skb_set_tunnel_key(skb, key, size, flags)
 *     retrieve or populate tunnel metadata
 *     @skb: pointer to skb
 *     @key: pointer to 'struct bpf_tunnel_key'
 *     @size: size of 'struct bpf_tunnel_key'
 *     @flags: room for future extensions
 *     Return: 0 on success or negative error
 *//*
 * u64 bpf_perf_event_read(map, flags)
 *     read perf event counter value
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     Return: value of perf event counter read or error code
 *//*
 * int bpf_redirect(ifindex, flags)
 *     redirect to another netdev
 *     @ifindex: ifindex of the net device
 *     @flags:
 *	  cls_bpf:
 *          bit 0 - if set, redirect to ingress instead of egress
 *          other bits - reserved
 *	  xdp_bpf:
 *	    all bits - reserved
 *     Return: cls_bpf: TC_ACT_REDIRECT on success or TC_ACT_SHOT on error
 *	       xdp_bfp: XDP_REDIRECT on success or XDP_ABORT on error
 *//*
 * int bpf_redirect_map(map, key, flags)
 *     redirect to endpoint in map
 *     @map: pointer to dev map
 *     @key: index in map to lookup
 *     @flags: --
 *     Return: XDP_REDIRECT on success or XDP_ABORT on error
 */
// ELAZAR: home brewed
static const struct EbpfHelperPrototype bpf_redirect_map_proto = {
    .name = "redirect_map",
    .return_type = EBPF_RETURN_TYPE_INTEGER,
    .argument_type = {
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
        EBPF_ARGUMENT_TYPE_ANYTHING,
        EBPF_ARGUMENT_TYPE_ANYTHING,
    },
};

/*
 * u32 bpf_get_route_realm(skb)
 *     retrieve a dst's tclassid
 *     @skb: pointer to skb
 *     Return: realm if != 0
 *//*
 * int bpf_perf_event_output(ctx, map, flags, data, size)
 *     output perf raw sample
 *     @ctx: struct pt_regs*
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     @data: data on stack to be output as raw data
 *     @size: size of data
 *     Return: 0 on success or negative error
 *//*
 * int bpf_get_stackid(ctx, map, flags)
 *     walk user or kernel stack and return id
 *     @ctx: struct pt_regs*
 *     @map: pointer to stack_trace map
 *     @flags: bits 0-7 - numer of stack frames to skip
 *             bit 8 - collect user stack instead of kernel
 *             bit 9 - compare stacks by hash only
 *             bit 10 - if two different stacks hash into the same stackid
 *                      discard old
 *             other bits - reserved
 *     Return: >= 0 stackid on success or negative error
 *//*
 * s64 bpf_csum_diff(from, from_size, to, to_size, seed)
 *     calculate csum diff
 *     @from: raw from buffer
 *     @from_size: length of from buffer
 *     @to: raw to buffer
 *     @to_size: length of to buffer
 *     @seed: optional seed
 *     Return: csum result or negative error code
 *//*
 * int bpf_skb_get_tunnel_opt(skb, opt, size)
 *     retrieve tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: option size
 *//*
 * int bpf_skb_set_tunnel_opt(skb, opt, size)
 *     populate tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: 0 on success or negative error
 *//*
 * int bpf_skb_change_proto(skb, proto, flags)
 *     Change protocol of the skb. Currently supported is v4 -> v6,
 *     v6 -> v4 transitions. The helper will also resize the skb. eBPF
 *     program is expected to fill the new headers via skb_store_bytes
 *     and lX_csum_replace.
 *     @skb: pointer to skb
 *     @proto: new skb->protocol type
 *     @flags: reserved
 *     Return: 0 on success or negative error
 *//*
 * int bpf_skb_change_type(skb, type)
 *     Change packet type of skb.
 *     @skb: pointer to skb
 *     @type: new skb->pkt_type type
 *     Return: 0 on success or negative error
 *//*
 * int bpf_skb_under_cgroup(skb, map, index)
 *     Check cgroup2 membership of skb
 *     @skb: pointer to skb
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 skb failed the cgroup2 descendant test
 *       == 1 skb succeeded the cgroup2 descendant test
 *        < 0 error
 *//*
 * u32 bpf_get_hash_recalc(skb)
 *     Retrieve and possibly recalculate skb->hash.
 *     @skb: pointer to skb
 *     Return: hash
 *//*
 * u64 bpf_get_current_task()
 *     Returns current task_struct
 *     Return: current
 *//*
 * int bpf_probe_write_user(void *dst, void *src, int len)
 *     safely attempt to write to a location
 *     @dst: destination address in userspace
 *     @src: source address on stack
 *     @len: number of bytes to copy
 *     Return: 0 on success or negative error
 *//*
 * int bpf_current_task_under_cgroup(map, index)
 *     Check cgroup2 membership of current task
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 current failed the cgroup2 descendant test
 *       == 1 current succeeded the cgroup2 descendant test
 *        < 0 error
 *
 * int bpf_skb_change_tail(skb, len, flags)
 *     The helper will resize the skb to the given new size, to be used f.e.
 *     with control messages.
 *     @skb: pointer to skb
 *     @len: new skb length
 *     @flags: reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_pull_data(skb, len)
 *     The helper will pull in non-linear data in case the skb is non-linear
 *     and not all of len are part of the linear section. Only needed for
 *     read/write with direct packet access.
 *     @skb: pointer to skb
 *     @len: len to make read/writeable
 *     Return: 0 on success or negative error
 *
 * s64 bpf_csum_update(skb, csum)
 *     Adds csum into skb->csum in case of CHECKSUM_COMPLETE.
 *     @skb: pointer to skb
 *     @csum: csum to add
 *     Return: csum on success or negative error
 *
 * void bpf_set_hash_invalid(skb)
 *     Invalidate current skb->hash.
 *     @skb: pointer to skb
 *
 * int bpf_get_numa_node_id()
 *     Return: Id of current NUMA node.
 *
 * int bpf_skb_change_head()
 *     Grows headroom of skb and adjusts MAC header offset accordingly.
 *     Will extends/reallocae as required automatically.
 *     May change skb data pointer and will thus invalidate any check
 *     performed for direct packet access.
 *     @skb: pointer to skb
 *     @len: length of header to be pushed in front
 *     @flags: Flags (unused for now)
 *     Return: 0 on success or negative error
 *
 * int bpf_xdp_adjust_head(xdp_md, delta)
 *     Adjust the xdp_md.data by delta
 *     @xdp_md: pointer to xdp_md
 *     @delta: An positive/negative integer to be added to xdp_md.data
 *     Return: 0 on success or negative on error
 *
 * int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
 *     Copy a NUL terminated string from unsafe address. In case the string
 *     length is smaller than size, the target is not padded with further NUL
 *     bytes. In case the string length is larger than size, just count-1
 *     bytes are copied and the last byte is set to NUL.
 *     @dst: destination address
 *     @size: maximum number of bytes to copy, including the trailing NUL
 *     @unsafe_ptr: unsafe address
 *     Return:
 *       > 0 length of the string including the trailing NUL on success
 *       < 0 error
 *
 * u64 bpf_get_socket_cookie(skb)
 *     Get the cookie for the socket stored inside sk_buff.
 *     @skb: pointer to skb
 *     Return: 8 Bytes non-decreasing number on success or 0 if the socket
 *     field is missing inside sk_buff
 *
 * u32 bpf_get_socket_uid(skb)
 *     Get the owner uid of the socket stored inside sk_buff.
 *     @skb: pointer to skb
 *     Return: uid of the socket owner on success or overflowuid if failed.
 *
 * u32 bpf_set_hash(skb, hash)
 *     Set full skb->hash.
 *     @skb: pointer to skb
 *     @hash: hash to set
 *
 * int bpf_setsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls setsockopt. Not all opts are available, only those with
 *     integer optvals plus TCP_CONGESTION.
 *     Supported levels: SOL_SOCKET and IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: SOL_SOCKET or IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 *
 * int bpf_getsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls getsockopt. Not all opts are available.
 *     Supported levels: IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 *
 * int bpf_sock_ops_cb_flags_set(bpf_sock_ops, flags)
 *     Set callback flags for sock_ops
 *     @bpf_sock_ops: pointer to bpf_sock_ops_kern struct
 *     @flags: flags value
 *     Return: 0 for no error
 *             -EINVAL if there is no full tcp socket
 *             bits in flags that are not supported by current kernel
 *
 * int bpf_skb_adjust_room(skb, len_diff, mode, flags)
 *     Grow or shrink room in sk_buff.
 *     @skb: pointer to skb
 *     @len_diff: (signed) amount of room to grow/shrink
 *     @mode: operation mode (enum bpf_adj_room_mode)
 *     @flags: reserved for future use
 *     Return: 0 on success or negative error code
 *
 * int bpf_sk_redirect_map(map, key, flags)
 *     Redirect skb to a sock in map using key as a lookup key for the
 *     sock in map.
 *     @map: pointer to sockmap
 *     @key: key to lookup sock in map
 *     @flags: reserved for future use
 *     Return: SK_PASS
 *
 * int bpf_sock_map_update(skops, map, key, flags)
 *	@skops: pointer to bpf_sock_ops
 *	@map: pointer to sockmap to update
 *	@key: key to insert/update sock in map
 *	@flags: same flags as map update elem
 *
 * int bpf_xdp_adjust_meta(xdp_md, delta)
 *     Adjust the xdp_md.data_meta by delta
 *     @xdp_md: pointer to xdp_md
 *     @delta: An positive/negative integer to be added to xdp_md.data_meta
 *     Return: 0 on success or negative on error
 *
 * int bpf_perf_event_read_value(map, flags, buf, buf_size)
 *     read perf event counter value and perf event enabled/running time
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return: 0 on success or negative error code
 *
 * int bpf_perf_prog_read_value(ctx, buf, buf_size)
 *     read perf prog attached perf event counter and enabled/running time
 *     @ctx: pointer to ctx
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return : 0 on success or negative error code
 *
 * int bpf_override_return(pt_regs, rc)
 *	@pt_regs: pointer to struct pt_regs
 *	@rc: the return value to set
 */

#define FN(x) bpf_##x##_proto
// keep this on a round line
const struct EbpfHelperPrototype prototypes[81] = {
    FN(unspec),
    FN(map_lookup_elem),
    FN(map_update_elem),
    FN(map_delete_elem),
    FN(probe_read),
    FN(ktime_get_ns),
    FN(trace_printk),
    FN(get_prandom_u32),
    FN(get_smp_processor_id),
    FN(skb_store_bytes),
    FN(l3_csum_replace),
    FN(l4_csum_replace),
    FN(tail_call),
    FN(clone_redirect),
    FN(get_current_pid_tgid),
    FN(get_current_uid_gid),
    FN(get_current_comm),
    FN(get_cgroup_classid),
    FN(skb_vlan_push),
    FN(skb_vlan_pop),
    FN(skb_get_tunnel_key),
    FN(skb_set_tunnel_key),
    FN(perf_event_read),
    FN(redirect),
    FN(get_route_realm),
    FN(perf_event_output),
    FN(skb_load_bytes),
    FN(get_stackid),
    FN(csum_diff),
    FN(skb_get_tunnel_opt),
    FN(skb_set_tunnel_opt),
    FN(skb_change_proto),
    FN(skb_change_type),
    FN(skb_under_cgroup),
    FN(get_hash_recalc),
    FN(get_current_task),
    FN(probe_write_user),
    FN(current_task_under_cgroup),
    FN(skb_change_tail),
    FN(skb_pull_data),
    FN(csum_update),
    FN(set_hash_invalid),
    FN(get_numa_node_id),
    FN(skb_change_head),
    FN(xdp_adjust_head),
    FN(probe_read_str),
    FN(get_socket_cookie),
    FN(get_socket_uid),
    FN(set_hash),
    FN(setsockopt),
    FN(skb_adjust_room),
    FN(redirect_map),
    FN(sk_redirect_map),
    FN(sock_map_update),
    FN(xdp_adjust_meta),
    FN(perf_event_read_value),
    FN(perf_prog_read_value),
    FN(getsockopt),
    FN(override_return),
    FN(sock_ops_cb_flags_set),
    FN(msg_redirect_map),
    FN(msg_apply_bytes),
    FN(msg_cork_bytes),
    FN(msg_pull_data),
    FN(bind),
    FN(xdp_adjust_tail),
    FN(skb_get_xfrm_state),
    FN(get_stack), // 67
    FN(skb_load_bytes_relative),
    FN(xdp_fib_lookup), // without xdp_ originally
    FN(sock_hash_update),
    FN(msg_redirect_hash),
    FN(sk_redirect_hash),
    FN(lwt_push_encap),
    FN(lwt_seg6_store_bytes),
    FN(lwt_seg6_adjust_srh),
    FN(lwt_seg6_action),
    FN(rc_repeat),
    FN(rc_keydown),
    FN(skb_cgroup_id),
    FN(get_current_cgroup_id),
};

bool is_helper_usable_linux(unsigned int n) {
    if (n >= sizeof(prototypes) / sizeof(prototypes[0]) || n < 0)
        return false;

    // If the helper has a context_descriptor, it must match the hook's context_descriptor.
    if ((prototypes[n].context_descriptor != nullptr) &&
        (prototypes[n].context_descriptor != global_program_info.type.context_descriptor))
        return false;

    return true;
}

EbpfHelperPrototype get_helper_prototype_linux(unsigned int n) {
    if (!is_helper_usable_linux(n))
        throw std::exception();
    return prototypes[n];
}
