// eBPF syscall counter: counts every syscall at the raw sys_enter
// tracepoint into a per-CPU array. Standalone: no kernel headers needed.
#define SEC(NAME) __attribute__((section(NAME), used))

typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;

char _license[] SEC("license") = "GPL";

struct bpf_map_def {
	u32 type, key_size, value_size, max_entries, map_flags;
};

struct bpf_raw_tracepoint_args {
	u64 args[6];
};

static void *(*bpf_map_lookup_elem)(const struct bpf_map_def *, const void *) =
	(void *)1;
static int (*bpf_get_current_pid_tgid)(void) = (void *)14;

#define BPF_MAP_TYPE_PERCPU_ARRAY 6

// legacy-style map: key = syscall nr, value = per-CPU counter
struct bpf_map_def counts SEC(".maps") = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 512,
	.map_flags = 0,
};

SEC("raw_tp/sys_enter")
int count_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	u32 nr = (u32)ctx->args[1];
	if (nr >= 512)
		return 0;
	u64 *cnt = bpf_map_lookup_elem(&counts, &nr);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	return 0;
}
