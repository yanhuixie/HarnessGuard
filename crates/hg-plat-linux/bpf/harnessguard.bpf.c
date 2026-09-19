// 未编译验证：待 Linux 环境确认（技术任务硬约束 3）。
// HarnessGuard eBPF 内核侧程序（vmlinux BTF CO-RE）。
//
// 编译（Linux 环境，需 clang + llvm ≥ 12，BPF 目标为 bpfel）：
//   clang -target bpfel -O2 -g -D__TARGET_ARCH_x86 -c bpf/harnessguard.bpf.c \
//         -o /usr/lib/harnessguard/harnessguard.bpf.o
//   （aarch64 主机加 -D__TARGET_ARCH_arm64；架构相关注意点：寄存器宽度由 BPF
//     ABI 统一为 64 位，x86_64 与 aarch64 同源编译——硬约束 4 的 Linux 对应物）
//
// 程序与用户态结构体 `crates/hg-plat-linux/src/ebpf.rs::BpfEvent` 布局一一对应。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// 用户态消费的事件环
struct event {
    __u32 kind;          // 0=exec 1=exit 2=fork 3=tcp_send
    __u32 pid;
    __u32 ppid;
    __u32 _pad;
    __u64 cookie;        // socket cookie（tcp_send）
    __u64 bytes;         // 本次发送字节（tcp_send）
    char filename[256];  // exec 的绝对路径
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16 /* 64KB */);
} events SEC(".maps");

// socket cookie → 累计上行字节（用户态周期收割；cookie 天然防复用）
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 65536);
} tcp_out_bytes SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_template *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->kind = 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0; // fork 事件流内由用户态 ProcTable 关联
    // filename 见于 sched_process_exec 的追踪点上下文（bpf_probe_read_kernel_str）
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), ctx->comm /* 校准点：bprm->filename */);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->kind = 1;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->kind = 2;
    e->pid = ctx->child_pid;
    e->ppid = ctx->parent_pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg_count, struct sock *sk, struct msghdr *msg, size_t size)
{
    __u64 cookie = bpf_get_socket_cookie(sk);
    if (!cookie)
        return 0;
    __u64 *cnt = bpf_map_lookup_elem(&tcp_out_bytes, &cookie);
    if (cnt) {
        __sync_fetch_and_add(cnt, size);
    } else {
        __u64 init = size;
        bpf_map_update_elem(&tcp_out_bytes, &cookie, &init, BPF_ANY);
    }
    // 超过单连接上报粒度（256KB 步进）推一条事件，用户态收割累计值
    if ((*cnt & 0x3FFFF) < (size & 0x3FFFF)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->kind = 3;
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->cookie = cookie;
            e->bytes = *cnt; // 连接累计（用户态按增量差分，溢出回绕容忍）
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}
