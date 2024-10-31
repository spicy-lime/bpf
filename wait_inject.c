#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TARGET "{TARGET.decode(utf-8)}"
#define KEYSZ {KEYSZ}

struct key_t
{{
  char key[KEYSZ];
}};

BPF_HASH( proc_map, struct key_t, u32 );

TRACEPOINT_PROBE( syscalls, sys_enter_execve )
{{
    struct key_t proc_key == {{}};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char filename[256] = {{0}};

    if( strncmp( filename, TARGET, sizeof(TARGET)-1 ) ) == 0)
    {{
        bpf_get_current_comm( proc_key.key, sizeof(proc_key.key) );
        proc_map.update( &proc_key, &pid );

        bpf_trace_printk( "Process with PID %d stopped", pid, proc_key.key );
        bpf_send_signal( SIGSTOP );
    }}
    return 0;

}}
