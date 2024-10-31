#!/usr/bin/env python3

from bcc import BPF
import time
import os
import signal
import frida

TARGET = b"/usr/bin/libreoffice"
KEYSZ = 32

bpf_code = f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TARGET "{TARGET.decode('ascii')}"
#define KEYSZ {KEYSZ}

struct key_t
{{
  char key[KEYSZ];
}};

BPF_HASH( proc_map, struct key_t, u32 );

TRACEPOINT_PROBE( syscalls, sys_enter_execve )
{{
    struct key_t proc_key = {{}};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char filename[256] = {{0}};
    bpf_probe_read_user_str(filename, sizeof(filename), args->filename);
    bpf_trace_printk("Process starting: %s \\n", filename);

    if( strncmp( filename, TARGET, sizeof(TARGET)-1 ) == 0)
    {{
        bpf_get_current_comm( proc_key.key, sizeof(proc_key.key) );
        proc_map.update( &proc_key, &pid );

        bpf_trace_printk( "Process with PID %d stopped", pid, proc_key.key );
        bpf_send_signal( SIGSTOP );
    }}
    return 0;

}}
"""

# Load and attach the BPF program
print(f"loading program: \n {bpf_code}")
bpf = BPF(text=bpf_code)
bpf.attach_tracepoint("syscalls:sys_enter_execve", "sys_enter_execve")

proc_map = bpf.get_table("proc_map")
print("Waiting for target")

#bpf.trace_print()
dev = frida.get_local_device()
while True:
    for name, pid in proc_map.items():
        proc_name = name.key.decode("utf-8").rstrip('x\00')
        print(f"Found target proc {proc_name} {pid.value}")
        time.sleep(1)
        try:
            session = dev.attach(pid.value)
            os.kill(pid.value, signal.SIGCONT)
            print("proc continued")
            session.detach()
        except Exception() as e:
            print(e);

        proc_map.pop(name)

    time.sleep(1)

# Print the trace output
