#ifndef MON_BPF_PROC_H
#define MON_BPF_PROC_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PROC_MAX_ENTRIES  32768
#define MAX_PATH_LEN      1024


typedef enum proc_entry_flags {
    PE_EXE_TRUNC        = 1u << 0,
    PE_CWD_TRUNC        = 1u << 1,
    PE_EXE_DELETED      = 1u << 2,  // binary unlinked while running (i_nlink == 0)
    PE_EXE_MISSING      = 1u << 3,  // mm->exe file was NULL
    PE_CWD_MISSING      = 1u << 4,  // task->fs was NULL
    PE_INHERITED        = 1u << 5,  // entry copied from parent (fork)
    PE_DISCOVERED       = 1u << 6,  // built at fork from the child task (parent unkown)
} proc_entry_flags_e;


typedef struct proc_entry {
    u32 pid;
    u32 ppid;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char exe[MAX_PATH_LEN];
    char cwd[MAX_PATH_LEN];
} proc_entry_t;




#endif /* MON_BPF_PROC_H */
