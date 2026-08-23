#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "proc.h"
#include "log.h"

char LICENSE[] SEC("license") = "GPL";

#define PF_KTHREAD 0x00200000

#define MAX_PATH_DEPTH 40

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROC_MAX_ENTRIES);
    __type(key, u32);
    __type(value, proc_entry_t);
} procs_map SEC(".maps");



#define MAX_DEPTH_PATH  40 
#define MAX_NAME        256
#define SCRATCH_LEN     (MAX_PATH_LEN+MAX_NAME)

struct scratch {
    char path[SCRATCH_LEN];
    proc_entry_t entry;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch);
} scratch SEC(".maps");


static __always_inline struct scratch *get_scratch(void)
{
    u32 zero = 0;
    return bpf_map_lookup_elem(&scratch, &zero);
}

static __always_inline void fill_identiry(struct task_struct *task, proc_entry_t *entry)
{
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);

    entry->pid = BPF_CORE_READ(task, tgid);
    entry->ppid = BPF_CORE_READ(task, real_parent, tgid);
    entry->flags = 0;
    BPF_CORE_READ_STR_INTO(&entry->comm, leader, comm);
}

static __always_inline struct mount *real_mount(struct vfsmount *m)
{
	return (struct mount *)((void *)m - bpf_core_field_offset(struct mount, mnt));
}


static __always_inline int walk_path(struct scratch *s, struct dentry *dentry,
				     struct vfsmount *vfsmnt, char *out, __u8 *truncated)
{
	char *buf = s->path;
	struct mount *mnt = real_mount(vfsmnt);
	int off = MAX_PATH_LEN - 1;
	int written = 0;
 
	*truncated = 0;
	if (!dentry || !vfsmnt)
		return -1;
	buf[MAX_PATH_LEN - 1] = '\0';
 
#ifdef PATH_STOP_AT_CHROOT
	struct path root;
	struct task_struct *cur = bpf_get_current_task_btf();
	bpf_core_read(&root, sizeof(root), &BPF_CORE_READ(cur, fs)->root);
#endif
 
	#pragma unroll
	for (int i = 0; i < MAX_PATH_DEPTH; i++) {
#ifdef PATH_STOP_AT_CHROOT
		if (dentry == root.dentry && vfsmnt == root.mnt)
			break;
#endif
		struct dentry *parent   = BPF_CORE_READ(dentry, d_parent);
		struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
 
		if (dentry == mnt_root || dentry == parent) {
			if (dentry != mnt_root)
				break;                          /* disconnected fs root */
			struct mount *mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
			if (mnt == mnt_parent)
				break;                          /* namespace root: done */
			dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt    = mnt_parent;
			vfsmnt = &mnt->mnt;
			continue;
		}
 
		__u32 len = BPF_CORE_READ(dentry, d_name.len) & (MAX_NAME - 1);
		const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
 
		if (off < (int)len + 1) {                   /* room check BEFORE moving */
			*truncated = 1;
			break;
		}
		off -= len + 1;
		off &= (MAX_PATH_LEN - 1);                  /* verifier: [0, MAX_PATH_LEN-1] */
 
		if (bpf_probe_read_kernel_str(&buf[off + 1], len + 1, name) < 0)
			return -1;
		/* read_str wrote NUL at buf[off+1+len]; restore next component's '/' */
		if (off + 1 + (int)len != MAX_PATH_LEN - 1)
			buf[(off + 1 + len) & (MAX_PATH_LEN - 1)] = '/';
		buf[off] = '/';
		written++;
		dentry = parent;
	}
  	if (written == MAX_PATH_DEPTH)
		*truncated = 1;                             /* may not have reached root */
	if (written == 0) {
		off = MAX_PATH_LEN - 2;
		buf[off] = '/';
	}

	long n = bpf_probe_read_kernel_str(out, MAX_PATH_LEN, &buf[off & (MAX_PATH_LEN - 1)]);
	return n < 0 ? -1 : (int)n;
}



static __always_inline void fill_exe(struct scratch *s, struct task_struct *task, proc_entry_t *e)
{
    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    struct path p;

    if (!exe_file || bpf_core_read(&p, sizeof(p), &exe_file->f_path) != 0) {
        e->flags |= PE_EXE_MISSING;
        return;
    }

    struct inode *ino = BPF_CORE_READ(p.dentry, d_inode);
    if (!ino) {
        if (BPF_CORE_READ(ino, i_nlink) == 0)
            e->flags |= PE_EXE_DELETED;
    }

    u8 trunc = 0;

    int n = walk_path(s, p.dentry, p.mnt, e->exe, &trunc);
    if (n > 0) {
        if (trunc) 
            e->flags |= PE_EXE_TRUNC;
    }
}

static __always_inline void fill_cwd(struct scratch *s, struct task_struct *task,
				     proc_entry_t *e)
{
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	struct path p;

	if (!fs || bpf_core_read(&p, sizeof(p), &fs->pwd) != 0) {
		e->flags |= PE_CWD_MISSING;
		return;
	}

	__u8 trunc = 0;
	int n = walk_path(s, p.dentry, p.mnt, e->cwd, &trunc);
	if (n > 0) {
		if (trunc)
			e->flags |= PE_CWD_TRUNC;
	}
}

// Reads the argv blob current has mapped at task->mm->arg_start (the same
// range /proc/pid/cmdline exposes). Only valid when task shares current's
// view of that range: at exec (task == current) and at fork (child is a
// fresh copy of current, the parent).
static __always_inline void fill_cmdline(struct task_struct *task, proc_entry_t *e)
{
    u64 arg_start = BPF_CORE_READ(task, mm, arg_start);
    u64 arg_end = BPF_CORE_READ(task, mm, arg_end);

    e->cmdline_len = 0;
    if (!arg_start || arg_end <= arg_start) {
        e->flags |= PE_CMDLINE_MISSING;
        return;
    }

    u64 len = arg_end - arg_start;
    if (len > MAX_CMDLINE_LEN) {
        len = MAX_CMDLINE_LEN;
        e->flags |= PE_CMDLINE_TRUNC;
    }

    if (bpf_probe_read_user(e->cmdline, len, (const void *)arg_start) != 0) {
        e->flags |= PE_CMDLINE_MISSING;
        return;
    }
    e->cmdline[MAX_CMDLINE_LEN - 1] = '\0';
    e->cmdline_len = len;
}

static __always_inline void build_entry(struct task_struct *task, struct scratch *s)
{
    proc_entry_t *entry = &s->entry;
    fill_identiry(task, entry);
    fill_exe(s, task, entry);
    fill_cwd(s, task, entry);
    fill_cmdline(task, entry);
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(mon_proc_exec, struct task_struct *task, pid_t old_pid,
             struct linux_binprm *bprm)
{
    if (BPF_CORE_READ(task, flags) & PF_KTHREAD)
        return 0;

    struct scratch *s = get_scratch();

    build_entry(task, s);
    bpf_map_update_elem(&procs_map, &s->entry.pid, &s->entry, BPF_ANY);

    proc_entry_t *pe = &s->entry;
    // The map holds its own copy by now, so the scratch cmdline can be
    // flattened (NUL separators -> spaces) for the log line.
    if (log_enabled(DEBUG)) {
        u32 n = pe->cmdline_len;
        for (u32 i = 0; i < MAX_CMDLINE_LEN - 1 && i + 1 < n; i++)
            if (pe->cmdline[i] == '\0')
                pe->cmdline[i] = ' ';
    }
    log_debug("add procs: pid=%d, ppid=%d, comm=%s, exe=%s, cwd=%s, cmdline=%s",
            pe->pid, pe->ppid, pe->comm, pe->exe, pe->cwd, pe->cmdline);

    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(mon_proc_fork, struct task_struct *parent, struct task_struct *child)
{
	if (BPF_CORE_READ(child, group_leader) != child)
		return 0;

	if (BPF_CORE_READ(child, flags) & PF_KTHREAD)
		return 0;
 
    struct scratch *s = get_scratch();
    if (!s)
        return 0;

    u32 child_pid = BPF_CORE_READ(child, tgid);
    u32 parent_pid = BPF_CORE_READ(parent, tgid);

    proc_entry_t *pe = bpf_map_lookup_elem(&procs_map, &parent_pid);
    if (pe) {
        bpf_map_update_elem(&procs_map, &child_pid, pe, BPF_ANY);
        log_debug("add procs: pid=%d, ppid=%d, comm=%s", pe->pid, pe->ppid, pe->comm);
        proc_entry_t *ce  = bpf_map_lookup_elem(&procs_map, &child_pid);
        if (!ce) 
            return 0;

        ce->pid = child_pid;
        ce->ppid = parent_pid;
        ce->flags =  (pe->flags & ~(PE_DISCOVERED)) | PE_INHERITED;
        return 0;
    }

    build_entry(child, s);
    s->entry.flags |= PE_DISCOVERED;
    bpf_map_update_elem(&procs_map, &child_pid, &s->entry, BPF_ANY);

    pe = &s->entry;
    log_debug("add procs: pid=%d, ppid=%d, comm=%s", pe->pid, pe->ppid, pe->comm);

    return 0;
} 

SEC("tp_btf/sched_process_exit")
int BPF_PROG(mon_proc_exit, struct task_struct *task, bool group_dead)
{
    // signal->live is decremented in do_exit() before this trace point. 
    // non-zero means other threads are still alive: not a process exit
    if (BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0;

    u32 pid = BPF_CORE_READ(task,tgid);
    if (bpf_map_delete_elem(&procs_map, &pid) == 0)
        log_debug("delete procs: pid=%d", pid);

    return 0;
}
