#ifndef MON_BPF_LOG_H
#define MON_BPF_LOG_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum mon_log_level {
    MON_LOG_DEBUG = 0,
    MON_LOG_INFO  = 1,
    MON_LOG_WARN  = 2,
    MON_LOG_ERROR = 3,
    MON_LOG_NONE  = 4,
};

// Set from userspace between open and load (rodata is frozen at load time),
// so the verifier sees the final value and removes disabled log calls as
// dead code.
const volatile u32 mon_log_level = MON_LOG_INFO;

// BPF_PROG places the program body in a ____-prefixed inner function; hide
// the prefix so logs show the program name. Constant-folded by clang since
// __func__ is known at compile time.
static __always_inline const char *___mon_log_func(const char *fn)
{
    if (fn[0] == '_' && fn[1] == '_' && fn[2] == '_' && fn[3] == '_')
        return fn + 4;
    return fn;
}

#define mon_log(lvl, tag, fmt, ...)                                     \
    do {                                                                \
        if ((lvl) >= mon_log_level)                                     \
            bpf_printk(tag " %s:%d " fmt, ___mon_log_func(__func__),    \
                       __LINE__, ##__VA_ARGS__);                        \
    } while (0)

#define log_debug(fmt, ...) mon_log(MON_LOG_DEBUG, "DBG", fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  mon_log(MON_LOG_INFO,  "INF", fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  mon_log(MON_LOG_WARN,  "WRN", fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) mon_log(MON_LOG_ERROR, "ERR", fmt, ##__VA_ARGS__)

#endif /* MON_BPF_LOG_H */
