/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <stddef.h>
typedef unsigned int uint32_t;
typedef short unsigned int umode_t;
//#include <stdint.h>
#include <linux/errno.h>
#undef offsetof
#define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* BPF module that implements an allowlist of mounts (identified by mount ID) for user namespaces (identified
 * by their inode number in nsfs) that restricts creation of inodes (which would inherit the callers UID/GID)
 * or changing of ownership (similar).
 *
 * This hooks into the varius path-based LSM entrypoints that control inode creation as well as chmod(), and
 * then looks up the calling process' user namespace in a global map of namespaces, which points us to
 * another map that is simply a list of allowed mnt_ids. */

// FIXME:
//
// - ACL adjustments are currently not blocked. There's no path-based LSM hook for setting xattrs or ACLs,
//   hence we cannot easily block them, even though we want that.

/* We are not using stub structures with __attribute__((preserve_access_index)) here, and instead opt to
 * '#include "vmlinux.h"', since there's apparently no CO-RE powered container_of() available? */

/* kernel currently enforces a maximum usernamespace nesting depth of 32, see create_user_ns() in the kernel sources */
#define USER_NAMESPACE_DEPTH_MAX 32U

struct {
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __type(key, unsigned);         /* userns inode */
        __type(value, uint32_t);       /* mnt_id set */
} userns_mnt_id_hash SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
} userns_ringbuf SEC(".maps") ;

struct vfsmount {
} __attribute__((preserve_access_index));

struct mount {
        struct vfsmount mnt;
        int mnt_id;
} __attribute__((preserve_access_index));

struct super_block {
       struct user_namespace *s_user_ns;
} __attribute__((preserve_access_index));

struct inode {
        struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
        struct inode *f_inode;
} __attribute__((preserve_access_index));

struct cred {
        struct user_namespace *user_ns;
} __attribute__((preserve_access_index));

struct task_struct {
        const struct cred *cred;
        struct task_struct *parent;
} __attribute__((preserve_access_index));

struct ns_common {
        unsigned int inum;
} __attribute__((preserve_access_index));

struct work_struct {
        int blah;
} __attribute__((preserve_access_index));

struct user_namespace {
        struct ns_common ns;
        struct work_struct work;
        struct user_namespace *parent;
} __attribute__((preserve_access_index));

struct dentry {
        struct inode *d_inode;
} __attribute__((preserve_access_index));

struct path {
        struct vfsmount *mnt;
        struct dentry *dentry;
} __attribute__((preserve_access_index));

static inline struct mount *real_mount(struct vfsmount *mnt) {
        return container_of(mnt, struct mount, mnt);
}

static int validate_inode_on_mount(struct inode *inode, struct vfsmount *v) {
        struct user_namespace *superblock_userns, *task_userns, *p;
        unsigned task_userns_inode;
        struct task_struct *task;
        void *mnt_id_map;
        struct mount *m;
        int mnt_id;

        superblock_userns = BPF_CORE_READ(inode, i_sb, s_user_ns);

        task = (struct task_struct*) bpf_get_current_task();
        task_userns = BPF_CORE_READ(task, cred, user_ns);

        /* Is the file on a superblock that belongs to our own user namespace or a child of it? If so, say
         * yes immediately. */
        p = superblock_userns;
        for (unsigned i = 0; i < USER_NAMESPACE_DEPTH_MAX; i++) {
                if (p == task_userns)
                        return 0; /* our task's user namespace (or a child thereof) owns this superblock: allow! */

                p = BPF_CORE_READ(p, parent);
                if (!p)
                        break;
        }

        /* Hmm, something is fishy if there's more than 32 levels of namespaces involved. Let's better be
         * safe than sorry, and refuse. */
        if (p)
                return -EPERM;

        /* This is a superblock foreign to our task's user namespace, let's consult our allow list */
        task_userns_inode = BPF_CORE_READ(task_userns, ns.inum);

        mnt_id_map = bpf_map_lookup_elem(&userns_mnt_id_hash, &task_userns_inode);
        if (!mnt_id_map) /* No rules installed for this userns? Then say yes, too! */
                return 0;

        m = real_mount(v);
        mnt_id = BPF_CORE_READ(m, mnt_id);

        /* Otherwise, say yes if the mount ID is allowlisted */
        return bpf_map_lookup_elem(mnt_id_map, &mnt_id) ? 0 : -EPERM;
}

static int validate_path(const struct path *path, int ret) {
        struct inode *inode;
        struct vfsmount *v;

        if (ret != 0) /* propagate earlier error */
                return ret;

        inode = BPF_CORE_READ(path, dentry, d_inode);
        v = BPF_CORE_READ(path, mnt);

        return validate_inode_on_mount(inode, v);
}

SEC("lsm/path_chown")
int BPF_PROG(userns_restrict_path_chown, struct path *path, void* uid, void *gid, int ret) {
        return validate_path(path, ret);
}

SEC("lsm/path_mkdir")
int BPF_PROG(userns_restrict_path_mkdir, struct path *dir, struct dentry *dentry, umode_t mode, int ret) {
        return validate_path(dir, ret);
}

SEC("lsm/path_mknod")
int BPF_PROG(userns_restrict_path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev, int ret) {
        return validate_path(dir, ret);
}

SEC("lsm/path_symlink")
int BPF_PROG(userns_restrict_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name, int ret) {
        return validate_path(dir, ret);
}

SEC("lsm/path_link")
int BPF_PROG(userns_restrict_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, int ret) {
        return validate_path(new_dir, ret);
}

SEC("kprobe/free_user_ns")
void BPF_KPROBE(userns_restrict_free_user_ns, struct work_struct *work) {
        struct user_namespace *userns;
        unsigned inode;
        void *mnt_id_map;

        /* Inform userspace that a user namespace just went away. I wish there was a nicer way to hook into
         * user namespaces being deleted than using kprobes, but couldn't find any. */

        userns = container_of(work, struct user_namespace, work);

        inode = BPF_CORE_READ(userns, ns.inum);

        mnt_id_map = bpf_map_lookup_elem(&userns_mnt_id_hash, &inode);
        if (!mnt_id_map) /* No rules installed for this userns? Then send no notification. */
                return;

        bpf_ringbuf_output(&userns_ringbuf, &inode, sizeof(inode), 0);
}

static const char _license[] SEC("license") = "GPL";
