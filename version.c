#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include "version.h"

static struct
{
    char *version;
    bool modified;
} modsys;

typedef struct file_sys
{
    char *buf;
    __kernel_size_t buf_sz;
} file_sys_t;

static inline int
get_version_string(char **p_vstr)
{
    char const *vstr = utsname()->version;
    __kernel_size_t vstr_sz = strlen(vstr);
    *p_vstr = kmalloc(vstr_sz, GFP_KERNEL);
    if (!*p_vstr)
        return -ENOMEM;
    memcpy(*p_vstr, vstr, vstr_sz);
    return vstr_sz;
}

static inline void
reset_version(file_sys_t *fsys)
{
    if (!modsys.modified)
        return;
    strcpy(utsname()->version, modsys.version);
    if (fsys)
        fsys->buf_sz = get_version_string(&fsys->buf);
    modsys.modified = false;
}

static int
version_open(struct inode *inode, struct file *filp)
{
    file_sys_t *sys = kmalloc(sizeof(*sys), GFP_KERNEL);
    if (!sys)
        return -ENOMEM;
    int buf_sz = get_version_string(&sys->buf);
    if (buf_sz < 0)
    {
        kfree(sys);
        return buf_sz;
    }
    sys->buf_sz = buf_sz;
    filp->private_data = sys;
    if (filp->f_flags & O_APPEND)
        filp->f_pos = sys->buf_sz;
    return 0;
}

static int
version_release(struct inode *inode, struct file *file)
{
    file_sys_t *sys = file->private_data;
    kfree(sys->buf);
    kfree(sys);
    return 0;
}

static loff_t
version_llseek(struct file *filp, loff_t pos, int whence)
{
    file_sys_t *sys = filp->private_data;
    switch (whence)
    {
        case SEEK_SET:
            if (pos < 0)
                return -EINVAL;
            break;
        case SEEK_CUR:
            pos = filp->f_pos + pos;
            if (pos < 0 || pos > sys->buf_sz)
                return -EINVAL;
            break;
        case SEEK_END:
            if (pos > 0)
                return -EINVAL;
            pos += sys->buf_sz;
            break;
        default:
            return -EINVAL;
    }
    filp->f_pos = pos;
    return pos;
}

static ssize_t
version_read(struct file *filp,
             char __user *buf, size_t buf_sz,
             loff_t *p_pos)
{
    file_sys_t *sys = filp->private_data;
    if (*p_pos == sys->buf_sz)
        return 0;
    __kernel_size_t rem_sz = sys->buf_sz - *p_pos;
    __kernel_size_t copy_sz = buf_sz < rem_sz ? buf_sz : rem_sz;
    if (copy_to_user(buf, sys->buf + *p_pos, copy_sz))
        return -EFAULT;
    *p_pos += copy_sz;
    return copy_sz;
}

static ssize_t
version_write(struct file *filp,
              char const __user *buf, size_t buf_sz,
              loff_t *p_pos)
{
    if (*p_pos + buf_sz > __NEW_UTS_LEN)
        return -EINVAL;

    char *version = utsname()->version;
    if (copy_from_user(version + *p_pos, buf, buf_sz))
        return -EFAULT;
    version[*p_pos + buf_sz] = 0;
    modsys.modified = true;

    file_sys_t *sys = filp->private_data;
    kfree(sys->buf);
    sys->buf_sz = get_version_string(&sys->buf);
    if (sys->buf_sz < 0)
        reset_version(sys);
    return buf_sz;
}

static long
version_ioctl(struct file *filp,
              unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
        case VERSION_MODIFIED:
            if (copy_to_user((bool *)arg, &modsys.modified, sizeof(bool)))
                return -EFAULT;
            break;
        case VERSION_RESET:
            reset_version(filp->private_data);
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

static struct file_operations const fops =
{
    .owner = THIS_MODULE,
    .llseek = version_llseek,
    .read = version_read,
    .write = version_write,
    .unlocked_ioctl = version_ioctl,
    .open = version_open,
    .release = version_release,
};

static struct miscdevice dev =
{
    .minor = MISC_DYNAMIC_MINOR,
    .name = "version",
    .fops = &fops,
};

static __init int
version_load(void)
{
    int r = misc_register(&dev);
    if (r)
    {
        pr_err("misc_register() failed: %d\n", r);
        return r;
    }
    r = get_version_string(&modsys.version);
    if (r < 0)
        return r;
    modsys.modified = false;
    return 0;
}

static __exit void
version_unload(void)
{
    reset_version(NULL);
    kfree(modsys.version);
    misc_deregister(&dev);
}

module_init(version_load);
module_exit(version_unload);

MODULE_AUTHOR("Victorien Le Couviour--Tuffet <victorien.lecouviour.tuffet@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernel version driver");
