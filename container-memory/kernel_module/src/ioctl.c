//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2018
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng, Yu-Chia Liu
//
//   Description:
//     Core of Kernel Module for Processor Container
//
////////////////////////////////////////////////////////////////////////

#include "memory_container.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>

typedef struct
{
    int pid;
    bool is_valid;
} Task;

typedef struct
{
    int oid;
    int size;
    void *data;
    bool is_valid;
    //struct mutex lock;
    unsigned long addr;
} Object;

typedef struct
{
    int cid;
    int num_tasks;
    int num_objects;
    bool is_valid;
    struct mutex lock;

    Task task_list[100000];
    Object object_list[100000];
} Container;

Container *container_list[10000] = {NULL};

void print_lists(void)
{
    if (container_list == NULL)
    {
        printk("No containers/threads present\n");
        printk("-----------------------------------------\n");
        return;
    }

    int i;
    for (i=0; i<MAX_SIZE; i++)
    {
        if (container_list[i] == NULL) {
            break;
        }
        if (container_list[i]->is_valid)
        {
            printk("Container id : %d\n", container_list[i]->cid);
            int j;
            for (j=0; j<MAX_SIZE; j++)
            {
                if (container_list[i]->task_list[j].is_valid)
                {
                    printk("Task id : %d\n", container_list[i]->task_list[j].pid);
                }
            }

            for (j=0; j<MAX_SIZE; j++)
            {
                if (container_list[i]->object_list[j].is_valid)
                {
                    printk("Object id : %d\n", container_list[i]->object_list[j].oid);
                }
            }
            printk("-----------------------------------------\n");
        }
    }

    printk("-----------------------------------------\n");
}

int get_cid(void)
{
    int i, j;
    for (i=0; i<10000; i++)
    {
        Container *curr = container_list[i];
        printk("i :%d\n", i);
        if (curr != NULL && curr->is_valid)
        {
            printk("valid i :%d\n", i);
            for (j=0; j<curr->num_tasks; j++)
            {
                if (curr->task_list[j].is_valid)
                {
                    printk("Checking cid: %d, pid: %d, tid: %d\n", i, current->pid, curr->task_list[j].pid);
                    if (curr->task_list[j].pid == current->pid)
                    {
                        printk("Found cid: %d, pid: %d\n", i, current->pid);
                        return i;
                    }
                }
            }
        } else {
            printk("invalid i :%d\n", i);
        }
    }
    return -1;
}

// vm_area_struct  -  object size and id
// get pid from current
// get cid from pid
// get object size and id from vma
// check if oid exist in cid
// if new id, kmalloc
// if old, remap
int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
    printk("Entered mmap for pid: %d\n", current->pid);
    int cid = get_cid();
    int oid = vma->vm_pgoff;
    unsigned long len = vma->vm_end - vma->vm_start;

    bool present = false;
    Container *curr = container_list[cid];
    int i;
    for (i=0; i<curr->num_objects; i++)
    {
        if (curr->object_list[i].is_valid && curr->object_list[i].oid == oid)
        {
            present = true;
            break;
        }
    }

    if (!present)
    {
        printk("Not present\n");
        // do kmalloc
        void *data = kmalloc(len, GFP_KERNEL);
        unsigned long pfn = (unsigned long)virt_to_phys((void *)data) >> PAGE_SHIFT;

        // add to list
        curr->object_list[i].oid = oid;
        curr->object_list[i].size = len;
        curr->object_list[i].is_valid = true;
        curr->object_list[i].addr = pfn;
        curr->object_list[i].data = data;
        curr->num_objects++;

        // do remap?
        int ret;
        ret = remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot);
        if (ret < 0) {
            printk("Could not map the address area\n");
        }
    }
    else
    {
        printk("Present\n");
        int ret;
        ret = remap_pfn_range(vma, vma->vm_start, curr->object_list[i].addr, curr->object_list[i].size, vma->vm_page_prot);
        if (ret < 0) {
            printk("Could not re-map the address area\n");
        }
    }

    printk("Exited mmap for pid: %d\n", current->pid);
//    print_lists();
    return 0;
}


int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
    // got tid
    // get cid from tid
    // mutex_lock()
    struct memory_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    printk("Entered lock for pid: %llu, oid: %llu\n", current->pid, kernel_cmd.oid);

    int cid = get_cid();
    if (cid == -1)
    {
        printk("Could not find container for pid: %llu\n", current->pid);
        return 0;
    }
    Container *curr = container_list[cid];

//    int i;
//    Object obj;
//    for (i=0; i<curr->num_objects; i++)
//    {
//        if (curr->object_list[i].is_valid && curr->object_list[i].oid == kernel_cmd.oid)
//        {
//            obj = curr->object_list[i];
//            break;
//        }
//    }

    mutex_lock(&curr->lock);
    printk("Exited lock for pid: %llu, oid: %llu\n", current->pid, kernel_cmd.oid);
    return 0;
}

// got tid
// get cid from tid
// mutex_unlock()
int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{
    printk("Entered unlock for tid: %llu\n", current->pid);

    struct memory_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));

    int cid = get_cid();
    if (cid == -1)
    {
        printk("Could not find container for pid: %llu\n", current->pid);
        return 0;
    }
    Container *curr = container_list[cid];

//    int i;
//    Object obj;
//    for (i=0; i<curr->num_objects; i++)
//    {
//        if (curr->object_list[i].is_valid && curr->object_list[i].oid == kernel_cmd.oid)
//        {
//            obj = curr->object_list[i];
//            break;
//        }
//    }
    mutex_unlock(&curr->lock);
    printk("Exited unlock for tid: %llu\n", current->pid);
    return 0;
}

// delete container
int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{
    struct memory_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    printk("Entered delete for pid:%llu\n", current->pid);

    int cid = get_cid();

//    container_list[cid]->is_valid = false;
//    container_list[cid]->num_tasks = 0;
//    container_list[cid]->num_objects = 0;

    printk("Exited delete for pid:%llu\n", current->pid);
    return 0;
}

// create
int memory_container_create(struct memory_container_cmd __user *user_cmd)
{
    struct memory_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    printk("Entered create for cid: %llu, pid:%llu\n", kernel_cmd.cid, current->pid);

    if (!container_list[kernel_cmd.cid])
    {
        printk("Container not present cid: %llu, pid:%llu\n", kernel_cmd.cid, current->pid);
        container_list[kernel_cmd.cid] = (Container *) kmalloc(sizeof(Container), GFP_KERNEL);
        container_list[kernel_cmd.cid]->num_tasks = 0;
        container_list[kernel_cmd.cid]->num_objects = 0;
        container_list[kernel_cmd.cid]->is_valid = true;
        mutex_init(&container_list[kernel_cmd.cid]->lock);
        printk("Created container cid: %llu, pid:%llu\n", kernel_cmd.cid, current->pid);
    }

    Container *curr = container_list[kernel_cmd.cid];
    curr->cid = kernel_cmd.cid;
    curr->is_valid = true;
    curr->task_list[curr->num_tasks].is_valid = true;
    curr->task_list[curr->num_tasks++].pid = current->pid;

    printk("Exited create for cid: %llu, pid: %llu\n", kernel_cmd.cid, current->pid);
//    print_lists();
    return 0;
}

// delete an object
int memory_container_free(struct memory_container_cmd __user *user_cmd)
{
    // got tid
    // get cid from tid
    // delete oid
    struct memory_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    printk("Entered free object for pid:%llu, oid:%llu\n", current->pid, kernel_cmd.oid);

    int cid = get_cid();
    if (cid == -1)
    {
        printk("Could not find container for pid: %llu\n", current->pid);
        return 0;
    }
    Container *curr = container_list[cid];

    int i;
    for (i=0; i<curr->num_objects; i++)
    {
        if (curr->object_list[i].is_valid && curr->object_list[i].oid == kernel_cmd.oid)
        {
            printk("Found object with oid: %llu, pid:%llu\n", kernel_cmd.oid, current->pid);
            break;
        }
    }

    curr->object_list[i].is_valid = false;
    printk("Doing kfree for object with oid: %llu, pid:%llu\n", kernel_cmd.oid, current->pid);
    kfree(curr->object_list[i].data);
    printk("Exited free object for pid:%llu\n", current->pid);
    return 0;
}


/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int memory_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case MCONTAINER_IOCTL_CREATE:
        return memory_container_create((void __user *)arg);
    case MCONTAINER_IOCTL_DELETE:
        return memory_container_delete((void __user *)arg);
    case MCONTAINER_IOCTL_LOCK:
        return memory_container_lock((void __user *)arg);
    case MCONTAINER_IOCTL_UNLOCK:
        return memory_container_unlock((void __user *)arg);
    case MCONTAINER_IOCTL_FREE:
        return memory_container_free((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
