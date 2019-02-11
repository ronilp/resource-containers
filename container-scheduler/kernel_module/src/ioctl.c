// Project 1: Ronil Pancholia, rpancho; Aishwarya Tirumala, atiruma;
//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2016
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

#include "processor_container.h"

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
    unsigned long long cid;
    struct Task *task_list_tail;
    struct Container *next;
} Container;

typedef struct
{
    unsigned long long tid;
    struct task_struct *thread;
    struct Task *next;
} Task;

Container *container_list_tail;

extern struct mutex my_mutex;

Container *add_container(unsigned long long data)
{
    Container *new_container = (Container *) kmalloc(sizeof(Container), GFP_KERNEL);
    new_container->cid = data;
    new_container->task_list_tail = NULL;
    new_container->next = new_container;

    if (container_list_tail == NULL)
    {
        return new_container;
    }

    Container *head = container_list_tail->next;
    container_list_tail->next = new_container;
    new_container->next = head;
    container_list_tail = new_container;
    return new_container;
}

Task *add_task(Task *tail)
{
    Task *new_task = (Task *) kmalloc(sizeof(Task), GFP_KERNEL);
    new_task->tid = current->pid;
    new_task->thread = current;
    new_task->next = new_task;

    if (tail == NULL)
    {
        return new_task;
    }

    Task *head = tail->next;
    tail->next = new_task;
    new_task->next = head;
    return new_task;
}

void print_lists(void)
{
    if (container_list_tail == NULL) {
        printk("No containers/threads present\n");
        printk("-----------------------------------------\n");
        return;
    }
    Container *temp = container_list_tail->next;
    do
    {
        printk("container = %llu\n", temp->cid);
        Task *tail = temp->task_list_tail;
        if (tail == NULL)
        {
            temp = temp->next;
            continue;
        }
        Task *task_head = tail->next;
        do
        {
            printk("thread = %llu\n", task_head->tid);
            task_head = task_head->next;
        } while (task_head != tail->next);
        temp = temp->next;
    } while (temp != container_list_tail->next);
    printk("-----------------------------------------\n");
}

void delete_container(int cid)
{
    if (container_list_tail == NULL)
    {
        return;
    }

    // if only 1 container present
    Container *next_container = container_list_tail->next;
    if (container_list_tail->cid == next_container->cid) {
        container_list_tail = NULL;
        printk("Deleted last container with cid: %llu\n", cid);
        return ;
    }

    Container *prev = container_list_tail;
    Container *cIter = container_list_tail->next;
    do {
        if (cIter->cid == cid)
        {
            prev->next = cIter->next;
            if (prev == cIter || prev->cid == cIter->cid) {
                container_list_tail = NULL;
                printk("Deleted last container fallback with cid: %llu\n", cid);
                return;
            }
            if (cIter == container_list_tail) {
                printk("Container tail removed\n");
                container_list_tail = prev;
            }
            cIter = NULL;
            printk("Deleted container with cid: %llu\n", cid);
            return;
        }
        prev = cIter;
        cIter = cIter->next;
    } while (container_list_tail->next != cIter);
}

/**
 * Delete the task in the container.
 *
 * external functions needed:
 * mutex_lock(), mutex_unlock(), wake_up_process(),
 *
 * Steps :
 * 1. Wake up next thread in the container head.
 * 2. delete head thread in the container head.
 */
int processor_container_delete(struct processor_container_cmd __user *user_cmd)
{
    struct processor_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user*)user_cmd, sizeof(struct processor_container_cmd));
    printk("Entered delete for cid: %llu, pid: %llu\n", kernel_cmd.cid, current->pid);

    mutex_lock(&my_mutex);
    printk("Acquired lock in container delete called for cid: %llu, tid: %llu\n", kernel_cmd.cid, current->pid);

    // if no containers present, return
    if (container_list_tail == NULL)
    {
        mutex_unlock(&my_mutex);
        return 0;
    }

    // find the container with cid = kernel_cmd.cid
    Container *cIter = container_list_tail;
    do {
        if (cIter->cid == kernel_cmd.cid)
        {
            break;
        }
        cIter = cIter->next;
    } while (cIter != container_list_tail);

    // if cid not present OR if no tasks present in the container, return
    if (kernel_cmd.cid != cIter->cid || cIter->task_list_tail == NULL)
    {
        mutex_unlock(&my_mutex);
        return 0;
    }

    // Get current tid
    unsigned long long dirty_tid = current->pid;

    printk("Attempting to delete task with id = %llu\n", dirty_tid);

    // find thread in the list
    Task *tTail = cIter->task_list_tail;
    Task *tIter = tTail->next;
    Task *prev = tTail;

    do {
        if (tIter->tid == dirty_tid)
        {
            break;
        }
        prev = tIter;
        tIter = tIter->next;
    } while (tIter != tTail->next);

    // if this is the only thread in the container
    if (prev->tid == tIter->tid)
    {
        printk("tid: %llu is the last in container with cid: %llu\n", dirty_tid, cIter->cid);
        delete_container(cIter->cid);
    }
    else
    {
        prev->next = tIter->next;
        // if this is the tail, assign new tail
        if (tIter->tid == tTail->tid)
        {
            cIter->task_list_tail =  tIter->next;
        }
        tIter = NULL;

        // Wake up next thread in container
        tTail = cIter->task_list_tail;
        Task *head = tTail->next;
        wake_up_process(head->thread);
        printk("Woke up thread with tid: %llu before deleting\n", head->tid);
    }

    printk("Deleted thread with tid: %llu\n", dirty_tid);
    print_lists();

    mutex_unlock(&my_mutex);
    printk("Released lock in container delete called for cid: %llu, tid: %llu\n", kernel_cmd.cid, current->pid);
    return 0;
}

/**
 * Create a task in the corresponding container.
 * external functions needed:
 * copy_from_user(), mutex_lock(), mutex_unlock(), set_current_state(), schedule()
 *
 * external variables needed:
 * struct task_struct* current
 *
 * Steps :
 * 1. Traverse thru the list of containers and find the container with cid = user_cmd->cid
 * 2. If no such container is present, then create it.
 * 3. Add task to the container with cid = user_cmd->cid.
 * 4. Sleep and return.
 */
int processor_container_create(struct processor_container_cmd __user *user_cmd)
{
    struct processor_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user*)user_cmd, sizeof(struct processor_container_cmd));
    printk("Entered create for cid: %llu, tid:%llu\n", kernel_cmd.cid, current->pid);

    mutex_lock(&my_mutex);
    printk("Acquired lock in container create called for cid: %llu, tid: %llu\n", kernel_cmd.cid, current->pid);

    // if list is empty, add a node with cid = kernel_cmd.cid
    if (container_list_tail == NULL)
    {
        container_list_tail = add_container(kernel_cmd.cid);
    }

    // find the node with cid = kernel_cmd.cid
    Container *temp = container_list_tail;
    do {
        if (temp->cid == kernel_cmd.cid)
        {
            break;
        }
        temp = temp->next;
    } while (temp != container_list_tail);

    // if container with cid = kernel_cmd.cid is not found, create and add it to the end
    if (temp->cid != kernel_cmd.cid)
    {
        temp = add_container(kernel_cmd.cid);
    }

    // temp is the container with cid = kernel_cmd.cid. Add the current task to this container
    Task *task_list_head = temp->task_list_tail;
    bool isEmpty = (temp->task_list_tail == NULL);
    temp->task_list_tail = add_task(task_list_head);

    printk("Released lock in container create called for cid: %llu, tid: %llu\n", kernel_cmd.cid, current->pid);

    if (!isEmpty)
    {
        printk("Putting thread to sleep since it is not the first in the container. cid: %llu, tid: %llu\n", kernel_cmd.cid, current->pid);
        set_current_state(TASK_INTERRUPTIBLE);
        mutex_unlock(&my_mutex);
        schedule();
        return 0;
    }

    mutex_unlock(&my_mutex);
    return 0;
}

Task* wake_next_thread(Container **container)
{
    if (*container == NULL)
    {
        return NULL;
    }

    Task *tail = (*container)->task_list_tail;
    Task *head = tail->next;
    Task *next = head->next;

    if (next->tid == head->tid || next->tid == current->pid)
    {
        printk("Skip container switch as only 1 thread present. tid: %llu\n", head->tid);
        return tail;
    }

    printk("Waking up thread with tid: %llu\n", next->tid);
    wake_up_process(next->thread);

    // update task list tail
    (*container)->task_list_tail = head;
    return head;
}

/**
 * switch to the next task in the next container
 *
 * external functions needed:
 * mutex_lock(), mutex_unlock(), wake_up_process(), set_current_state(), schedule()
 *
 * Steps :
 * 1. Iterate over containers.
 * 2. Wake up head thread.
 * 3. Sleep current thread.
 */
int processor_container_switch(struct processor_container_cmd __user *user_cmd)
{
    if (container_list_tail == NULL)
    {
        printk("Skipping thread switch as container list is null\n");
        return 0;
    }

    printk("Container switch called for cid: %llu, tid: %llu\n", container_list_tail->cid, current->pid);
    mutex_lock(&my_mutex);
    printk("Acquired lock in container switch called for cid: %llu, tid: %llu\n", container_list_tail->cid, current->pid);
    print_lists();

    Container *cIter = container_list_tail;
    do {
        printk("Switching thread for container with cid: %llu\n", cIter->cid);
        cIter->task_list_tail = wake_next_thread(&cIter);
        cIter = cIter->next;
    } while (cIter->cid != container_list_tail->cid);

    container_list_tail = cIter;

    // loop thru containers and check if current thread is the only thread
    bool only_thread = false;
    do {

        Task *task_tail = cIter->task_list_tail;
        if (task_tail->tid == current->pid) {
            only_thread = true;
            break;
        }
        cIter = cIter->next;
    } while (cIter->cid != container_list_tail->cid);

    mutex_unlock(&my_mutex);

    if (!only_thread) {
        printk("Sleeping thread with tid: %llu\n", current->pid);
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    } else {
        set_current_state(TASK_RUNNING);
    }
    printk("Released lock in container switch called for tid: %llu\n", current->pid);
    printk("Switching thread complete for tid: %llu\n", current->pid);
    return 0;
}

/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int processor_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case PCONTAINER_IOCTL_CSWITCH:
        return processor_container_switch((void __user *)arg);
    case PCONTAINER_IOCTL_CREATE:
        return processor_container_create((void __user *)arg);
    case PCONTAINER_IOCTL_DELETE:
        return processor_container_delete((void __user *)arg);
    default:
        return -ENOTTY;
    }
}