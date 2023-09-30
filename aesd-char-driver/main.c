/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include <linux/slab.h>
#include "aesd_ioctl.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Samuel Greene"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    PDEBUG("open");
    /**
     * TODO: COMPLETED handle open
     */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;


    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *read_entry;
    size_t find_entry_rtn = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */

    //PDEBUG("locking mutex");
    if (mutex_lock_interruptible(&dev->lock))
    {
        retval = -ERESTARTSYS;
        goto exit;
    }

    //PDEBUG("reading from circular buffer");
    read_entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &find_entry_rtn);
    if(read_entry == NULL)
    {
        retval = 0;
        goto exit;
    }
    retval = read_entry->size - find_entry_rtn;

    //PDEBUG("copy_to_user");
    if(copy_to_user(buf, (char *)read_entry->buffptr, retval) == 0)
    {
        *f_pos += retval;
        PDEBUG("Copied buffer was %s", buf);
    }
    else
    {
        retval = -EFAULT;
        goto exit;
    }

    goto exit;

    exit:
        mutex_unlock(&dev->lock);
        return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    //char newline = '\n';
    const char *add_rtn = NULL;
    bool found_newline = false;
    int i = 0;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

     //interruptable mutex
    //PDEBUG("locking mutex");
	if (mutex_lock_interruptible(&dev->lock))
    {
        retval = -ERESTARTSYS;
        goto exit;
    }
	
    //malloc
    //PDEBUG("beginning kmalloc");  
    dev->write_entry.buffptr = krealloc(dev->write_entry.buffptr, dev->write_entry.size + count, GFP_KERNEL);
    if(!dev->write_entry.buffptr)
    {
        PDEBUG("kmalloc return error");
        retval = -EFAULT; 
        goto exit;
    }

    //get buffer from user space
    //PDEBUG("beginning copy_from_user");
    if(copy_from_user((void *)(dev->write_entry.buffptr + dev->write_entry.size), buf, count))
    {
        retval = -EFAULT;
        goto exit;
    }
    //PDEBUG("User buffer was %s", buf);
    PDEBUG("Copied buffer was %s", dev->write_entry.buffptr);

    dev->write_entry.size += count;
    retval = count;
    *f_pos += retval;

    //search for newline
    for(i = 0; i < dev->write_entry.size; i++)
    {
        if(dev->write_entry.buffptr[i] == '\n')
        {
            found_newline = true;
            break;
        }
    }

    if(found_newline)
    {
        //PDEBUG("found newline");
        //PDEBUG("adding entry to circular_buffer");
        add_rtn = aesd_circular_buffer_add_entry(&dev->circular_buffer, &dev->write_entry);
        if(add_rtn)
        {
            kfree(add_rtn);
        }

        //PDEBUG("resetting entry");
        dev->write_entry.size = 0;
        dev->write_entry.buffptr = NULL;
    }
    else
    {
        goto exit;
    }

    exit:
        PDEBUG("total buffer size: %zu", dev->circular_buffer.buffer_size);
	    mutex_unlock(&dev->lock);
        return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    loff_t retval = -EINVAL;
    PDEBUG("llseek begin");

    if (mutex_lock_interruptible(&dev->lock))
    {
        retval = -ERESTARTSYS;
        goto exit;
    }

    retval = fixed_size_llseek(filp, off, whence, dev->circular_buffer.buffer_size);
    
    goto exit;

    exit:
	    mutex_unlock(&dev->lock);
        return retval;
}


/*
*   Adjust the file offset (f_pos) parameter of @param filp based on the location specified by
*   @param write_cmd (the zero referenced command to locate)
*   and @param write_cmd_offset (the zero referenced offset into the command)
*   @return 0 if successful, negative if error occured:
*       -ERESTARTSYS if mutex could not be obtained
*       -EINVAL if write command or write_cmd_offset was out of range;
*/
static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    struct aesd_dev *dev = filp->private_data;
    long retval = -EINVAL;
    int i;
    size_t offset = 0;

    PDEBUG("aesd_adjust_file_offset begin");
    
    if (mutex_lock_interruptible(&dev->lock))
    {
        retval = -ERESTARTSYS;
        goto exit;
    }
    //determine if write_cmd is valid when buffer is full
    if(dev->circular_buffer.full)
    {
        if(write_cmd >= 10)
        {
            retval = -EINVAL;
            goto exit;
        }
    }
    else  //determine if write_cmd is valid when buffer is not full
    {
        if(write_cmd >= dev->circular_buffer.in_offs)
        {
            retval = -EINVAL;
            goto exit;
        }
    }
    //determine if write_cmd_offset is out of range
    if(write_cmd_offset >= dev->circular_buffer.entry[write_cmd].size)
    {
        retval = -EINVAL;
        goto exit;
    }

    for(i=0; i<write_cmd ;i++)
    {
        PDEBUG("i:%d", i);
        PDEBUG("write_cmd:%d", write_cmd);
        offset += dev->circular_buffer.entry[i].size;
    }
    offset += write_cmd_offset; 
    filp->f_pos = offset;
    retval = 0;

    goto exit;

    exit:
	    mutex_unlock(&dev->lock);
        return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    
    long retval = -EINVAL;
    //struct aesd_dev *dev = filp->private_data;
    struct aesd_seekto seekto;
    PDEBUG("ioctl begin");

    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;

    //AESDCHAR_IOCSEEKTO
    if(cmd == AESDCHAR_IOCSEEKTO)
    {
        /*if (mutex_lock_interruptible(&dev->lock))
        {
            retval = -ERESTARTSYS;
            goto exit;
        }*/
        if(copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
        {
            retval = EFAULT;
            goto exit;
        }
        else
        {
            retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
            goto exit;
        }
    }
    goto exit;

    exit:
        //mutex_unlock(&dev->lock);
        return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&aesd_device.circular_buffer);
    aesd_device.write_entry.size = 0;
    aesd_device.write_entry.buffptr = NULL;
    mutex_init(&aesd_device.lock);
    //end todo

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    struct aesd_buffer_entry *entry;
    uint8_t index = 0;
    cdev_del(&aesd_device.cdev);
    PDEBUG("Cleanup Module");
    /**
     * TODO completed: cleanup AESD specific poritions here as necessary
     */
    PDEBUG("free circular buffer entries");
    AESD_CIRCULAR_BUFFER_FOREACH(entry,&aesd_device.circular_buffer,index)
    {
        kfree(entry->buffptr);
    }

    PDEBUG("free working entry");
    kfree(aesd_device.write_entry.buffptr);
    PDEBUG("destroy mutex");
    mutex_destroy(&aesd_device.lock);
    //end of todo

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
