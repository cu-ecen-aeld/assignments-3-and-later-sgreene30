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

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    //char *read_buf;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    /*struct aesd_dev *dev = filp->private_data;

    
    PDEBUG("locking mutex");
	if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;

    PDEBUG("beginning kmalloc");    
    //read_buf = kmalloc(count*sizeof(char *), GFP_KERNEL);
    if(!read_buf)
    {
        PDEBUG("kmalloc return error"); 
        goto exit;
    }
    memset(read_buf, 0, count * sizeof(char *));

    PDEBUG("reading from circular buffer"); 
    


    goto exit;

    exit:
	    mutex_unlock(&dev->lock);*/
        return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

     //interruptable mutex
    PDEBUG("locking mutex");
	if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;

    //malloc
    PDEBUG("beginning kmalloc");  
    dev->entry.buffptr = krealloc(dev->entry.buffptr, dev->entry.size + count, GFP_KERNEL);
    if(!dev->entry.buffptr)
    {
        PDEBUG("kmalloc return error"); 
        goto exit;
    }

    //get buffer from user space
    PDEBUG("beginning copy_from_user");
    if(copy_from_user((char *)dev->entry.buffptr, buf, count))
    {
        retval = -EFAULT;
    }


    PDEBUG("User buffer was %s", buf);
    PDEBUG("Copied buffer was %s", dev->entry.buffptr);
    //PDEBUG("*write_buf: %d",  *write_buf);
    //PDEBUG("&write_buf: %d", (int)&write_buf);

    dev->entry.size += count;
    retval = count;

    /*char newline = '\n';
    if(strchr(dev->entry.buffptr, newline))
    {
        PDEBUG("found newline");

        PDEBUG("free oldest entry if buffer is full");
        if(dev->circular_buffer.full)
        {
            kfree(&dev->circular_buffer.entry[dev->circular_buffer.out_offs]);
        }

        PDEBUG("adding entry to circular_buffer");
        aesd_circular_buffer_add_entry(dev->circular_buffer, dev->entry);
        PDEBUG("resetting entry");
        dev->entry.size = 0;
        dev->entry.buffptr = NULL;
    }*/


    PDEBUG("adding packet to circular buffer");
    //aesd_circular_buffer_add_entry(dev->circular_buffer, dev->entry);
    exit:
        //kfree(write_buf);
	    mutex_unlock(&dev->lock);
        return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
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
    aesd_device.entry.size = 0;
    aesd_device.entry.buffptr = NULL;
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
    kfree(aesd_device.entry.buffptr);
    PDEBUG("destroy mutex");
    mutex_destroy(&aesd_device.lock);
    //end of todo

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
