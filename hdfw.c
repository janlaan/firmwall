/*
 * HDFW: Loadable Linux kernel module for monitoring and blocking suspicious hard drive activity.
 *
 * HDFW Copyright (C) 2014 Jan Laan, Niels van Dijkhuizen
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/highmem.h>
#include <asm/unistd.h>
#include <scsi/sg.h>
#include <linux/errno.h>
#include <linux/hdreg.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include "sgio.h"
#include "hdfw.h"


int in_use = 0; //Only allow one access to our management device at a time
int is_set = 0; //Determines whether our ioctl replacement is active or not.
char * whitelist[WHITELIST_SIZE];
int whitelist_size = 0;
unsigned long *sys_call_table = (unsigned long*)0xffffffff8155d200;

/* Hook for open management device */
static int our_open(struct inode *inode, struct file *file)
{
   if(in_use)
      return -EBUSY;
   in_use++;
   return 0;
}

/* Hook for close management device */
static int our_release(struct inode *inode, struct file *file)
{
   in_use--;
   return 0;
}

/* This function will handle ioctl calls performed on our device
 * Patches or unpatches the sys_call_table,
 * Adds or removes items from the whitelist. */
static int our_ioctl(struct file *file, unsigned int cmd, char* arg)
{
   int retval = 0,
       arg_size,
       i,
       found;

   char * data;

   switch(cmd)
   {
      case IOCTL_PATCH_TABLE:
         if(is_set == 0)
         {
            make_rw((unsigned long)sys_call_table);
            real_ioctl = (void*)*(sys_call_table + __NR_ioctl);
            *(sys_call_table + __NR_ioctl) = (unsigned long)custom_ioctl;
            make_ro((unsigned long)sys_call_table);
            is_set=1;
            printk(KERN_WARNING "[HDFW] Blocking / Monitoring: Enabled\n");
         }
         break;
      case IOCTL_FIX_TABLE:
         if(is_set == 1)
         {
            make_rw((unsigned long)sys_call_table);
            *(sys_call_table + __NR_ioctl) = (unsigned long)real_ioctl;
            make_ro((unsigned long)sys_call_table);
            is_set=0;
            printk(KERN_WARNING "[HDFW] Blocking / Monitoring: Disabled\n");
         }
         break;
      case IOCTL_WHITELIST_ADD:
         if(whitelist_size == WHITELIST_SIZE)
         {
            printk(KERN_WARNING "[HDFW] Whitelist full, adding failed!\n");
            return -1;
         }
         arg_size = strlen_user(arg);
         if((data = kmalloc(arg_size, GFP_KERNEL)))
         {
            if(strncpy_from_user(data, arg, arg_size) > 0)
            {
               whitelist[whitelist_size++] = data;
               printk(KERN_WARNING "[HDFW] Added to Whitelist: %s", data);
            }
            else
            {
               printk(KERN_WARNING "[HDFW] Strncpy failed, nothing added to whitelist\n");
            }
         }
         break;
      case IOCTL_WHITELIST_REMOVE:
         arg_size = strlen_user(arg);
         found = -1;
         for(i = 0; i < whitelist_size; i++)
         {
            if(!strcmp(whitelist[i], arg))
            {
               found = i;
               break;
            }
         }
         if(found > -1)
         {
            for(i = 0; i < whitelist_size; i++)
            {
               if(i == found)
               {
                  printk(KERN_WARNING "[HDFW] Removed from Whitelist: %s", whitelist[i]);
                  kfree(whitelist[i]);
               }
               else if(i > found)
               {
                     whitelist[i-1] = whitelist[i];
               }
            }
            whitelist_size--;
         }
         break;
      case IOCTL_WHITELIST_LIST:
         list_whitelist();
         break;
      default: //anything else is unsupported
         retval = EINVAL;
         break;
   }

   return retval;
}
static const struct file_operations our_fops =
{
   .owner = THIS_MODULE,
   .open = &our_open,
   .release = &our_release,
   .unlocked_ioctl = (void*)&our_ioctl,
   .compat_ioctl = (void*)&our_ioctl
};

static struct miscdevice our_device =
{
   MISC_DYNAMIC_MINOR,
   "hdfw_mgmt",
   &our_fops
};

/* Init: Register device */
static int __init vslog_init(void)
{

   int retval = misc_register(&our_device);

   printk(KERN_WARNING "[HDFW] HDFW: Kernel module loaded\n");
   return retval;
}


/* Make a page writable */
int make_rw(unsigned long address)
{
   unsigned int level;
   pte_t *pte = lookup_address(address, &level);
   if(pte->pte &~ _PAGE_RW)
      pte->pte |= _PAGE_RW;
   return 0;
}

/* Make a page write protected */
int make_ro(unsigned long address)
{
   unsigned int level;
   pte_t *pte = lookup_address(address, &level);
   pte->pte = pte->pte &~ _PAGE_RW;
   return 0;
}

/*  Module cleanup. Make sure the sys call table is restored to its original version */
static void __exit vslog_cleanup(void)
{
   misc_deregister(&our_device);
   if(is_set)
   {
      make_rw((unsigned long)sys_call_table);
      *(sys_call_table + __NR_ioctl) = (unsigned long)real_ioctl;
      make_ro((unsigned long)sys_call_table);
   }
   if(whitelist_size > 0)
   {
       int i;
       for(i = 0; i < whitelist_size; i++)
       {
          kfree(whitelist[i]);
       }
   }
   printk(KERN_WARNING "[HDFW] HDFW: Unloaded\n");
   return;
}


/* Pointer to the real ioctl function */
asmlinkage int (*real_ioctl)(int , int , void *);

/*
 * Our ioctl replacement
 * Most of the time just passes through the requests to the real ioctl function.
 * Intercepts, and blocks non-defined ata commands, unless the requesting executable is whitelisted.
 */
asmlinkage int custom_ioctl(int fd, int request, void* arg)
{
   int suspicious = 0;
   sg_io_hdr_t* io_hdr;
   unsigned char* cdb;
   unsigned int command = 0x9999;
   struct hdio_taskfile* taskfile;
   if(request == SG_IO) //transfer data to device
   {
         suspicious = 1;
         io_hdr  = (sg_io_hdr_t*) arg;
         cdb = io_hdr->cmdp;
         if(cdb == NULL)
         {
            //invalid command, cdb should not be null.
            suspicious = 0;
         }
         else if(cdb[0] == SG_ATA_12)
         {
            command = cdb[9];
         }
         else if(cdb[0] == SG_ATA_16)
         {
            command = cdb[14];
         }
         else
         {
            int scsi_cdb_code = cdb[0];
            printk(KERN_WARNING "[HDFW] Non-ATA 12 or 16 command, SCSI CDB command: %s [0x%X]\n", CDB_OPCODE[scsi_cdb_code], scsi_cdb_code);
            suspicious = 0; //dangerous assumption
         }

   }

   if(suspicious == 1)
   {
      int level = 9999, i;
      for(i = 0; i < ATA_DEFINED_SIZE; i++)
      {
         if(command == ATA_DEFINED[i])
         {
            level = 0;
            continue;
         }
      }
      if(level > 0)
      {
         int whitelisted = -1;
         int requestingpid = current->pid;
         char * exename = "";
         exename = current_exename(exename);
         whitelisted = check_whitelist(exename);
         if(whitelisted != 0)
         {
            printk(KERN_CRIT "[HDFW] Intercepted: ioctl(%d, 0x%X) from PID %d, exe: %s\n", fd, request, requestingpid, exename);
            printk(KERN_CRIT "[HDFW] Blocked non-defined command: 0x%X\n", command);
            send_sig(SIGKILL, current, true);
            return EINVAL;
         }
         else
         {
            printk(KERN_WARNING "[HDFW] Whitelist match, skipping\n");
         }
      }
   }

   return real_ioctl(fd, request, arg);
}

/* Get the name of the executable name from the current struct */
char* current_exename(char *p)
{
   char *pathname;
   struct mm_struct* mm = current->mm;
   if (mm)
   {
      down_read(&mm->mmap_sem); //Enter critical section for the mm
      if (mm->exe_file)
      {
         pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
         if (pathname)
         {
            p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
         }
         kfree(pathname);
      }
      up_read(&mm->mmap_sem);
   }
   return p;
}

/* Print the entire whitelist to stdout */
void list_whitelist(void)
{
   int i;
   printk(KERN_WARNING "[HDFW] Whitelist:");
   for(i = 0; i < whitelist_size; i++)
   {
      printk(KERN_WARNING "[HDFW]  - %s\n", whitelist[i]);
   }
}

/* Check for the occurence of "name" in our whitelist
 * returns 0 if this is the case. */
int check_whitelist(char * name)
{
   int i, retval = -1;
   for(i = 0; i < whitelist_size; i++)
   {
      if(strcmp(name, whitelist[i]) == 0)
      {
         retval = 0;
         break;
      }
   }
   return retval;
}

/* hook module insertion and removal */
module_init(vslog_init);
module_exit(vslog_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jan Laan, Niels van Dijkhuizen");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Kernel module to log and possibly block suspicious (vendor specific) commands to hard drives using the SG_IO or HDIO_DRIVE_TASKFILE ioctl");
