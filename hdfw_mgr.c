/*
 * HDFW: Loadable Linux kernel module for monitoring and blocking suspicious ha$
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
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Define ioctl commands */
#define IOCTL_PATCH_TABLE       0x00000001
#define IOCTL_FIX_TABLE         0x00000004
#define IOCTL_WHITELIST_ADD     0x00030300
#define IOCTL_WHITELIST_LIST    0x00001234
#define IOCTL_WHITELIST_REMOVE  0x34324342

/* Performs management functions for our firmware monitor. Supported:

- [on], enables the monitor
- [off], disables the monitor,
- [<number>], enables the monitor for the specified number of seconds, then disables it
- [wl.add <exe>], adds the specified executable to the whitelist
- [wl.del <exe>], remove the executable from the whitelist
- [wl.list], show the entire whitelist
*/
int main(int argc, char* argv[])
{

   if(geteuid() != 0)
   {
      printf("This program must be ran as root\n");
      return -1;
   }
   if(argc == 1 || argc > 3)
   {
      printf("Error, only 1 argument supported.\n");
      return 1;
   }

   printf("hdfw_mgr: %s\n", argv[1]);
   if(!strcmp(argv[1],"on"))
   {
      int device = open("/dev/hdfw_mgmt", O_RDWR);
      ioctl(device, IOCTL_PATCH_TABLE);
      close(device);
      printf("Manager enabled, don't forget to turn it off again.\n");
      return 0;
   }
   else if(!strcmp(argv[1], "off"))
   {
      int device = open("/dev/hdfw_mgmt", O_RDWR);
      ioctl(device, IOCTL_FIX_TABLE);
      close(device);
      printf("Manager shut off.\n");
      return 0;
   }
   else if(!strcmp(argv[1], "wl.add") && argc == 3)
   {
      int device = open("/dev/hdfw_mgmt", O_RDWR);
      ioctl(device, IOCTL_WHITELIST_ADD, argv[2]);
      close(device);
      printf("Added to Whitelist: %s\n", argv[2]);
   }
   else if(!strcmp(argv[1], "wl.del") && argc == 3)
   {
      int device = open("/dev/hdfw_mgmt", O_RDWR);
      ioctl(device, IOCTL_WHITELIST_REMOVE, argv[2]);
      close(device);
      printf("Removed from Whitelist: %s\n", argv[2]);
   }

   else if(!strcmp(argv[1], "wl.list"))
   {
      int device = open("/dev/hdfw_mgmt", O_RDWR);
      ioctl(device, IOCTL_WHITELIST_LIST);
      close(device);
      printf("See the proper logging for the listing.\n");
   }
   else
   {
      int time = atoi(argv[1]);
      if(time <= 0)
      {
         printf("Parameter should be either on, off or a time > 0.\n");
      }
      else {
      
         int device = open("/dev/hdfw_mgmt", O_RDWR);
         ioctl(device, IOCTL_PATCH_TABLE);
         sleep(time);
         ioctl(device, IOCTL_FIX_TABLE);
         close(device);
      }
   }
   return 0;
}
