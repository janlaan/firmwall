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

/* IOCTL commands */
#define IOCTL_PATCH_TABLE      0x00000001
#define IOCTL_FIX_TABLE        0x00000004
#define IOCTL_WHITELIST_ADD    0x00030300
#define IOCTL_WHITELIST_REMOVE 0x34324342
#define IOCTL_WHITELIST_LIST   0x00001234

/* misc defines */
#define WHITELIST_SIZE 20
#define SG_ATA_12  0xa1
#define SG_ATA_16  0x85

/* functions */
static int our_open(struct inode *inode, struct file *file);
static int our_release(struct inode *inode, struct file *file);
static int our_ioctl(struct file *file, unsigned int cmd, char* arg);
static int __init vslog_init(void);
int make_rw(unsigned long address);
int make_ro(unsigned long address);
static void __exit vslog_cleanup(void);
asmlinkage int (*real_ioctl)(int , int , void *);
asmlinkage int custom_ioctl(int fd, int request, void* arg);
char* current_exename(char*);
void list_whitelist(void);
int check_whitelist(char*);

/* misc. */
int ATA_DEFINED_SIZE = 59;
int ATA_DEFINED[] = {0x00, 0x08, 0x24,0x25,0x26,0x27,0x29,0x2f,0x34,0x35,0x36,0x37,0x38,0x39,0x3f,
   0x40,0x42,0x70,0x90,0x92,0xa0,0xa1,0xa2,0xb0,0xb1,0xc4,0xc5,0xc6,0xc7,0xc8,0xca,0xcc,0xcd,
   0xd0,0xd1,0xda,0xde,0xdf,0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xea,0xec,0xed,0xef,
   0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf8,0xf9};
char* CDB_OPCODE[] = {"test unit ready","rewind","unknown","request sense","format","read block limits","unknown","reassign blocks","read(6)","unknown","write(6)","seek(6)","unknown","unknown","unknown","read reverse(6)","write filemarks(6)","space(6)","inquiry","verify(6)","recover buffered data","mode select(6)","reserve(6)","release(6)","copy","erase (6)","mode sense (6)","start stop unit","receive diagnostic results","send diagnostic","prevent allow medium removal","unknown","unknown","unknown","unknown","read format capacities","unknown","read capacity(10)","unknown","unknown","read(10)","read generation","write(10)","seek(10)","erase(10)","read updated block","write and verify(10)","verify(10)","unknown","unknown","unknown","set limits(10)","pre-fetch(10)","synchronize cache(10)","lock unlock cache(10)","read defect data(10)","medium scan","compare","copy and verify","write buffer","read buffer","update block","read long(10)","write long(10)","change definition","write same(10)","unknown","read toc/pma/atip","report density support","play audio(10)","get configuration","play audio msf","sanitize","unknown","get event status notification","pause/resume","log select","log sense","unknown","unknown","xdwrite(10)","xpwrite(10)","xdread(10)","xdwriteread(10)","send opc information","mode select(10)","reserve(10)","release(10)","repair track","unknown","mode sense(10)","close track/session","read buffer capacity","send cue sheet","persistent reserve in","persistent reserve out","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","extended cdb","variable length cdb","xdwrite extended(16)","read reverse(16)","unknown","third-party copy out commands","third-party copy in commands","ata pass-through(16)","access control in","access control out","read(16)","compare and write","write(16)","orwrite","read attribute","write attribute","write and verify(16)","verify(16)","pre-fetch(16)","synchronize cache(16)","lock unlock cache(16)","write same(16)","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","service action bidirectional","service action in(16)","service action out(16)","report luns","ata pass-through(12)","security protocol in","maintenance in","maintenance out","move medium","exchange medium","move medium attached","read(12)","service action out(12)","write(12)","service action in(12)","erase(12)","read dvd structure","write and verify(12)","verify(12)","search data high(12)","search data equal(12)","search data low(12)","set limits(12)","read element status attached","security protocol out","send volume tag","read defect data(12)","read element status","read cd msf","redundancy group (in)","redundancy group (out)","spare (in)","spare (out)","volume set (in)","volume set (out)","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown"};
