#This is the list of modules that the kernel building system needs to build
obj-m := hdfw.o
#Kernel building system (include files mostly)
KDIR := /lib/modules/`uname -r`/build
PWD := `pwd`
RMMOD := `/sbin/rmmod`

default:
	make -C $(KDIR) M=$(PWD) modules
	gcc -o hdfw_mgr hdfw_mgr.c

clean:
	rm -f hdfw.mod.c hdfw.ko hdfw_mgr modules.order Module.symvers *.o
