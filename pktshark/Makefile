obj-m += pktshark.o
pktshark-y := main.o jprobe.o netlink.o  
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean