# pktshark

A simple kernel module for skb trace analysis (and a user mode program to receive the data).

It is just a prototype.

### Usage

1. Build a `linux-4.14.170`  kernel, overwrite the source code  `skbuff.h` to `/usr/src/linux-4.14.170/include/linux/skbuff.h` and  `skbuff.c` to `/usr/src/linux-4.14.170/net/core/skbuff.c` .

2. Rebuild the kernel.

3. Compile the kernel module `pktshark`.

	```bash
	cd pktshark
	make
	```

	Then you can get a kernel module called `pktshark.ko`.

4. Install the kernel module `pktshark.ko`:

	```bash
	insmod pktshark.ko
	```

	You can use command `dmesg | tail` to show the kernel module is installed and running.

5. Build the user mode program pktshark-monitor. This program is modified from https://github.com/nhorman/dropwatch. You should install the dependencies of `dropwatch` and use autotools to build (same to `dropwatch`):

	```bash
	cd pktshark_monitor
	./autogen.sh
	./configure
	make
	```

	Then you get a executable file in `/pktshark_monitor/src`. 

6. Run it.

### More To do

This module is just a prototype hooking only 3 easy-to-hook function `ip_do_fragment`, `ip_output`, `ip_send_skb` to test its basic functionalities by using `jprobe`.

To trace more functions, you should build the module into the kernel and manually add the `pktshark_tracepoint` into the kernel code.

