#include <linux/module.h>
#include <linux/kernel.h>

#include "jprobe.h"
#include "netlink.h"
static int pktshark_init(void){
	if (init_pkrshark_netlink()){
		return -1;
	}
	if (!jprobe_init()){
	 	printk(KERN_INFO "pktshark: started\n");
	}else return -1;
	 return 0;
}

static void pktshark_exit(void){
	jprobe_exit();
	exit_pkrshark_netlink();
	printk(KERN_INFO "pktshark: stopped\n");
}

module_init(pktshark_init);
module_exit(pktshark_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("infinityedge");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("pktshark");
