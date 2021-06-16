#include <linux/ktime.h>
#include <linux/kprobes.h>
#include <net/pkt_sched.h>
#include <net/ip.h>
#include "jprobe.h"
#include "netlink.h"
static int jprobe_ip_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		   int (*output)(struct net *, struct sock *, struct sk_buff *)){
    pktshark_tracepoint(skb, 1);
    jprobe_return();
    return 0;
}

static int jprobe_ip_output(struct net *net, struct sock *sk, struct sk_buff *skb){
    pktshark_tracepoint(skb, 2);
    jprobe_return();
    return 0;
}

static int jprobe_ip_send_skb(struct net *net, struct sk_buff *skb){
    pktshark_tracepoint(skb, 3);
    jprobe_return();
    return 0;
}

static struct jprobe trace_ip_do_fragment = {
    .kp = { .symbol_name = "ip_do_fragment",},
    .entry = jprobe_ip_do_fragment,
};
static struct jprobe trace_ip_output = {
    .kp = { .symbol_name = "ip_output",},
    .entry = jprobe_ip_output,
};
static struct jprobe trace_ip_send_skb = {
    .kp = { .symbol_name = "ip_send_skb",},
    .entry = jprobe_ip_send_skb,
};
int jprobe_init(void){
    trace_ip_do_fragment.kp.symbol_name = "ip_do_fragment";
    trace_ip_do_fragment.entry = jprobe_ip_do_fragment;
    trace_ip_output.kp.symbol_name = "ip_output";
    trace_ip_output.entry = jprobe_ip_output;
    trace_ip_send_skb.kp.symbol_name = "ip_send_skb";
    trace_ip_send_skb.entry = jprobe_ip_send_skb;
    //Register jprobe hook
    BUILD_BUG_ON(__same_type(ip_do_fragment, jprobe_ip_do_fragment) == 0);
    if (register_jprobe(&trace_ip_do_fragment)){
        printk(KERN_INFO "Cannot register the jprobe hook for ip_do_fragment\n");
        return -1;
    }
    BUILD_BUG_ON(__same_type(ip_output, jprobe_ip_output) == 0);
    if (register_jprobe(&trace_ip_output)){
        printk(KERN_INFO "Cannot register the jprobe hook for ip_output\n");
        return -1;
    }
    BUILD_BUG_ON(__same_type(ip_send_skb, jprobe_ip_send_skb) == 0);
    if (register_jprobe(&trace_ip_send_skb)){
        printk(KERN_INFO "Cannot register the jprobe hook for ip_send_skb\n");
        return -1;
    }
    printk(KERN_INFO "Register jprobe hooks successfully.\n");
    return 0;
}

void jprobe_exit(void){
    unregister_jprobe(&trace_ip_do_fragment);
    unregister_jprobe(&trace_ip_output);
    unregister_jprobe(&trace_ip_send_skb);
    printk(KERN_INFO "Unregister jprobe hooks successfully.\n");
}
