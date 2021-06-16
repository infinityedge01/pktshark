#include <linux/ktime.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <net/genetlink.h>
#include "netlink.h"
#include "jprobe.h"

static int max_send_size = 256;
static int tracing = 0;
struct send_data {
	spinlock_t		lock;
	struct sk_buff		*skb;
}pktshark_data;

static const struct genl_multicast_group pktshark_mcgrps[] = {
	{ .name = "notify", },
};

static int cmd_trace(struct sk_buff *skb, struct genl_info *info){
	if(info->genlhdr->cmd == NET_PKTSHARK_CMD_START){
		tracing = 1;	
	}else{
		tracing = 0;
	}
	return 0;
}

static const struct genl_ops pktshark_ops[] = {
	{
		.cmd = NET_PKTSHARK_CMD_START,
		.doit = cmd_trace,
	},
	{
		.cmd = NET_PKTSHARK_CMD_STOP,
		.doit = cmd_trace,
	},
};

static struct genl_family net_pktshark_family __ro_after_init = {
	.hdrsize        = 0,
	.name           = "NET_PKTSHARK",
	.version        = 2,
	.module		= THIS_MODULE,
	.ops		= pktshark_ops,
	.n_ops		= ARRAY_SIZE(pktshark_ops),
	.mcgrps		= pktshark_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(pktshark_mcgrps),
};



static struct sk_buff *reset_skb(struct send_data *data){
	size_t al;
	struct pktshark_alert_msg *msg;
	struct nlattr *nla;
	struct sk_buff *skb;
	void *msg_header;

	al = sizeof(struct pktshark_alert_msg);
	al += max_send_size * sizeof(struct pktshark_tracepoint_info);
	al += sizeof(struct nlattr);

	skb = genlmsg_new(al, GFP_KERNEL);

	if (!skb) goto err;

	msg_header = genlmsg_put(skb, 0, 0, &net_pktshark_family, 0, NET_PKTSHARK_CMD_ALERT);
	if (!msg_header) {
		nlmsg_free(skb);
		skb = NULL;
		goto err;
	}
	nla = nla_reserve(skb, NLA_UNSPEC, sizeof(struct pktshark_alert_msg));
	if (!nla) {
		nlmsg_free(skb);
		skb = NULL;
		goto err;
	}
	msg = nla_data(nla);
	memset(msg, 0, al);
err:
	swap(data->skb, skb);
	if (skb) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
		struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlh);
		genlmsg_end(skb, genlmsg_data(gnlh));
	}
	return skb;
}


static void send_pktshark_alert(void){
	struct sk_buff *skb;
	skb = reset_skb(&pktshark_data);
	if (skb){
		genlmsg_multicast(&net_pktshark_family, skb, 0,
				  0, GFP_KERNEL);
		printk(KERN_INFO "sended data pack\n");
	}
}

void pktshark_tracepoint(struct sk_buff *skb, __u8 tpid){
	struct pktshark_tracepoint_info tp;
	struct pktshark_alert_msg *msg;
	struct nlmsghdr *nlh;
	struct nlattr *nla;
	struct sk_buff *dskb;
	if(!tracing) return;
	if(!skb) return;
    if(!skb->skb_tag) return;
    tp.skb_tag = skb->skb_tag;
	tp.tracepoint_id = tpid;
    tp.curtime = ktime_get();
	//printk(KERN_INFO "traced skb %x at time %lld in tracepoint_id %d\n", tp.skb_tag, tp.curtime, (int)(tp.tracepoint_id));
	spin_lock(&pktshark_data.lock);
	dskb = pktshark_data.skb;
	if (!dskb)
		goto out;
	nlh = (struct nlmsghdr *)dskb->data;
	nla = genlmsg_data(nlmsg_data(nlh));
	msg = nla_data(nla);
	if(msg->entries == max_send_size) goto send_out;
	/*
	 * We need to create a new entry
	 */
	__nla_reserve_nohdr(dskb, sizeof(struct pktshark_tracepoint_info));
	nla->nla_len += NLA_ALIGN(sizeof(struct pktshark_tracepoint_info));
	
	memcpy(&(msg->points[msg->entries]), &tp, sizeof(struct pktshark_tracepoint_info));
	msg->entries++;
	//printk(KERN_INFO "current msg_entries %d\n", msg->entries);
send_out:
	if(msg->entries == max_send_size) send_pktshark_alert();
out:
	spin_unlock(&pktshark_data.lock);
}	

int init_pkrshark_netlink(void){
    int rc;
	printk(KERN_INFO "genl_register_family\n");
	rc = genl_register_family(&net_pktshark_family);
	if (rc) {
		pr_err("Could not create pktshark netlink family\n");
		return rc;
	}
	
	printk(KERN_INFO "genl_register_family successfully %d %d\n", net_pktshark_family.mcgrp_offset, NET_PKTSHARK_GRP_ALERT);
    WARN_ON(net_pktshark_family.mcgrp_offset != NET_PKTSHARK_GRP_ALERT);
	spin_lock_init(&pktshark_data.lock);
	printk(KERN_INFO "spin_lock init successfully\n");
	reset_skb(&pktshark_data);
    return 0;
}

void exit_pkrshark_netlink(void){
	unsigned long flags;	
	local_irq_save(flags);
	spin_lock(&pktshark_data.lock);
	send_pktshark_alert();
	spin_unlock_irqrestore(&pktshark_data.lock, flags);
    BUG_ON(genl_unregister_family(&net_pktshark_family));
}