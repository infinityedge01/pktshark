#ifndef __PKTSHARK_NETLINK_H
#define __PKTSHARK_NETLINK_H

#include <linux/types.h>
#include <linux/netlink.h>

struct pktshark_tracepoint_info {
	__u32 skb_tag;
    __u8 tracepoint_id;
    __u8 padding[3];
	__u64 curtime;
};

struct pktshark_alert_msg {
	__u32 entries;
	struct pktshark_tracepoint_info points[0];
};

enum {
	NET_PKTSHARK_CMD_UNSPEC = 0,
	NET_PKTSHARK_CMD_ALERT,
	NET_PKTSHARK_CMD_CONFIG,
	NET_PKTSHARK_CMD_START,
	NET_PKTSHARK_CMD_STOP,
	NET_PKTSHARK_CMD_PACKET_ALERT,
	_NET_PKTSHARK_CMD_MAX,
};

#define NET_PKTSHARK_GRP_ALERT 4
#endif
