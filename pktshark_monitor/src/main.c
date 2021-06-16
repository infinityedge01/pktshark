/*
 * Copyright (C) 2009, Neil Horman <nhorman@redhat.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Opens our netlink socket.  Returns the socket descriptor or < 0 on error
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <asm/types.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "netlink.h"
/*
 * This is just in place until the kernel changes get committed 
 */

struct netlink_message {
	void *msg;
	struct nl_msg *nlbuf;
	int refcnt;
	LIST_ENTRY(netlink_message) ack_list_element;
	int seq;
	void (*ack_cb)(struct netlink_message *amsg, struct netlink_message *msg, int err);
};

LIST_HEAD(ack_list, netlink_message);
struct ack_list ack_list_head = {NULL};
void handle_pktshark_alert_msg(struct netlink_message *msg, int err);
void handle_pktshark_start_msg(struct netlink_message *amsg, struct netlink_message *msg, int err);
void handle_pktshark_stop_msg(struct netlink_message *amsg, struct netlink_message *msg, int err);
int disable_pktshark_monitor();

static void(*type_cb[_NET_PKTSHARK_CMD_MAX])(struct netlink_message *, int err) = {
	NULL,
	handle_pktshark_alert_msg,
	NULL,
	NULL,
	NULL,
	NULL,
};

static struct nl_sock *nsd;
static int nsf;
static FILE * fp;
enum {
	STATE_IDLE = 0,
	STATE_ACTIVATING,
	STATE_RECEIVING,
	STATE_RQST_DEACTIVATE,
	STATE_RQST_ACTIVATE,
	STATE_DEACTIVATING,
	STATE_FAILED,
	STATE_EXIT,
};

static int state = STATE_IDLE;

int strtobool(const char *str, bool *p_val){
	bool val;
	if (!strcmp(str, "true") || !strcmp(str, "1"))
		val = true;
	else if (!strcmp(str, "false") || !strcmp(str, "0"))
		val = false;
	else
		return -EINVAL;
	*p_val = val;
	return 0;
}

void sigint_handler(int signum){
	if ((state == STATE_RECEIVING) ||
	   (state == STATE_RQST_DEACTIVATE)) {
		disable_pktshark_monitor();
		state = STATE_DEACTIVATING;
	} else {
		printf("Got a sigint while not receiving\n");
	}
	return;
}

struct nl_sock *setup_netlink_socket(){
	struct nl_sock *sd;
	int family;
	sd = nl_socket_alloc();
	genl_connect(sd);
	family = genl_ctrl_resolve(sd, "NET_PKTSHARK");
	if (family < 0) {
		printf("Unable to find NET_PKTSHARK family, dropwatch can't work\n");
		goto out_close;
	}
	nsf = family;
	nl_close(sd);
	nl_socket_free(sd);
	sd = nl_socket_alloc();
	genl_connect(sd);
	nl_socket_add_memberships(sd, NET_PKTSHARK_GRP_ALERT, 0);
	//nl_connect(sd, NETLINK_GENERIC);
	return sd;
out_close:
	nl_close(sd);
	nl_socket_free(sd);
	return NULL;
}

struct netlink_message *alloc_netlink_msg(uint32_t type, uint16_t flags, size_t size)
{
	struct netlink_message *msg;
	static uint32_t seq = 0;

	msg = (struct netlink_message *)malloc(sizeof(struct netlink_message));

	if (!msg)
		return NULL;

	msg->refcnt = 1;
	msg->nlbuf = nlmsg_alloc();
	msg->msg = genlmsg_put(msg->nlbuf, 0, seq, nsf, size, flags, type, 1);

	msg->ack_cb = NULL;
	msg->seq = seq++;

	return msg;
}

void set_ack_cb(struct netlink_message *msg,
			void (*cb)(struct netlink_message *, struct netlink_message *, int))
{
	if (msg->ack_cb)
		return;

	msg->ack_cb = cb;
	msg->refcnt++;
	LIST_INSERT_HEAD(&ack_list_head, msg, ack_list_element);
}

struct netlink_message *wrap_netlink_msg(struct nlmsghdr *buf)
{
	struct netlink_message *msg;

	msg = (struct netlink_message *)malloc(sizeof(struct netlink_message));
	if (msg) {
		msg->refcnt = 1;
		msg->msg = buf;
		msg->nlbuf = NULL;
	}

	return msg;
}

int free_netlink_msg(struct netlink_message *msg)
{
	int refcnt;

	msg->refcnt--;

	refcnt = msg->refcnt;

	if (!refcnt) {
		if (msg->nlbuf)
			nlmsg_free(msg->nlbuf);
		else
			free(msg->msg);
		free(msg);
	}

	return refcnt;
}

int send_netlink_message(struct netlink_message *msg)
{
	return nl_send(nsd, msg->nlbuf);
}

struct netlink_message *recv_netlink_message(int *err)
{
	static struct nlmsghdr *buf;
	struct netlink_message *msg;
	struct genlmsghdr *glm;
	struct sockaddr_nl nla;
	int type;
	int rc;

	*err = 0;

	do {
		rc = nl_recv(nsd, &nla, (unsigned char **)&buf, NULL);
		if (rc < 0) {
			switch (errno) {
			case EINTR:
				/*
				 * Take a pass through the state loop
				 */
				return NULL;
				break;
			default:
				perror("Receive operation failed:");
				return NULL;
				break;
			}
		}
	} while (rc == 0);

	msg = wrap_netlink_msg(buf);

	type = ((struct nlmsghdr *)msg->msg)->nlmsg_type;

	/*
	 * Note the NLMSG_ERROR is overloaded
	 * Its also used to deliver ACKs
	 */
	if (type == NLMSG_ERROR) {
		struct netlink_message *am;
		struct nlmsgerr *errm = nlmsg_data(msg->msg);
		LIST_FOREACH(am, &ack_list_head, ack_list_element) {
			if (am->seq == errm->msg.nlmsg_seq)
				break;
		}

		if (am) {
			LIST_REMOVE(am, ack_list_element);
			am->ack_cb(msg, am, errm->error);
			free_netlink_msg(am);
		} else {
			printf("Got an unexpected ack for sequence %d\n", errm->msg.nlmsg_seq);
		}

		free_netlink_msg(msg);
		return NULL;
	}

	glm = nlmsg_data(msg->msg);
	type = glm->cmd;
	printf("%d\n", type);
	if ((type > _NET_PKTSHARK_CMD_MAX) ||
	    (type <= NET_PKTSHARK_CMD_UNSPEC)) {
		printf("Received message of unknown type %d\n",
			type);
		free_netlink_msg(msg);
		return NULL;
	}

	return msg;
}

void process_rx_message(void){
	struct netlink_message *msg;
	int err;
	int type;
	sigset_t bs;
	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);
	msg = recv_netlink_message(&err);
	sigprocmask(SIG_BLOCK, &bs, NULL);
	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct genlmsghdr *glh = nlmsg_data(nlh);
		type = glh->cmd;
		type_cb[type](msg, err);
	}
	return;
}

/*
 * These are the received message handlers
 */
void handle_pktshark_alert_msg(struct netlink_message *msg, int err){
	int i;
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct pktshark_alert_msg *alert = nla_data(genlmsg_data(glh));
	if (state != STATE_RECEIVING)
		goto out_free;
	for (i=0; i < alert->entries; i++) {
		printf("skb %08x at tracepoint %d at time %lld\n", alert->points[i].skb_tag, alert->points[i].tracepoint_id, alert->points[i].curtime);
	}
out_free:
	free_netlink_msg(msg);
}


void handle_pktshark_start_msg(struct netlink_message *amsg, struct netlink_message *msg, int err){
	if (err != 0) {
		char *erm = strerror(err*-1);
		printf("Failed activation request, error: %s\n", erm);
		state = STATE_FAILED;
		goto out;
	}

	if (state == STATE_ACTIVATING) {
		struct sigaction act;
		memset(&act, 0, sizeof(struct sigaction));
		act.sa_handler = sigint_handler;
		act.sa_flags = SA_RESETHAND;
		printf("Kernel monitoring activated.\n");
		printf("Issue Ctrl-C to stop monitoring\n");
		sigaction(SIGINT, &act, NULL);

		state = STATE_RECEIVING;
	} else {
		printf("Odd, the kernel told us that it activated and we didn't ask\n");
		state = STATE_FAILED;
	}
out:
	return;
}

void handle_pktshark_stop_msg(struct netlink_message *amsg, struct netlink_message *msg, int err){
	char *erm;
	if ((err == 0) || (err == -EAGAIN)) {
		printf("Got a stop message\n");
		state = STATE_EXIT;
	} else {
		erm = strerror(err*-1);
		printf("Stop request failed, error: %s\n", erm);
	}
}

int enable_pktshark_monitor(){
	struct netlink_message *msg;
	msg = alloc_netlink_msg(NET_PKTSHARK_CMD_START, NLM_F_REQUEST|NLM_F_ACK, 1);
	set_ack_cb(msg, handle_pktshark_start_msg);
	return send_netlink_message(msg);
	free_netlink_msg(msg);
	return -EMSGSIZE;
}


int disable_pktshark_monitor(){
	struct netlink_message *msg;
	msg = alloc_netlink_msg(NET_PKTSHARK_CMD_STOP, NLM_F_REQUEST|NLM_F_ACK, 0);
	set_ack_cb(msg, handle_pktshark_stop_msg);
	return send_netlink_message(msg);
	free_netlink_msg(msg);
	return -EMSGSIZE;
}


void enter_state_loop(void){
	int should_rx = 0;
	state = STATE_RQST_ACTIVATE;
	while (1) {
		switch(state) {
		case STATE_IDLE:
			should_rx = 0;
			state = STATE_EXIT;
			break;
		case STATE_RQST_ACTIVATE:
			printf("Enabling monitoring...\n");
			if (enable_pktshark_monitor() < 0) {
				perror("Unable to send activation msg:");
				state = STATE_FAILED;
			} else {
				state = STATE_ACTIVATING;
				should_rx = 1;
			}
			break;
		case STATE_ACTIVATING:
			printf("Waiting for activation ack....\n");
			break;
		case STATE_RECEIVING:
			printf("Waiting for activation ack....\n");
			break;
		case STATE_RQST_DEACTIVATE:
			printf("Deactivation requested, turning off monitoring\n");
			if (disable_pktshark_monitor() < 0) {
				perror("Unable to send deactivation msg:");
				state = STATE_FAILED;
			} else
				state = STATE_DEACTIVATING;
			should_rx = 1;
			break;
		case STATE_DEACTIVATING:
			printf("Waiting for deactivation ack...\n");
			break;
		case STATE_EXIT:
		case STATE_FAILED:
			should_rx = 0;
			return;
		default:
			printf("Unknown state received!  exiting!\n");
			state = STATE_FAILED;
			should_rx = 0;
			break;
		}
		/*
		 * After we process our state loop, look to see if we have messages
		 */
		if (should_rx)
			process_rx_message();
	}
}

int main (int argc, char **argv){
	nsd = setup_netlink_socket();
	if (nsd == NULL) {
		printf("Cleaning up on socket creation error\n");
		goto out;
	}
	fp = fopen("out.trace", "w");
	enter_state_loop();
	printf("Shutting down ...\n");
	nl_close(nsd);
	fclose(fp);
	exit(0);
out:
	exit(1);
}
