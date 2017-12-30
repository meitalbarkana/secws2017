#include "fw.h"


/**
 *	Returns the direction of the packet,
 *	by comparing the interfaces' names
 * 
 *	@in
 *  @out
 *	are two pointers to the net_device structure,
 *  which are what Linux kernel uses to describe network interface,
 *  as defined in /lib/modules/$(uname -r)/build/include/linux/netdevice.h.
 *  In the hook function, describes the network interface the packet pass through.
 *  Therefore, depending on the packets traversal, either in or out will be NULL.
 * (from: http://www.roman10.net/2011/07/23/how-to-filter-network-packets-using-netfilterpart-2-implement-the-hook-function/)
 **/
direction_t get_direction(const struct net_device* in, const struct net_device* out){
	
	if (in){ //"in" isn't NULL
		if (strcmp(in->name, IN_NET_DEVICE_NAME) == 0){ //Packets' origin is eth1
			return DIRECTION_OUT;
		} else if (strcmp(in->name, OUT_NET_DEVICE_NAME) == 0) { //Packets' origin is eth2
			return DIRECTION_IN;
		}
		return DIRECTION_ANY;
	} else if (out){
		if (strcmp(out->name, IN_NET_DEVICE_NAME) == 0){ //Packets' dest is eth1
			return DIRECTION_IN;
		} else if (strcmp(out->name, OUT_NET_DEVICE_NAME) == 0) { //Packets' dest is eth2
			return DIRECTION_OUT;
		}
		return DIRECTION_ANY;
	}
	
	printk(KERN_ERR "get_direction fuction got NULL arguments\n");
	return DIRECTION_ANY;
}

/**
 *	Gets a TCP header,
 *	Returns the type of that TCP packet
 *	[values from tcp_packet_t]
 * 
 **/
tcp_packet_t get_tcp_packet_type(struct tcphdr* tcp_hdr){
	
	if (tcp_hdr == NULL) {
		printk(KERN_ERR "In function get_tcp_packet_type(), function got NULL argument.\n");
		return TCP_ERROR_PACKET;
	}
	
	//Note: no URG check, since (I think) it might be used
	
	if (tcp_hdr->ack == 0) {
		if ((tcp_hdr->syn == 1) &&
			(tcp_hdr->fin == 0) &&
			(tcp_hdr->rst == 0) &&
			(tcp_hdr->psh == 0) ) 
		{
			return TCP_SYN_PACKET;
		} 
		//Only (the first) SYN packet has ack==0
		printk(KERN_INFO "In function get_tcp_packet_type(), TCP packet has invalid flags (ack is 0).\n");
		return TCP_INVALID_PACKET;
	}
	
	//If gets here, ptr_tcp_hdr->ack == 1:

	if (tcp_hdr->syn == 1) {
		if ((tcp_hdr->fin == 0) &&
			(tcp_hdr->rst == 0) &&
			(tcp_hdr->psh == 0)) 
		{
			return TCP_SYN_ACK_PACKET;
		}
		//Only SYN-ACK packets have ack==1 & syn==1 
		printk(KERN_INFO "In function get_tcp_packet_type(), TCP packet has invalid flags (ack&syn are 1).\n");
		return TCP_INVALID_PACKET;
	}
	
	if (tcp_hdr->fin == 1) {
		return TCP_FIN_PACKET;
	}
	
	if (tcp_hdr->rst == 1) {
		return TCP_RESET_PACKET;
	}
	
	return TCP_OTHER_PACKET;
}

