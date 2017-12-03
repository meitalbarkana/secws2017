#include "hook_utils.h"

/**
 *	This function would be called as a helper function,
 *  when hooknum is NF_INET_FORWARD, for IPv4 packets
 *
 *	@skb - contains all of packet's data
 *	@in - pointer to net_device representing the network inteface
 * 		  the packet pass through. NULL if packet traversal is "out".
 *	@out - pointer to net_device representing the network inteface
 * 		  the packet pass through. NULL if packet traversal is "in".
 * 
 *	Returns: NF_ACCEPT/NF_DROP according to packet data & firewall's status
 **/
static unsigned int check_packet_hookp_forward(struct sk_buff* skb, 
		const struct net_device* in, const struct net_device* out)
{
	//create & initiate: ptr_pckt_lg_info, packet_ack , packet_direction
	//call function decide_packet_action
	return 0;
}
