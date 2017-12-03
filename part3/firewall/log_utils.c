#include "log_utils.h"

/**
 *	Updates:
 * 			1. *ptr_pckt_lg_info fields to contain the packet information
 * 			2. *ack to contain the packets ack value (ACK_ANY if not TCP)
 * 			3. *direction to contain the packets direction
 * 
 *	@skb - the packet
 *	@ptr_pckt_lg_info - a pointer to log_row_t to be initiated
 *	@hooknumber - as received from netfilter hook
 *	@ack - a pointer to ack_t to be updated
 *	@direction - a pointer to direction_t to be updated
 *	@in - pointer to net_device representing the network inteface
 * 		  the packet pass through. NULL if packet traversal is "out".
 *	@out - pointer to net_device representing the network inteface
 * 		  the packet pass through. NULL if packet traversal is "in".
 * 
 * 	Note: fields: action, reason, count are only initiallized to default!
 *
 *	Returns true on success, false if an error happened (skb==NULL)
 **/
bool init_log_row(struct sk_buff* skb, log_row_t* ptr_pckt_lg_info,
		unsigned char hooknumber, ack_t* ack, direction_t* direction,
		const struct net_device* in, const struct net_device* out){
	
	struct iphdr* ptr_ipv4_hdr;		//pointer to ipv4 header
	struct tcphdr* ptr_tcp_hdr;		//pointer to tcp header
	struct udphdr* ptr_udp_hdr;		//pointer to udp header
	__u8 ip_h_protocol = 0;
	__be16 temp_port_num;
	struct timespec ts = { .tv_sec = 0,.tv_nsec = 0};
	getnstimeofday(&ts);
    
    ptr_pckt_lg_info->timestamp = ts.tv_sec;
	ptr_pckt_lg_info->hooknum = hooknumber;
	
	//Default values:
	ptr_pckt_lg_info->count = 1;
	ptr_pckt_lg_info->action = RULE_NOT_RELEVANT;
	ptr_pckt_lg_info->reason = NO_REASON;
	ptr_pckt_lg_info->src_port = 0;
	ptr_pckt_lg_info->dst_port = 0;
	*ack = ACK_NO; //Default since if it isn't a tcp packet, there's no ack
	*direction = DIRECTION_ANY;
	
	if (skb) {
		ptr_ipv4_hdr = ip_hdr(skb);
		if(ptr_ipv4_hdr){
			
			ptr_pckt_lg_info->src_ip = ntohl(ptr_ipv4_hdr->saddr);
			ptr_pckt_lg_info->dst_ip = ntohl(ptr_ipv4_hdr->daddr);
			
			//Network order. convertion done in 2 stages since there's a casting from ushort to uchar:
			ip_h_protocol = ptr_ipv4_hdr->protocol; 
			//Convert to local-endianness:
			ip_h_protocol = ntohs(ip_h_protocol);
			
			switch (ip_h_protocol){
				case (PROT_ICMP):
				case (PROT_TCP):		
				case (PROT_UDP):
				case (PROT_ANY):
					ptr_pckt_lg_info->protocol = ip_h_protocol;
					break;
				default: //PROT_OTHER
					ptr_pckt_lg_info->protocol = PROT_OTHER;
			}
			
			if (ip_h_protocol == PROT_TCP){
				ptr_tcp_hdr = (struct tcphdr*)((char*)ptr_ipv4_hdr + (ptr_ipv4_hdr->ihl * 4));
				temp_port_num = ptr_tcp_hdr->source;
				ptr_pckt_lg_info->src_port = ntohs(temp_port_num); //Convert to local-endianness
				temp_port_num = ptr_tcp_hdr->dest;
				ptr_pckt_lg_info->dst_port = ntohs(temp_port_num); //Convert to local-endianness
				*ack = ((ptr_tcp_hdr->ack) == 1) ? ACK_YES : ACK_NO; //Updates *ack
				
			} else if (ip_h_protocol == PROT_UDP) {
				ptr_udp_hdr = (struct udphdr*)((char*)ptr_ipv4_hdr + (ptr_ipv4_hdr->ihl * 4));
				temp_port_num = ptr_udp_hdr->source;
				ptr_pckt_lg_info->src_port = ntohs(temp_port_num); //Convert to local-endianness
				temp_port_num = ptr_udp_hdr->dest;
				ptr_pckt_lg_info->dst_port = ntohs(temp_port_num); //Convert to local-endianness
			}
			//TODO:: take care of direction!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			return true;
		}
		
	} 
	
	printk(KERN_ERR "In init_log_row, skb or ptr_ipv4_hdr is NULL\n"); 
	return false;
	
}
