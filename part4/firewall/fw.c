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
	
	printk(KERN_ERR "Function get_direction() got NULL arguments: both 'in' and 'out'.\n");
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


/**
 * 	Checks if a given IPv4 packet is XMAS packet.
 *	
 *	@skb - pointer to struct sk_buff that represents current packet
 *	
 *	Returns true if it represent a Christmas Tree Packet
 *	(TCP packet with PSH, URG, FIN flags on)
 * 
 *	struct iphdr->protocol values are from: 
 *	http://elixir.free-electrons.com/linux/latest/source/include/uapi/linux/in.h#L37
 *	here we're only interested in values that appear in enum prot_t. 
 **/
bool is_XMAS(struct sk_buff* skb){
	
	struct tcphdr* ptr_tcp_hdr = get_tcp_header(skb); //pointer to tcp header
	
	if (ptr_tcp_hdr){ //Means it's a TCP packet, ptr_tcp_hdr isn't NULL
		if ( (ptr_tcp_hdr->psh == 1) && (ptr_tcp_hdr->urg == 1)
			&& (ptr_tcp_hdr->fin == 1) ) 
		{
				return true;
		}
	}
	
	return false;
}

/**
 * 	Checks if a given IPv4 packet is a TCP packet,
 *  Returns: its tcp header if it is,
 * 			 NULL otherwise.
 *	
 *	@skb - pointer to struct sk_buff that represents current packet
 *
 **/
struct tcphdr* get_tcp_header(struct sk_buff* skb){
	
	struct iphdr* ptr_ipv4_hdr; //pointer to ipv4 header
	
	if (skb){ 
		ptr_ipv4_hdr = ip_hdr(skb);
		if(ptr_ipv4_hdr){
			//Protocol is 1 byte - no need to consider Endianness
			if (ptr_ipv4_hdr->protocol == PROT_TCP) {	//Checks in local endianness
				//ihl holds the ip_header length in number of words, 
				//each word is 32 bit long = 4 bytes 
				return ((struct tcphdr*)((char*)ptr_ipv4_hdr + (ptr_ipv4_hdr->ihl * 4)));
			}
		} else {
			printk(KERN_ERR "In get_tcp_header(), couldn't extract ipv4-header from skb.\n");
		}
	} else {
		printk(KERN_ERR "In get_tcp_header(), function got NULL argument.\n");
	}
	
	return NULL;
}

/**
 *	Fakes packet details according to values received
 * 
 *	@skb - pointer to struct sk_buff that represents current packet
 *	@fake_src -	1. true - if we want to fake the source ip&port
 * 				2. false - if we want to fake the destination ip&port
 *	@fake_ip - the ip we want to fake (to), in LOCAL ENDIANNESS!
 *	@fake_port - the port we want to fake (to), in LOCAL ENDIANNESS!
 * 
 *	Returns false if failed 
 **/
bool fake_packets_details(struct sk_buff *skb, bool fake_src, __be32 fake_ip, __be16 fake_port)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	int tcplen;
	
	if ( skb == NULL 
		|| skb_linearize(skb) != 0
		|| (ip_header = ip_hdr(skb)) == NULL
		|| (tcp_header = get_tcp_header(skb)) == NULL )
	{
		printk(KERN_ERR "Error: function fake_packets_details() failed.\n");
		return false;
	}

	//Change routing:
	if (fake_src){
		ip_header->saddr = htonl(fake_ip);
		tcp_header->source = htons(fake_port);
	} else {
		ip_header->daddr = htonl(fake_ip);
		tcp_header->dest = htons(fake_port);
	}

	//Fix checksum for both IP and TCP:
	tcplen = (skb->len - ((ip_header->ihl )<< 2));
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

#ifdef FAKING_DEBUG_MODE
	if (fake_src) {
		printk(KERN_INFO "In fake_packets_details(), faked source details.\n");
	} else {
		printk(KERN_INFO "In fake_packets_details(), faked destination details.\n");
	}
#endif	

	return true;
}

