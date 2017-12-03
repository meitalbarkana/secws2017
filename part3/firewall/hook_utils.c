#include "hook_utils.h"

static struct nf_hook_ops	nfho_to_fw,
							nfho_from_fw,
							nfho_others;

/**
 *	This function would be called as a helper function,
 *  when hooknum is NF_INET_FORWARD for IPv4 packets
 *
 *	@skb - contains all of packet's data
 *	@in - pointer to net_device representing the network interface
 * 		  the packet pass through. NULL if packet traversal is "out".
 *	@out - pointer to net_device representing the network inteface
 * 		  the packet pass through. NULL if packet traversal is "in".
 * 
 *	Returns: NF_ACCEPT/NF_DROP according to packet data & firewall's status
 **/
static unsigned int check_packet_hookp_forward(struct sk_buff* skb, 
		const struct net_device* in, const struct net_device* out)
{
	//TODO:: after finishing user-space, MAYBE change to dynamic allocation
	//TODO:: add write to logger
	log_row_t pckt_lg_info; 
	ack_t packet_ack;
	direction_t packet_direction;
	
	//Initiate: pckt_lg_info, packet_ack , packet_direction
	if(!init_log_row(skb, &pckt_lg_info, NF_INET_FORWARD,
		&packet_ack, &packet_direction, in, out))
	{
		//An error occured, never supposed to get here:
		return NF_ACCEPT;
	}
	
	//Calls function that decides packet-action
	decide_packet_action(skb, &pckt_lg_info, &packet_ack, &packet_direction);
#ifdef DEBUG_MODE
	print_log_row(&pckt_lg_info, 777);
#endif
	return pckt_lg_info.action;
}

/**
 *	This function would be called as a helper function,
 *  when hooknum is NF_INET_LOCAL_IN / NF_INET_LOCAL_OUT
 *  for IPv4 packets
 *
 *	@skb - contains all of packet's data
 *	@in - pointer to net_device.
 *	@out - pointer to net_device.
 *	@hooknum - NF_INET_LOCAL_IN / NF_INET_LOCAL_OUT
 * 
 *	Returns: NF_ACCEPT/NF_DROP according to packet data.
 *	
 *	Note: WILL ALLOW ONLY PACKETS FROM LOCALHOST TO ITSELF
 **/
static unsigned int check_packet_hookp_in_out(struct sk_buff* skb, 
		const struct net_device* in, const struct net_device* out,
		unsigned int hooknum)
{
	//NOTE: NO NEED TO LOG
	log_row_t pckt_lg_info; 
	ack_t packet_ack;
	direction_t packet_direction;
	
	//Initiate: pckt_lg_info, packet_ack , packet_direction
	if(!init_log_row(skb, &pckt_lg_info, hooknum,
		&packet_ack, &packet_direction, in, out))
	{
		return NF_ACCEPT;//An error occured, never supposed to get here:
	}
	
	return ( decide_inner_packet_action(&pckt_lg_info, &packet_ack,
			&packet_direction) );
}

/**
 * Main hook - function.
 * Will use:
 * 		check_packet_hookp_in_out()
 * 		check_packet_hookp_forward()
 * to decide what to do with the packet.
 * 
 * NOTE: gets only IPv4 packets!
 **/
static unsigned int hook_func_callback(unsigned int hooknum, 
		struct sk_buff* skb, const struct net_device* in, 
		const struct net_device* out, int(*okfn)(struct sk_buff*) )
{

	if (hooknum == NF_INET_FORWARD) 
	{
		return check_packet_hookp_forward(skb, in, out);
	}
	else if( (hooknum == NF_INET_LOCAL_IN) || (hooknum == NF_INET_LOCAL_OUT) )
	{	
		return check_packet_hookp_in_out(skb, in, out, hooknum);	
	}
	
	//An error occured, never supposed to get here:
	printk(KERN_ERR "in hook_func_callback(), got invalid hooknum.\n");
	return NF_ACCEPT;
							
}


/**
 * Help function that updates nfho fields and hooks it (see documentation below)
 * 
 * Returns 0 on success, -1 when failes.
 * 
 * Note: nf_hookfn is a typedef defined in linux/netfilter.h,
 *		 (it's the type of functions that can be associated with the hook)
 * */
static int registers_hook(struct nf_hook_ops* nfho, nf_hookfn* okfn, int pf, int hooknum, int priority){
	(*nfho).hook = okfn;			// Function to call when all conditions below are met
	(*nfho).pf = pf;				// Protocol Family: IPv4/IPv6
	(*nfho).hooknum = hooknum;		// When to call the function (in which hook point)
	(*nfho).priority = priority;	// Sets the priority of the okfn()
	if(nf_register_hook(nfho)) {	// Register the hook
		printk(KERN_INFO "*** Error: failed register hook ***\n");
		return -1;
	}
	return 0;
} 

/**
 * Help function that unregisters "hookedNfhos" number of hooks -
 * BY THE ORDER THER WERE HOOKED IN "registerHooks()":
 **/
static void unregistersHook(enum hooked_nfhos hookedNfhos){
	switch (hookedNfhos){
		case (ALL_H):
			nf_unregister_hook(&nfho_others);
		case (OTHERS_H):
			nf_unregister_hook(&nfho_from_fw);
		case (FROM_FW_H):
			nf_unregister_hook(&nfho_to_fw);
		// The default case is when there's no need to unregister anything.	
	}
} 

/**
 * 	A help function that registers all hooks,
 * 	Returns 0 on success, -1 on failure. 
 **/
int registerHooks(void){

	/**
	 * Takes care of packets sent to fw:
	 * 		hook_func_callback: main hook function
	 * 		PF_INET: only packets of IPv4
	 * 		NF_INET_LOCAL_IN: called after classifing the packet as LOCAL_IN
	 * 		NF_IP_PRI_FIRST: sets the priority of hook_func_callback() as the highest
	 **/
	if(registers_hook(&nfho_to_fw, hook_func_callback, PF_INET, NF_INET_LOCAL_IN, NF_IP_PRI_FIRST)){
		// Registers_hook failed when trying to register "nfho_to_fw"
		return -1;
	}
	
	/** 
	 * Takes care of packets sent from fw:
	 * 		hook_func_callback: main hook function
	 *		PF_INET: packets of IPv4
	 *		NF_INET_LOCAL_OUT: called after classifing the packet as LOCAL_OUT
	 *		NF_IP_PRI_FIRST: sets the priority of hook_func_callback() as the highest
	 **/
	if (registers_hook(&nfho_from_fw, hook_func_callback, PF_INET, NF_INET_LOCAL_OUT, NF_IP_PRI_FIRST)){
		// Registers_hook failed on "nfho_from_fw", so we need to unregister accordingly:
		unregistersHook(FROM_FW_H);
		return -1;
	}
	
	/** 
	 * Takes care of packets who aren't designated to fw:
	 * 		hook_func_callback: main hook function		
	 * 		PF_INET: packets of IPv4
	 * 		NF_INET_FORWARD: called after classifing the packet as not 
	 * 						designated to fw - at "FORWARD"-hook-point
	 *		NF_IP_PRI_FIRST: sets the priority of hook_func_callback() as the highest
	 **/
	if (registers_hook(&nfho_others, hook_func_callback, PF_INET, NF_INET_FORWARD, NF_IP_PRI_FIRST)){
		// Registers_hook failed on "nfho_others", so we need to unregister accordingly:
		unregistersHook(OTHERS_H);
		return -1;
	}
	
	return 0;
}

/**
 *	Unregisters all hooks
 **/
void unRegisterHooks(void){
	unregistersHook(ALL_H);
}
