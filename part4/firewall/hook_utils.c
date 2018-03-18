#include "hook_utils.h"

static struct nf_hook_ops	nfho_pre_route,
							nfho_from_fw;

/**
 *	This function would be called as a helper function,
 *  when hooknum is NF_INET_PRE_ROUTING for IPv4 packets
 *
 *	Inserts relevant row to log.
 * 
 *	@skb - contains all of packet's data
 *	@in - pointer to net_device representing the network interface
 * 		  the packet pass through. NULL if packet traversal is "out".
 *	@out - pointer to net_device representing the network inteface
 * 		  the packet pass through. NULL if packet traversal is "in".
 * 
 *	Returns: NF_ACCEPT/NF_DROP according to packet data & firewall's status
 * 
 * 
 *	Note:	1. In case of allocation error - default is to pass the packet.
 * 			2. User of this function should free memory located for
 * 			   pckt_lg_info (allocated in init_log_row())
 **/
static unsigned int check_packet_hookp_pre_routing(struct sk_buff* skb, 
		const struct net_device* in, const struct net_device* out)
{
	
	log_row_t* pckt_lg_info = NULL; 
	ack_t packet_ack;
	direction_t packet_direction;
	
	//Initiate: pckt_lg_info, packet_ack , packet_direction
	if( (pckt_lg_info = init_log_row(skb, NF_INET_PRE_ROUTING,
		&packet_ack, &packet_direction, in, out)) == NULL)
	{
		//An error occured, never supposed to get here:
		//(Error already been printed inside init_log_row)
		return NF_ACCEPT;
	}
	///TODO:: EDIT THIS FUNCTION!!
	//Calls function that decides packet-action
	decide_packet_action(skb, pckt_lg_info, &packet_ack, &packet_direction);
	
	
	//TODO:: add here an "if" that checks if pckt_lg_info->reason == REASON_LOOPBACK_PACKET,
	//		and if it does - frees that log-row.
	//something like:	kfree(pckt_lg_info);
	//					return pckt_lg_info->action;
	//
	
	
	//TODO:: delete this "if":
	if(pckt_lg_info->action == NF_DROP){
		printk(KERN_INFO "***ALERT***: dropping packet - its info:\n");
		print_log_row(pckt_lg_info);
	}

	//Inserts row to log-rows:
	if (!insert_row(pckt_lg_info)){ ///TODO:: not sure if any row should be inserted!
		//An error occured, error already printed in insert_row()
		kfree(pckt_lg_info);
		return NF_ACCEPT;
	}
	return pckt_lg_info->action;
}

/**
 *	This function would be called as a helper function,
 *  when hooknum is NF_INET_LOCAL_OUT
 *  for IPv4 packets
 *
 *	@skb - contains all of packet's data
 *	@in - pointer to net_device.
 *	@out - pointer to net_device.
 *	@hooknum - NF_INET_LOCAL_OUT
 * 
 *	Returns: NF_ACCEPT/NF_DROP according to packet data.
 *	
 *	Note: WILL ALLOW ONLY PACKETS FROM LOCALHOST TO ITSELF
 **/
static unsigned int check_packet_hookp_out(struct sk_buff* skb, 
		const struct net_device* in, const struct net_device* out,
		unsigned int hooknum)
{
	///TODO:: EDIT THIS FUNCTION!
	//NOTE: NO NEED TO LOG - so memory allocated is freed at the end
	log_row_t* pckt_lg_info = NULL; 
	ack_t packet_ack;
	direction_t packet_direction;
	unsigned int ans;
	
	//Initiate: pckt_lg_info, packet_ack , packet_direction
	if( (pckt_lg_info = init_log_row(skb, hooknum, &packet_ack,
			&packet_direction, in, out)) == NULL)
	{
		return NF_ACCEPT;//An error occured, never supposed to get here.
	}
	
	ans = decide_outer_packet_action(skb, pckt_lg_info, &packet_ack,
			&packet_direction);
	
	//Frees memory allocated in init_log_row
	kfree(pckt_lg_info);
	return ans;
}

/**
 * Main hook - function.
 * Will use:
 * 		check_packet_hookp_out()
 * 		check_packet_hookp_pre_routing()
 * to decide what to do with the packet.
 * 
 * NOTE: gets only IPv4 packets!
 **/
static unsigned int hook_func_callback(unsigned int hooknum, 
		struct sk_buff* skb, const struct net_device* in, 
		const struct net_device* out, int(*okfn)(struct sk_buff*) )
{

	if (hooknum == NF_INET_PRE_ROUTING) 
	{
#ifdef FAKING_DEBUG_MODE
		printk(KERN_INFO "IN hook_func_callback, hooknum is NF_INET_PRE_ROUTING\n");
#endif
		return check_packet_hookp_pre_routing(skb, in, out);
	}
	else if (hooknum == NF_INET_LOCAL_OUT) 
	{
#ifdef FAKING_DEBUG_MODE
		printk(KERN_INFO "IN hook_func_callback, hooknum is NF_INET_LOCAL_OUT\n");
#endif	
		return check_packet_hookp_out(skb, in, out, hooknum);	
	}
	
	//An error occured, never supposed to get here:
	printk(KERN_ERR "Function hook_func_callback() got invalid hooknum, accepting packet.\n");
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
			nf_unregister_hook(&nfho_from_fw);
		case (FROM_FW_H):
			nf_unregister_hook(&nfho_pre_route);
		// The default case is when there's no need to unregister anything.	
	}
} 

/**
 * 	A help function that registers all hooks,
 * 	Returns 0 on success, -1 on failure. 
 **/
int registerHooks(void){

	/**
	 * Takes care of packets catched pre-routing:
	 * 		hook_func_callback: main hook function
	 * 		PF_INET: only packets of IPv4
	 * 		NF_INET_PRE_ROUTING: called BEFORE classifing the packet as LOCAL_IN/FORWARD
	 * 		NF_IP_PRI_FIRST: sets the priority of hook_func_callback() as the highest
	 **/
	if(registers_hook(&nfho_pre_route, hook_func_callback, PF_INET, NF_INET_PRE_ROUTING, NF_IP_PRI_FIRST)){
		// Registers_hook failed when trying to register "nfho_pre_route"
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
	
	return 0;
}

/**
 *	Unregisters all hooks
 **/
void unRegisterHooks(void){
	unregistersHook(ALL_H);
}
