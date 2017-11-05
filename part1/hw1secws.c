#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


static struct nf_hook_ops nfho_to_fw, nfho_from_fw, nfho_others, nfho_of_incoming_ipv6, nfho_of_outgoing_ipv6;
enum hooked_nfhos {
	TO_FW_H,
	FROM_FW_H,
	OTHERS_H,
	INCOMING_IPV6_H,
	OUTGOING_IPV6_H,
	ALL_H
};


/**
 * A hook function that deals with packets that comes to fw / goes out of fw - accepts them (lets them pass)
 **/
static unsigned int hook_func_allow(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in,  
							const struct net_device* out, int(*okfn)(struct sk_buff*) ){
		printk(KERN_INFO "*** packet passed ***");
		return NF_ACCEPT;					
}

 /**
 * A hook function that deals with packets that are designated to host1 or host2
 * 		(or anywhere else who's not fw but tries to pass through fw), and packets from type IPv6 - blocks them
 **/
static unsigned int hook_func_block(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in,  
							const struct net_device* out, int(*okfn)(struct sk_buff*) ){
		printk(KERN_INFO "*** packet blocked ***");
		return NF_DROP;						
}

/**
 * Help function that updates nfho fiels and hooks it - see documentation below.
 * Returns 0 on success, -1 when failes.
 * 
 * Note: nf_hookfn is a typedef defined in linux/netfilter.h, and it's the type of the functions that can be associated with the hook
 * */
static int registers_hook(struct nf_hook_ops* nfho, nf_hookfn* okfn, int pf, int hooknum, int priority){
	(*nfho).hook = okfn; // Function to call when all conditions below are met
	(*nfho).pf = pf; // Protocol Family: IPv4/IPv6
	(*nfho).hooknum = hooknum; // When to call the function (in which hook point)
	(*nfho).priority = priority; // Sets the priority of the okfn()
	if(nf_register_hook(nfho)) { // Register the hook
		printk(KERN_INFO "*** Error: failed register hook ***");
		return -1;
	}
	return 0;
} 


/**
 * Help function that unregisters "hookedNfhos" number of hooks - BY THE ORDER THER WERE HOOKED IN "init()":
 * For example: if hookedNfhos==OTHERS_H(==2), the function will unregister: nfho_from_fw, nfho_to_fw.
 * 				if hookedNfhos==ALL_H(==5), all 5 nf_hook_ops will be unregistered.
 **/
static void unregistersHook(enum hooked_nfhos hookedNfhos){
	switch (hookedNfhos){
		case (ALL_H):
			nf_unregister_hook(&nfho_of_outgoing_ipv6);
		case (OUTGOING_IPV6_H):
			nf_unregister_hook(&nfho_of_incoming_ipv6);
		case (INCOMING_IPV6_H):
			nf_unregister_hook(&nfho_others);
		case (OTHERS_H):
			nf_unregister_hook(&nfho_from_fw);
		case (FROM_FW_H):
			nf_unregister_hook(&nfho_to_fw);
		// The default case is when hookedNfhos==TO_FW_H, where there's no need to unregister anything.	
	}
} 

static int __init my_init_func(void){

	/** Takes care of packets sent to fw:
	 * 		hook_func_allow: because we want to allow the packet to pass
	 * 		PF_INET: packets of IPv4
	 * 		NF_INET_LOCAL_IN: called after classifing the packet as "INPUT", at "INPUT" hook-point
	 * 		NF_IP_PRI_FIRST: sets the priority of the hook_func_allow() as the highest
	 **/
	if(registers_hook(&nfho_to_fw, hook_func_allow, PF_INET, NF_INET_LOCAL_IN, NF_IP_PRI_FIRST)){
		// If gets here, registers_hook failed when trying to register "nfho_to_fw",
		// so no need to call unregistersHook - we'll just return -1 (nothing was registered)
		return -1;
	}
	
	
	/** Takes care of packets sent from fw:
	 * 		hook_func_allow: allows the packet to move
	 *		PF_INET: packets of IPv4
	 *		NF_INET_LOCAL_OUT: called after classifing the packet as "OUTPUT", at fw's-"OUTPUT"-hook-point
	 *		NF_IP_PRI_FIRST: sets the priority of the hook_func_allow() as the highest
	 **/
	if (registers_hook(&nfho_from_fw, hook_func_allow, PF_INET, NF_INET_LOCAL_OUT, NF_IP_PRI_FIRST)){
		// If gets here, registers_hook failed on "nfho_from_fw", so we need to unregister accordingly:
		unregistersHook(FROM_FW_H);
		return -1;
	}

	
	/** Takes care of packets who aren't designated to fw:
	 * 		hook_func_block: because we want to block the packet		
	 * 		PF_INET: packets of IPv4
	 * 		NF_INET_FORWARD: called after classifing the packet as not designated to fw - at "FORWARD"-hook-point
	 *		NF_IP_PRI_FIRST: sets the priority of the hook_func_block() as the highest
	 **/ 
	if (registers_hook(&nfho_others, hook_func_block, PF_INET, NF_INET_FORWARD, NF_IP_PRI_FIRST)){
		// If gets here, registers_hook failed on "nfho_others", so we need to unregister accordingly:
		unregistersHook(OTHERS_H);
		return -1;
	}
	
	
	/** Takes care of incoming IPv6 packets - blocks them, as said at the lecture:
	 * 		hook_func_block: to block the IPv6 packet
	 * 		PF_INET6: packets of IPv6
	 * 		NF_INET_PRE_ROUTING: because in case of IPv6, blocking function should be called even before
	 * 							 deciding if the packet is for/from fw or to/from host1/host2
	 * 		NF_IP_PRI_FIRST: sets the priority of the hook_func_block() as the highest
	 **/
	if (registers_hook(&nfho_of_incoming_ipv6, hook_func_block, PF_INET6, NF_INET_PRE_ROUTING, NF_IP_PRI_FIRST)){
		// If gets here, registers_hook failed on "nfho_of_incoming_ipv6", so we need to unregister accordingly:
		unregistersHook(INCOMING_IPV6_H);
		return -1;
	}
	
	
	/** Takes care of outgoing (from fw) IPv6 packets - blocks them, as said at the lecture:
	 * 		hook_func_block: to block the outgoing IPv6 packet
	 * 		PF_INET6: packets of IPv6
	 * 		NF_INET_LOCAL_OUT: called for an outgoing packet
	 * 		NF_IP_PRI_FIRST: sets the priority of the hook_func_block() as the highest
	 **/
	if (registers_hook(&nfho_of_outgoing_ipv6, hook_func_block, PF_INET6, NF_INET_LOCAL_OUT, NF_IP_PRI_FIRST)){
		// If gets here, registers_hook failed on "nfho_of_outgoing_ipv6", so we need to unregister accordingly:
		unregistersHook(OUTGOING_IPV6_H);
		return -1;
	}

	return 0;
}

static void __exit my_exit_func(void){
	/** Cleans up: unregisters all 5 hooks, using unregisters_hook(): **/
	unregistersHook(ALL_H);
}

module_init(my_init_func);
module_exit(my_exit_func);

