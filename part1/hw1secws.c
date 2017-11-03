#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


static struct nf_hook_ops nfho_to_fw, nfho_from_fw, nfho_others, nfho_of_incoming_ipv6, nfho_of_outgoing_ipv6;

/**
 * A hook function that deals with packets that comes to fw / goes out of fw - accepts them (lets them pass)
 **/
unsigned int hook_func_allow(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in,  
							const struct net_device* out, int(*okfn)(struct sk_buff*) ){
		printk(KERN_INFO "*** packet passed ***");
		return NF_ACCEPT;					
}

 /**
 * A hook function that deals with packets that are designated to host1 or host2
 * 		(or anywhere else who's not fw but tries to pass through fw), and packets from type IPv6 - blocks them
 **/
 unsigned int hook_func_block(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in,  
							const struct net_device* out, int(*okfn)(struct sk_buff*) ){
		printk(KERN_INFO "*** packet blocked ***");
		return NF_DROP;						
}

static int __init my_init_func(void){

	//TODO:: ADD FAILURE TESTS? ALSO, TO MANY PACKETS ARE PASSING :(

	/** Takes care of packets sent to fw: **/
	nfho_to_fw.hook = hook_func_allow; // Function to call when all conditions below are met - allows the packet to move
	nfho_to_fw.pf = PF_INET; // Packets of IPv4
	nfho_to_fw.hooknum = NF_INET_LOCAL_IN; // Called after classifing the packet as "INPUT", at "INPUT" hook-point
	nfho_to_fw.priority = NF_IP_PRI_FIRST; // Sets the priority of the hook_func_allow() as the highest
	nf_register_hook(&nfho_to_fw); // Register the hook
	
	/** Takes care of packets sent from fw: **/
	nfho_from_fw.hook = hook_func_allow; // Function to call when all conditions below are met - allows the packet to move
	nfho_from_fw.pf = PF_INET;
	nfho_from_fw.hooknum = NF_INET_LOCAL_OUT; // Called after classifing the packet as "OUTPUT", at fw's-"OUTPUT"-hook-point
	nfho_from_fw.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_from_fw); 
	
	/** Takes care of packets who aren't designated to fw: **/ 
	nfho_others.hook = hook_func_block; // Function to call when all conditions below are met - blocks the packet
	nfho_others.pf = PF_INET; // Packets of IPv4
	nfho_others.hooknum = NF_INET_FORWARD; // Called after classifing the packet as not designated to fw - at "FORWARD"-hook-point
	nfho_others.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_others);
	
	/** Takes care of incoming IPv6 packets - blocks them, as said at the lecture **/
	nfho_of_incoming_ipv6.hook = hook_func_block;// Function to call when all conditions below are met - blocks the packet
	nfho_of_incoming_ipv6.pf = PF_INET6; // Packets of IPv6!
	nfho_of_incoming_ipv6.hooknum = NF_INET_PRE_ROUTING; //Called even before deciding if the packet is for/from fw or to/from host1/host2
	nfho_of_incoming_ipv6.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_of_incoming_ipv6);
	
	/** Takes care of outgoing IPv6 packets - blocks them, as said at the lecture **/
	nfho_of_outgoing_ipv6.hook = hook_func_block;// Function to call when all conditions below are met - blocks the packet
	nfho_of_outgoing_ipv6.pf = PF_INET6; // Packets of IPv6!
	nfho_of_outgoing_ipv6.hooknum = NF_INET_LOCAL_OUT; //Called for an outgoing packet
	nfho_of_outgoing_ipv6.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_of_outgoing_ipv6);

	return 0;
}

static void __exit my_exit_func(void){
	
	/** Cleans up: unregisters all hooks: **/
	nf_unregister_hook(&nfho_to_fw);
	nf_unregister_hook(&nfho_from_fw);
	nf_unregister_hook(&nfho_others);
	nf_unregister_hook(&nfho_of_incoming_ipv6);
	nf_unregister_hook(&nfho_of_outgoing_ipv6);
}

module_init(my_init_func);
module_exit(my_exit_func);

