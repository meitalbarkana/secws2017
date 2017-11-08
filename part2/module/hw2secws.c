#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>

/**
 * Based on Reuven Plevinsky's sysfs_example that can be found in: http://course.cs.tau.ac.il//secws17/lectures/ 
 **/
MODULE_LICENCE("GPL");
MODULE_AUTHOR("Meital Bar-Kana Swissa");


static int major_number; // Will contain our device's major number - its unique ID
static struct class* sysfs_class = NULL; // A class to categorize our device
static struct device* sysfs_device = NULL; // Our device

/** Counter-variables that maintain information the user would want **/
static unsigned int packets_blocked_so_far = 0; 
static unsigned int packets_passed_so_far = 0;

/** File operations for our device: we'll want it to maintain counting of packets blocked/passed **/
static struct file_operations fops = {
	.owner = THIS_MODULE
};

/**
 *	Returns 1 if count=1 and the first char at "buf" is '0' [this counts as the only valid user-input],
 * 	-1 otherwise.
 **/
static inline int validate_user_input(const char* buf, size_t count){
	if((count==1) && (buf[0]=='0'))
		return 1;
	return -1;
}

/**
 *	This function will be called when user tries to read from the device.  
 **/
ssize_t ret_packets_summary(struct device* dev, struct device_attribute* attr, char* buf){
		ssize_t ret = scnprintf(buf, PAGE_SIZE, "#passed packets: %u, #blocked packets: %u\n",
								packets_passed_so_far, packets_blocked_so_far);
		if (ret<=0){
			printk(KERN_INFO "*** Error: failed writing to user's buffer ***");
		}
		return ret;
}

/**
 * 	This function will be called when user tries to write to the device,
 * 	meaning that the user wants to reset the counter-variables.
 * 	Will return 2*sizeof(unsigned int) on success,
 * 	a negative number otherwise.
 * 	If user provided buffer containing something other than "0" - will fail! 
 **/
ssize_t reset_packet_counters((struct device* dev, struct device_attribute* attr, const char* buf, size_t count){
	if (validate_user_input(buf, count)<=0){
		printk(KERN_INFO "*** Error: user sent invalid writing-command! ***");
		return -EPERM; // Returns an error of operation not permitted
	}
	packets_blocked_so_far = 0; 
	packets_passed_so_far = 0;
	return 2*sizeof(unsigned int);
}

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
 * Increases the value of the counter packets_passed_so_far by 1.
 **/
static unsigned int hook_func_allow(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in,  
							const struct net_device* out, int(*okfn)(struct sk_buff*) ){
		printk(KERN_INFO "*** packet passed ***");
		packets_passed_so_far++;
		return NF_ACCEPT;					
}

 /**
 * A hook function that deals with packets that are designated to host1 or host2
 * 		(or anywhere else who's not fw but tries to pass through fw), and packets from type IPv6 - blocks them
 * Increases the value of the counter packets_blocked_so_far by 1.
 **/
static unsigned int hook_func_block(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in,  
							const struct net_device* out, int(*okfn)(struct sk_buff*) ){
		printk(KERN_INFO "*** packet blocked ***");
		packets_blocked_so_far++;
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

/**
 * 	Link device to the attributes, such that:
 * 		.attr.name = "sysfs_att" (access it through: dev_attr_sysfs_att)
 * 		.attr.mode = S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH, giving the owner and other user read&write permissions
 * 		.show = ret_packets_summary
 * 		.store = reset_packet_counters
 **/
static DEVICE_ATTR(sysfs_att, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH, ret_packets_summary, reset_packet_counters);

/**
 * 	A help function that registers all hooks,
 * 	Returns 0 on success, -1 on failure. 
 **/
static int registerHooks(void){

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

/**
 * 	A help function that initiates our char-device.
 * 	Returns 0 on success, -1 on failure. 
 **/
static int initDevice(void){
	
}

static int __init my_init_func(void){
	
	// Call the function that registers all hooks:
	if(registerHooks()!=0){
		return -1;
	}
	if(initDevice()!=0){
		return -1;
	}
	return 0;
	
}

static void __exit my_exit_func(void){
	/** Cleans up: unregisters all 5 hooks, using unregistersHook(): **/
	unregistersHook(ALL_H);
	//TODO:: add deleteing the device
}

module_init(my_init_func);
module_exit(my_exit_func);
