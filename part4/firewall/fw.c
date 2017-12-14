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
