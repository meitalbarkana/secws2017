#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h> //For kmalloc
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter.h> //For ipv6 packets
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h> //For bool type
#include <linux/uaccess.h> //For allowing user-space access
#include <linux/time.h> //For timestamp value
#include <linux/list.h> //For log's list

/**
 * If DEBUG_MODE/LOG_DEBUG_MODE defined, code will print debug messages to KERN_INFO
 **/
//#define DEBUG_MODE (1) 	//For debug-printing 
//#define LOG_DEBUG_MODE (1)	//For logger-debug-printing

#define NO_REASON (-777)
/*For test-printing mainly:*/
#define MAX_STRLEN_OF_ULONG (20)//MAX_U_LONG = 2^64-1 = 18446744073709551615, 20 digits
#define MAX_STRLEN_OF_BE32 (10)	//MAX_U_INT = 2^32-1 = 4294967295, 10 digits
#define MAX_STRLEN_OF_BE16 (5)	//MAX_U_SHORT = 2^16-1 = 65535, 5 digits
#define MAX_STRLEN_OF_U8 (3)	//MAX_U_CHAR = 2^8-1 = 255, 3 digits

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define PORT_ERROR 		(-1) //NOTE: not to be confused with "PROT_ERR"
#define MAX_RULES		(50)
#define MAX_LOG_ROWS	(1000)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars(includes '\0')
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char  	hooknum;      	// as received from netfilter hook
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
	struct list_head list;			// For saving kernel-list of all log-rows
} log_row_t;

//Enum to help deciding about packets
enum action_t {
	RULE_ACCEPTS_PACKET = NF_ACCEPT,
	RULE_DROPS_PACKET = NF_DROP,
	RULE_NOT_RELEVANT = 66,
};

/**
 *	Enum describing tcp_state.
 * 
 *	NOTE: "client" is refering to whoever started the connection
 *		  OR the side asking to end the connection!
 * 
 *	Names were defined based on Dr. David Movshovitz's lecture: "Network Firewalls"
 **/
enum tcp_state_t {	 

	//"State" before a connection actually begins OR after it's closed:
	TCP_CLOSED = 1,
	
	//State a server is in when waiting for a request to start a connection:
	TCP_LISTEN = 2,
	
	//State after client sent a SYN packet and is waiting for SYN-ACK reply:
	TCP_SYN_SENT = 3,
	
	//State a server is in after receiving a SYN packet and replying with its SYN-ACK reply:
	TCP_SYN_RCVD = 4,
	
	//State a connection is in after its necessary ACK packet has been received - 
	// client goes into this state after receiving a SYN-ACK,
	// server goes into this state after receiving the lone ACK:
	TCP_ESTABLISHED = 5,
	
	//Client's state after he sent an initial FIN packet asking for a graceful close of the TCP connection:
	TCP_FIN_WAIT_1 = 6,
	
	//Server's state after it receives an initial FIN and sends back an ACK to acknowledge the FIN:
	TCP_CLOSE_WAIT = 7,
	
	//Client's state when receiving the ACK response to its initial FIN,
	// as it waits for a final FIN from server:
	TCP_FIN_WAIT_2 = 8,
	
	//Server's state when just sent the second FIN needed to gracefully
	// close the TCP connection back to (initiating) client, while it waits for acknowledgment:
	TCP_LAST_ACK = 9,
	
	//State of the initiating client that received the final FIN and has sent
	// an ACK to close the connection:
	TCP_TIME_WAIT = 10
};

//Struct representing a row in connection-table:
struct connection_row_t{
	
	__be32	 		src_ip;	
	__be16			src_port;
	__be32			dst_ip;
	__be16			dst_port;
	tcp_state_t		tcp_state;
	unsigned long	timestamp;		// Time of creation/last update

	///TODO:: add fields for faked directions

	struct list_head list;			// For saving kernel-list of all connection-rows

};


direction_t get_direction(const struct net_device* in, const struct net_device* out);

#endif // _FW_H_
