#ifndef _USER_FW_H_
#define _USER_FW_H_
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h> // For open()
#include <sys/types.h> // For open()
#include <sys/stat.h> // For open()
#include <errno.h>
#include <unistd.h> // For close(), write(), read()
#include <stdlib.h> // For calloc()
#include <arpa/inet.h> //For inet_pton()
#include <stdbool.h> //For bool
#include <linux/netfilter.h> //For NF_ACCEPT, NF_DROP
#include <ctype.h> //For isdigit()

//#define USER_DEBUG_MODE (1) //For debug-printing 

#define PATH_TO_RULE_DEV "/dev/fw_rules"
#define PATH_TO_ACTIVE_ATTR "/sys/class/fw/fw_rules/active"
#define PATH_TO_RULES_SIZE_ATTR "/sys/class/fw/fw_rules/rules_size"
#define PATH_TO_LOG_DEV "/dev/fw_log"
#define PATH_TO_LOG_SIZE_ATTR "/sys/class/fw/fw_log/log_size"
#define PATH_TO_LOG_CLEAR_ATTR "/sys/class/fw/fw_log/log_clear"
#define PATH_TO_CONN_TAB_ATTR "/sys/class/fw/fw/conn_tab"
#define DEACTIVATE_STRING "0"
#define ACTIVATE_STRING "1"
#define ACTIVE_STR_LEN (1)
#define CLEAR_RULES_STRING "0"
#define DELETE_LOG_STRING "D"
#define NUM_FIELDS_IN_CONN_ROW_FORMAT (10)

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
//Only the above are considered valid procotol when setting the rules
//Added for catching "errors" (invalid protocol):
	PROT_ERROR = 144 
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
#define PORT_ERROR (-1) 	//NOTE: not to be confused with "PROT_ERR"
#define MAX_RULES		(50)

// For knowing if all rules sent were recieved by fw:
enum rules_recieved_t {
	NO_RULE_RECIEVED,
	PARTIAL_RULE_RECIEVED,
	ALL_RULE_RECIEVED
};

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
	DIRECTION_ERROR = 0x04
} direction_t;

// rule base
typedef struct {
	char rule_name[20];					// names will be no longer than 20 chars(includes '\0')
	direction_t direction;
	unsigned int src_ip;
	unsigned int src_prefix_mask; 		// e.g., 255.255.255.0 as int in the local endianness
	unsigned char src_prefix_size; 		// valid values: 0-32, e.g., /24 for the example above
	unsigned int dst_ip;
	unsigned int dst_prefix_mask; 		// as above
	unsigned char dst_prefix_size; 		// as above	
	unsigned short src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	unsigned short dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	unsigned char protocol; 			// values from: prot_t
	ack_t ack; 							// values from: ack_t
	unsigned char action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long timestamp;     	// time of creation/update
	unsigned char protocol;     	// values from: prot_t
	unsigned char action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char hooknum;      	// as received from netfilter hook
	unsigned int src_ip;		  	
	unsigned int dst_ip;		  	
	unsigned short src_port;
	unsigned short dst_port;
	reason_t reason;      		 	// rule#index, or values from: reason_t
	unsigned int count;        		// counts this line's hits
} log_row_t;

#endif // _USER_FW_H_
