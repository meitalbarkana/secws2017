#ifndef RULES_UTILS_H
#define RULES_UTILS_H
#include "conn_tab_utils.h"

#define MAX_NUM_OF_RULES (50)

/** Constants for printing & formatting: **/
/*For test-printing mainly:*/
#define MAX_LEN_RULE_NAME (20) //Including null-terminator byte 
#define NUM_OF_FIELDS_IN_RULE_T (13)
#define NUM_OF_FIELDS_IN_FORMAT (11)
#define MAX_STRLEN_OF_D (10)	//as in MAX_U_INT...

/*For formatting input:*/
/* Valid rule-string-format is:
"<rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>"*/
#define NUM_OF_SPACES_IN_FORMAT	(10)	
#define MAX_STRLEN_OF_RULE_FORMAT (NUM_OF_SPACES_IN_FORMAT+(MAX_LEN_RULE_NAME-1)+ 4*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16 + 4*MAX_STRLEN_OF_U8)
//MAX_STRLEN_OF_RULE_FORMAT doesn't count the null-terminator and the '\n'.

#define MAX_LEN_ALL_RULES_BUFF ((MAX_NUM_OF_RULES*MAX_STRLEN_OF_RULE_FORMAT) + MAX_NUM_OF_RULES)
//MAX_LEN_ALL_RULES_BUFF doesn't count the '\0'

//Since each field has at least 1 character (length doesn't include '\n','\0'):
#define MIN_RULE_FORMAT_LEN (NUM_OF_SPACES_IN_FORMAT+NUM_OF_FIELDS_IN_FORMAT)
/*******************************/

#define FW_ON 1
#define FW_OFF 0

#define CLEAR_RULES '0'
#define DELIMETER_STR "\n"
#define LOCALHOST_IP (2130706433u) // <=> 127.0.0.1
#define LOCALHOST_MASK_LEN (8) 
#define LOCALHOST_PREFIX_MASK (4278190080u) // <=> mask of length 8

//Enum that helps deciding which fields to update (source or destination):
enum src_or_dst_t {
	SRC,
	DST
};

//Enum that helps "folding" up stages, 
//used when: - initiating device stopped because of some error 
//			 - device is destroyed.
enum state_to_fold {
	UNREG_DES,
	DEVICE_DES,
	FIRST_FILE_DES,
	ALL_DES
};

//Firewalls' build-in rule: to allow connection between localhost to itself:
static const rule_t g_buildin_rule = 
{
	.rule_name = "build-in-rule",
	.direction = DIRECTION_ANY,
	.src_ip = LOCALHOST_IP,
	.src_prefix_mask = LOCALHOST_PREFIX_MASK,
	.src_prefix_size = LOCALHOST_MASK_LEN,
	.dst_ip = LOCALHOST_IP,
	.dst_prefix_mask = LOCALHOST_PREFIX_MASK,
	.dst_prefix_size = LOCALHOST_MASK_LEN,
	.src_port = PORT_ANY,
	.dst_port = PORT_ANY,
	.protocol = PROT_ANY,
	.ack = ACK_ANY,
	.action = NF_ACCEPT
};

//Functions that will be used outside rules_utils: 
void decide_packet_action(struct sk_buff* skb, log_row_t* ptr_pckt_lg_info, ack_t* packet_ack, direction_t* packet_direction);
unsigned int decide_inner_packet_action(log_row_t* ptr_pckt_lg_info, ack_t* packet_ack, direction_t* packet_direction);
int init_rules_device(struct class* fw_class);
void destroy_rules_device(struct class* fw_class);
#endif /* RULES_UTILS_H */
