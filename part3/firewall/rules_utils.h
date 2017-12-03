#ifndef RULES_UTILS_H
#define RULES_UTILS_H
#include "fw.h"

#define MAX_NUM_OF_RULES (50)

/** Constants for printing & formatting: **/
/*For test-printing mainly:*/
#define MAX_LEN_RULE_NAME (20) //Including null-terminator byte 
#define NUM_OF_FIELDS_IN_RULE_T (13)
#define NUM_OF_FIELDS_IN_FORMAT (11)
#define MAX_STRLEN_OF_BE32 (10)	//MAX_U_INT = 2^32-1 = 4294967295, 10 digits
#define MAX_STRLEN_OF_BE16 (5)	//MAX_U_SHORT = 2^16-1 = 65535, 5 digits
#define MAX_STRLEN_OF_U8 (3)	//MAX_U_CHAR = 2^8-1 = 255, 3 digits
#define MAX_STRLEN_OF_D (10)	//as in MAX_U_INT...

/*For formatting input:*/
/* Valid rule-string-format is:
"<rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>"*/
#define NUM_OF_SPACES_IN_FORMAT	(10)	
#define MAX_STRLEN_OF_RULE_FORMAT (NUM_OF_SPACES_IN_FORMAT+(MAX_LEN_RULE_NAME-1)+ 4*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16 + 4*MAX_STRLEN_OF_U8)
//MAX_STRLEN_OF_RULE_FORMAT doesn't count the null-terminator and the '\n'.

#define MAX_LEN_ALL_RULES_BUFF ((MAX_NUM_OF_RULES*MAX_STRLEN_OF_RULE_FORMAT) + MAX_NUM_OF_RULES)
//MAX_LEN_ALL_RULES_BUFF doesn't count the '\0'
/*******************************/

#define FW_ON 1
#define FW_OFF 0

#define CLEAR_RULES '0'
#define DELIMETER_STR "\n"
#define LOCALHOST_IP (2130706433u) // <=> 127.0.0.1
#define LOCALHOST_MASK_LEN (8) 
#define LOCALHOST_PREFIX_MASK (4278190080u) // <=> mask of length 8

enum src_or_dst_t {
	SRC,
	DST
};

bool is_XMAS(struct sk_buff* skb);

#endif /* RULES_UTILS_H */
