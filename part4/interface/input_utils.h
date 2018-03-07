#ifndef _INPUT_UTILS_H_
#define _INPUT_UTILS_H_
#include "user_fw.h"

#define MAX_NUM_OF_RULES (50)
// Constants for rule-string-format:"<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <dource port> <dest port> <ack> <action>"
#define NUM_OF_SPACES_IN_FORMAT	(8)	
#define NUM_OF_TOKENS_IN_FORMAT (9)	
#define MAX_LEN_OF_NAME_RULE (19) 		// Since rule_t.rule_name is of length 20, including null-terminator
#define MAX_STRLEN_OF_DIRECTION (3)		// maximum length value of("in","out","any") = 3
#define MAX_STRLEN_OF_IP_ADDR (18)		// strlen("XXX.XXX.XXX.XXX/YY") = 18
#define MAX_STRLEN_OF_PROTOCOL (5)		// maximum length value of("icmp","tcp","udp","any","other","XXX") = 5
#define MAX_STRLEN_OF_PORT (5)			// maximum length value of(">1023","any","XXXXX") = 5
#define MAX_STRLEN_OF_ACK (3)			// maximum length value of("no","yes","any") = 3
#define MAX_STRLEN_OF_ACTION (6)		// maximum length value of("accept","drop") = 6
//MAX_STRLEN_OF_RULE_FORMAT doesn't count the null-terminator:
#define MAX_STRLEN_OF_RULE_FORMAT (NUM_OF_SPACES_IN_FORMAT+MAX_LEN_OF_NAME_RULE+MAX_STRLEN_OF_DIRECTION+2*MAX_STRLEN_OF_IP_ADDR+MAX_STRLEN_OF_PROTOCOL+2*MAX_STRLEN_OF_PORT+MAX_STRLEN_OF_ACK+MAX_STRLEN_OF_ACTION)
#define MAX_PREFIX_LEN_VALUE (32)

#define MAX_ADD_LEN_TRANSLATE (10)		//When translating from int ip to string "XXX.XXX.XXX.XXX" * 2
/** CONSTANTS FOR FW RULE FORMAT! **/
/** FW format is: <rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>**/
#define NUM_OF_FIELDS_IN_FWRULE (11)
#define MAX_STRLEN_OF_BE32 (10)			//MAX_U_INT = 2^32-1 = 4294967295, 10 digits
#define MAX_STRLEN_OF_BE16 (5)			//MAX_U_SHORT = 2^16-1 = 65535, 5 digits
#define MAX_STRLEN_OF_U8 (3)			//MAX_U_CHAR = 2^8-1 = 255, 3 digits
#define SPACES_IN_FWFORMAT	(10)
#define LEN_FWRULE_NAME (20) 			//Including null-terminator byte 
#define MAX_STRLEN_OF_FW_RULE_FORMAT (SPACES_IN_FWFORMAT+(LEN_FWRULE_NAME-1)+ 4*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16 + 4*MAX_STRLEN_OF_U8)
//MAX_STRLEN_OF_FW_RULE_FORMAT doesn't count the null-terminator and the '\n'.


#define MAX_LINES_TO_CHECK_IN_FILE (200)//To avoid infinit loop

#define MIN_LEN_OF_NAME_RULE (0) 
#define MIN_STRLEN_OF_DIRECTION (2)		// minimum length value of("in","out","any) = 2
#define MIN_STRLEN_OF_IP_ADDR (3)		// "any"
#define MIN_STRLEN_OF_PROTOCOL (3)		// minimum length value of("icmp","tcp","udp","any","other","XXX") = 3
#define MIN_STRLEN_OF_PORT (1)			// minimum length value of(">1023","any","X") = 1
#define MIN_STRLEN_OF_ACK (2)			// minimum length value of("no","yes","any") = 2
#define MIN_STRLEN_OF_ACTION (4)		// minimum length value of("accept","drop") = 4
#define MIN_STRLEN_OF_RULE_FORMAT (NUM_OF_SPACES_IN_FORMAT+MIN_LEN_OF_NAME_RULE+MIN_STRLEN_OF_DIRECTION+2*MIN_STRLEN_OF_IP_ADDR+MIN_STRLEN_OF_PROTOCOL+2*MIN_STRLEN_OF_PORT+MIN_STRLEN_OF_ACK+MIN_STRLEN_OF_ACTION)

//All legal commands:
#define STR_ACTIVATE "activate"
#define STR_DEACTIVATE "deactivate"
#define STR_GET_ACTIVE_STAT "show_active"
#define STR_SHOW_RULES "show_rules"
#define STR_CLEAR_RULES "clear_rules"
#define STR_LOAD_RULES "load_rules"
#define STR_SHOW_LOG "show_log"
#define STR_CLEAR_LOG "clear_log"
#define STR_GET_LOG_SIZE "get_log_size"
#define STR_GET_RULES_SIZE "get_rules_size" //To add later
#define STR_SHOW_CONN_TAB "show_connection_table"

/**
 * LOGROW format:
 * <timestamp> <protocol> <action> <hooknum> <src ip> <dst ip> <source port> <dest port> <reason> <count>'\n'. 
 * Therefore:
 * 
 * NOTE: MAX_STRLEN_OF_LOGROW_FORMAT includes '\n' and spaces (thats why I added NUM_OF_FIELDS_IN_LOF_ROW_T)
 **/
#define MAX_NUM_OF_LOG_ROWS (1000)
#define NUM_OF_FIELDS_IN_LOG_ROW_T (10)
#define MAX_STRLEN_OF_ULONG (20)			//MAX_U_LONG = 2^64-1 = 18446744073709551615, 20 digits
#define MAX_STRLEN_OF_LOGROW_FORMAT (MAX_STRLEN_OF_ULONG + 3*MAX_STRLEN_OF_U8 + 4*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16 + NUM_OF_FIELDS_IN_LOG_ROW_T)
#define MIN_STRLEN_OF_LOGROW_FORMAT ((NUM_OF_FIELDS_IN_LOF_ROW_T-1)+2*MIN_STRLEN_OF_IP_ADDR+MIN_STRLEN_OF_PROTOCOL+2*MIN_STRLEN_OF_PORT+MIN_STRLEN_OF_ACTION+4)
#define MAX_STRLEN_OF_REASON (20)

#define CHAR_CR (13)
#define CHAR_LF (10)
#define DELIMETER_STR "\n"

int read_rules_from_file(const char* file_path);
bool valid_file_path(const char* path);
enum rules_recieved_t send_rules_to_fw(void);
int get_fw_active_stat(void);
int print_all_rules_from_fw(void);
int clear_rules(void);
int clear_log(void);
int print_all_log_rows(void);
int get_num_log_rows(void);
bool tran_uint_to_ipv4str(unsigned int ip, char* str, size_t len_str);

#endif // _INPUT_UTILS_H_
