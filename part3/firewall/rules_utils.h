#ifndef RULES_UTILS_H
#define RULES_UTILS_H
#include "fw.h"

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

#define MIN_LEN_OF_NAME_RULE (0) 
#define MIN_STRLEN_OF_DIRECTION (2)		// minimum length value of("in","out","any) = 2
#define MIN_STRLEN_OF_IP_ADDR (9)		// strlen("X.X.X.X/Y") = 9
#define MIN_STRLEN_OF_PROTOCOL (3)		// minimum length value of("icmp","tcp","udp","any","other","XXX") = 3
#define MIN_STRLEN_OF_PORT (3)			// minimum length value of(">1023","any","XXXXX") = 3
#define MIN_STRLEN_OF_ACK (2)			// minimum length value of("no","yes","any") = 2
#define MIN_STRLEN_OF_ACTION (4)		// minimum length value of("accept","drop") = 4
#define MIN_STRLEN_OF_RULE_FORMAT (NUM_OF_SPACES_IN_FORMAT+MIN_LEN_OF_NAME_RULE+MIN_STRLEN_OF_DIRECTION+2*MIN_STRLEN_OF_IP_ADDR+MIN_STRLEN_OF_PROTOCOL+2*MIN_STRLEN_OF_PORT+MIN_STRLEN_OF_ACK+MIN_STRLEN_OF_ACTION)



/**
 * Returns a representation of a rule as a string on success,
 * NULL if failed,
 * NOTE: user should free memory allocated in it.
 **/
char* get_rule_as_str(rule_t* rule);

/**
 *	Gets a string that supposed to represent a proper rule.
 * 	Creates a rule according to str.
 * 	NOTE: str format should be:
 * 	<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>
 *	
 * If succedded, returns the pointer to rule_t created,
 * Otherwise - returns NULL
 **/
rule_t* get_rule_from_string(char* str, rule_t** ptr_to_all_rules_table);


#endif /* RULES_UTILS_H */
