#ifndef RULES_UTILS_H
#define RULES_UTILS_H
#include "fw.h"

#define MAX_NUM_OF_RULES (50)
// Constants for rule-string-format:"<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <dource port> <dest port> <ack> <action>"
#define NUM_OF_SPACES_IN_FORMAT	(8)	
#define NUM_OF_TOKENS_IN_FORMAT (9)	
#define MAX_LEN_OF_NAME_RULE (19) 		// Since rule_t.rule_name is of length 20, including null-terminator
#define MAX_STRLEN_OF_DIRECTION (3)		// maximum length value of("in","out","any) = 3
#define MAX_STRLEN_OF_IP_ADDR (18)		// strlen("XXX.XXX.XXX.XXX/YY") = 18
#define MAX_STRLEN_OF_PROTOCOL (5)		// maximum length value of("icmp","tcp","udp","any","other","XXX") = 5
#define MAX_STRLEN_OF_PORT (5)			// maximum length value of(">1023","any","XXXXX") = 5
#define MAX_STRLEN_OF_ACK (3)			// maximum length value of("no","yes","any") = 3
#define MAX_STRLEN_OF_ACTION (6)		// maximum length value of("accept","drop") = 6
#define MAX_STRLEN_OF_RULE_FORMAT (NUM_OF_SPACES_IN_FORMAT+MAX_LEN_OF_NAME_RULE+MAX_STRLEN_OF_DIRECTION+2*MAX_STRLEN_OF_IP_ADDR+MAX_STRLEN_OF_PROTOCOL+2*MAX_STRLEN_OF_PORT+MAX_STRLEN_OF_ACK+MAX_STRLEN_OF_ACTION)

/**
 *	Gets a string that supposed to represent a proper rule.
 * 	Creates a rule according to str.
 * 	NOTE: str format should be:
 * 	<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <dource port> <dest port> <ack> <action>
 *	
 * If succedded, returns the pointer to rule_t created,
 * Otherwise - returns NULL
 **/
//rule_t* get_rule_from_string(const char* str);





#endif /* RULES_UTILS_H */
