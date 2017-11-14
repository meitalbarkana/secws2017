#ifndef RULES_UTILS_H
#define RULES_UTILS_H

#include "fw.h"
#define MAX_LEN_OF_NAME_RULE 19 //since rule_t.rule_name is of length 20, including 

/**
 * Gets a string that supposed to represent rule's name:
 * Returns: true if str can represent a valid rule's name
 * 			false otherwise
 **/
bool get_rule_name(const char* str);

/**
 * Gets a string that supposed to represent a direction
 * If succedded, returns the relevant direction_t value
 * Otherwise - returns DIRECTION_ERROR
 **/
direction_t translate_str_to_direction(const char* str);

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
