#ifndef RULES_UTILS_H
#define RULES_UTILS_H

#include "fw.h"
#define MAX_LEN_OF_NAME_RULE 19 //since rule_t.rule_name is of length 20, including 

/**
 * Gets a string that supposed to represent rule's name:
 * Returns: true if str can represent a valid rule's name
 * 			false otherwise
 **/
bool is_rule_name(const char* str);

/**
 * Gets a string that supposed to represent a direction
 * If succedded, returns the relevant direction_t value
 * Otherwise - returns DIRECTION_ERROR
 **/
direction_t translate_str_to_direction(const char* str);

/**
 *  Helper function for input-validation:
 * 	Gets a string and checks if it's in IPv4 format - including netmask
 * 	<XXX.XXX.XXX.XXX/YY>
 *  Assuming the input's format is Big-Endian!
 * 	Returns: true if it is, false otherwise.
 * 	If the string is valid, updates: 1. ipv4value to contain the unsigned-int value of the ip 
 * 									 2. prefixLength to contain the length of the subnet prefix
 * 
 *  Note: str shouldn't be const- so copy it if needed before sending input to this function!
 **/
 bool is_ipv4_subnet_format(char* str, __be32* ipv4value, __u8* prefixLength);


/**
 * Gets a string that supposed to represent the protocol
 * If succedded, returns the relevant prot_t value
 * Otherwise - returns PROT_ERROR
 **/
prot_t translate_str_to_protocol(const char* str);


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
