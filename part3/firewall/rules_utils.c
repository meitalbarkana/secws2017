#include "rules_utils.h"

/**
 * Inner function.
 * Gets a (non-NULL!) string that supposed to represent rule's name:
 * Returns: true if str can represent a valid rule's name
 * 			false otherwise
 **/
static bool is_rule_name(const char* str){
	return (strnlen(str, MAX_LEN_OF_NAME_RULE+2) <= MAX_LEN_OF_NAME_RULE);
}

/**
 * Gets a (non-NULL!) string that supposed to represent a direction
 * If succedded, returns the relevant direction_t value
 * Otherwise - returns DIRECTION_ERROR
 **/
static direction_t translate_str_to_direction(const char* str){
	//By strcmp() documentation, since we're comparing between strings with constatn length ("in","out", etc.) - it's safe 
	if((strcmp(str, "in") == 0) || (strcmp(str, "IN") == 0)){
		return DIRECTION_IN;
	}
	if((strcmp(str, "out") == 0) || (strcmp(str, "OUT") == 0)){
		return DIRECTION_OUT;
	}
	if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0)){
		return DIRECTION_ANY;
	}
	
	return DIRECTION_ERROR;
}

/**
 *  Helper function for input-validation:
 * 	Gets a (non-NULL!) string and checks if it's in IPv4 format - including netmask
 * 	<XXX.XXX.XXX.XXX/YY>
 *  Assuming the input's format is Big-Endian!
 * 	Returns: true if it is, false otherwise.
 * 	If the string is valid, updates: 1. ipv4value to contain the unsigned-int value of the ip 
 * 									 2. prefixLength to contain the length of the subnet prefix
 * 
 *  Note: str shouldn't be const- so copy it if needed before sending input to this function!
 **/
static bool is_ipv4_subnet_format(char* str, __be32* ipv4value, __u8* prefixLength){
	
	size_t maxFormatLen = strlen("XXX.XXX.XXX.XXX/YY"); // = 18
	size_t minFormatLen = strlen("X.X.X.X/Y"); // = 9
	size_t strLength = strnlen(str, maxFormatLen+2); //Because there's no need to check more chars than that..
	
	/** These variables are declared here only to avoid warning:"ISO C90 forbids mixed declarations and code"
	 * (I'd put them after the first "if")**/
	//Will contain "XXX" or "YY" string:
	char* currToken; 
	//Will contain the value "XXX" or "YY" represent:
	unsigned long temp = 0; 
	//Will contain the relevant multiplicand needed for calculating ip address:
	// 2^24 = 256^3 = 16,777,216 , 2^16 = 256^2 = 65536
	// 2^8 = 256^1 = 256 , 2^0 = 256^0 = 1 
	unsigned int multiplicand = 1; 
	size_t i = 0;	
	
	if ((strLength < minFormatLen) || (strLength > maxFormatLen)){
		return false;
	}

	*ipv4value = 0;
	*prefixLength = 0;

	for (i = 0; i <= 4; ++i){
		currToken = strsep(&str, "./");
		if (currToken == NULL){
			return false;
		}
		if (i == 4) { //means we're at the part of the string representing the netmask length 
			if((strict_strtoul(currToken, 10,&temp) != 0) || (temp > 32)){ //strict_strtoul() returns 0 on success
				return false;
			}
			*prefixLength = (__u8)temp;	//Safe casting, since temp <= 32
		} else { // i is 0/1/2/3
			if((strict_strtoul(currToken, 10,&temp) != 0) || (temp > 255)){
				return false;
			}
			multiplicand = 1 << (8*(3-i));
			(*ipv4value)+= multiplicand*(unsigned int)temp; //Safe casting, since temp <= 255
		}
	}
	
	//Makes sure str didn't contain any invalid characters
	currToken = strsep(&str, "./");
	if (currToken != NULL){
		return false;
	}
	
	return true;
}

/**
 * Gets a (non-NULL!) string that supposed to represent the protocol
 * If succedded, returns the relevant prot_t value
 * Otherwise - returns PROT_ERROR
 **/
static prot_t translate_str_to_protocol(const char* str){
	
	unsigned long temp = 0; //Might be needed in case of "other" protocol
	
	//By strcmp() documentation, since we're comparing between strings with constatn length ("any","ICMP", etc.) - it's safe 
	if((strcmp(str, "icmp") == 0) || (strcmp(str, "ICMP") == 0) || (strcmp(str, "1") == 0)){
		return PROT_ICMP;
	}
	if((strcmp(str, "tcp") == 0) || (strcmp(str, "TCP") == 0) || (strcmp(str, "6") == 0)){
		return PROT_TCP;
	}
	if((strcmp(str, "udp") == 0) || (strcmp(str, "UDP") == 0) || (strcmp(str, "17") == 0)){
		return PROT_UDP;
	}
	if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0) || (strcmp(str, "143") == 0)){
		return PROT_ANY;
	}
	if ((strcmp(str, "other") == 0) || (strcmp(str, "OTHER") == 0) || (strcmp(str, "255") == 0)){
		return PROT_OTHER;
	}
	/** 
	 *  0<=protocol<=255 (since it's of type __u8), so any string representing
	 *	a number in that range (different from 1/6/17/143) will be considered as "other"
	 *	if str's length is more than 3 (3+'\0'), sure it can't represent a number in [0,255] range
	 * 	[we send strnlen 5 because: 3+1(for '\0')+1(to make sure str isn't longer, because strnlen checks null-terminator char)]
	 **/
	if((strnlen(str,5) <= 3) && (strict_strtoul(str, 10,&temp) == 0) && (temp <= 255)){
		return PROT_OTHER;
	}
	
	return PROT_ERROR;
}

/**
 * Gets a (non-NULL!) string that supposed to represent port number(s)
 * String valid values are:
 * 		1. "0" / "any" / "ANY" - a special value that means any port
 * 		2. any specific number between 1 to 65535 except for 1023 - see below (__be16 <=> unsigned short <=> 2 bytes)
 * 		3. "1023" / ">1023" - means any port number > 1023
 * If succedded, returns an int(!!) of the relevant value (PORT_ANY / specific number / PORT_ABOVE_1023)
 * Otherwise - returns PORT_ERROR (-1)
 * 
 * NOTE: need to check return value from this function,
 *  	 and make casting to unsigned short if a valid (non PORT_ERROR) value returned
 **/
static int translate_str_to_int_port_number(const char* str){
	unsigned long temp = 0;
	if(strnlen(str,7) <= 5){ //Since the maximum valid str length is 5+1(for '\0')+1 (to make sure str isn't longer)
		if ((strcmp(str, ">1023") == 0) || (strcmp(str, "1023") == 0)) {
			return PORT_ABOVE_1023;
		}
		if ((strict_strtoul(str, 10,&temp) == 0) && (temp <= 65535)){
			return ((int)temp); //Safe casting since 0<=temp<=65535
		}
	}
	return PORT_ERROR;
}

//rule_t* get_rule_from_string(const char* str){	
//}


