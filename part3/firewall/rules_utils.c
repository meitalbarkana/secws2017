#include "rules_utils.h"

bool is_rule_name(const char* str){
	return (strnlen(str, MAX_LEN_OF_NAME_RULE+2) <= MAX_LEN_OF_NAME_RULE);
}

direction_t translate_str_to_direction(const char* str){
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

bool is_ipv4_subnet_format(char* str, __be32* ipv4value, __u8* prefixLength){
	
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

//rule_t* get_rule_from_string(const char* str){	
//}


