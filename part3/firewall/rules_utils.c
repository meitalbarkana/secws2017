#include "rules_utils.h"

bool get_rule_name(const char* str){
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


//rule_t* get_rule_from_string(const char* str){	
//}


