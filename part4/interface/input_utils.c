#include "input_utils.h"

static size_t g_num_of_valid_rules = 0;
static rule_t g_all_rules_table[MAX_NUM_OF_RULES];

/**
 * Gets a string, nullify ('\0') its characters, starting from start_index upto last_index, including both
 **/
static void nullify_str(char* str, size_t start_index, size_t last_index){
	size_t i = 0;
	for (i = start_index; i <= last_index; ++i){
		(str)[i] = '\0';
	}
}

/**
 * Gets a rulename,
 * Returns true if a rule with name "rulename" already exists in g_all_rules_table.
 **/
static bool does_rulename_already_exists(const char* rulename){
	size_t i = 0;
	for (i = 0; i < g_num_of_valid_rules; ++i){
		if (strncmp(((g_all_rules_table)[i]).rule_name, rulename, MAX_LEN_OF_NAME_RULE+1) == 0){
			return true; //rulename already exists
		}
	}
	return false;
}

/**
 * Inner function.
 * Gets a (non-NULL!) string that supposed to represent rule's name:
 * Returns: true if str can represent a valid rule's name (an empty string is valid as a rule name)
 * 			false otherwise
 **/
static bool is_rule_name(const char* str){
	if (str == NULL){
		printf("function is_rule_name got NULL value\n");
		return false;
	}
	return (strnlen(str, MAX_LEN_OF_NAME_RULE+2) <= MAX_LEN_OF_NAME_RULE);
}

/**
 *   Gets a VALID user name (its length < MAX_LEN_OF_NAME_RULE && it's not a name of any other rule)
 * 	 and a pointer to rule_t, and updates the rule so it's name would be "valid_rule_name"
 **/
 static void update_rule_name(rule_t* rule_ptr, const char* valid_rule_name){
		//Updates rule's name:
	 	strncpy(rule_ptr->rule_name, valid_rule_name, MAX_LEN_OF_NAME_RULE+1);
	 	//Makes sure a '\0' is placed at the end of the string rule_name:
	 	nullify_str(rule_ptr->rule_name, strlen(valid_rule_name), MAX_LEN_OF_NAME_RULE); 
 }

/**
 * Gets a (non-NULL!) string that supposed to represent a direction
 * If succedded, returns the relevant direction_t value
 * Otherwise - returns DIRECTION_ERROR
 **/
static direction_t translate_str_to_direction(const char* str){
	if (str == NULL){
		printf("function translate_str_to_direction got NULL value\n");
		return DIRECTION_ERROR;
	}
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
 *	Helper function: gets a string, 
 *	checks all str's characters are digits [no -,+]
 *	if they are - 
 *	Updates *num to contain the unsigned long str represents.
 * 
 * @str - string to check, HAS TO BE OF LENGTH <= max_len, otherwise false is returned
 * @max_len - str's length
 * @num - value to be updated
 * 
 * 	Returns true on success.
 **/
static bool my_strict_strtoul(const char* str, size_t max_len, unsigned long* num){
	
	char* endPtr;
	
	if (max_len == 0){
#ifdef USER_DEBUG_MODE
		printf("Tried to convert an empty string to numeric value and failed\n");
#endif
		return false;
	}
	
	if (strnlen(str, max_len+2) > max_len) {
		return false;
	}
								
	for (size_t i = 0; i < strlen(str); ++i){ //Safe to use strlen now
		if (!isdigit(str[i])){
			return false;
		}
	}
	
	//Safe to use strtoul:
	unsigned long temp = strtoul(str, &endPtr,10);
	if ((*endPtr == '\0') && (*str != '\0')){
		*num = temp;
		return true;
	}
#ifdef USER_DEBUG_MODE
	printf ("strtoul failed, endPtr is: %c\n", *endPtr);
#endif
	return false;
}


/**
 *  Helper function for input-validation:
 * 	Gets a (non-NULL!) string and checks if it's in IPv4 format - including netmask
 * 	<XXX.XXX.XXX.XXX/YY>
 *  Assuming the input's format is Big-Endian!
 * 	Returns: true if it is, false otherwise.
 * 	If the string is valid, updates: 1. ipv4value to contain the unsigned-int value of the ip 
 * 									 2. prefixLength to contain the length of the subnet prefix
 **/
static bool is_ipv4_subnet_format(const char* const_str, unsigned int* ipv4value, unsigned char* prefixLength){
	
	size_t strLength = strnlen(const_str, MAX_STRLEN_OF_IP_ADDR+2); //Because there's no need to check more chars than that..
	
	/** These variables are declared here only to avoid warning:"ISO C90 forbids mixed declarations and code"
	 * (I'd put them after the first "if")**/
	//currToken will contain "XXX" or "YY" string:
	char *currToken, *str ,*pStr; 
	//Will contain the value "XXX" or "YY" represent:
	unsigned long temp = 0; 
	//Will contain the relevant multiplicand needed for calculating ip address:
	// 2^24 = 256^3 = 16,777,216 , 2^16 = 256^2 = 65536
	// 2^8 = 256^1 = 256 , 2^0 = 256^0 = 1 
	unsigned int multiplicand = 1; 
	size_t i = 0;
	//Initiating values to zero:	
	*ipv4value = 0;
	*prefixLength = 0;
	
	//any IPv4 address <=> 0.0.0.0/0 :
	if ((strLength == 3) && ((strcmp(const_str, "any") == 0) || (strcmp(const_str, "ANY") == 0)) ){
		return true;
	}
	
	if ((strLength < MIN_STRLEN_OF_IP_ADDR) || (strLength > MAX_STRLEN_OF_IP_ADDR)){
		return false;
	}
	
	//Creating a copy of const_str:
	if((str = calloc((strLength+1),sizeof(char))) == NULL){
		printf("Failed allocating space for copying IPv4 string\n");
		return false;
	}
	strncpy(str, const_str, strLength+1);
	pStr = str;
	
	for (i = 0; i <= 4; ++i){
		currToken = strsep(&str, "./");
		if (currToken == NULL){
			free(pStr);
			return false;
		}
		if (i == 4) { //means we're at the part of the string representing the netmask length 		
			if( (!my_strict_strtoul(currToken, strLength ,&temp)) || (temp > 32)){
				free(pStr);
				return false;
			}
			*prefixLength = (unsigned char)temp; //Safe casting, since temp <= 32
		} else { // i is 0/1/2/3
			if((!my_strict_strtoul(currToken, strLength ,&temp)) || (temp > 255)){
				free(pStr);
				return false;
			}
			multiplicand = 1 << (8*(3-i));
			(*ipv4value)+= multiplicand*(unsigned int)temp; //Safe casting, since temp <= 255
		}
	}
	
	//Makes sure str didn't contain any invalid characters
	currToken = strsep(&str, "./");
	if (currToken != NULL){
		free(pStr);
		return false;
	}

	free(pStr);
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
	 *  0<=protocol<=255 (since it's of type unsigned char), so any string representing
	 *	a number in that range (different from 1/6/17/143) will be considered as "other"
	 *	if str's length is more than 3 (3+'\0'), sure it can't represent a number in [0,255] range
	 * 	[we send strnlen 5 because: 3+1(for '\0')+1(to make sure str isn't longer, because strnlen checks null-terminator char)]
	 **/
	if((strnlen(str,5) <= 3) && (sscanf(str,"%lu", &temp) == 1) && (temp <= 255)){
		return PROT_OTHER;
	}
	
	return PROT_ERROR;
}

/**
 * Gets a (non-NULL!) string that supposed to represent port number(s)
 * String valid values are:
 * 		1. "0" / "any" / "ANY" - a special value that means any port
 * 		2. any specific number between 1 to 65535 except for 1023 - see below (unsigned short <=> 2 bytes)
 * 		3. "1023" / ">1023" - means any port number > 1023
 * If succedded, returns an int(!!) of the relevant value (PORT_ANY / specific number / PORT_ABOVE_1023)
 * Otherwise - returns PORT_ERROR (-1)
 * 
 * NOTE: need to check return value from this function,
 *  	 and make casting to unsigned short if a valid (non PORT_ERROR) value returned
 **/
static int translate_str_to_int_port_number(const char* str){
	
	unsigned long temp = 0;
	
	//Since the maximum valid str length is MAX_STRLEN_OF_PORT+1(for '\0')+1 (to make sure str isn't longer):
	if(strnlen(str,MAX_STRLEN_OF_PORT+2) <= MAX_STRLEN_OF_PORT){ 
		if ((strcmp(str, ">1023") == 0) || (strcmp(str, "1023") == 0)) {
			return PORT_ABOVE_1023;
		}
		if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0)){
			return PORT_ANY;
		}
		if ((sscanf(str,"%lu", &temp) == 1) && (temp <= 65535)){
			return ((int)temp); //Safe casting since 0<=temp<=65535
		}
	}
	return PORT_ERROR;
}

/**
 * Gets a string that supposed to represent status of ack-bit and a pointer to ack (
 * String valid values are:
 * 		1. "any" / "ANY" - a special value that means any ack
 * 		2. "no" / "NO" - means ack-bit off
 * 		3. "yes" / "YES" - means ack bit on
 * If succedded, returns true and updates *ack to be the relevant value: ACK_ANY / ACK_YES / ACK_NO
 * Otherwise - returns false
 **/
static bool translate_str_to_ack(const char* str, ack_t* ack){
	//Since the maximum valid str length is MAX_STRLEN_OF_ACK+1(for '\0')+1 (to make sure str isn't longer)
	if((str != NULL) && strnlen(str,MAX_STRLEN_OF_ACK+2) <= MAX_STRLEN_OF_ACK){ 
		if ((strcmp(str, "yes") == 0) || (strcmp(str, "YES") == 0)) {
			*ack = ACK_YES;
			return true;
		}
		if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0)){
			*ack = ACK_ANY;
			return true;
		}
		if((strcmp(str, "no") == 0) || (strcmp(str, "NO") == 0)){
			*ack = ACK_NO;
			return true;
		}
	}
	return false;
}

/**
 * Gets a string that supposed to represent action to do on the packet,
 * and a pointer to "action" (unsigned char)
 * 
 * String valid values are:
 * 		1. "accept" / "ACCEPT" - means accept the message (let it pass)
 * 		2. "drop" / "DROP" - means drop the package
 * 
 * If succedded, updates *action to contain the relevant value: NF_ACCEPT, NF_DROP and returns true,
 * Otherwise - returns false
 **/
static bool translate_str_to_action(const char* str, unsigned char* action){
	//Since the maximum valid str length is MAX_STRLEN_OF_ACTION+1(for '\0')+1 (to make sure str isn't longer):

	if( (str != NULL) && (strnlen(str,MAX_STRLEN_OF_ACTION+2) <= MAX_STRLEN_OF_ACTION)){ 
		if ((strcmp(str, "accept") == 0) || (strcmp(str, "ACCEPT") == 0)) {
			*action = NF_ACCEPT;
			return true;
		}
		if((strcmp(str, "drop") == 0) || (strcmp(str, "DROP") == 0)){
			*action = NF_DROP;
			return true;
		}
	}

	return false;
}


/**
 * 	Gets a prefix_length (Big-Endian, value between 0-32)
 * 	Returns the prefix mask that prefix_length represent, in the local endianness
 **/
static unsigned int get_prefix_mask(unsigned char prefix_length){
	//0xffffffff = 11111111 11111111 11111111 11111111
	unsigned int temp = 0xffffffff;
	if (prefix_length == 32){
		return temp;
	}
	temp = temp >> (32-prefix_length); // For example: if prefix = 3, temp will contain: 00011111 11111111 11111111 11111111
	temp = temp ^ 0xffffffff; // XORing with 11...11 so that, in our example, temp =  11100000 00000000 00000000 00000000
	
	return temp;
}

/**
 *	Gets unsigned int and updates str to contain its IPv4 string representation
 *  [Format of: "XXX.XXX.XXX.XXX"]
 * 	If succeeds, returns true
 * 
 *	@str - string to be updated
 *	@len_str - str's length, should be: strlen("XXX.XXX.XXX.XXX")+1 (includs '\0')
 *
 **/
static bool tran_uint_to_ipv4str(unsigned int ip, char* str, size_t len_str){

	unsigned int p0, p1, p2, p3;
	int num_of_chars_written = 0;
	
	p3 = ip%256;
	ip = ip/256;
	p2 = ip%256;
	ip = ip/256;
	p1 = ip%256;
	ip = ip/256;
	p0 = ip%256;
	
	num_of_chars_written = snprintf(str,len_str, "%u.%u.%u.%u", p0,p1,p2,p3);
	if ( num_of_chars_written < strlen("X.X.X.X")){
		printf("Failed translating to string representation of IPv4\n");
		return false;
	}

	return true;
}

/**
 *	Gets direction_t and updates str to contain its string representation
 * 	If succeeds, returns true
 *	
 *	@str - string to be updated
 * 
 * NOTE: str's length, should be: MAX_STRLEN_OF_DIRECTION+1 (includs '\0')
 **/
static bool tran_direction_t_to_str(direction_t direc, char* str){
	
	switch (direc) {
		case(DIRECTION_IN):
			strncpy(str, "in", MAX_STRLEN_OF_DIRECTION+1);
			break;
		case(DIRECTION_OUT):
			strncpy(str, "out", MAX_STRLEN_OF_DIRECTION+1);
			break;
		case(DIRECTION_ANY):
		 	strncpy(str, "any", MAX_STRLEN_OF_DIRECTION+1);
			break;
		default: //Never supposed to get here if used correctly.
			printf("Error - tried translating wrong direction_t\n");
			return false;
	}
	return true;
}

/**
 *	Gets prot_t and updates str to contain its string representation
 * 	If succeeds, returns true
 * 
 *  @str - string to be updated
 *	NOTE: str's length, should be: MAX_STRLEN_OF_PROTOCOL+1 (includs '\0')
 **/
static bool tran_prot_t_to_str(prot_t prot, char* str){
	
	switch (prot) {
		case(PROT_ICMP):
			strncpy(str,"icmp", MAX_STRLEN_OF_PROTOCOL+1);
			break;
		case(PROT_TCP):
			strncpy(str,"tcp", MAX_STRLEN_OF_PROTOCOL+1);
			break;
		case(PROT_UDP):
			strncpy(str,"udp", MAX_STRLEN_OF_PROTOCOL+1);
			break;
		case(PROT_OTHER):
			strncpy(str,"other", MAX_STRLEN_OF_PROTOCOL+1);
			break;
		case(PROT_ANY):
			strncpy(str,"any", MAX_STRLEN_OF_PROTOCOL+1);
			break;
		default: //Never supposed to get here if used correctly.
			printf("Error - tried translating wrong prot_t\n");
			return false;
	}
	return true;
}

/**
 *	Gets unsigned short representing port number
 *  and updates str to contain its string representation
 * 	If succeeds, returns true
 * 
 *  @str - string to be updated
 *	NOTE: str's length, should be: MAX_STRLEN_OF_PORT+1 (includs '\0')
 **/
static bool tran_port_to_str(unsigned short port, char* str){
	
	switch (port) {
		case (PORT_ANY):
			strncpy(str,"any", MAX_STRLEN_OF_PORT+1);
			break;
		case(PORT_ABOVE_1023):
			strncpy(str,">1023", MAX_STRLEN_OF_PORT+1);
			break;
		default: //port is a specific number
			snprintf(str, MAX_STRLEN_OF_PORT+1, "%u", port);	
		//Note: guaranteed that port!=PORT_ERROR since PORT_ERROR==-1, and port is unsigned short
	}
	return true;
}

/**
 *	Gets ack_t representing ack
 *  and updates str to contain its string representation
 * 	If succeeds, returns true
 * 
 *  @str - string to be updated
 *	NOTE: str's length, should be: MAX_STRLEN_OF_ACK+1 (includs '\0')
 **/
static bool tran_ack_to_str(ack_t ack, char* str){
	
	switch (ack) {	
			case (ACK_ANY):
				strncpy(str,"any", MAX_STRLEN_OF_ACK+1);
				break;
			case(ACK_YES):
				strncpy(str,"yes", MAX_STRLEN_OF_ACK+1);
				break;		
			default: // == ACK_NO
				strncpy(str,"no", MAX_STRLEN_OF_ACK+1);
	}
	return true;
}

/**
 *	Gets unsigned char representing action, 
 *  updates str to contain its string representation
 * 	If succeeds, returns true
 * 
 *  @str - string to be updated
 *	NOTE: str's length, should be: MAX_STRLEN_OF_ACTION+1 (includs '\0')
 **/
static bool tran_action_to_str(unsigned char action, char* str){
	
	switch (action) {	
		case (NF_ACCEPT):
			strncpy(str, "accept", MAX_STRLEN_OF_ACTION+1);
			break;
		case(NF_DROP):
			strncpy(str, "drop", MAX_STRLEN_OF_ACTION+1);
			break;
		default: //Never supposed to get here if used correctly.
			printf("Error - tried translating wrong action\n");
			return false;
	}
	return true;
}

/**
 *	Gets an int representing reason, 
 *  updates str to contain its string representation
 * 	If succeeds, returns true
 * 
 *  @str - string to be updated
 *	NOTE: str's length, should be: MAX_STRLEN_OF_REASON+1 (includs '\0')
 **/
static bool tran_reason_to_str(int reason, char* str){

	switch (reason) {	
		case (REASON_FW_INACTIVE):
			strncpy(str, "Fw's not active", MAX_STRLEN_OF_REASON+1);
			break;
		case(REASON_NO_MATCHING_RULE):
			strncpy(str, "No matching rule", MAX_STRLEN_OF_REASON+1);
			break;
		case(REASON_XMAS_PACKET):
			strncpy(str, "XMAS packet", MAX_STRLEN_OF_REASON+1);
			break;
		case(REASON_ILLEGAL_VALUE):
			strncpy(str, "Illegal value", MAX_STRLEN_OF_REASON+1);
			break;
		default: //reason is an index
			snprintf(str, MAX_STRLEN_OF_REASON, "Rule number: %d", reason);
	}
	return true;
}


/**
 * ONLY FOR TESTS.
 * 
 * Updates str to contain a representation of a rule as a string.
 * Returns true on success.
 * 
 * NOTE: str's length, should be: MAX_STRLEN_OF_RULE_FORMAT+1 (includs '\0')
 **/
 /**
static bool get_rule_as_str(rule_t* rule, char* str){
	size_t ip_len_str = strlen("XXX.XXX.XXX.XXX")+1;
	char ip_dst_str[ip_len_str];
	char ip_src_str[ip_len_str];
	char direc_str[MAX_STRLEN_OF_DIRECTION+1];
	char protocol_str[MAX_STRLEN_OF_PROTOCOL+1];
	char s_port_str[MAX_STRLEN_OF_PORT+1];
	char d_port_str[MAX_STRLEN_OF_PORT+1];
	char ack_str[MAX_STRLEN_OF_ACK+1];
	char action_str[MAX_STRLEN_OF_ACTION+1];
	int num_of_chars_written = 0;
	
	if ( !(tran_uint_to_ipv4str(rule->src_ip, ip_src_str, ip_len_str))
		|| !(tran_uint_to_ipv4str(rule->dst_ip, ip_dst_str, ip_len_str))
		|| !(tran_direction_t_to_str(rule->direction,direc_str)) 
		|| !(tran_prot_t_to_str(rule->protocol, protocol_str))
		|| !(tran_port_to_str(rule->src_port,s_port_str))
		|| !(tran_port_to_str(rule->dst_port,d_port_str))
		|| !(tran_ack_to_str(rule->ack,ack_str)) 
		|| !(tran_action_to_str(rule->action,action_str)) )
	{
		return false;
	}
	
	//<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>
	num_of_chars_written = snprintf(str, MAX_STRLEN_OF_RULE_FORMAT+1,
									"%s %s %s/%u %s/%u %s %s %s %s %s",
									rule->rule_name,
									direc_str,
									ip_src_str,
									rule->src_prefix_size,
									ip_dst_str,
									rule->dst_prefix_size,
									protocol_str,
									s_port_str,
									d_port_str,
									ack_str,
									action_str);

	if (num_of_chars_written < MIN_STRLEN_OF_RULE_FORMAT){
		printf("Failed translating rule_t to string\n");
		return false;
	}
	
	return true;
}
**/

/**
 *	Gets a string that supposed to represent a proper rule
 *
 *  If g_num_of_valid_rules < MAX_NUM_OF_RULES:
 *  	creates a rule according to str,
 * 		inserts it to the relevant place in rule table (g_all_rules_table)
 * 		and updates g_num_of_valid_rules.
 * 
 * 	If succedded, returns true
 * 	
 * 	NOTE:1. user of this funtion should free memory allocated by it.
 * 		 2. str (inside function) is ruined (by strsep)
 * 		 3. valid str format should is:
 * 		    <rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>
 * 		 4. rules' logic is NOT tested here, user should check it!
 **/
static bool update_rule_from_string(const char* const_str){

#ifdef USER_DEBUG_MODE
	printf("str sent to update_rule_from_string() is: %s*********************\n", const_str);
#endif	

	char *str, *pStr;
	size_t i = 0;
	rule_t* rule_ptr = NULL;
	char* curr_token = NULL;
	int temp_val = 0;
	
	//Makes sure there aren't too much rules & that str isn't longer than MAX_STRLEN_OF_RULE_FORMAT
	if ((g_num_of_valid_rules >= MAX_NUM_OF_RULES) || (const_str == NULL) ||
		(strnlen(const_str, MAX_STRLEN_OF_RULE_FORMAT+2) > MAX_STRLEN_OF_RULE_FORMAT)){ 
		return false;
	}

	rule_ptr = &g_all_rules_table[g_num_of_valid_rules];
	
	//Creating a copy of const_str:
	if((str = calloc((strlen(const_str)+1), sizeof(char))) == NULL){
		printf("Error allocating memory for const_str copy inside update_rule_from_string(), ");
		return false;
	}
	strncpy(str, const_str, strlen(const_str)+1);
	pStr = str;
	
	while (i < NUM_OF_TOKENS_IN_FORMAT){
		if ((curr_token = strsep(&str, " ")) == NULL) {
			break;
		}
		if (i == 0) { //Checks curr_token is valid rule-name:
			if( is_rule_name(curr_token) && (!does_rulename_already_exists(curr_token)) ){ 
				update_rule_name(rule_ptr, curr_token); //Updates current rule's name
			} else { //not a valid rule name
				printf("Invalid rule: invalid rule-name or a rule with the same name already exists, ");
				break;
			}
		}
		else if (i == 1) { //Checks curr_token is valid direction:
			if ((rule_ptr->direction = translate_str_to_direction(curr_token)) == DIRECTION_ERROR){
				printf("Invalid rule: direction is wrong, ");
				break;
			}
		}
		else if (i == 2) { //Check curr_token is <src ip>/<nps>
			if (!is_ipv4_subnet_format(curr_token, &(rule_ptr->src_ip), &(rule_ptr->src_prefix_size))){
				printf("Invalid rule: <src ip>/<nps> is wrong, ");
				break;				
			}
			rule_ptr->src_prefix_mask = get_prefix_mask(rule_ptr->src_prefix_size);
		}
		else if (i == 3) { //Check curr_token is <dst ip>/<nps>
			if (!is_ipv4_subnet_format(curr_token, &(rule_ptr->dst_ip), &(rule_ptr->dst_prefix_size))){
				printf("Invalid rule: <dst ip>/<nps> is wrong, ");
				break;				
			}
			rule_ptr->dst_prefix_mask = get_prefix_mask(rule_ptr->dst_prefix_size);	
		}
		else if (i == 4) { //Checks curr_token is <protocol>
			if ((rule_ptr->protocol = translate_str_to_protocol(curr_token)) == PROT_ERROR){
				printf("Invalid rule: <protocol> is wrong, ");
				break;
			}
		}
		else if ((i == 5) || (i == 6)) { //Check curr_token is <source port> / <dest port>
			if ((temp_val = translate_str_to_int_port_number(curr_token)) == PORT_ERROR){
				printf("Invalid rule: <dest/src port> is wrong, ");
				break;
			}
			if (i == 5){
				rule_ptr->src_port = (unsigned short)temp_val; // Safe casting since temp_val!=PORT_ERROR
			} else { // i is 6, update dst_port:
				rule_ptr->dst_port = (unsigned short)temp_val;
			}
		}
		else if (i == 7) { //Check curr_token is <ack>
			if (!translate_str_to_ack(curr_token, &(rule_ptr->ack))){
				printf("Invalid rule: <ack> is wrong, ");
				break;
			}	
		}
		else { // i == 8, last index that is < NUM_OF_TOKENS_IN_FORMAT. Check curr_token is <action> 
			if(!translate_str_to_action(curr_token, &(rule_ptr->action))){
				printf("Invalid rule: <action> is wrong, ");
				break;
			}
		}
		
		++i;
	}
	
	if ( i != NUM_OF_TOKENS_IN_FORMAT) { // Means loop was broken - str isn't a valid rule
		free(pStr);
		return false;		
	}
	
	//Makes sure str didn't contain any invalid characters (at its end)
	curr_token = strsep(&str, " ");
	if (curr_token != NULL){
		free(pStr);
		return false;
	}

	//If gets here, we have a valid rule:
	free(pStr);
	++g_num_of_valid_rules;
	
#ifdef USER_DEBUG_MODE
	printf("g_num_of_valid_rules is updated to: %u.\n",g_num_of_valid_rules);
#endif

	return true;

}


/**
 * @rule - pointer to initialized rule_t that we check if 
 * 		   can indeed represent a reasonable rule.
 * 
 * Returns true if it is.
 **/
static bool is_valid_rule_logic(rule_t* rule){
	
	//Rule that is NOT about TCP / UDP, has to have
	// dst_port==src_port==PORT_ANY to be considered valid:
	if ( (rule->protocol != PROT_TCP) && (rule->protocol != PROT_UDP)
		&& ((rule->src_port != PORT_ANY) || (rule->dst_port != PORT_ANY) )){
		return false;
	}
	
	//Rule that is NOT about TCP, has to have ACK == ACK_ANY 
	//	or ACK == ACK_NO to be considered valid:
	if ((rule->protocol != PROT_TCP) && (rule->ack == ACK_YES)) {
		return false;
	}
	
	//TODO:: think of more ideas to test..
	return true;
}

/**
 *	Gets a NULL TERMINATED string,
 *	Removes '\n' characters from the end of it
 * (2 chars if str was created from windows-compatible source)
 * 
 **/
static void delete_backslash_n(char* str){
	size_t len = strlen(str);
	if (len == 0){
		return;
	}
	if (len == 1) {
		if ((str[0] == CHAR_CR) || (str[0] == CHAR_LF)){
			str[0] = '\0';
		}
		return;
	}
	//str length >=2:
	if ((str[len-1] == CHAR_CR) || (str[len-1] == CHAR_LF)){
		str[len-1] = '\0';
	}
	if ((str[len-2] == CHAR_CR) || (str[len-2] == CHAR_LF)){
		str[len-2] = '\0';
	}
}


/**
 * Gets a path to file containing all rules,
 * initiates g_all_rules_table accordingly.
 * 
 * File should contain rules in format of: <rule>\n<rule>\n...
 * 
 * Rule format: <rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>
 * 
 * Returns: number of rules written to rules-table on success,
 * 			(-1) if failed.
 * 
 * NOTE: if table already has rules, this function will discard all old rules!
 **/
int read_rules_from_file(const char* file_path){
	
	g_num_of_valid_rules = 0;
	
	struct stat st;
	
	//st_size is of type off_t which is signed integer - so might be negative, if an error occurred..
	if ((stat(file_path, &st) != 0) || (st.st_size <= 0)) { 
		printf ("Error getting file's stat\n");
		return -1;
	}
	
	FILE* fp;
	char* buffer = NULL; 
	size_t bytes_allocated = 0;
	ssize_t line_length = 0;
	int lines_checked = 0;
	
	if((fp = fopen(file_path,"r")) == NULL){
		printf ("Error opening rules-filet\n");
		return -1;
	}
	
	//Read file line-by-line:
	while ((g_num_of_valid_rules < MAX_NUM_OF_RULES) && 
			((line_length = getline(&buffer, &bytes_allocated, fp)) != -1)
			&&(lines_checked < MAX_LINES_TO_CHECK_IN_FILE) )
	{
		if (line_length < MIN_STRLEN_OF_RULE_FORMAT) { 
			printf("Invalid line in file, discarded it.\n");
		} 
		else {
			//Gets rid of '\n' at the end of buffer:
			delete_backslash_n(buffer);
			if (!update_rule_from_string(buffer)) {
				printf("Invalid format line in file, discarded it.\n");
			} 
			else { 
				
				//A rule was added. checks rule has reasonable logic:
				//the (-1) since g_num_of_valid_rules was already updated in update_rule_from_string
				if (!is_valid_rule_logic(&(g_all_rules_table[g_num_of_valid_rules-1]))){ 
					printf("Rule has no reasonable logic. It was removed from g_all_rules_table.\n");
					--g_num_of_valid_rules;
				}
				
			}
		}
		++lines_checked;
		free(buffer);
		buffer = NULL;
	}
	
	free(buffer);
	fclose(fp);

	return g_num_of_valid_rules;
}

/**
 * Returns true if path is a file (not a directory)
 **/
bool valid_file_path(const char* path){
	struct stat fileData;
	if (stat(path, &fileData) == 0 && S_ISREG(fileData.st_mode)){
		return true;
	}
	return false;
} 


/**
 *	Build a buffer that contain all rules from g_all_rules_table,
 * 	in format expected by the firewall:
 * 
 * 	FORMAT:
 * 		Buffer := [RULE]\n...[RULE]\n
 * 		RULE := <rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>
 *
 *	Returns: buffer on success, NULL if error happened 
 *
 *	Note: user should free memory allocated for string returned!
 **/
static char* build_all_rules_format(){
	
	size_t enough_len = (MAX_STRLEN_OF_FW_RULE_FORMAT*MAX_NUM_OF_RULES) + MAX_NUM_OF_RULES + 1; //for 50*'\n' & '\0' 
	char* buffer = calloc(enough_len,sizeof(char));
	if (buffer == NULL) {
		printf("Error: allocation failed, couldn't build all-rule-format\n");
		return NULL;
	}
	
	size_t buff_offset = 0;
	
	rule_t* rulePtr;
	
	for (size_t i = 0; i < g_num_of_valid_rules; ++i){
		rulePtr = &(g_all_rules_table[i]);
		if ((sprintf( (buffer+buff_offset),		//pointer arithmetic
				"%s %d %u %hhu %u %hhu %hhu %hu %hu %d %hhu\n",
				rulePtr->rule_name,
				rulePtr->direction,
				rulePtr->src_ip,
				rulePtr->src_prefix_size,
				rulePtr->dst_ip,
				rulePtr->dst_prefix_size,
				rulePtr->protocol,
				rulePtr->src_port,
				rulePtr->dst_port,
				rulePtr->ack,
				rulePtr->action)
		) < (NUM_OF_FIELDS_IN_FWRULE+SPACES_IN_FWFORMAT+1))
		{
			printf("Error formatting rule to its string representation\n"); //Should never get here..
			free(buffer);
			return NULL;
		} 
		
		buff_offset = strlen(buffer);
	}

	return buffer;
	
}


/**
 *	Sends all rules in g_all_rules_table to fw.
 * 
 *	Returns:	1. NO_RULE_RECIEVED - if fw didn't add any rule
 * 				2. PARTIAL_RULE_RECIEVED - if fw added some of the rules
 * 				3. ALL_RULE_RECIEVED - if fw added all rule
 **/
enum rules_recieved_t send_rules_to_fw(void){
	
	char* buff = build_all_rules_format();
	
	if ((buff == NULL) || (strlen(buff) == 0)){
		printf("Error: failed to create all-rules buffer.\n");
		return NO_RULE_RECIEVED;
	}

	int fd = open(PATH_TO_RULE_DEV,O_WRONLY); // Open device with write only permissions
	if (fd < 0){
		printf("Error accured trying to open fw_rules device, error number: %d\n", errno);
		free (buff);
		return NO_RULE_RECIEVED;
	}
	
	int bytes_to_write = strlen(buff);
	int bytes_written = -1;
	
#ifdef USER_DEBUG_MODE	
	printf("Bytes supposed to be written to fw_rules: %d\n", bytes_to_write);
#endif	

	if ( (bytes_written = write(fd, buff, bytes_to_write)) < 0){
		printf("Error accured trying to write rules into fw_rules device\n");
		close(fd);
		free(buff);
		return NO_RULE_RECIEVED;
	}
	close(fd);
	
#ifdef USER_DEBUG_MODE	
	printf("Bytes supposed to be written to fw_rules: %d, acctually written: %d\n", bytes_to_write, bytes_written);
#endif	
	
	
#ifdef USER_DEBUG_MODE
	printf ("BUFF IS:\n***********************************************************************\n");
	printf("%s", buff);
	/**
	for (size_t i = 0; i < strlen(buff); ++i){
		if ( buff[i] == CHAR_CR || buff[i] == CHAR_LF){
			printf("**%d**\n",buff[i]);
		} else {
			printf("%c",buff[i]);
		}
	}
	**/
#endif		

	free(buff);
	
	return ((bytes_written < bytes_to_write) ? PARTIAL_RULE_RECIEVED : ALL_RULE_RECIEVED);
}

/**
 *	Reads active status from fw
 * 
 *	Returns: 0 - if fw is deactivated
 * 			 1 - if fw is active
 * 			-1 - if an error occured
 * 
 **/
int get_fw_active_stat(void){
	
	char* buff;
	
	if ( (buff = calloc(2,sizeof(char))) == NULL){
		printf("Allocating buffer failed\n");
		return -1;
	} 
	
	int fd = open(PATH_TO_ACTIVE_ATTR,O_RDONLY); // Open device with read only permissions
	if (fd < 0){
		printf("Error accured trying to open the rules-device for reading status, error number: %d\n", errno);
		free(buff);
		return -1;
	}
	
	if (read(fd, buff, 1) <= 0){
		printf("Error accured trying to read firewall's active state, error number: %d\n", errno);
		free(buff);
		close(fd);
		return -1;
	}
	close(fd);
	if (strcmp(buff, DEACTIVATE_STRING) == 0) {
		free(buff);
		return 0;
	} else if (strcmp(buff, ACTIVATE_STRING) == 0) {
		free(buff);
		return 1;
	}
	
	//Never supposed to get here:
	printf ("Error: buffer returned with unknown value\n");
	free(buff);
	return -1;
}

/**
 *	Gets a buffer that contain all rules from g_all_rules_table,
 * 	in format:
 * 
 * 	FORMAT:
 * 		Buffer := [RULE]\n...[RULE]\n
 * 		RULE := <rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>
 *
 *	Returns: buffer on success, NULL if error happened 
 *
 *	Note: user should free memory allocated for string returned!
 **/
static char* get_all_rules_from_fw(void){
	
	int curr_read_bytes = 0;
	size_t total_bytes_read = 0;
	
	//Allocates room for MAX_NUM_OF_RULES+1 rules (to make sure there's enough room)
	//the "+ MAX_NUM_OF_RULES + 1" is for all seperating'\n' and for '\0': 
	size_t enough_len = (MAX_STRLEN_OF_FW_RULE_FORMAT*(MAX_NUM_OF_RULES+1))
							+ MAX_NUM_OF_RULES + 1; 
	char* buffer = calloc(enough_len,sizeof(char));
	if (buffer == NULL) {
		printf("Error: allocation failed, couldn't get all rules from fw\n");
		return NULL;
	}
	
	size_t len_to_read = enough_len-1;
	int fd = open(PATH_TO_RULE_DEV,O_RDONLY); // Open device with read only permissions
	if (fd < 0){
		printf("Error accured trying to open the rules-device for reading all rules, error number: %d\n", errno);
		free(buffer);
		return NULL;
	}

	while ( (len_to_read >= MAX_STRLEN_OF_FW_RULE_FORMAT+1 ) &&
			((curr_read_bytes = read(fd, buffer+total_bytes_read, len_to_read)) > 0) )
	{
		total_bytes_read+=curr_read_bytes;
		if (curr_read_bytes <= len_to_read){
			len_to_read = len_to_read - curr_read_bytes;
		} else {
			printf("No room to read any more data from fw\n");
			len_to_read = 0;
		}
		
	}

	close(fd);
	
	if (curr_read_bytes < 0) {
		//Some error accured
		printf("Failed reading all rules from fw.\n");
		free(buffer);
		return NULL;
	}
	
	return buffer;
}

/**
 *	Gets a string representing rule, in format:
 *	<rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>
 *	and print it in format:
 *	<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>'\n'
 *	
 *	Returns true on success.
 **/
static bool print_token_rule(char* rule_token){
	
	//Temporeries:
	char str[MAX_STRLEN_OF_RULE_FORMAT+MAX_ADD_LEN_TRANSLATE+1];
	char t_rule_name[MAX_LEN_OF_NAME_RULE+1];
	int t_direction = 0;
	unsigned int t_src_ip = 0;
	unsigned char t_src_prefix_length = 0;
	unsigned int t_dst_ip = 0;
	unsigned char t_dst_prefix_length = 0;
	unsigned char t_protocol = 0;
	unsigned short t_src_port = 0;
	unsigned short t_dst_port = 0;
	int t_ack = 0;
	unsigned char t_action = 0;
	
	size_t ip_len_str = strlen("XXX.XXX.XXX.XXX")+1;
	char ip_dst_str[ip_len_str];
	char ip_src_str[ip_len_str];
	char direc_str[MAX_STRLEN_OF_DIRECTION+1];
	char protocol_str[MAX_STRLEN_OF_PROTOCOL+1];
	char s_port_str[MAX_STRLEN_OF_PORT+1];
	char d_port_str[MAX_STRLEN_OF_PORT+1];
	char ack_str[MAX_STRLEN_OF_ACK+1];
	char action_str[MAX_STRLEN_OF_ACTION+1];
	
	if(rule_token == NULL) {
#ifdef USER_DEBUG_MODE
		printf("function print_token_rule() got NULL argument\n");
#endif
		return false;
	}
	
	if ( (sscanf(rule_token, "%19s %10d %u %hhu %u %hhu %hhu %hu %hu %d %hhu",
			t_rule_name,
			&t_direction,
			&t_src_ip,
			&t_src_prefix_length,
			&t_dst_ip,
			&t_dst_prefix_length,
			&t_protocol,
			&t_src_port,
			&t_dst_port,
			&t_ack,
			&t_action)) < NUM_OF_FIELDS_IN_FWRULE ) 
	{
		
#ifdef USER_DEBUG_MODE
		printf("Couldn't parse rule_token to valid fields.\n");
#endif
		return false;
	}
	
	if ( !(tran_uint_to_ipv4str(t_src_ip, ip_src_str, ip_len_str))
		|| !(tran_uint_to_ipv4str(t_dst_ip, ip_dst_str, ip_len_str))
		|| !(tran_direction_t_to_str(t_direction,direc_str)) 
		|| !(tran_prot_t_to_str(t_protocol, protocol_str))
		|| !(tran_port_to_str(t_src_port,s_port_str))
		|| !(tran_port_to_str(t_dst_port,d_port_str))
		|| !(tran_ack_to_str(t_ack,ack_str)) 
		|| !(tran_action_to_str(t_action,action_str)) )
	{
		return false;
	}
	
	//<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>
	int num_of_chars_written = snprintf(str, MAX_STRLEN_OF_RULE_FORMAT+1,
									"%s %s %s/%u %s/%u %s %s %s %s %s",
									t_rule_name,
									direc_str,
									ip_src_str,
									t_src_prefix_length,
									ip_dst_str,
									t_dst_prefix_length,
									protocol_str,
									s_port_str,
									d_port_str,
									ack_str,
									action_str);

	if (num_of_chars_written < MIN_STRLEN_OF_RULE_FORMAT){
#ifdef USER_DEBUG_MODE
		printf("Failed translating rule to string\n");
#endif
		return false;
	}
	
	printf("%s\n", str);
	
	return true;
	
}



/**
 *	Reads all rules from fw and prints them by format:
 *	<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>'\n'...
 *	
 *	Returns 0 on success, -1 if failed
 **/
int print_all_rules_from_fw(void){
	
	char* rule_token = NULL;
	char* ptr_copy_buffer;
	char* buffer = get_all_rules_from_fw();
	bool error_occured = false;

	if (buffer == NULL) {
		return -1;
	}
	
	//Since strsep ruin buffer:
	ptr_copy_buffer = buffer;
	
	while ((rule_token = strsep(&buffer, DELIMETER_STR)) != NULL
			&& (strlen(rule_token) > 0)) //Last token is empty if valid format recieved
	{
		if (!print_token_rule(rule_token)) {
			error_occured = true;
		}
	}	
	
	free(ptr_copy_buffer);
	
	if (error_occured) {
		printf("Some of the rules weren't printed.\n");
		return -1;
	}
	
	return 0;
		
}

/**
 *	Sends firewall the "clear rules" sign
 * 
 *	Returns 0 on success, -1 if failed (prints relevant errors to screen)
 **/
int clear_rules(void){
	
	char* buff = CLEAR_RULES_STRING;

	int fd = open(PATH_TO_RULE_DEV,O_WRONLY); // Open device with write only permissions
	if (fd < 0){
		printf("Error accured trying to open fw_rules device for clearing all rules, error number: %d\n", errno);
		return -1;
	}
	
#ifdef USER_DEBUG_MODE	
	printf("Bytes supposed to be written to fw_rules: %d\n", strlen(buff));
#endif	

	if ( write(fd, buff, strlen(buff)) <= 0){
		printf("Error accured trying to clear all fw rules\n");
		close(fd);
		return -1;
	}
	close(fd);

	printf("Successfully sent fw command to clear all rules. Use show_rules to make sure everything was deleted.\n");
	return 0;
}


/**
 * Sends relevant clear-log string to fw.
 * 
 * Returns 0 on success, -1 if failed
 *	
 * Note: function prints errors, if any, to screen
 **/
int clear_log(void){
	char* buff = DELETE_LOG_STRING;

	// Open device with write only permissions:
	int fd = open(PATH_TO_LOG_CLEAR_ATTR,O_WRONLY); 
	if (fd < 0){
		printf("Error accured trying to open fw_log device for clearing all log-rows, error number: %d\n", errno);
		return -1;
	}

	if ( write(fd, buff, strlen(buff)) <= 0){
		printf("Error accured trying to clear log-rows\n");
		close(fd);
		return -1;
	}
	close(fd);

	printf("Successfully sent fw command to clear log. Use show_log to make sure everything was deleted.\n");
	return 0;
}

/**
 *	Gets a buffer that contain all fw's log-rows,
 * 	in format:
 * 
 * 	FORMAT:
 * 		Buffer := [log_row]\n...[log_row]\n
 * 		log_row := <timestamp> <protocol> <action> <hooknum> <src ip> <dst ip> <source port> <dest port> <reason> <count>
 *
 *	Returns: buffer on success, NULL if error happened 
 *
 *	Note: user should free memory allocated for string returned!
 **/
static char* get_log_rows_from_fw(){
	int curr_read_bytes = 0;
	size_t total_bytes_read = 0;
	
	//Allocates room for MAX_NUM_OF_LOG_ROWS+1 (to make sure there's enough room)
	//+1 is for '\0': 
	size_t enough_len = (MAX_STRLEN_OF_LOGROW_FORMAT*(MAX_NUM_OF_LOG_ROWS+1)) + 1; 
	char* buffer = calloc(enough_len,sizeof(char));
	if (buffer == NULL) {
		printf("Error: allocation failed, couldn't get all rules from fw\n");
		return NULL;
	}
	
	size_t len_to_read = enough_len-1;
	// Open device with read only permissions:
	int fd = open(PATH_TO_LOG_DEV,O_RDONLY);
	if (fd < 0){
		printf("Error accured trying to open the log-device for reading all log-rows, error number: %d\n", errno);
		free(buffer);
		return NULL;
	}

	while ( (len_to_read >= MAX_STRLEN_OF_LOGROW_FORMAT+1 ) &&
			((curr_read_bytes = read(fd, buffer+total_bytes_read, len_to_read)) > 0) )
	{
		total_bytes_read+=curr_read_bytes;
		if (curr_read_bytes <= len_to_read){
			len_to_read = len_to_read - curr_read_bytes;
		} else {
			printf("No room to read any more data from fw (log device)\n");
			len_to_read = 0;
		}
		
	}

	close(fd);
	
	if (curr_read_bytes < 0) {
		//Some error accured
		printf("Failed reading log-rows from fw.\n");
		free(buffer);
		return NULL;
	}
	
	return buffer;
}


/**
 *	Gets a string representing log-row, in format:
 *	<timestamp> <protocol> <action> <hooknum> <src ip> <dst ip> <source port> <dest port> <reason> <count>
 *	and print it in format:
 *	<timestamp> <protocol> <action> <hooknum> <src ip> <dst ip> <source port> <dest port> <reason> <count>'\n'
 *	(in their string representation)
 * 
 *	Returns true on success.
 **/
static bool print_log_row_format(char* log_token){
		
	//Temporeries:
	char str[MAX_STRLEN_OF_LOGROW_FORMAT+MAX_ADD_LEN_TRANSLATE+1];
	unsigned long t_timestamp = 0;
	unsigned char t_protocol = 0;
	unsigned char t_action = 0;
	unsigned char t_hooknum = 0;
	unsigned int t_src_ip = 0;
	unsigned int t_dst_ip = 0;
	unsigned short t_src_port = 0;
	unsigned short t_dst_port = 0;
	int t_reason = 0;
	unsigned int t_count = 0;
	
	size_t ip_len_str = strlen("XXX.XXX.XXX.XXX")+1;
	char ip_dst_str[ip_len_str];
	char ip_src_str[ip_len_str];
	char protocol_str[MAX_STRLEN_OF_PROTOCOL+1];
	char s_port_str[MAX_STRLEN_OF_PORT+1];
	char d_port_str[MAX_STRLEN_OF_PORT+1];
	char action_str[MAX_STRLEN_OF_ACTION+1];
	char reason_str[MAX_STRLEN_OF_REASON+1];
	
	if(log_token == NULL) {
#ifdef USER_DEBUG_MODE
		printf("function print_log_row_format() got NULL argument\n");
#endif
		return false;
	}
	
	if ( (sscanf(log_token, "%lu %hhu %hhu %hhu %u %u %hu %hu %d %u\n",
			&t_timestamp,
			&t_protocol,
			&t_action,
			&t_hooknum,
			&t_src_ip,
			&t_dst_ip,
			&t_src_port,
			&t_dst_port,
			&t_reason,
			&t_count)) < NUM_OF_FIELDS_IN_LOG_ROW_T ) 
	{
		
#ifdef USER_DEBUG_MODE
		printf("Couldn't parse log_token to valid fields.\n");
#endif
		return false;
	}
	
	if ( !(tran_uint_to_ipv4str(t_src_ip, ip_src_str, ip_len_str))
		|| !(tran_uint_to_ipv4str(t_dst_ip, ip_dst_str, ip_len_str)) 
		|| !(tran_prot_t_to_str(t_protocol, protocol_str))
		|| !(tran_port_to_str(t_src_port,s_port_str))
		|| !(tran_port_to_str(t_dst_port,d_port_str))
		|| !(tran_action_to_str(t_action,action_str))
		|| !(tran_reason_to_str(t_reason, reason_str)) )
	{
		return false;
	}
	
	//<timestamp> <protocol> <action> <hooknum> <src ip> <dst ip> <source port> <dest port> <reason> <count>'\n'
	int num_of_chars_written = snprintf(str, MAX_STRLEN_OF_LOGROW_FORMAT+1,
									"%lu %s %s %hhu %s %s %s %s %s %u",
									t_timestamp,
									protocol_str,
									action_str,
									t_hooknum,
									ip_src_str,
									ip_dst_str,
									s_port_str,
									d_port_str,
									reason_str,
									t_count);

	if (num_of_chars_written < MIN_STRLEN_OF_RULE_FORMAT){
#ifdef USER_DEBUG_MODE
		printf("Failed translating log-row to string\n");
#endif
		return false;
	}
	
	printf("%s\n", str);
	
	return true;
	
}

/**
 *	Reads all log-rows from fw and prints them by format:
 *	<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>'\n'...
 *	
 *	Returns 0 on success, -1 if failed
 **/
int print_all_log_rows(void){
	
	char* log_token = NULL;
	char* ptr_copy_buffer;
	char* buffer = get_log_rows_from_fw();
	bool error_occured = false;

	if (buffer == NULL) {
		return -1;
	}
	
	//Since strsep ruin buffer:
	ptr_copy_buffer = buffer;
	
	while ((log_token = strsep(&buffer, DELIMETER_STR)) != NULL
			&& (strlen(log_token) > 0)) //Last token is empty if valid format recieved
	{
		if (!print_log_row_format(log_token)) {
			error_occured = true;
		}
	}	
	
	free(ptr_copy_buffer);
	
	if (error_occured) {
		printf("Some of the log-rows weren't printed.\n");
		return -1;
	}
	
	return 0;
		
}

/**
 *	Reads fw_log_size to get its size.
 *	On success - returns size,
 * 	Otherwise returns -1.
 * 
 **/
int get_num_log_rows(void){
	
	char* buff;
	
	if ( (buff = calloc(MAX_STRLEN_OF_BE32+2,sizeof(char))) == NULL){ //+2 for '\0', +/- sign
		printf("Allocating buffer for getting number of rows from fw_log failed\n");
		return -1;
	} 
	
	// Open device with read only permissions:
	int fd = open(PATH_TO_LOG_SIZE_ATTR,O_RDONLY);
	if (fd < 0){
		printf("Error occured trying to open the log-device for reading number of rows, error number: %d\n", errno);
		free(buff);
		return -1;
	}
	
	if (read(fd, buff, 1) <= 0){
		printf("Error occured trying to read number of rows in firewall's log, error number: %d\n", errno);
		free(buff);
		close(fd);
		return -1;
	}
	close(fd);
	
	int num = -1;
	//If sscanf failes, num is already initiated to -1:
	sscanf(buff, "%11d",&num);
	
	free(buff);
	return num;
	
}


