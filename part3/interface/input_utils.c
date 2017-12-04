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
 *  Helper function for input-validation:
 * 	Gets a (non-NULL!) string and checks if it's in IPv4 format - including netmask
 * 	<XXX.XXX.XXX.XXX/YY>
 *  Assuming the input's format is Big-Endian!
 * 	Returns: true if it is, false otherwise.
 * 	If the string is valid, updates: 1. ipv4value to contain the unsigned-int value of the ip 
 * 									 2. prefixLength to contain the length of the subnet prefix
 **/
static bool is_ipv4_subnet_format(const char* const_str, unsigned int* ipv4value, unsigned char* prefixLength){
	
	//MAX_STRLEN_OF_IP_ADDR = strlen("XXX.XXX.XXX.XXX/YY") = 18
	//MIN_STRLEN_OF_IP_ADDR = strlen("X.X.X.X/Y") = 9
	size_t strLength = strnlen(const_str, MAX_STRLEN_OF_IP_ADDR+2); //Because there's no need to check more chars than that..
	
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
	
	char ip[strLength];
	
	if ( (sscanf(const_str,"%15s/%2hhu", ip, prefixLength) != 2) || 
		 (*prefixLength > MAX_PREFIX_LEN_VALUE) )
	{
		return false;
	}
	//If got here, 0<=*prefixLength<=32
	
	struct in_addr addr;

    if (inet_pton(AF_INET, ip , &addr) == 1){ 
		//Conerting string to ip address, network order, succeeded:
        *ipv4value = ntohl(addr.s_addr);
    } else {
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
	if((str != NULL) && strnlen(str,MAX_STRLEN_OF_ACTION+2) <= MAX_STRLEN_OF_ACTION){ 
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
 * Updates str to contain a representation of a rule as a string.
 * Returns true on success.
 * 
 * NOTE: str's length, should be: MAX_STRLEN_OF_RULE_FORMAT+1 (includs '\0')
 **/
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
		printf("Error allocating memory for const_str copy inside update_rule_from_string().\n");
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
				break;
			}
		}
		else if (i == 1) { //Checks curr_token is valid direction:
			if ((rule_ptr->direction = translate_str_to_direction(curr_token)) == DIRECTION_ERROR){
				break;
			}
		}
		else if (i == 2) { //Check curr_token is <src ip>/<nps>
			if (!is_ipv4_subnet_format(curr_token, &(rule_ptr->src_ip), &(rule_ptr->src_prefix_size))){
				break;				
			}
			rule_ptr->src_prefix_mask = get_prefix_mask(rule_ptr->src_prefix_size);
		}
		else if (i == 3) { //Check curr_token is <dst ip>/<nps>
			if (!is_ipv4_subnet_format(curr_token, &(rule_ptr->dst_ip), &(rule_ptr->dst_prefix_size))){
				break;				
			}
			rule_ptr->dst_prefix_mask = get_prefix_mask(rule_ptr->dst_prefix_size);	
		}
		else if (i == 4) { //Checks curr_token is <protocol>
			if ((rule_ptr->protocol = translate_str_to_protocol(curr_token)) == PROT_ERROR){
				break;
			}
		}
		else if ((i == 5) || (i == 6)) { //Check curr_token is <source port> / <dest port>
			if ((temp_val = translate_str_to_int_port_number(curr_token)) == PORT_ERROR){
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
				break;
			}	
		}
		else { // i == 8, last index that is < NUM_OF_TOKENS_IN_FORMAT. Check curr_token is <action> 
			if(!translate_str_to_action(curr_token, &(rule_ptr->action))){
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
	printf("g_num_of_valid_rules is updated y 1 to: %u.\n",g_num_of_valid_rules);
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
static int read_rules_from_file(const char* file_path){
	
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
			if (!update_rule_from_string(buffer)) {
				printf("Invalid format line in file, discarded it.\n");
			} 
			else { //A rule was added:
				//Checks rule has reasonable logic:
				if (!is_valid_rule_logic(&(g_all_rules_table[g_num_of_valid_rules]))){
					printf("Rule has no reasonable logic. It wasn't added to g_all_rules_table.\n");
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