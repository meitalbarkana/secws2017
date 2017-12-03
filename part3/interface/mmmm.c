#include "rules_utils.h"

static size_t g_num_of_valid_rules = 0;
static rule_t** g_all_rules_table;

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
	printk(KERN_INFO "******************In does_rulename_already_exists\n");//TODO::DELETE THIS, TEST
	for (i = 0; i < g_num_of_valid_rules; ++i){
		if (strncmp(((g_all_rules_table)[i])->rule_name, rulename, MAX_LEN_OF_NAME_RULE+1) == 0){
			return true; //rulename already exists
		}
	}
	printk(KERN_INFO "******************In does_rulename_already_exists, returning false :)\n");//TODO::DELETE THIS, TEST
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
		printk(KERN_ERR "function is_rule_name got NULL value\n");
		return false;
	}
	printk(KERN_INFO "******************In is_rule_name, str isnt NULL\n");//TODO::DELETE THIS, TEST
	return (strnlen(str, MAX_LEN_OF_NAME_RULE+2) <= MAX_LEN_OF_NAME_RULE);
}

/**
 *   Gets a VALID user name (its length < MAX_LEN_OF_NAME_RULE && it's not a name of any other rule)
 * 	 and a pointer to rule_t, and updates the rule so it's name would be "valid_rule_name"
 **/
 static void update_rule_name(rule_t* rule_ptr, const char* valid_rule_name){
	 	strncpy(rule_ptr->rule_name, valid_rule_name, MAX_LEN_OF_NAME_RULE+1); //Updates rule's name
	 	nullify_str(rule_ptr->rule_name, strlen(valid_rule_name), MAX_LEN_OF_NAME_RULE); //Makes sure a '\0' is placed at the end of the string rule_name
 }

/**
 * Gets a (non-NULL!) string that supposed to represent a direction
 * If succedded, returns the relevant direction_t value
 * Otherwise - returns DIRECTION_ERROR
 **/
static direction_t translate_str_to_direction(const char* str){
	if (str == NULL){
		printk(KERN_ERR "function translate_str_to_direction got NULL value\n");
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
static bool is_ipv4_subnet_format(const char* const_str, __be32* ipv4value, __u8* prefixLength){
	
	size_t maxFormatLen = MAX_STRLEN_OF_IP_ADDR; //strlen("XXX.XXX.XXX.XXX/YY") = 18
	size_t minFormatLen = MIN_STRLEN_OF_IP_ADDR; //strlen("X.X.X.X/Y") = 9
	size_t strLength = strnlen(const_str, maxFormatLen+2); //Because there's no need to check more chars than that..
	
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
	
	if ((strLength < minFormatLen) || (strLength > maxFormatLen)){
		return false;
	}
	
	//Creating a copy of const_str:
	if((str = kmalloc(sizeof(char)*(strLength+1),GFP_KERNEL)) == NULL){
		printk(KERN_ERR "Failed allocating space for copying IPv4 string\n");
		return false;
	}
	strncpy(str, const_str, strLength+1);
	pStr = str;
	
	for (i = 0; i <= 4; ++i){
		currToken = strsep(&str, "./");
		if (currToken == NULL){
			kfree(pStr);
			return false;
		}
		if (i == 4) { //means we're at the part of the string representing the netmask length 
			if((strict_strtoul(currToken, 10,&temp) != 0) || (temp > 32)){ //strict_strtoul() returns 0 on success
				kfree(pStr);
				return false;
			}
			*prefixLength = (__u8)temp;	//Safe casting, since temp <= 32
		} else { // i is 0/1/2/3
			if((strict_strtoul(currToken, 10,&temp) != 0) || (temp > 255)){
				kfree(pStr);
				return false;
			}
			multiplicand = 1 << (8*(3-i));
			(*ipv4value)+= multiplicand*(unsigned int)temp; //Safe casting, since temp <= 255
		}
	}
	
	//Makes sure str didn't contain any invalid characters
	currToken = strsep(&str, "./");
	if (currToken != NULL){
		kfree(pStr);
		return false;
	}
	
	kfree(pStr);
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
	if(strnlen(str,MAX_STRLEN_OF_PORT+2) <= MAX_STRLEN_OF_PORT){ //Since the maximum valid str length is 5(MAX_STRLEN_OF_PORT)+1(for '\0')+1 (to make sure str isn't longer)
		if ((strcmp(str, ">1023") == 0) || (strcmp(str, "1023") == 0)) {
			return PORT_ABOVE_1023;
		}
		if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0)){
			return PORT_ANY;
		}
		if ((strict_strtoul(str, 10,&temp) == 0) && (temp <= 65535)){
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
	if((str != NULL) && strnlen(str,MAX_STRLEN_OF_ACK+2) <= MAX_STRLEN_OF_ACK){ //Since the maximum valid str length is 3+1(for '\0')+1 (to make sure str isn't longer)
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
 * Gets a string that supposed to represent action to do on the packet and a pointer to "action" (unsigned char)
 * String valid values are:
 * 		1. "accept" / "ACCEPT" - means accept the message (let it pass)
 * 		2. "drop" / "DROP" - means drop the package
 * If succedded, updates *action to contain the relevant value: NF_ACCEPT, NF_DROP and returns true,
 * Otherwise - returns false
 **/
static bool translate_str_to_action(const char* str, __u8* action){
	if((str != NULL) && strnlen(str,MAX_STRLEN_OF_ACTION+2) <= MAX_STRLEN_OF_ACTION){ //Since the maximum valid str length is 6(MAX_STRLEN_OF_ACTION)+1(for '\0')+1 (to make sure str isn't longer)
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
static __be32 get_prefix_mask(__u8 prefix_length){
	//0xffffffff = 11111111 11111111 11111111 11111111
	__be32 temp = 0xffffffff;
	if (prefix_length == 32){
		return temp;
	}
	temp = temp >> (32-prefix_length); // For example: if prefix = 3, temp will contain: 00011111 11111111 11111111 11111111
	temp = temp ^ 0xffffffff; // XORing with 11...11 so that, in our example, temp =  11100000 00000000 00000000 00000000
	
	return temp;
}

/**
 *	Gets unsigned int and returns its IPv4 string representation
 *  [Format of: "XXX.XXX.XXX.XXX"]
 * 	If failed, returns NULL
 **/
static char* tran_uint_to_ipv4str(__be32 ip){
	char* str;
	__be32 p0, p1, p2, p3;
	int num_of_chars_written = 0;
	size_t len_str = strlen("XXX.XXX.XXX.XXX")+1;
	if((str = kmalloc(len_str * sizeof(char),GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Failed allocating space for string representing IPv4\n");
		return NULL;	
	}
	
	p3 = ip%256;
	ip = ip/256;
	p2 = ip%256;
	ip = ip/256;
	p1 = ip%256;
	ip = ip/256;
	p0 = ip%256;
	
	num_of_chars_written = snprintf(str,len_str, "%u.%u.%u.%u", p0,p1,p2,p3);
	if ( num_of_chars_written < strlen("X.X.X.X")){
		kfree(str);
		printk(KERN_ERR "Failed translating to string representation of IPv4\n");
		return NULL;
	}
	
	nullify_str(str, num_of_chars_written, len_str-1);//Makes sure a '\0' is placed at the end of the string

	return str;
}

/**
 *	Gets direction_t and returns its string representation
 * 	If failed, returns NULL
 **/
static char* tran_direction_t_to_str(direction_t direc){
	char* str;
	if ((str = kmalloc((MAX_STRLEN_OF_DIRECTION+1)*sizeof(char), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Failed allocating space for string representing direction\n");
		return NULL;
	}
	nullify_str(str, 0, MAX_STRLEN_OF_DIRECTION); //Makes sure str is nullified.
	
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
			printk(KERN_ERR "Error - tried translating wrong direction_t\n");
			kfree(str);
			return NULL;
	}
	return str;
}

/**
 *	Gets prot_t and returns its string representation
 * 	If failed, returns NULL
 **/
static char* tran_prot_t_to_str(prot_t prot){
	char* str;
	if ((str = kmalloc((MAX_STRLEN_OF_PROTOCOL+1)*sizeof(char), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Failed allocating space for string representing protocol\n");
		return NULL;
	}
	nullify_str(str, 0, MAX_STRLEN_OF_PROTOCOL); //Makes sure str is nullified.
	
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
			printk(KERN_ERR "Error - tried translating wrong prot_t\n");
			kfree(str);
			return NULL;
	}
	return str;
}

/**
 *	Gets unsigned short representing port number
 *  Returns its string representation
 * 	If failed, returns NULL
 **/
static char* tran_port_to_str(__be16 port){
	char* str;
	if ((str = kmalloc((MAX_STRLEN_OF_PORT+1)*sizeof(char), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Failed allocating space for string representing port number\n");
		return NULL;
	}
	nullify_str(str, 0, MAX_STRLEN_OF_PORT); //Makes sure str is nullified.
	
	switch (port) {
		case (PORT_ANY):
			strncpy(str,"any", MAX_STRLEN_OF_PORT+1);
			break;
		case(PORT_ABOVE_1023):
			strncpy(str,">1023", MAX_STRLEN_OF_PORT+1);
			break;
		default: //port is a specific number
			snprintf(str, MAX_STRLEN_OF_PORT+1, "%u", port);
			
		//Note: guaranteed that port!=PORT_ERROR since PORT_ERROR==-1, and port is __be16 (unsigned)
	}
	return str;
}

/**
 *	Gets ack_t representing ack, Returns its string representation
 * 	If failed, returns NULL
 **/
static char* tran_ack_to_str(ack_t ack){
	char* str;
	if ((str = kmalloc((MAX_STRLEN_OF_ACK+1)*sizeof(char), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Failed allocating space for string representing ack\n");
		return NULL;
	}
	nullify_str(str, 0, MAX_STRLEN_OF_ACK); //Makes sure str is nullified.
	
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
	return str;
}

/**
 *	Gets __u8 (unsigned char) representing action, Returns its string representation
 * 	If failed, returns NULL
 **/
static char* tran_action_to_str(__u8 action){
	char* str;
	if ((str = kmalloc((MAX_STRLEN_OF_ACTION+1)*sizeof(char), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Failed allocating space for string representing action\n");
		return NULL;
	}
	nullify_str(str, 0, MAX_STRLEN_OF_ACTION); //Makes sure str is nullified.
	
	switch (action) {	
		case (NF_ACCEPT):
			strncpy(str, "accept", MAX_STRLEN_OF_ACTION+1);
			break;
		case(NF_DROP):
			strncpy(str, "drop", MAX_STRLEN_OF_ACTION+1);
			break;
		default: //Never supposed to get here if used correctly.
			printk(KERN_ERR "Error - tried translating wrong action\n");
			kfree(str);
			return NULL;
	}
	return str;
}

/**
 *  Helper function - to free allocated strings if creating the string representation of the rule failed
 **/
static void free_unnecessary_strs( char* str,char* ip_dst_str,char* ip_src_str, char* direc_str,
			char* protocol_str,	char* s_port_str,char* d_port_str,char* ack_str,char* action_str)
{ //TODO:: check if one can change it to use va_list
	if (str != NULL){
		kfree(str);
	}
	if (ip_dst_str != NULL){
		kfree(ip_dst_str);
	}
	if (ip_src_str != NULL){
		kfree(ip_src_str);
	}
	if (direc_str != NULL){
		kfree(direc_str);
	}
	if (protocol_str != NULL){
		kfree(protocol_str);
	}
	if (s_port_str != NULL){
		kfree(s_port_str);
	}
	if (d_port_str != NULL){
		kfree(d_port_str);
	}
	if (ack_str != NULL){
		kfree(ack_str);
	}
	if (action_str != NULL){
		kfree(action_str);
	}		
}

/**
 * Returns a representation of a rule as a string on success,
 * NULL if failed,
 * NOTE: user should free memory allocated (for char* returned) in it.
 **/
char* get_rule_as_str(rule_t* rule){
	
	char *str, *ip_dst_str, *ip_src_str, *direc_str, *protocol_str, *s_port_str, *d_port_str, *ack_str, *action_str;
	int num_of_chars_written = 0;
	
	if((str = kmalloc((MAX_STRLEN_OF_RULE_FORMAT+1)*sizeof(char), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Failed allocating space for string representing rule_t\n");
		return NULL;
	}
	//Make sure str is nullified:
	nullify_str(str, 0, MAX_STRLEN_OF_RULE_FORMAT);
	
	if ((ip_src_str = tran_uint_to_ipv4str(rule->src_ip)) == NULL){
		printk(KERN_ERR "Failed translating source ip address to string\n");
		kfree(str);
		return NULL;
	}
	
	if ((ip_dst_str = tran_uint_to_ipv4str(rule->dst_ip)) == NULL){
		printk(KERN_ERR "Failed translating destination ip address to string\n");
		free_unnecessary_strs(str, ip_src_str, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		return NULL;
	}
	
	if ((direc_str = tran_direction_t_to_str(rule->direction)) == NULL){
		printk(KERN_ERR "Failed translating direction to string\n");
		free_unnecessary_strs(str, ip_src_str, ip_dst_str, NULL, NULL, NULL, NULL, NULL, NULL);
		return NULL;
	}
	if ((protocol_str = tran_prot_t_to_str(rule->protocol)) == NULL){
		printk(KERN_ERR "Failed translating protocol to string\n");
		free_unnecessary_strs(str, ip_src_str, ip_dst_str, direc_str, NULL, NULL, NULL, NULL, NULL);
		return NULL;
	}	
	
	if ((s_port_str = tran_port_to_str(rule->src_port)) == NULL){
		printk(KERN_ERR "Failed translating source port to string\n");
		free_unnecessary_strs(str, ip_src_str, ip_dst_str, direc_str, protocol_str, NULL, NULL, NULL, NULL);
		return NULL;
	}	

	if ((d_port_str = tran_port_to_str(rule->dst_port)) == NULL){
		printk(KERN_ERR "Failed translating destination port to string\n");
		free_unnecessary_strs(str, ip_src_str, ip_dst_str, direc_str, protocol_str, s_port_str, NULL, NULL, NULL);
		return NULL;
	}
	if ((ack_str = tran_ack_to_str(rule->ack)) == NULL){
		printk(KERN_ERR "Failed translating ack to string\n");
		free_unnecessary_strs(str, ip_src_str, ip_dst_str, direc_str, protocol_str, s_port_str, d_port_str, NULL, NULL);
		return NULL;
	}	

	if ((action_str = tran_action_to_str(rule->action)) == NULL){
		printk(KERN_ERR "Failed translating action to string\n");
		free_unnecessary_strs(str, ip_src_str, ip_dst_str, direc_str, protocol_str, s_port_str, d_port_str, ack_str, NULL);
		return NULL;
	}
	
	//<rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>
	num_of_chars_written = snprintf(str, MAX_STRLEN_OF_RULE_FORMAT+1, "%s %s %s/%u %s/%u %s %s %s %s %s", rule->rule_name, direc_str, ip_src_str, rule->src_prefix_size, 
									ip_dst_str, rule->dst_prefix_size, protocol_str, s_port_str, d_port_str, ack_str, action_str);

	free_unnecessary_strs(NULL, ip_src_str, ip_dst_str, direc_str, protocol_str, s_port_str, d_port_str, ack_str, action_str);
	
	if (num_of_chars_written < MIN_STRLEN_OF_RULE_FORMAT){
		printk(KERN_ERR "Failed translating rule_t to string\n");
		kfree(str);
		return NULL;
	}
	
	return str;
}

/**
 *	Gets a string that supposed to represent a proper rule
 *
 *  If g_num_of_valid_rules<MAX_NUM_OF_RULES,
 *  creates a rule according to str, inserts it to the rule table (g_all_rules_table) and updates g_num_of_valid_rules.
 * 	If succedded, returns the pointer to rule_t created & allocated & inserted to the rule table
 *	Otherwise - returns NULL
 * 	
 * 	NOTE:1. user of this funtion should free memory allocated by it.
 * 		 2. str will be ruined
 * 		 3. valid str format should be:
 * 		    <rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>
 **/
rule_t* get_rule_from_string(const char* const_str){
	
	char *str, *pStr;
	size_t i = 0;
	rule_t* rule_ptr = NULL;
	char* curr_token = NULL;
	int temp_val = 0;
	
	if ((g_num_of_valid_rules >= MAX_NUM_OF_RULES) || (const_str == NULL) ||
		(strnlen(const_str, MAX_STRLEN_OF_RULE_FORMAT+2) > MAX_STRLEN_OF_RULE_FORMAT)){ //To make sure there aren't too much rules & that str isn't longer than MAX_STRLEN_OF_RULE_FORMAT
		return NULL;
	}
	if ((rule_ptr = kmalloc(sizeof(rule_t),GFP_KERNEL)) == NULL) {
		return NULL;
	}
	
	//Creating a copy of const_str:
	if((str = kmalloc(sizeof(char)*(strlen(const_str)+1),GFP_KERNEL)) == NULL){
		kfree(rule_ptr);
		return NULL;
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
				rule_ptr->src_port = (__be16)temp_val; // Safe casting since temp_val!=PORT_ERROR
			} else { // i is 6, update dst_port:
				rule_ptr->dst_port = (__be16)temp_val;
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
		kfree(pStr);
		kfree(rule_ptr);
		return NULL;		
	}
	
	//Makes sure str didn't contain any invalid characters (at its end)
	curr_token = strsep(&str, " ");
	if (curr_token != NULL){
		kfree(pStr);
		kfree(rule_ptr);
		return NULL;
	}

	//If gets here, we have a valid rule:
	kfree(pStr);
	g_all_rules_table[g_num_of_valid_rules] = rule_ptr;
	++g_num_of_valid_rules;
	printk(KERN_INFO "g_num_of_valid_rules is: %u \n",g_num_of_valid_rules);//TODO::DELETE THIS, TEST
	return rule_ptr;

}

/**
 * 	Initiates (allocates space for)  g_all_rules_table, returns true on success
 **/
static bool init_rules_table(){
	if ((g_all_rules_table = kmalloc(sizeof(rule_t*)*MAX_NUM_OF_RULES, GFP_KERNEL)) == NULL) {
		return false;
	}
	return true;
}

/**
 * Frees all memory allocated for g_all_rules_table 
 **/
static void destroy_rule_table(){
	size_t i = 0;
	for (i = 0; i < g_num_of_valid_rules; i++){
		kfree(g_all_rules_table[i]);//TODO:: check if * needed??
	}
	g_num_of_valid_rules = 0;
	kree(g_all_rules_table);
}

/**
 * Gets a buffer containing all rules, initiates g_all_rules_table accordingly.
 * buffer should contain rules in format of: <rule>\n<rule>\n...
 * rule-format: <rule name> <direction> <src ip>/<nps> <dst ip>/<nps> <protocol> <source port> <dest port> <ack> <action>
 * Returns true on success.
 **/
static bool read_rules_from_buffer(const char* buffer){
	
}

/**
 * @rule - pointer to initialized rule_t that we check if 
 * 		   can indeed represent reasonable rule.
 * 
 * Returns true if it is.
 **/
static bool is_valid_rule_logic(rule_t* rule){
	
	//Rule that is NOT about TCP, has to have ACK == ACK_ANY to be considered valid:
	if (rule->protocol != PROT_TCP) && (rule->ack != ACK_ANY) {
		return false;
	}
	
	//TODO::
	//		probably more checks: direction and stuff
	return true;

/**
USAGE:
	if (!is_valid_rule_logic(rule)){
		printk(KERN_ERR "Rule has no reasonable logic. It wasn't added to g_all_rules_table.\n");
		return false;
	}

**/

}



