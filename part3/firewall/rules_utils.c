#include "rules_utils.h"

/** 	
 * Used: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 * as a reference.
 **/
static unsigned char g_num_of_valid_rules = 0;
static rule_t g_all_rules_table[MAX_NUM_OF_RULES];
static unsigned char g_fw_is_active = FW_OFF;
static int g_usage_counter = 0;

/** Globals for reading/writing char device **/
//Contains the data user wrote to device:
static char* g_write_to_buff = NULL;
//Will contain the current length of g_write_to_buff, NOT including '\0':
static long g_write_buff_len = 0; //long to make sure it is signed and enough to contain all unsigned int values
static int g_bytes_written_so_far = 0;
static int g_num_rules_have_been_read = 0;

static int rules_dev_major_number = 0; // Will contain rules-device's major number - its unique ID
static struct device* rules_device = NULL;

// Prototype functions declarations for the character driver - must come before the struct definition
static ssize_t rfw_dev_read(struct file *filp, char *buffer, size_t len, loff_t *offset);
static ssize_t rfw_dev_write(struct file* filp, const char* buffer, size_t len, loff_t *offset);
static int rfw_dev_open(struct inode *inodep, struct file *fp);
static int rfw_dev_release(struct inode *inodep, struct file *fp);
 
/**
 * 	Devices are represented as file structure in the kernel.
 *  The file_operations structure from /linux/fs.h lists the callback
 *  functions that we wish to associate with our file operations
 *  using a C99 syntax structure.
 */
static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = rfw_dev_open,
	.read = rfw_dev_read,
	.write = rfw_dev_write,
	.release = rfw_dev_release
};

/**
 * Helper function: frees g_write_to_buff and initializes all relevant values
 **/
static void clean_g_write_buff(bool clear_g_num_rules_have_been_read){

	if (g_write_to_buff != NULL) {
		kfree(g_write_to_buff);
		g_write_to_buff = NULL;
	}
	
	g_write_buff_len = 0; 
	g_bytes_written_so_far = 0;
	if (clear_g_num_rules_have_been_read) {
		g_num_rules_have_been_read = 0;
	}
}

//For tests alone! prints rule to kernel
///TODO:: comment it
static void print_rule(rule_t* rulePtr){
	
	size_t add_to_len = strlen("rule name is: ,\ndirection: ,\nsrc_ip: ,\nsrc_prefix_mask: ,\nsrc_prefix_size: /,\ndst_ip: ,\ndst_prefix_mask: ,\ndst_prefix_size: ,\nsrc_port: ,\ndst_port: ,\nprotocol: ,\nack: ,\naction: \n");
	char str[MAX_LEN_RULE_NAME+ 4*MAX_STRLEN_OF_BE32+ 2*MAX_STRLEN_OF_BE16 + 4*MAX_STRLEN_OF_U8 +2*MAX_STRLEN_OF_D + add_to_len+3]; //+3: 1 for null-terminator, 2 more to make sure 
	
	if ((sprintf(str,
				"rule name is: %s,\ndirection: %d,\nsrc_ip: %u,\nsrc_prefix_mask: %u,\nsrc_prefix_size: %hhu,\ndst_ip: %u,\ndst_prefix_mask: %u,\ndst_prefix_size: %hhu,\nsrc_port: %hu,\ndst_port: %hu,\nprotocol: %hhu,\nack: %d,\naction: %hhu\n",
				rulePtr->rule_name,
				rulePtr->direction,
				rulePtr->src_ip,
				rulePtr->src_prefix_mask,
				rulePtr->src_prefix_size,
				rulePtr->dst_ip,
				rulePtr->dst_prefix_mask,
				rulePtr->dst_prefix_size,
				rulePtr->src_port,
				rulePtr->dst_port,
				rulePtr->protocol,
				rulePtr->ack,
				rulePtr->action)
		) < NUM_OF_FIELDS_IN_RULE_T)
	{
		printk(KERN_INFO "Error printing rule presentation");
	} 
	else
	{
		printk (KERN_INFO "%s",str);
	}
}

 /**
 *	This function will be called when user tries to read from the "active" device.
 * 	
 *  NOTE: writes to "buf" the value of of g_fw_is_active, in (string) format:
 * 		<g_fw_is_active> (would be "0" or "1")
 * 
 * [writes minimal amount of characters, as it's a kernel function]
 **/
ssize_t read_active_stat(struct device* dev, struct device_attribute* attr, char* buf){
		ssize_t ret = scnprintf(buf, PAGE_SIZE, "%hhu", g_fw_is_active);
		if (ret <= 0){
			printk(KERN_ERR "*** Error: failed writing to user's buffer in function read_active_stat() ***\n");
		}
		return ret;
}

/**
 *	Returns: true if count=1 and the first char at "buf" is '0' or '1'  
 * 			 [these are the only valid user-input]
 * 			 false otherwise.
 **/
static inline bool validate_activate_input(const char* buf, size_t count){
	if( (buf!=NULL) && (count==1) && ((buf[0]=='0') || (buf[0] =='1')) ){
		return true;
	}
	return false;
}

/**
 * 	This function will be called when user tries to write to the "active" device,
 * 	meaning that the user wants to activate/diactivate the firewall.
 *  Returns:	sizeof(unsigned char) on success,
 * 				a negative number otherwise.
 * 
 * 	Buffer should contain: 	'0' - if user wants to deactivate the firewall,
 * 							'1' - if user wants to activate the firewall
 * 
 * 	If user provided buffer containing something other than those 2 valid values,
 * 	or passed a "count" value that is different from 1 - will fail! 
 * 	[count represent the length of buf ('\0' not included)]
 **/
ssize_t change_active_stat(struct device* dev, struct device_attribute* attr, const char* buf, size_t count){
	
	if( !validate_activate_input(buf, count) ){
		printk(KERN_ERR "*** Error: user sent invalid input to change_active_stat() ***\n");
		return -EPERM; // Returns an error of operation not permitted
	}
	
	if (buf[0]=='0'){
		if (g_fw_is_active == FW_OFF){
			printk(KERN_INFO "User tried do deactivate already-off firewall\n");
		} else {
			printk(KERN_INFO "User successfully deactivated firewall\n");
			g_fw_is_active = FW_OFF;
		}
	} else { //buf[0] =='1'
		if (g_fw_is_active == FW_ON){
			printk(KERN_INFO "User tried do activate already-on firewall\n");
		} else {
			printk(KERN_INFO "User successfully activated firewall\n");
			g_fw_is_active = FW_ON;
		}
	}
	
	return sizeof(unsigned char);//because we've changed the value of 1 unsigned char.
	
}

 /**
 *	This function will be called when user tries to read from the "rules_size" device.
 * 	
 *  NOTE: writes to "buf" the value of of g_num_of_valid_rules, in (string) format:
 * 		<g_num_of_valid_rules>
 * 
 * [writes minimal amount of characters, as it's a kernel function]
 **/
ssize_t read_rules_size(struct device* dev, struct device_attribute* attr, char* buf){
		ssize_t ret = scnprintf(buf, PAGE_SIZE, "%hhu", g_num_of_valid_rules);
		if (ret <= 0){
			printk(KERN_ERR "*** Error: failed writing to user's buffer in function read_rules_size() ***\n");
		}
		return ret;
}

/**
 * 	Declaring a variable of type struct device_attribute, its name would be "dev_attr_active",
 * 	will be used to link device to the "active" attribute
 * 		.attr.name = "active" (access it through: dev_attr_active)
 * 		.attr.mode = S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH, giving the owner and other user read&write permissions
 * 		.show = read_active_stat
 * 		.store = change_active_stat
 **/
static DEVICE_ATTR(active, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH, read_active_stat, change_active_stat);
/**
 * 	Declaring a variable of type struct device_attribute, its name would be "dev_attr_rules_size",
 * 	will be used to link device to the "rules_size" attribute
 * 		.attr.name = "rules_size" (access it through: dev_attr_rules_size)
 * 		.attr.mode = S_IRUSR | S_IROTH, giving the owner and other user read permissions
 * 		.show = read_rules_size
 * 		.store = NULL (no writing function)
 **/
static DEVICE_ATTR(rules_size, S_IRUSR | S_IROTH, read_rules_size, NULL);

/**
 * Inner function.
 * Gets a string that supposed to represent rule's name:
 * Returns: true if str can represent a valid rule's name (an empty string is valid as a rule name)
 * 			false otherwise
 **/
static bool is_rule_name(const char* str){
	if (str == NULL){
		printk(KERN_ERR "Function is_rule_name got NULL value\n");
		return false;
	}
	return (strnlen(str, MAX_LEN_RULE_NAME+1) < MAX_LEN_RULE_NAME); //makes sure str has less than MAX_LEN_RULE_NAME characters
}

/**
 * Gets a rulename,
 * Returns true if a rule with name "rulename" already exists in g_all_rules_table.
 **/
static bool does_rulename_already_exists(const char* rulename){
	unsigned char i = 0;
	for (i = 0; i < g_num_of_valid_rules; ++i){
		if (strncmp(((g_all_rules_table)[i]).rule_name, rulename, MAX_LEN_RULE_NAME) == 0){ 
			printk(KERN_ERR "User tried to add rule with the same name as another rule.\n");
			return true; //rulename already exists
		}
	}
	return false;
}

/**
 * Gets a rule-name and a pointer to rule_t that should be updated with rulename if it's valid.
 * 
 * Updates rule->rule_name IF rule_name is VALID
 * 
 * Returns true if rulename is valid, false otherwise
 **/
static bool is_valid_rule_name(const char* rulename, rule_t* rule){
	if (rulename == NULL){
		printk (KERN_ERR "#####NULL - Function is_valid_rule_name got NULL argument (rulename)\n");
		return false;
	}
	if( is_rule_name(rulename) && (!does_rulename_already_exists(rulename)) ){ 
		strncpy(rule->rule_name, rulename, MAX_LEN_RULE_NAME);
		return true;
	} 
	return false; //not a valid rule name
}

/**
 * @num - an integer to check if it's valid rule direction,
 * @rule - pointer to rule_t that should be updated with direction if it's valid.
 * 
 * Updates rule->direction IF num is valid direction.
 * 
 * Returns true if num is valid direction, false otherwise
 **/
static bool is_valid_direction(int num, rule_t* rule){
	if( (num == DIRECTION_IN) || (num == DIRECTION_OUT) || (num == DIRECTION_ANY) ){ 
		rule->direction = (direction_t)(num); //Safe casting
		return true;
	}
	printk(KERN_ERR "User tried to add rule with invalid direction.\n"); 
	return false; //not a valid direction
}

/**
 * 	@prefix_length (Big-Endian, value between 0-32)
 * 
 * 	Returns the prefix mask that prefix_length represent
 **/
static __be32 get_prefix_mask(unsigned char prefix_length){
	//0xffffffff = 11111111 11111111 11111111 11111111
	__be32 temp = 0xffffffff;
	if (prefix_length == 32){//Since right shifting of width of type (=32) has undefined behavior
		return temp;
	}
	temp = temp >> prefix_length; // For example: if prefix = 3, temp will contain: 00011111 11111111 11111111 11111111
	temp = temp ^ 0xffffffff; // XORing with 11...11 so that, in our example, temp =  11100000 00000000 00000000 00000000
	
	return temp;
}

/**
 * @num - unsigned char to check if it's valid src/dst prefix size (between 0-32),
 * @rule - pointer to rule_t that should be updated with src/dst prefix mask&size  if it's valid.
 * @src_or_dst - by it the right prefix mask&size will be updated
 * 
 * IF num is valid prefix size,
 * updates: rule->dst/src_prefix_mask
 * 			rule->dst/src_prefix_size  
 * 
 * Returns true if num is valid prefix size, false otherwise
 **/
static bool is_valid_mask_prefix_size(unsigned char num, rule_t* rule, enum src_or_dst_t src_or_dst){
	if(num <= 32){ // 0<=num for sure as it's unsigned...
		if (src_or_dst == SRC){
 			rule->src_prefix_size = num;
 			rule->src_prefix_mask = get_prefix_mask(num);
		}
		else { //src_or_dst == DST
			rule->dst_prefix_size = num;
			rule->dst_prefix_mask = get_prefix_mask(num);
		}
		return true;
	}
	printk(KERN_ERR "User tried to add rule with invalid mask-prefix length.\n"); 
	return false;
}

/**
 * @num - an unsigned char to check if it's valid protocol (value from prot_t),
 * @rule - pointer to rule_t that should be updated with protocol if it's valid.
 * 
 * Updates rule->protocol IF num is valid prot_t.
 * 
 * Returns true if num is valid protocol, false otherwise
 **/
static bool is_valid_protocol(unsigned char num, rule_t* rule){
	
	if( (num == PROT_ICMP) || (num == PROT_TCP) || (num == PROT_UDP) || (num == PROT_OTHER) || (num == PROT_ANY) ){ 
		rule->protocol = (prot_t)num; //Safe casting
		return true;
	} 
	printk(KERN_ERR "User tried to add rule with invalid protocol number.\n"); 
	return false;
}

/**
 * @num - an int to check if it's valid ack (value from ack_t),
 * @rule - pointer to rule_t that should be updated with ack if it's valid.
 * 
 * Updates rule->ack IF num is valid ack_t.
 * 
 * Returns true if num is valid ack, false otherwise
 **/
static bool is_valid_ack(int num, rule_t* rule){
	if((num == ACK_NO) || (num == ACK_YES) || (num == ACK_ANY)){ 
		rule->ack = (ack_t)num; //Safe casting
		return true;
	} 
	printk(KERN_ERR "User tried to add rule with invalid ack value.\n"); 
	return false;
}

/**
 * @num - an unsigned char to check if it's valid action (NF_ACCEPT/NF_DROP),
 * @rule - pointer to rule_t that should be updated with relevant action if it's valid.
 * 
 * Updates rule->action IF num is valid.
 * 
 * Returns true if num is valid action, false otherwise
 **/
static bool is_valid_action(unsigned char num, rule_t* rule){
	if( (num == NF_ACCEPT) || (num == NF_DROP) ){ 
		rule->action = num;
		return true;
	} 
	printk(KERN_ERR "User tried to add rule with invalid action value.\n"); 
	return false; //not a valid action
}



/**
 * Checks if rule is valid, if it does adds it to g_all_rules_table.
 * 
 * @rule_str - null-terminated STRING representing ONE rule
 * 
 *	VALID RULE FORMAT WOULD CONSIST OF THE FOLLOWING, SEPERATED BY WHITESPACES:
 *		1.<rule name> - string of maximum length of MAX_LEN_RULE_NAME (includeing '\0')
 * 		2.<direction> - string representing an int
 * 		3.<src ip> - string representing an unsigned int
 * 		4.<src prefix length> - string representing an unsigned char
 * 		5.<dst ip> - string representing an unsigned int
 * 		6.<dst prefix length> - string representing an unsigned char
 * 		7.<protocol> - string representing an unsigned char
 * 		8.<source port> - string representing an unsigned short
 * 		9.<dest port> - string representing an unsigned short
 * 		10.<ack> - string representing an int
 * 		11.<action> - string representing an unsigned char
 * 
 * NOTE: 1.	function updates g_all_rules_table[g_num_of_valid_rules]
 * 			to contain this (if valid) rule
 * 		 2. function updates (if valid rule) g_num_of_valid_rules
 * 		 3. adding a rule to table DOESN'T check its logic!
 * 
 * Returns true on success. 
 **/
static bool is_valid_rule(const char* rule_str){

	rule_t* rule = &(g_all_rules_table[g_num_of_valid_rules]);
	//Declaring temporaries:
	char t_rule_name[MAX_LEN_RULE_NAME];
	int t_direction = 0;
	__u8    t_src_prefix_len;
	__u8    t_dst_prefix_size;
	__u8	t_protocol;
	int	t_ack;
	__u8	t_action;

#ifdef DEBUG_MODE
	printk(KERN_INFO "In function is_valid_rule, testing rule number: %hhu. ",g_num_of_valid_rules);
	if (rule_str != NULL){
		printk(KERN_INFO "rule_str is: %s\n", rule_str);
	} else {
		printk(KERN_INFO "rule_str is: NULL!!!\n");
	}
#endif
	
	//Makes sure there aren't too much rules & that rule_str isn't longer than MAX_STRLEN_OF_RULE_FORMAT
	if ((g_num_of_valid_rules >= MAX_NUM_OF_RULES) || (rule_str == NULL) ||
		(strnlen(rule_str, MAX_STRLEN_OF_RULE_FORMAT+2) > MAX_STRLEN_OF_RULE_FORMAT)){ 
		printk(KERN_ERR "Rule format is invalid: too long or NULL accepted.\n");
		return false;
	}
	
	//Since any unsigned int represent a valid IPv4 address, src_ip & dst_ip are updated here
	//Since any unsigned short represent a valid port number, src_port & dst_port are updated here:
	if ( (sscanf(rule_str, "%19s %10d %u %hhu %u %hhu %hhu %hu %hu %d %hhu", t_rule_name, &t_direction,
			&(rule->src_ip), &t_src_prefix_len, &(rule->dst_ip), &t_dst_prefix_size, &t_protocol,
			&(rule->src_port), &(rule->dst_port), &t_ack, &t_action)) < NUM_OF_FIELDS_IN_FORMAT ) 
	{
		printk(KERN_ERR "Couldn't parse rule to valid fields.\n");
		return false;
	}
	
	if( (!is_valid_rule_name(t_rule_name, rule)) ||
		(!is_valid_direction(t_direction, rule)) ||
		(!is_valid_mask_prefix_size(t_src_prefix_len, rule, SRC)) ||
		(!is_valid_mask_prefix_size(t_dst_prefix_size, rule, DST)) ||
		(!is_valid_protocol(t_protocol, rule)) ||
		(!is_valid_ack(t_ack, rule)) || 
		(!is_valid_action(t_action, rule)) )
	{
		return false;
	}
	
	//If gets here, rule_str was valid & added to g_all_rules_table[g_num_of_valid_rules]
	++g_num_of_valid_rules;
	
#ifdef DEBUG_MODE
	printk(KERN_INFO "In function is_valid_rule, done testing a VALID rule. Total valid rules so far: %hhu, \n",g_num_of_valid_rules);
	print_rule(&(g_all_rules_table[(g_num_of_valid_rules-1)]));
#endif	

	return true;
}

/** 
 * 	This function will be called whenever the device is being written to (from user space) -
 *  meaning that data is sent to the device from the user.
 *  
 *	@filp - a pointer to a file object (here it's not relevant)
 *  @buffer - the buffer that contains the string user wants to write to the device
 *  @len - the length of buffer (not includes '\0')
 *  @offset - the offset if required (here it's not relevant)
 * 
 * 	Returns: number of bytes from buffer that have been "written" in our device,
 * 			 negative number if failed (zero if no rule was added)
 * 
 * 
 *	Note: rules won't be updated here! only when closing the device (in rfw_dev_release())
 */
static ssize_t rfw_dev_write(struct file* filp, const char* buffer, size_t len, loff_t *offset){

	size_t len_to_allocate = 0;
#ifdef DEBUG_MODE
	printk (KERN_INFO "START OF rfw_dev_write(), length got from user is: %u\n", len);
#endif	

	//Basic input check:
	if (len == 0){
		return 0;
	}
	
	if (g_bytes_written_so_far == 0){
	//Means that's the first time asked to write to device:
		
		//Safe since MAX_LEN_ALL_RULES_BUFF << MAX_UINT
		len_to_allocate = (len < (MAX_LEN_ALL_RULES_BUFF+1)) ? 
						(len+1) : (MAX_LEN_ALL_RULES_BUFF+2);//+1 for '\0', 2 for '\0'&'\n'
		//Sanity check:
		if (g_write_to_buff != NULL) {
			printk (KERN_ERR "Freeing allocated user-input buff, g_bytes_written_so_far was zero\n");
			clean_g_write_buff(false);
		}
		
		//Allocate memory for user's input
		if((g_write_to_buff = kmalloc(sizeof(char)*len_to_allocate,GFP_KERNEL)) == NULL){
			printk(KERN_ERR "Failed allocating space for getting user input\n");
			return -ENOMEM;
		}
		g_write_buff_len = len_to_allocate - 1; //>0 for sure.
		memset(g_write_to_buff, 0, len_to_allocate);
		
#ifdef DEBUG_MODE
		printk (KERN_INFO "In rfw_dev_write(), successfully allocated %u bytes for buffer\n", len_to_allocate);
#endif	
		//Now we're ready to write
	
	}//Otherwise, we're just continuing writing:
	
	if (len > g_write_buff_len - g_bytes_written_so_far) {
#ifdef DEBUG_MODE
		printk (KERN_INFO "In rfw_dev_write(), user asked to write more than possible, updates that value (len) \n");
#endif	
		//Sanity check, never supposed to get here:
		if ((g_write_buff_len - g_bytes_written_so_far) < 0) {
			printk (KERN_ERR "ERROR In rfw_dev_write(), number of bytes written is larger than buffer allocated\n");
			clean_g_write_buff(false);
			return -ENOMEM;
		}
		
		len = g_write_buff_len - g_bytes_written_so_far;//Safe casting
	}

	if (copy_from_user(g_write_to_buff+g_bytes_written_so_far, buffer, len )){
		//Copying from user failed - aborts.
		clean_g_write_buff(false);
		return -EFAULT;
	}

#ifdef DEBUG_MODE
		printk (KERN_INFO "Total bytes written to fw_rules in current write: %u, total written so far: %u\n",
				len, g_bytes_written_so_far);
#endif	

	g_bytes_written_so_far += len;
	return len;
	
}


/** 
 * 	This function is called whenever device is being read from user space
 *  i.e. data is being sent from the device to the user. 
 * 	We use copy_to_user() function to copy rules (in their string format)
 * 	to buffer.
 * 
 *	rule format:
 * <rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>'\n'
 * 
 *  @filp - a pointer to a file object (here it's not relevant)
 *  @buffer - pointer to the buffer to which this function will write the data
 *  @len - length of the buffer, excluding '\0'. 
 *  @offset - the offset if required (here it's not relevant)
 * 
 * Note: 1. if len isn't enough for one rule, action will fail.
 * 		 2. g_num_rules_have_been_read will be updated (+1) on success.
 * 		 3. User should allocate enough space, and if he wants all rules - 
 * 			read until EOF (0).
 * 		 4. In case of consecutive calls, in USER's responsibility to 
 * 			update buffer's pointer (offset is ignored).
 * 
 * Returns: 
 * 		 1. In case there were rules to read 
 * 			(i.e. g_num_rules_have_been_read < g_num_of_valid_rules)
 *  		returns the number of bytes written (sent) to buffer.
 * 		 2. In case there were NO rules left to read - returns 0 
 * 		 3. (-EFAULT) if copy_to_user failed / (-1) if other failure happened
 */
static ssize_t rfw_dev_read(struct file *filp, char *buffer, size_t len, loff_t *offset){
	
	rule_t* rulePtr;
	char str[MAX_STRLEN_OF_RULE_FORMAT+2]; //+2: for '\n' and '\0'
	
	//Checks if user already finished reading all rules:
	if (g_num_rules_have_been_read == g_num_of_valid_rules) { 
		g_num_rules_have_been_read = 0;//So next user could read
		return 0;
	}
	
	rulePtr = &(g_all_rules_table[g_num_rules_have_been_read]);

	if (rulePtr == NULL){ //Sanity check
		printk(KERN_ERR "add_str_rule_to_buffer - NULL pointer\n");
		return -1;
	}
	
	if ((sprintf(str,
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
		) < (MIN_RULE_FORMAT_LEN+1))
	{
		//Should never get here:
		printk(KERN_ERR "Error formatting rule to its string representation\n");
		return -1;
	} 
	
	if (len < strlen(str)){
		printk(KERN_ERR "Error: user provided too-small buffer\n");
		return -EFAULT;
	}
	
	// copy_to_user has the format ( * to, *from, size) and returns 0 on success
	if ( copy_to_user(buffer, str, strlen(str)) != 0 ) {
		printk(KERN_INFO "Function copy_to_user failed - writing rule to user's buffer failed\n");
		return -EFAULT; //Return a bad address message
	}
	
#ifdef DEBUG_MODE
	printk(KERN_INFO "In function add_str_rule_to_buffer, done sending it:\n%s\n",str);
#endif	
	++g_num_rules_have_been_read;
	return strlen(str);
	
}

/** 
 * 	The device open function (called each time the device is opened):
 * 	
 *	Increments g_usage_counter (although ".owner" is defined so it's not mandatory)
 * 
 *	@inodep - pointer to an inode object)
 *  @fp - pointer to a file object
 */
static int rfw_dev_open(struct inode *inodep, struct file *fp){
	g_usage_counter++;
#ifdef DEBUG_MODE 
   printk(KERN_INFO "fw_rules: device is opened by %d process(es)\n", g_usage_counter);
#endif
	return 0;
}

/** 
 * 	The device release function - called whenever the device is 
 *	closed/released by the userspace program.
 * 		1. Decrements g_usage_counter
 *		2. If g_write_to_buff - WRITES RULES by that buffer, continuing 
 * 			from last rule.
 * 			USER HAS TO CLEAR RULES BEFORE WRITING NEW ONES IF HE WANTS 
 * 			A NEW LIST OF RULES!
 * 			RULES WOULD BE APPENDED (AT THE LAST!)
 *  	3. If wrote rules - updates g_num_rules_have_been_read to 0.
 * 			 
 *  @inodep - pointer to an inode object
 *  @fp - pointer to a file object
 * 
 *  NOTE:	1. if user sent 1 as len (inside g_write_buff_len)
 * 			   and buffer[0] (g_write_to_buff[0]) == CLEAR_RULES,
 * 				it means he wanted to clear rules-table.
 * 			2. otherwise, we treat g_write_to_buff as a "list" of rules, in format:
 *	<rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>'\n'			
 * 	<rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>'\n'...
 *
 */
static int rfw_dev_release(struct inode *inodep, struct file *fp){

	char *ptr_buff_copy, *rule_token;
	
#ifdef DEBUG_MODE
	printk (KERN_INFO "START OF rfw_dev_release(), In it - rules would be updated (if needed)\n");
#endif
	
	if (g_usage_counter != 0){
		g_usage_counter--;
	}
	 
	// Check if there's anything to write:
	if ( (g_write_to_buff != NULL) && (g_write_buff_len != 0) ) 
	{
#ifdef DEBUG_MODE
		printk (KERN_INFO "In rfw_dev_release(), updates rules. g_write_to_buff is: %s, g_write_buff_len is: %ld\n",
				g_write_to_buff, g_write_buff_len);
#endif
		
		//Case user wanted to clean rule-table:
		if ((g_write_buff_len == 1) && g_write_to_buff[0]==CLEAR_RULES){
			g_num_of_valid_rules = 0;
			clean_g_write_buff(true);
			printk(KERN_INFO "fw_rules: All rules were cleaned. Device successfully closed\n");
			return 0;
		} 	
		
		//Saving a ptr so we can free it later (strsep "ruins" g_write_to_buff)
		ptr_buff_copy = g_write_to_buff;
		 
		while( ((rule_token = strsep(&g_write_to_buff, DELIMETER_STR)) != NULL) 
				&& (g_num_of_valid_rules < MAX_NUM_OF_RULES)
				&& (strlen(rule_token) > 0) ) //Last token is empty, in a valid format
		{
			if(is_valid_rule(rule_token)){
#ifdef DEBUG_MODE
				printk(KERN_INFO "Another rule added to device.\n");
#endif
			}
		}
		
		//If g_write_to_buff!=NULL it means some rules weren't written
		if (g_write_to_buff != NULL) {
			printk(KERN_INFO "Some of the rules weren't written - probably no space left. Number of rules: %hhu\n", g_num_of_valid_rules);
			g_write_to_buff = NULL;
			g_write_buff_len = 0; 
			g_bytes_written_so_far = 0;			
		} else {
			clean_g_write_buff(true);
		}
		
		kfree(ptr_buff_copy);
		g_num_rules_have_been_read = 0;	
		
	}
	
#ifdef DEBUG_MODE 
   printk(KERN_INFO "fw_rules: device successfully closed\n");
#endif

   return 0;
}


/*** FUNCTIONS FOR TESTING IF RULE IS RELEVANT TO PACKET ***/

/**
 *	Checks if given packet_direction is relevant to rule_direction
 *	Returns true is it is.
 **/
static bool is_relevant_direction(direction_t rule_direction, direction_t packet_direction){
	return ( (rule_direction == packet_direction) || 
			(rule_direction == DIRECTION_ANY) || 
			(packet_direction == DIRECTION_ANY) );
}

/**
 *	Checks if given packet_ip is relevant
 * 	according to rule_ip & rule_prefix_mask
 * 	(if packet_ip is inside the sub-network defined by rule_ip & rule_prefix_mask)
 * 
 *	Returns true is it is.
 * 	
 * 	@rule_ip - rule's ip in LOCAL endianness
 * 	@rule_prefix_mask
 * 	@packet_ip - packet's ip in LOCAL endianness
 **/
static bool is_relevant_ip(__be32 rule_ip, __be32 rule_prefix_mask, __be32 packet_ip){
	__be32 network_prefix = rule_ip & rule_prefix_mask; //Bitwise and. 
	__be32 p_network_prefix = packet_ip & rule_prefix_mask;
	return ( p_network_prefix == network_prefix );
}

/**
 *	Checks if given packet_port is relevant to rule_port
 *	Returns true is it is.
 * 
 * 	Note:	rule_port value can be: 
 * 			1. a specific port number in range [1,..,65535]\{1023}
 * 			2. PORT_ANY (0) for any port
 * 			3. PORT_ABOVE_1023	(1023) for any port number > 1023 
 **/
static bool is_relevant_port(__be16 rule_port, __be16 packet_port){
	return ( (rule_port == PORT_ANY) || 
			((rule_port == PORT_ABOVE_1023)	&& (packet_port > PORT_ABOVE_1023))
			|| (rule_port == packet_port) );
}

/**
 *	Checks if given packet_protocol is relevant to rule_protocol
 *	Returns true is it is.
 **/
static bool is_relevant_protocol(prot_t rule_protocol, __u8 packet_protocol){
	return ( (rule_protocol == PROT_ANY) || 
			(packet_protocol == (unsigned char)rule_protocol) ); //Safe casting 
}

/**
 *	Checks if given (TCP) packet's ack value is relevant to rule_ack
 *	
 *	Returns true is it is.
 * 
 *	@rule_ack - rule's ack value
 *	@packet_ack - packets' ack valuer.
 * 
 *	Note: 1. packet_ack value allowed values are only ACK_YES/ACK_NO
 * 			(since if packet isn't a tcp packet this function would never be called)
 *		  2. the return value is strongly based on how we defined ack_t values!
 *		 	accessing specific bits through struct fields is endian-safe.
 **/
static bool is_relevant_ack(ack_t rule_ack, ack_t packet_ack){

	if (packet_ack == ACK_ANY) { //Should never get here
		printk (KERN_ERR "In function is_relevant_ack(), got invalid packet_ack argument (ACK_ANY)\n");
	}
		
	// packet_ack&rule_ack == 0 only when one is ACK_YES and the other is ACK_NO:
	return ( (packet_ack & rule_ack) != 0 );
}

/**
 * 	DEPRECATED since the hook that checks rule-table checks only IPv4 packets. 
 *  Returns true if a given packet is an IPv4 packet.
 *	
 *	@skb - pointer to struct sk_buff that represents the packet
 *	
 *	struct sk_buff->protocol values are from: 
 *	https://elixir.free-electrons.com/linux/v4.3/source/include/uapi/linux/if_ether.h#L46
 * (under: Ethernet Protocol ID's)
 *	here we're only interested in IPv4 value.
 **/
/**
bool is_ipv4_packet(struct sk_buff* skb){
	if (skb && (skb->protocol == ETH_P_IP)){
		return true;
	}
	return false;
}
**/

/**
 * 	Checks if a given IPv4 packet is XMAS packet.
 *	
 *	@skb - pointer to struct sk_buff that represents current packet
 *	
 *	Returns true if it represent a Christmas Tree Packet
 *	(TCP packet with PSH, URG, FIN flags on)
 * 
 *	struct iphdr->protocol values are from: 
 *	http://elixir.free-electrons.com/linux/latest/source/include/uapi/linux/in.h#L37
 *	here we're only interested in values that appear in enum prot_t. 
 **/
static bool is_XMAS(struct sk_buff* skb){
	
	struct iphdr* ptr_ipv4_hdr; //pointer to ipv4 header
	struct tcphdr* ptr_tcp_hdr; //pointer to tcp header
	
	if (skb){ 
		ptr_ipv4_hdr = ip_hdr(skb);
		if(ptr_ipv4_hdr){
			//Protocol is 1 byte - no need to consider Endianness
			if (ptr_ipv4_hdr->protocol == PROT_TCP) {	//Checks in local endianness
				ptr_tcp_hdr = (struct tcphdr*)((char*)ptr_ipv4_hdr + (ptr_ipv4_hdr->ihl * 4));
				//accessing specific bits through struct fields is Endian-safe:	
				
				if ( ptr_tcp_hdr && (ptr_tcp_hdr->psh == 1) && (ptr_tcp_hdr->urg == 1)
					&& (ptr_tcp_hdr->fin == 1) ) 
				{
						return true;
				}
			}
		}
	}
	
	return false;
}

/**
 *	Checks if rule is relevant to packet represented by ptr_pckt_lg_info.
 *	
 *	Updates: ptr_pckt_lg_info->action (if rule is relevant to current packet)
 * 
 *	Returns: 1. if rule is relevant: RULE_ACCEPTS_PACKET = NF_ACCEPT/	
 *									 RULE_DROPS_PACKET = NF_DROP
 *			 2. if rule's irrelevant: RULE_NOT_RELEVANT
 * 
 *	Note: 1. function should be called AFTER ptr_pckt_lg_info,
 * 			 *packet_ack and *packet_direction were initiated
 * 			 (using init_log_row).
 * 		  2. function should be called AFTER making sure packet isn't XMAS 
 **/
static enum action_t is_relevant_rule(const rule_t* rule, log_row_t* ptr_pckt_lg_info,
		ack_t* packet_ack, direction_t* packet_direction)
{
	
	//Makes sure the packet isn't checked twice if it's action have
	//already been set (never supposed to get in)
	if (ptr_pckt_lg_info->action != RULE_NOT_RELEVANT) {
		printk(KERN_ERR "In is_relevant_rule(), invalid argument - packet with already set action\n");
		return (enum action_t)ptr_pckt_lg_info->action;
	}
	
	if( is_relevant_protocol(rule->protocol, ptr_pckt_lg_info->protocol) &&
		is_relevant_direction(rule->direction, *packet_direction) &&
		is_relevant_ip(rule->src_ip, rule->src_prefix_mask, ptr_pckt_lg_info->src_ip) &&
		is_relevant_ip(rule->dst_ip, rule->dst_prefix_mask, ptr_pckt_lg_info->dst_ip) )
	{
		if ( (rule->protocol == PROT_TCP) || (rule->protocol == PROT_UDP) )
		{
			//In those protocols, also ports should be checked:
			if ( is_relevant_port(rule->src_port, ptr_pckt_lg_info->src_port) &&
				 is_relevant_port(rule->dst_port, ptr_pckt_lg_info->dst_port) )
			{	
				//If TCP, also ack value should be checked
				//If UDP, rule fits packet
				if ( ((rule->protocol == PROT_TCP) && 
					(is_relevant_ack(rule->ack, *packet_ack))) ||
					(rule->protocol == PROT_UDP) )
				{		
					ptr_pckt_lg_info->action = rule->action;
					return (enum action_t)rule->action;		
				} 
			}
			//Otherwise, rule isn't relevant to packet - ports/ack(TCP alone)
			//don't fit, will continue to "rule isn't relevant to packet"
					
		} else { //Not a tcp/udp rule&packet, and they fit:
			//Set packets' action according to this rule:
			ptr_pckt_lg_info->action = rule->action;
#ifdef LOG_DEBUG_MODE
			printk (KERN_INFO "inside is_relevant_rule(), packet fits rule, rule's action is: %d\n", rule->action);
#endif
			return (enum action_t)rule->action;
		}	
	}
	
	//rule isn't relevant to packet:
	return RULE_NOT_RELEVANT;

}

/**
 *	Checks if g_all_rules_table contains a rule which is relevant
 *  to packet represented by ptr_pckt_lg_info.
 *	
 *	Updates: if found relevant rule:
 * 			1.ptr_pckt_lg_info->action to NF_ACCEPT/NF_DROP
 * 			2.ptr_pckt_lg_info->reason to rules' index
 *
 * 
 *	Returns: 1. if found relevant rule: it's index
 *			 2. if no relevant rule was found: (-1)
 * 
 *	Note: 1. function should be called AFTER ptr_pckt_lg_info,
 * 			 *packet_ack and *packet_direction were initiated
 * 			 (using init_log_row).
 * 		  2. function should be called AFTER making sure packet isn't XMAS 
 **/
static int get_relevant_rule_num_from_table(log_row_t* ptr_pckt_lg_info,
		ack_t* packet_ack, direction_t* packet_direction)
{

	size_t index = 0;
	for (index = 0; index < g_num_of_valid_rules; ++index) {
#ifdef LOG_DEBUG_MODE
	printk(KERN_INFO "In function get_relevant_rule_num_from_table, current index is: %u.\n",index);
#endif	

		if ( (is_relevant_rule(&(g_all_rules_table[index]),
				ptr_pckt_lg_info,packet_ack, packet_direction))
			!= RULE_NOT_RELEVANT )
		{ 
		//Rule is relevant, ptr_pckt_lg_info->action was updated in is_relevant_rule()
			ptr_pckt_lg_info->reason = index;
#ifdef LOG_DEBUG_MODE
			printk(KERN_INFO "In function get_relevant_rule_num_from_table, found relevant rule, its index is: %u.\n",index);
#endif
			return index;
		}
	}
	//No rule was found
#ifdef LOG_DEBUG_MODE
	printk(KERN_INFO "In function get_relevant_rule_num_from_table, NO relevant rule was found.\n");
#endif
	return (-1);
}



/**
 *	Decides the action that should be taken on packet:
 *	Updates: ptr_pckt_lg_info->action
 * 			 ptr_pckt_lg_info->reason
 * 
 *	Note: function should be called AFTER ptr_pckt_lg_info,
 * 		  *packet_ack and *packet_direction were initiated
 * 		  (using init_log_row).
 **/
void decide_packet_action(struct sk_buff* skb, log_row_t* ptr_pckt_lg_info,
		ack_t* packet_ack, direction_t* packet_direction)
{
	if (g_fw_is_active == FW_OFF) {
		ptr_pckt_lg_info->action = NF_ACCEPT;
		ptr_pckt_lg_info->reason = REASON_FW_INACTIVE;
		return;
	}
	
	if (is_XMAS(skb)){
		ptr_pckt_lg_info->action = NF_DROP;
		ptr_pckt_lg_info->reason = REASON_XMAS_PACKET;
		return;
	} 
	//If gets here, g_fw_is_active == FW_ON & packet isn't XMAS
	
	if ( (get_relevant_rule_num_from_table(ptr_pckt_lg_info,
						packet_ack, packet_direction)) <  0 )
	{//Meaning no relevant rule was found:
		ptr_pckt_lg_info->action = NF_ACCEPT;
		ptr_pckt_lg_info->reason = REASON_NO_MATCHING_RULE;	
			
	} //Otherwise, ptr_pckt_lg_info->action & reason were updated during get_relevant_rule_num_from_table()
	
}


/**
 *	Decides the action that should be taken on AN INNER packet
 *	(a packet caught in hook-points: NF_INET_LOCAL_IN/NF_INET_LOCAL_OUT) 
 * 
 *	Updates: ptr_pckt_lg_info->action 
 * 			(if build-in rule is relevant to current packet)
 * 
 *	Note: 1.function should be called AFTER ptr_pckt_lg_info,
 * 		  	*packet_ack and *packet_direction were initiated
 * 		  	(using init_log_row).
 *		  2.function should be used on packets that WON'T BE LOGGED,
 * 			using log_row_t* since it's easier :)
 * 		
 **/
unsigned int decide_inner_packet_action(log_row_t* ptr_pckt_lg_info,
		ack_t* packet_ack, direction_t* packet_direction )
{
	enum action_t answer = is_relevant_rule(&g_buildin_rule, ptr_pckt_lg_info, packet_ack, packet_direction);
	if (answer == RULE_NOT_RELEVANT) {
		//Since in those hook-points, we block any packet which doesn't fit g_buildin_rule:
#ifdef LOG_DEBUG_MODE
		printk(KERN_INFO "In decide_inner_packet_action(), returning NF_DROP\n");
#endif
		return NF_DROP;
	}
	//If gets here, ptr_pckt_lg_info->action must be NF_ACCEPT
#ifdef LOG_DEBUG_MODE
		printk(KERN_INFO "In decide_inner_packet_action(), returning NF_ACCEPT\n");
#endif
	return ptr_pckt_lg_info->action;
}

/**
 * Help function that cleans up everything associated with creating our device,
 * According to the state that's been given.
 **/
static void destroyRulesDevice(struct class* fw_class, enum state_to_fold stateToFold){
	switch (stateToFold){
		case(ALL_DES):
			device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		case(FIRST_FILE_DES):
			device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		case(DEVICE_DES):
			device_destroy(fw_class, MKDEV(rules_dev_major_number, MINOR_RULES));
		case (UNREG_DES):
			unregister_chrdev(rules_dev_major_number, DEVICE_NAME_RULES);
	}
}

/**
 *	Initiates rule-device.
 *	Returns: 0 on success, -1 if failed. 
 * 
 *	Note: user should destroy fw_class if this function returned -1!
 **/
int init_rules_device(struct class* fw_class){
	
	//Initiates global values, just to make sure:
	g_num_of_valid_rules = 0;
	g_fw_is_active = FW_OFF;
	g_usage_counter = 0;
	g_num_rules_have_been_read = 0;
	g_write_to_buff = NULL;
	g_write_buff_len = 0;
	g_bytes_written_so_far = 0;
	g_num_rules_have_been_read = 0;
	
	//Create char device
	rules_dev_major_number = register_chrdev(0, DEVICE_NAME_RULES, &fops);
	if (rules_dev_major_number < 0){
		printk(KERN_ERR "Error: failed registering rules-char-device.\n");
		return -1;
	}
	
	//Create rules-sysfs device:
	rules_device = device_create(fw_class, NULL, MKDEV(rules_dev_major_number, MINOR_RULES), NULL, CLASS_NAME "_" DEVICE_NAME_RULES);
	if (IS_ERR(rules_device))
	{
		printk(KERN_ERR "Error: failed creating rules-char-device.\n");
		destroyRulesDevice(fw_class,UNREG_DES);
		return -1;
	}
	
	//Create "active"-sysfs file attributes:
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr))
	{
		printk(KERN_ERR "Error: failed creating active-sysfs-file inside rules-char-device.\n");
		destroyRulesDevice(fw_class, DEVICE_DES);
		return -1;
	}
	
	//Create "rules_size"-sysfs file attributes:
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr))
	{
		printk(KERN_ERR "Error: failed creating rules_size-sysfs-file inside rules-char-device.\n");
		destroyRulesDevice(fw_class, FIRST_FILE_DES);
		return -1;
	}
	
#ifdef DEBUG_MODE 
   printk(KERN_INFO "fw_rules: device successfully initiated.\n");
#endif
	return 0;
}

/**
 *	Destroys rule-device
 **/
void destroy_rules_device(struct class* fw_class){
	clean_g_write_buff(true);
	destroyRulesDevice(fw_class, ALL_DES);
#ifdef DEBUG_MODE 
	printk(KERN_INFO "fw_rules: device destroyed.\n");
#endif
}
