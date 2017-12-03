#include "rules_utils.h"

/** 	
 * Used: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 * as a reference.
 **/

static unsigned char g_num_of_valid_rules = 0;
static rule_t g_all_rules_table[MAX_NUM_OF_RULES];
static unsigned char g_fw_is_active = FW_OFF;
static int g_usage_counter = 0;
static unsigned char g_num_rules_have_been_read = 0;

//Firewalls' build-in rule: to allow connection between localhost to itself:
static const rule_t g_buildin_rule = 
{
	.rule_name = "build-in-rule",
	.direction = DIRECTION_ANY,
	.src_ip = LOCALHOST_IP,
	.src_prefix_mask = LOCALHOST_PREFIX_MASK,
	.src_prefix_size = LOCALHOST_MASK_LEN,
	.dst_ip = LOCALHOST_IP,
	.dst_prefix_mask = LOCALHOST_PREFIX_MASK,
	.dst_prefix_size = LOCALHOST_MASK_LEN,
	.src_port = PORT_ANY,
	.dst_port = PORT_ANY,
	.protocol = PROT_ANY,
	.ack = ACK_ANY,
	.action = NF_ACCEPT
};

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


//For tests alone! prints rule to kernel
/**
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
**/

 /**
 *	This function will be called when user tries to read from the "active" device.
 * 	
 *  NOTE: writes to "buf" the value of of g_fw_is_active, in (string) format:
 * 		<g_fw_is_active>
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
			g_fw_is_active = FW_OFF;
		}
	} else { //buf[0] =='1'
		if (g_fw_is_active == FW_ON){
			printk(KERN_INFO "User tried do activate already-on firewall\n");
		} else {
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
	size_t i = 0;
	for (i = 0; i < g_num_of_valid_rules; ++i){
		if (strncmp(((g_all_rules_table)[i]).rule_name, rulename, MAX_LEN_RULE_NAME) == 0){ 
			return true; //rulename already exists
		}
	}
	printk(KERN_ERR "User tried to add rule with the same name as another rule.\n");
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
	printk(KERN_INFO "In function is_valid_rule, testing rule number: %huu\n",g_num_of_valid_rules);
#endif
	
	//Makea sure there aren't too much rules & that rule_str isn't longer than MAX_STRLEN_OF_RULE_FORMAT
	if ((g_num_of_valid_rules >= MAX_NUM_OF_RULES) || (rule_str == NULL) ||
		(strnlen(rule_str, MAX_STRLEN_OF_RULE_FORMAT+2) > MAX_STRLEN_OF_RULE_FORMAT)){ 
		printk(KERN_ERR "Rule format is invalid: too long or NULL accepted.\n");
		return false;
	}
	
	//Since any unsigned int represent a valid IPv4 address, src_ip & dst_ip are updated here
	//Since any unsigned short represent a valid port number, src_port & dst_port are updated here:
	if ( (sscanf(rule_str, "%19s %10d %u %hhu %u %hhu %hu %hu %hhu %d %hhu", t_rule_name, &t_direction,
			&(rule->src_ip), &t_src_prefix_len, &(rule->dst_ip), &t_dst_prefix_size, &(rule->src_port), &(rule->dst_port),
			&t_protocol, &t_ack, &t_action)) < NUM_OF_FIELDS_IN_FORMAT ) 
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
	printk(KERN_INFO "In function is_valid_rule, done testing a VALID rule. Total valid rules so far: %huu, \n",g_num_of_valid_rules);
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
 * 	NOTE:	1. if user sends 1 as len & buffer[0] = CLEAR_RULES,
 * 				it means he wants to clear rules-table.
 * 			2. otherwise, we treat buffer as a "list" of rules, in format:
 *	<rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>'\n'			
 * 	<rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>'\n'...
 * 
 * 	Returns: number of bytes from buffer that have been "written" in our device,
 * 			 negative number if failed (zero if no rule was added)
 */
static ssize_t rfw_dev_write(struct file* filp, const char* buffer, size_t len, loff_t *offset){
	
	size_t buff_len;
	ssize_t written_bytes = 0;
	char *buff_copy, *ptr_buff_copy, *rule_token; 
	
	//Basic input checks:
	if ((buffer == NULL) || (len == 0) || (len > MAX_LEN_ALL_RULES_BUFF)
		|| ( (buff_len = strnlen(buffer, MAX_LEN_ALL_RULES_BUFF+2)) > MAX_LEN_ALL_RULES_BUFF ) ) 
	{
		return -1;
	}
	//Case user wanted to clean rule-table:
	if ((len == 1) && buffer[0]==CLEAR_RULES){
		g_num_of_valid_rules = 0;
		return len;
	} 
	
	/*Create a copy of buffer (because it's const):*/
	if((buff_copy = kmalloc(sizeof(char)*(buff_len+1),GFP_KERNEL)) == NULL){
		printk(KERN_ERR "Failed allocating space for copying all-rules string\n");
		return -1;
	}
	//buffer is guaranteed to have '\0' at its end, from passing basic input check:
	strncpy(buff_copy, buffer, MAX_LEN_ALL_RULES_BUFF+1); 
	//Saving a ptr so we can free it later (strsep "ruins" buff_copy)
	ptr_buff_copy = buff_copy; 
	
	while ( ((rule_token = strsep(&buff_copy, DELIMETER_STR)) != NULL) 
			&& (g_num_of_valid_rules < MAX_NUM_OF_RULES) ) 
	{
		if(is_valid_rule(rule_token)){
			written_bytes += strnlen(rule_token, MAX_STRLEN_OF_RULE_FORMAT+2);
		}
	}
	
	return written_bytes;
	
}


/**
 * A helper function to dev_read: writes rulePrt representation
 * as string into buffer, using copy_to_user, in format:
 * <rule name> <direction> <src ip> <src prefix length> <dst ip> <dst prefix length> <protocol> <source port> <dest port> <ack> <action>'\n'
 * 
 * @rulePtr - pointer to rule to be "printed" into buffer
 * @buffer
 * 
 * Returns - on success: number of bytes written (sent) to buffer,
 * 			 on failure: -EFAULT if copy_to_user failed,
 * 						 -1 if other failure happened
 **/
static int send_str_rule_to_buffer(rule_t* rulePtr, char* buffer){
	
	char str[MAX_STRLEN_OF_RULE_FORMAT+2]; //+2: for '\n' and '\0' 
	
	if (rulePtr == NULL){
		printk(KERN_ERR "add_str_rule_to_buffer got NULL value\n");
		return -1;
	}
	
	if ((sprintf(str,
				"%s %d %u %hhu: %u %hhu %hu %hu %hhu %d %hhu\n",
				rulePtr->rule_name,
				rulePtr->direction,
				rulePtr->src_ip,
				rulePtr->src_prefix_size,
				rulePtr->dst_ip,
				rulePtr->dst_prefix_size,
				rulePtr->src_port,
				rulePtr->dst_port,
				rulePtr->protocol,
				rulePtr->ack,
				rulePtr->action)
		) < NUM_OF_FIELDS_IN_RULE_T)
	{
		printk(KERN_ERR "Error formatting rule to its string representation\n"); //Should never get here..
		return -1;
	} 
	
	// copy_to_user has the format ( * to, *from, size) and returns 0 on success
	if ( copy_to_user(buffer, str, strnlen(str,MAX_STRLEN_OF_RULE_FORMAT+2)) != 0 ) {
		printk(KERN_INFO "Function copy_to_user failed - writing rule to user's buffer failed\n");
		return -EFAULT; //Return a bad address message
	}
	
#ifdef DEBUG_MODE
	printk(KERN_INFO "In function add_str_rule_to_buffer, done adding it:\n%s\n",str);
#endif	
	
	return strnlen(str,MAX_STRLEN_OF_RULE_FORMAT+2);
	
}


/** 
 * 	This function is called whenever device is being read from user space
 *  i.e. data is being sent from the device to the user. 
 * 	We use copy_to_user() function to copy rules (in their string format)
 * 	to buffer.
 * 
 *  @filp - a pointer to a file object (here it's not relevant)
 *  @buffer - pointer to the buffer to which this function will write the data
 *  @len - length of the buffer, excluding '\0'. 
 *  @offset - the offset if required (here it's not relevant)
 * 
 * Note: 1. if len isn't enough for all rules, buffer will be filled 
 * 			with as many rules as send_str_rule_to_buffer will succeed.
 * 		 2. g_num_rules_have_been_read will be updated according to
 * 			rules that have been read (for further reading)
 * 		 3. User should allocate enough space and check he got all rules.
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
	
	int temp = 0;
	size_t i = g_num_rules_have_been_read;
	ssize_t bytes_read = 0;
	
	//Checks if user already finished reading all rules:
	if (g_num_rules_have_been_read == g_num_of_valid_rules) { 
		g_num_rules_have_been_read = 0; //To allow another reading if he wants
		return 0;
	}
	
	while ( (i < g_num_of_valid_rules) && (bytes_read < len) ) {
		temp = send_str_rule_to_buffer(&(g_all_rules_table[i]), buffer+bytes_read );
		if (temp <= 0){ //copy_to_user failed/other error: stop trying to copy all other rules
			break;
		}
		bytes_read += temp;
		++g_num_rules_have_been_read;
		++i;
	}
	
	if (bytes_read == 0 && temp < 0){ //No rules were written at all because of an error 
		return -1;
	}
	
	return bytes_read;
	
}

/** 
 * 	The device open function (called each time the device is opened):
 * 		1. Increments g_usage_counter (although ".owner" is defined so it's not mandatory)
 *  	2. Updates g_num_rules_have_been_read to 0.
 * 
 *	@inodep - pointer to an inode object)
 *  @fp - pointer to a file object
 */
static int rfw_dev_open(struct inode *inodep, struct file *fp){
   g_usage_counter++;
   g_num_rules_have_been_read = 0;
   
#ifdef DEBUG_MODE 
   printk(KERN_INFO "fw_rules: device has been opened %d time(s)\n", g_usage_counter);
#endif

   return 0;
}

/** 
 * 	The device release function - called whenever the device is 
 *	closed/released by the userspace program.
 * 		1. Decrements g_usage_counter
 *  	2. Updates g_num_rules_have_been_read to 0.
 *
 *  @inodep - pointer to an inode object
 *  @fp - pointer to a file object
 */
static int rfw_dev_release(struct inode *inodep, struct file *fp){
	if (g_usage_counter != 0){
		g_usage_counter--;
	}
	g_num_rules_have_been_read = 0;
	
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
			(packet_direction == DIRECTION_ANY) ); //TODO::check about this line - since packet_direction supposed to be final(??)
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
 * 			(since if packet isn't a tcp packet, deafult ack value is ACK_NO)
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
bool is_XMAS(struct sk_buff* skb){
	
	struct iphdr* ptr_ipv4_hdr; //pointer to ipv4 header
	struct tcphdr* ptr_tcp_hdr; //pointer to tcp header
	__u8 ip_h_protocol = 0;
	
	if (skb){ 
		ptr_ipv4_hdr = ip_hdr(skb);
		if(ptr_ipv4_hdr){
			ip_h_protocol = ptr_ipv4_hdr->protocol; //Network order!
			if (ntohs(ip_h_protocol) == PROT_TCP) {	//Checks in local endianness
				ptr_tcp_hdr = (struct tcphdr*)((char*)ptr_ipv4_hdr + (ptr_ipv4_hdr->ihl * 4));
				//accessing specific bits through struct fields is endian-safe:
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
 * 			 *packet_ack and *packet_directionwas were initiated
 * 			 (using init_log_row).
 * 		  2. function should be called AFTER making sure packet isn't XMAS 
 **/
enum action_t is_relevant_rule(rule_t* rule, log_row_t* ptr_pckt_lg_info,
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
 * 			 *packet_ack and *packet_directionwas were initiated
 * 			 (using init_log_row).
 * 		  2. function should be called AFTER making sure packet isn't XMAS 
 **/
int get_relevant_rule_num_from_table(log_row_t* ptr_pckt_lg_info,
		ack_t* packet_ack, direction_t* packet_direction)
{
	size_t index = 0;
	for (index = 0; index < g_num_of_valid_rules; ++index) {
		if ( is_relevant_rule(&(g_all_rules_table[index]),
				ptr_pckt_lg_info,packet_ack, packet_direction)
			!= RULE_NOT_RELEVANT )
		{ 
		//Rule is relevant, ptr_pckt_lg_info->action was updated in is_relevant_rule()
			ptr_pckt_lg_info->reason = index;
#ifdef DEBUG_MODE
			printk(KERN_INFO "In function get_relevant_rule_num_from_table, found relevant rule, its index is: %u.\n",index);
#endif
			return index;
		}
	}
	//No rule was found
#ifdef DEBUG_MODE
	printk(KERN_INFO "In function get_relevant_rule_num_from_table, NO relevant rule was found.\n");
#endif
	return (-1);
}

