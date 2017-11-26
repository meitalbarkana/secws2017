#include "rules_utils.h"

static unsigned char g_num_of_valid_rules = 0;
static rule_t g_all_rules_table[MAX_NUM_OF_RULES];
static unsigned char g_fw_is_active = FW_OFF;
 
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
		if (strncmp(((g_all_rules_table)[i]).rule_name, rulename, MAX_LEN_OF_NAME_RULE+1) == 0){
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
		rule->direction = (direction_t)num; //Safe casting
		return true;
	} 
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
	if (prefix_length == 32){
		return temp;
	}
	temp = temp >> (32-prefix_length); // For example: if prefix = 3, temp will contain: 00011111 11111111 11111111 11111111
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
	return false; //not a valid direction
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
	return false; //not a valid protocol
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
	return false; //not a valid protocol
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
	return false; //not a valid action
}

/**
 * @ruleStr -
 * Returns true if 
 **/
static bool is_valid_rule(const char* ruleStr){
	//TODO:: 
}
