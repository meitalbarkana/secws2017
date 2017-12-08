#include "log_utils.h"

//Global counter of number of rows, to make sure < MAX_LOG_ROWS
static int g_num_of_rows = 0;

/**
 *	Variables that will hold all log-row's list:
 *	g_logs_list is the head of the list [it's some kind of a Dummy, won't
 *	contain "real" log-row information].
 * 
 *	New elements will always be inserted first (list is ordered from newest to oldest)
 **/
static LIST_HEAD(g_logs_list); // Declares (static) g_logs_list of type struct list_head

static int g_num_rows_read = 0;
static int g_log_usage_counter = 0;
static struct list_head* g_last_row_read = NULL; 

// Will contain log-device's major number - its unique ID:
static int log_dev_major_number = 0; 
static struct device* log_device = NULL;

// Prototype functions declarations for the character driver - must come before the struct definition
static ssize_t lfw_dev_read(struct file *filp, char *buffer, size_t len, loff_t *offset);
static int lfw_dev_open(struct inode *inodep, struct file *fp);
static int lfw_dev_release(struct inode *inodep, struct file *fp);
 
static struct file_operations log_fops = {
	.owner = THIS_MODULE,
	.open = lfw_dev_open,
	.read = lfw_dev_read,
	.release = lfw_dev_release
};

/** 
 * 	The device open function (called each time the device is opened):
 * 		1. Increments g_log_usage_counter
 *  	2. Updates g_num_rows_read to 0, and g_last_row_read to point
 * 		   the head of the list 
 * 
 *	@inodep - pointer to an inode object)
 *  @fp - pointer to a file object
 */
static int lfw_dev_open(struct inode *inodep, struct file *fp){
	
	g_log_usage_counter++;
	g_num_rows_read = 0;
	g_last_row_read = &g_logs_list;
	
#ifdef LOG_DEBUG_MODE 
	printk(KERN_INFO "fw_log: device is opened by %d process(es)\n", g_log_usage_counter);
#endif
	return 0;
}

/** 
 * 	The device release function - called whenever the device is 
 *	closed/released by the userspace program.
 *
 *	Decrements g_log_usage_counter	
 * 	 
 *  @inodep - pointer to an inode object
 *  @fp - pointer to a file object
 * 
 */
static int lfw_dev_release(struct inode *inodep, struct file *fp){
	
	if (g_log_usage_counter != 0){
		g_log_usage_counter--;
	}

#ifdef LOG_DEBUG_MODE 
   printk(KERN_INFO "fw_log: device successfully closed\n");
#endif

   return 0;
}


/** 
 * 	This function is called whenever device is being read from user space
 *  i.e. data is being sent from the device to the user. 
 * 	We use copy_to_user() function to copy log-rows 
 * (as numbers in their string format) to buffer.
 * 
 *	log-row format:
 * <timestamp> <protocol> <action> <hooknum> <src ip> <dst ip> <source port> <dest port> <reason> <count>'\n'
 * 
 *  @filp - a pointer to a file object (here it's not relevant)
 *  @buffer - pointer to the buffer to which this function will write data
 *  @len - length of the buffer, excluding '\0'. 
 *  @offset - the offset if required (here it's not relevant)
 * 
 * Note: 1. if len isn't enough for one row, action will fail.
 * 		 2. g_num_rows_read will be updated (+1) on success.
 * 		 3. User should allocate enough space, and if he wants all rows - 
 * 			read until EOF (0).
 * 		 4. In case of consecutive calls, in USER's responsibility to 
 * 			update buffer's pointer (offset is ignored).
 * 
 * Returns: 
 * 		 1. In case there were log-rows to read 
 * 			(i.e. g_num_rows_read < g_num_of_rows) returns the number
 *			of bytes written (sent) to buffer.
 * 		 2. In case there were NO rows left to read - returns 0 
 * 		 3. (-EFAULT) if copy_to_user failed / (-1) if other failure happened
 */
static ssize_t lfw_dev_read(struct file *filp, char *buffer, size_t len, loff_t *offset){

	log_row_t* rowPtr = NULL;
	char str[MAX_STRLEN_OF_LOGROW_FORMAT+1]; //for '\0'
		
	//Checks if user already finished reading all rows:
	if ((g_num_rows_read == g_num_of_rows) || (g_num_of_rows == 0)){ 
		g_num_rows_read = 0;//So next user could read
		g_last_row_read = &g_logs_list; 
		return 0;
	}
	
	rowPtr = list_entry(g_last_row_read->next, log_row_t, list);

	if ((sprintf(str,
				"%lu %hhu %hhu %hhu %u %u %hu %hu %d %u\n",
				rowPtr->timestamp,
				rowPtr->protocol,
				rowPtr->action,
				rowPtr->hooknum,
				rowPtr->src_ip,
				rowPtr->dst_ip,
				rowPtr->src_port,
				rowPtr->dst_port,
				rowPtr->reason,
				rowPtr->count)
		) < (MIN_LOGROW_FORMAT_LEN))
	{
		//Should never get here:
		printk(KERN_ERR "Error formatting log-row to its string representation\n");
		return -1;
	} 
	
	if (len < strlen(str)){
		printk(KERN_ERR "Error: user provided a buffer too small for log-row format\n");
		return -EFAULT;
	}
	
	// copy_to_user has the format ( * to, *from, size) and returns 0 on success
	if ( copy_to_user(buffer, str, strlen(str)) != 0 ) {
		printk(KERN_INFO "Function copy_to_user failed - writing log-row to user's buffer failed\n");
		return -EFAULT; //Return a bad address message
	}

		
#ifdef LOG_DEBUG_MODE
	printk(KERN_INFO "In function lfw_dev_read, done sending it:\n%s\n",str);
#endif

	g_last_row_read = g_last_row_read->next;
	++g_num_rows_read;
	return strlen(str);
}


/**
 *	Deletes all log-rows from g_logs_list
 *	(frees all allocated memory)
 **/
static void delete_all_rows(void){

	log_row_t *row, *temp_row;
	
	list_for_each_entry_safe(row, temp_row, &g_logs_list, list) {
		list_del(&row->list);
		kfree(row);
	}
	g_num_of_rows = 0;
	g_num_rows_read = 0;
#ifdef LOG_DEBUG_MODE
	printk(KERN_INFO "All log-rows were deleted from list\n"); 
#endif
}


/**
 * 	This function will be called when user tries to write to "log_clear"
 *  Returns:	count on success,
 * 				a negative number otherwise.
 * 
 * 	Buffer should contain exactly one character to clear all log-rows.
 * 
 * 	If user provided buffer containing something other that valid value,
 * 	or passed a "count" value that is different from 1 - will fail! 
 * 	[count represent the length of buf ('\0' not included)]
 **/
ssize_t clear_log_list(struct device* dev, struct device_attribute* attr, const char* buf, size_t count){

	if( (buf == NULL) || (count != 1) || (strnlen(buf,3) != 1) ){
		printk(KERN_ERR "*** Error: user sent invalid input to clear log ***\n");
		return -EPERM; // Returns an error of operation not permitted
	}
	
	delete_all_rows();
	
	return count;

}


 /**
 *	This function will be called when user tries to read from "log_size"
 * 	
 *  NOTE: writes to "buf" the value of of g_num_of_rows, in (string) format:
 * 		<g_num_of_rows>
 * 
 * [writes minimal amount of characters, as it's a kernel function]
 **/
ssize_t read_log_size(struct device* dev, struct device_attribute* attr, char* buf){
		ssize_t ret = scnprintf(buf, PAGE_SIZE, "%d", g_num_of_rows);
		if (ret <= 0){
			printk(KERN_ERR "*** Error: failed writing to user's buffer in function read_log_size() ***\n");
		}
		return ret;
}


/**
 * 	Declaring a variable of type struct device_attribute, its name would be "dev_attr_log_clear",
 * 	will be used to link device to the "log_clear" attribute
 * 		.attr.name = "log_clear" (access it through: dev_attr_log_clear)
 * 		.attr.mode = S_IWUSR | S_IWOTH, giving the owner and other user write permissions
 * 		.show = NULL (no reading function)
 * 		.store = clear_log_list
 **/
static DEVICE_ATTR(log_clear, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH, NULL, clear_log_list);
/**
 * 	Declaring a variable of type struct device_attribute, its name would be "dev_attr_log_size",
 * 	will be used to link device to the "log_size" attribute
 * 		.attr.name = "log_size" (access it through: dev_attr_log_size)
 * 		.attr.mode = S_IRUSR | S_IROTH, giving the owner and other user read permissions
 * 		.show = read_log_size
 * 		.store = NULL (no writing function)
 **/
static DEVICE_ATTR(log_size, S_IRUSR | S_IROTH, read_log_size, NULL);


/**
 *	Creates (allocates) a new log-row: *ptr_pckt_lg_info.
 *	Updates:
 * 			1. *ptr_pckt_lg_info fields to contain the packet information
 * 			2. *ack to contain the packets ack value (ACK_ANY if not TCP)
 * 			3. *direction to contain the packets direction
 * 
 *	@skb - the packet
 *	@ptr_pckt_lg_info - a pointer to a pointer of log_row_t to be initiated
 *	@hooknumber - as received from netfilter hook
 *	@ack - a pointer to ack_t to be updated
 *	@direction - a pointer to direction_t to be updated
 *	@in - pointer to net_device representing the network inteface
 * 		  the packet pass through. NULL if packet traversal is "out".
 *	@out - pointer to net_device representing the network inteface
 * 		  the packet pass through. NULL if packet traversal is "in".
 * 
 * 	Note: fields: action, reason, count are only initiallized to default!
 *
 *	Returns true on success, false if an error happened (skb==NULL)
 **/
bool init_log_row(struct sk_buff* skb, log_row_t** ptr_ptr_pckt_lg_info,
		unsigned char hooknumber, ack_t* ack, direction_t* direction,
		const struct net_device* in, const struct net_device* out)
{

	struct iphdr* ptr_ipv4_hdr;		//pointer to ipv4 header
	struct tcphdr* ptr_tcp_hdr;		//pointer to tcp header
	struct udphdr* ptr_udp_hdr;		//pointer to udp header
	__u8 ip_h_protocol = 0;
	__be16 temp_port_num;
	//Make it easier to read:
    log_row_t* ptr_pckt_lg_info = *ptr_ptr_pckt_lg_info;
	struct timespec ts = { .tv_sec = 0,.tv_nsec = 0};
	getnstimeofday(&ts);
    

    
    //Allocates memory for log-row:
    if((ptr_pckt_lg_info = kmalloc(sizeof(log_row_t),GFP_KERNEL)) == NULL){
		printk(KERN_ERR "Failed allocating space for packet's info (log_row_t)\n");
		return false;
	}
	memset(ptr_pckt_lg_info, 0, sizeof(log_row_t)); 
    
    //Initiates known values:
    ptr_pckt_lg_info->timestamp = ts.tv_sec;
	ptr_pckt_lg_info->hooknum = hooknumber;
	*direction = get_direction(in, out);
	INIT_LIST_HEAD(&(ptr_pckt_lg_info->list));
	
	//Initiates default values:
	ptr_pckt_lg_info->count = 1;
	ptr_pckt_lg_info->action = RULE_NOT_RELEVANT;
	ptr_pckt_lg_info->reason = NO_REASON;
	ptr_pckt_lg_info->src_port = PORT_ANY;
	ptr_pckt_lg_info->dst_port = PORT_ANY;
	*ack = ACK_ANY; //Default value, according to rules_0.txt example
	
	if (skb) {
		ptr_ipv4_hdr = ip_hdr(skb);
		if(ptr_ipv4_hdr){
			
			ptr_pckt_lg_info->src_ip = ntohl(ptr_ipv4_hdr->saddr);
			ptr_pckt_lg_info->dst_ip = ntohl(ptr_ipv4_hdr->daddr);
			
			//Protocol is 1 byte - no need to convert Endianness.
			ip_h_protocol = ptr_ipv4_hdr->protocol; 
#ifdef LOG_DEBUG_MODE
			printk(KERN_INFO "Packets protocol is: %hhu\n", ip_h_protocol);
#endif
		
			switch (ip_h_protocol){
				case (PROT_ICMP):
				case (PROT_TCP):		
				case (PROT_UDP):
				case (PROT_ANY):
					ptr_pckt_lg_info->protocol = ip_h_protocol;
					break;
				default: //PROT_OTHER
					ptr_pckt_lg_info->protocol = PROT_OTHER;
			}

			if (ip_h_protocol == PROT_TCP){
				ptr_tcp_hdr = (struct tcphdr*)((char*)ptr_ipv4_hdr + (ptr_ipv4_hdr->ihl * 4));
				temp_port_num = ptr_tcp_hdr->source;
				ptr_pckt_lg_info->src_port = ntohs(temp_port_num); //Convert to local-endianness
				temp_port_num = ptr_tcp_hdr->dest;
				ptr_pckt_lg_info->dst_port = ntohs(temp_port_num); //Convert to local-endianness
				*ack = ((ptr_tcp_hdr->ack) == 1) ? ACK_YES : ACK_NO; //Updates *ack

			} else if (ip_h_protocol == PROT_UDP) {
				ptr_udp_hdr = (struct udphdr*)((char*)ptr_ipv4_hdr + (ptr_ipv4_hdr->ihl * 4));
				temp_port_num = ptr_udp_hdr->source;
				ptr_pckt_lg_info->src_port = ntohs(temp_port_num); //Convert to local-endianness
				temp_port_num = ptr_udp_hdr->dest;
				ptr_pckt_lg_info->dst_port = ntohs(temp_port_num); //Convert to local-endianness

			}
			return true;
		}
		
	} 
	
	printk(KERN_ERR "In init_log_row, skb or ptr_ipv4_hdr is NULL\n"); 
	kfree(ptr_pckt_lg_info);
	return false;
	
}

//For tests alone! prints log-row to kernel
void print_log_row(log_row_t* logrowPtr){
	size_t add_to_len = strlen("log row details:\ntimestamp: ,\nprotocol: ,\naction: ,\nhooknum: ,\nsrc_ip: ,\ndst_ip: ,\nsrc_port: ,\ndst_port: ,\nreason: ,\ncount: .\n");
	char str[MAX_STRLEN_OF_ULONG + 3*MAX_STRLEN_OF_U8 + 5*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16 + add_to_len+3]; //+3: 1 for null-terminator, 2 more to make sure 
	
	if ((sprintf(str,
				"log row details:\ntimestamp: %lu,\nprotocol: %hhu,\naction: %hhu,\nhooknum: %hhu,\nsrc_ip: %u,\ndst_ip: %u,\nsrc_port: %hu,\ndst_port: %hu,\nreason: %d,\ncount: %u.\n",
				logrowPtr->timestamp,
				logrowPtr->protocol,
				logrowPtr->action,
				logrowPtr->hooknum,
				logrowPtr->src_ip,
				logrowPtr->dst_ip,
				logrowPtr->src_port,
				logrowPtr->dst_port,
				logrowPtr->reason,
				logrowPtr->count )
		) < NUM_OF_FIELDS_IN_LOF_ROW_T + 1)
	{
		printk(KERN_INFO "Error printing log-row presentation");
	} 
	else
	{
		printk (KERN_INFO "%s",str);
	}
}

/**
 *	Gets 2 pointers to log-rows, returns true if they're similar
 * 
 *	[Similar := source ip, destination ip, source port, destination port, protocol,
 * 				hooknum,  action, reason are equal.] 
 * 
 **/
static bool are_similar(log_row_t* row_a, log_row_t* row_b) {

	if (row_a == NULL || row_b == NULL){
		printk(KERN_ERR "Function are_similar() got NULL argument.\n");
	}

	return (row_b->protocol == row_a->protocol &&
			row_b->action == row_a->action &&
			row_b->hooknum == row_a->hooknum &&
			row_b->src_ip == row_a->src_ip &&
			row_b->dst_ip == row_a->dst_ip &&
			row_b->src_port == row_a->src_port &&
			row_b->dst_port == row_a->dst_port &&	
			row_b->reason == row_a->reason);
	
}

/**
 *	Gets a pointer to a new log_row_t which was ALREADY initiated (in
 *	init_log_row()) and allocated (dynamically).
 *	searches g_logs_list for a similar log-row: if finds one, 
 *	UPDATES row's count (by the count of the similar) and deletes 
 *	the old log_row.
 * 
 *	Inserts row at the start of g_logs_list,
 *	to maintain the order from newest (first) to oldest (last element) 
 *	in g_logs_list.
 *	
 *	Returns: true on success, false if any error happened.
 **/
bool insert_row(log_row_t* row){
	
	struct list_head *pos, *q;
	log_row_t* temp_row;
	
	if (row == NULL) {
		printk(KERN_ERR "In insert_row(), function got NULL argument.\n");
		return false;
	}
	
	list_for_each_safe(pos, q, &g_logs_list){
		temp_row = list_entry(pos, log_row_t, list);
		if (are_similar(temp_row, row)) {
			row->count = 1+temp_row->count;
#ifdef LOG_DEBUG_MODE
			printk(KERN_INFO "Found similar row in list, about to delete it. Its details:\n");
			print_log_row(temp_row);
#endif
			list_del(pos);
			kfree(temp_row);
			--g_num_of_rows; //Since we deleted one (will be updated later)
			break;
		}
	}
	
	if (g_num_of_rows >= MAX_LOG_ROWS) { //Note: it was enough just to check "=="
	
		//Delete old row before inserting - the last row is the oldest:
		if ( (g_logs_list.prev) != &g_logs_list) { 
			//^ Makes sure last element in list isn't the head (empty list)
			temp_row = list_entry((g_logs_list.prev), log_row_t, list);
			list_del(g_logs_list.prev);
			kfree(temp_row);
			--g_num_of_rows;
		} else {
			printk(KERN_ERR "In insert_row(), large number of rows but list is empty!\n");
			return false;
		}
	}
	
	list_add(&(row->list), &g_logs_list);
	
	++g_num_of_rows;
	return true;
	
}

/**
 * Help function that cleans up everything associated with creating our device,
 * According to the state that's been given.
 **/
static void destroyLogDevice(struct class* fw_class, enum l_state_to_fold stateToFold){
	switch (stateToFold){
		case(L_ALL_DES):
			device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
		case(L_FIRST_FILE_DES):
			device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
		case(L_DEVICE_DES):
			device_destroy(fw_class, MKDEV(log_dev_major_number, MINOR_LOG));
		case (L_UNREG_DES):
			unregister_chrdev(log_dev_major_number, DEVICE_NAME_LOG);
	}
}


/**
 *	Initiates log-device.
 *	Returns: 0 on success, -1 if failed. 
 * 
 *	Note: user should destroy fw_class if this function returned -1!
 **/
int init_log_device(struct class* fw_class){
	
	//Initiates global values, just to make sure:
	g_num_of_rows = 0;
	g_num_rows_read = 0;
	g_log_usage_counter = 0;
	g_last_row_read = NULL; 
	
	//Create char device
	log_dev_major_number = register_chrdev(0, DEVICE_NAME_LOG, &log_fops);
	if (log_dev_major_number < 0){
		printk(KERN_ERR "Error: failed registering log-char-device.\n");
		return -1;
	}
	
	//Create log-sysfs device:
	log_device = device_create(fw_class, NULL, MKDEV(log_dev_major_number, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);
	if (IS_ERR(log_device))
	{
		printk(KERN_ERR "Error: failed creating log-char-device.\n");
		destroyLogDevice(fw_class,L_UNREG_DES);
		return -1;
	}
	
	//Create "log_clear"-sysfs file attributes:
	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_log_clear.attr))
	{
		printk(KERN_ERR "Error: failed creating log_clear-sysfs-file inside log-char-device.\n");
		destroyLogDevice(fw_class, L_DEVICE_DES);
		return -1;
	}
	
	//Create "log_size"-sysfs file attributes:
	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr))
	{
		printk(KERN_ERR "Error: failed creating log_size-sysfs-file inside log-char-device.\n");
		destroyLogDevice(fw_class, L_FIRST_FILE_DES);
		return -1;
	}
	
	printk(KERN_INFO "fw_log: device successfully initiated.\n");

	return 0;
}

/**
 *	Destroys log-device
 **/
void destroy_log_device(struct class* fw_class){
	
	delete_all_rows();
	destroyLogDevice(fw_class, L_ALL_DES);
	printk(KERN_INFO "fw_log: device destroyed.\n");

}

