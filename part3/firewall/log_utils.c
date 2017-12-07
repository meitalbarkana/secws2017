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

// Will contain log-device's major number - its unique ID:
static int log_dev_major_number = 0; 
static struct device* log_device = NULL;

/**
 *	Updates:
 * 			1. *ptr_pckt_lg_info fields to contain the packet information
 * 			2. *ack to contain the packets ack value (ACK_ANY if not TCP)
 * 			3. *direction to contain the packets direction
 * 
 *	@skb - the packet
 *	@ptr_pckt_lg_info - a pointer to log_row_t to be initiated
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
bool init_log_row(struct sk_buff* skb, log_row_t* ptr_pckt_lg_info,
		unsigned char hooknumber, ack_t* ack, direction_t* direction,
		const struct net_device* in, const struct net_device* out)
{
	
	struct iphdr* ptr_ipv4_hdr;		//pointer to ipv4 header
	struct tcphdr* ptr_tcp_hdr;		//pointer to tcp header
	struct udphdr* ptr_udp_hdr;		//pointer to udp header
	__u8 ip_h_protocol = 0;
	__be16 temp_port_num;
	struct timespec ts = { .tv_sec = 0,.tv_nsec = 0};
	getnstimeofday(&ts);
    
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
	return false;
	
}

//For tests alone! prints log-row to kernel
void print_log_row(log_row_t* logrowPtr, int logrow_num){
	
	size_t add_to_len = strlen("log row number: ,\ntimestamp: ,\nprotocol: ,\naction: ,\nhooknum: ,\nsrc_ip: ,\ndst_ip: ,\nsrc_port: ,\ndst_port: ,\nreason: ,\ncount: .\n");
	char str[MAX_STRLEN_OF_ULONG + 3*MAX_STRLEN_OF_U8 + 5*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16 + add_to_len+3]; //+3: 1 for null-terminator, 2 more to make sure 
	
	if ((sprintf(str,
				"log row number: %d,\ntimestamp: %lu,\nprotocol: %hhu,\naction: %hhu,\nhooknum: %hhu,\nsrc_ip: %u,\ndst_ip: %u,\nsrc_port: %hu,\ndst_port: %hu,\nreason: %d,\ncount: %u.\n",
				logrow_num,
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
		printk(KERN_ERR "In get_similar_row(), function got NULL argument.\n");
		return false;
	}
	
	list_for_each_safe(pos, q, &g_logs_list){
		temp_row = list_entry(pos, log_row_t, list);
		if (are_similar(temp_row, row)) {
			row->count = 1+temp_row->count;
#ifdef LOG_DEBUG_MODE
			printk(KERN_INFO "Found similar row in list, about to delete it. Its details:\n");
			print_log_row(temp_row, -1);
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
