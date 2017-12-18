#include "conn_tab_utils.h"

//Declares (static) g_connections_list of type struct list_head:
static LIST_HEAD(g_connections_list); 




/**
 *	Deletes a specific row from connection-list, by specific node
 * 
 *	@node - a pointer to the relevant list_head object to be deleted. 
 * 
 *	NOTE: USE SAFELY!! (WITH "list_for_each_safe()")
 **/
static void delete_specific_row_by_list_node(struct list_head* node){
	connection_row_t* temp_row;
	if (node == NULL) {
		printk(KERN_ERR "In delete_specific_row_by_list_node(), function got NULL argument\n");
		return;
	}
	temp_row = list_entry(node, connection_row_t, list);
	list_del(node);
	kfree(temp_row);
} 

/**
 *	Deletes a specific row from connection-list, by specific connection_row_t
 * 
 *	@row - a pointer to the relevant row to be deleted. 
 * 
 *	NOTE: USE SAFELY!! (WITH "list_for_each_safe()")
 **/
static void delete_specific_row_by_conn_ptr(connection_row_t* row){
	if (row == NULL) {
		printk(KERN_ERR "In delete_specific_row_by_conn_ptr(), function got NULL argument\n");
		return;
	}
	list_del(&(row->list));
	kfree(row);
} 

/**
 *	Deletes all connection-rows from g_connections_list
 *	(frees all allocated memory)
 **/
static void delete_all_conn_rows(void){

	connection_row_t *row, *temp_row;
	
	list_for_each_entry_safe(row, temp_row, &g_connections_list, list) {
		list_del(&row->list);
		kfree(row);
	}

#ifdef CONN_DEBUG_MODE
	printk(KERN_INFO "All connection-rows were deleted from list\n"); 
#endif
}


/**
 *	Checks if the given row has timedout (at least TIMEOUT_SECONDS
 *	passed since it was written)
 * 
 *	Returns true if it is, false otherwise.
 **/
static bool is_row_timedout(connection_row_t* row){
	struct timespec ts = { .tv_sec = 0,.tv_nsec = 0};
	getnstimeofday(&ts);
	return ( (ts.tv_sec - (row->timestamp)) >= TIMEOUT_SECONDS ); 
}

/**
 *	Gets a pointer to a SYN packet's log_row_t, 
 *	adds a relevant NEW connection to g_connections_list.
 * 
 *	Returns true on success, false if any error occured.
 **/
bool add_first_SYN_connection(log_row_t* syn_pckt_lg_info){
	
	connection_row_t* new_conn = NULL;
	
	if(syn_pckt_lg_info == NULL){
		printk(KERN_ERR "In function add_first_SYN_connection(), function got NULL argument");
	}
	
	//Allocates memory for connection-row:
    if((new_conn = kmalloc(sizeof(connection_row_t),GFP_ATOMIC)) == NULL){
		printk(KERN_ERR "Failed allocating space for new connection row.\n");
		return false;
	}
	memset(new_conn, 0, sizeof(connection_row_t)); 
	
	new_conn->src_ip = syn_pckt_lg_info->src_ip;
	new_conn->src_port = syn_pckt_lg_info-> src_port;
	new_conn->dst_ip = syn_pckt_lg_info->dst_ip;
	new_conn->dst_port = syn_pckt_lg_info->dst_port;
	//Since it's a (first) SYN packet:
	new_conn->tcp_state = syn_pckt_lg_info->TCP_STATE_SYN_SENT;
	new_conn->timestamp = syn_pckt_lg_info->timestamp;
	INIT_LIST_HEAD(&(new_conn->list));
	
	list_add(&(new_conn->list), &g_connections_list);
	return true;
}


/**
 *	Sets a TCP packet's action, according to current connection-list
 *	
 *	NOTE: packet SHOULDN'T BE A SYN PACKET! (assuming those were 
 * 		  already been taking care of).
 * 
 *	Updates:	1. pckt_lg_info->action
 * 				2. pckt_lg_info->reason
 * 				3. if packet's valid: g_connections_list to fit the connection state
 *	
 *	Returns: true on success, false if any error occured
 *	NOTE: if returned false, take care of pckt_lg_info->action, pckt_lg_info->reason!
 **/
bool check_tcp_packet(log_row_t* pckt_lg_info, tcp_packet_t tcp_pckt_type){
		
	if(pckt_lg_info == NULL || tcp_hdr == NULL){
		printk(KERN_ERR "In function check_tcp_packet(), function got NULL argument(s).\n");
		return false;
	}
	
	switch (tcp_pckt_type){	
		
		case(TCP_SYN_PACKET):
			printk(KERN_ERR "In function check_tcp_packet(), function got SYN packet info.\n");
			return false;
			
		case(TCP_SYN_ACK_PACKET):
			//TODO::
			break;
		
		case(TCP_FIN_PACKET):
			//TODO::
			break;
		
		case(TCP_OTHER_PACKET):
			//TODO::
			break;
		
		case(TCP_RESET_PACKET):
			//TODO::
			break;

		case(TCP_INVALID_PACKET):
			pckt_lg_info->action = NF_DROP
			pckt_lg_info->reason = REASON_ILLEGAL_VALUE;
			break;
			
		default: //TCP_ERROR_PACKET
			return false;
	}
	
	return true;
}
