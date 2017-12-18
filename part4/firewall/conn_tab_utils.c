#include "conn_tab_utils.h"

//Declares (static) g_connections_list of type struct list_head:
static LIST_HEAD(g_connections_list); 


/**
 *	Gets tcp_state_t representing the state of a TCP connection,
 *  Updates str to contain its string representation.
 * 
 *  @str - string to be updated
 *	NOTE: str's length, should be: MAX_STRLEN_OF_TCP_STATE+1 (includs '\0')
 **/
static void tran_tcp_state_to_str(tcp_state_t tcpState, char* str){

	switch (tcpState) {	
		case (TCP_STATE_CLOSED):
			strncpy(str,"CLOSED", MAX_STRLEN_OF_TCP_STATE+1);
			break;
		case(TCP_STATE_LISTEN):
			strncpy(str,"LISTEN", MAX_STRLEN_OF_TCP_STATE+1);
			break;		
		case(TCP_STATE_SYN_SENT):
			strncpy(str,"SYN-SENT", MAX_STRLEN_OF_TCP_STATE+1);
			break;
		case(TCP_STATE_SYN_RCVD):
			strncpy(str,"SYN-RCVD", MAX_STRLEN_OF_TCP_STATE+1);
			break;
		case(TCP_STATE_ESTABLISHED):
			strncpy(str,"ESTABLISHED", MAX_STRLEN_OF_TCP_STATE+1);
			break;
		case (TCP_STATE_FIN_WAIT_1):
			strncpy(str,"FIN-WAIT1", MAX_STRLEN_OF_TCP_STATE+1);
			break;
		case(TCP_STATE_CLOSE_WAIT):
			strncpy(str,"CLOSE-WAIT", MAX_STRLEN_OF_TCP_STATE+1);
			break;			
		case(TCP_STATE_FIN_WAIT_2):
			strncpy(str,"FIN-WAIT2", MAX_STRLEN_OF_TCP_STATE+1);
			break;
		case(TCP_STATE_LAST_ACK):
			strncpy(str,"LAST-ACK", MAX_STRLEN_OF_TCP_STATE+1);
			break;
		default: // == TCP_STATE_TIME_WAIT 
			strncpy(str,"TIME-WAIT", MAX_STRLEN_OF_TCP_STATE+1);
	}
}


/**
 *	Gets tcp_packet_t representing the type of a TCP packet,
 *  Updates str to contain its string representation.
 * 
 *  @str - string to be updated
 *	NOTE: str's length, should be: MAX_STRLEN_OF_TCP_PACKET_TYPE+1 (includs '\0')
 **/
static void tran_tcp_packet_type_to_str(tcp_packet_t p_type, char* str){
	
	switch (p_type) {	
		case (TCP_SYN_PACKET):
			strncpy(str,"SYN", MAX_STRLEN_OF_TCP_PACKET_TYPE+1);
			break;
		case(TCP_SYN_ACK_PACKET):
			strncpy(str,"SYN-ACK", MAX_STRLEN_OF_TCP_PACKET_TYPE+1);
			break;		
		case(TCP_FIN_PACKET):
			strncpy(str,"FIN-ACK", MAX_STRLEN_OF_TCP_PACKET_TYPE+1);
			break;
		case(TCP_OTHER_PACKET):
			strncpy(str,"OTHER", MAX_STRLEN_OF_TCP_PACKET_TYPE+1);
			break;
		case(TCP_RESET_PACKET):
			strncpy(str,"RESET", MAX_STRLEN_OF_TCP_PACKET_TYPE+1);
			break;
		default: // == TCP_ERROR_PACKET or TCP_INVALID_PACKET, never supposed to get here
			strncpy(str,"ERROR/INVALID", MAX_STRLEN_OF_TCP_PACKET_TYPE+1);
	}

}

//For tests alone! prints connection-row to kernel
static void print_conn_row(connection_row_t* conn_row){
	
	char str_connection_state[MAX_STRLEN_OF_TCP_STATE+1];
	size_t add_to_len = strlen("Connection-row details:\nsrc_ip: ,\nsrc_port: ,\ndst_ip: ,\ndst_port: ,\nTCP state: ,\ntimestamp: .\n");
	char str[MAX_STRLEN_OF_ULONG + 2*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16 + add_to_len+MAX_STRLEN_OF_TCP_STATE+3]; //+3: 1 for null-terminator, 2 more to make sure 
	
	if (conn_row == NULL) {
		printk(KERN_ERR "In print_conn_row(), function got NULL argument!\n");
		return;
	}
	
	tran_tcp_state_to_str(conn_row->tcp_state,str_connection_state);
	
	if ((sprintf(str,
				"Connection-row details:\nsrc_ip: %u,\nsrc_port: %hu,\ndst_ip: %u,\ndst_port: %hu,\nTCP state: %s,\ntimestamp: %lu.\n",
				conn_row->src_ip,
				conn_row->src_port,				
				conn_row->dst_ip,
				conn_row->dst_port,
				str_connection_state,
				conn_row->timestamp) ) < 7)
	{
		printk(KERN_ERR "Error printing Connection-row presentation\n");
	} 
	else
	{
		printk (KERN_INFO "%s",str);
	}
}


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
 *	Gets a pointer to packet's info, and a connection-row
 *
 *	Returns true if packet is relevant to that connection row,
 * 			false otherwise.
 **/
static bool packet_fits_conn_row(log_row_t* pckt_lg_info, connection_row_t* row){
	
	if (pckt_lg_info == NULL || row == NULL){
		printk(KERN_ERR "In packet_fits_conn_row(), function got NULL argument(s).\n");
		return false;
	}
	
	return ( (pckt_lg_info->src_ip == row->src_ip) &&
			 (pckt_lg_info->src_port == row->src_port) &&
			 (pckt_lg_info->dst_ip == row->dst_ip) &&
			 (pckt_lg_info->dst_port == row->dst_port) );
}

/**
 *	Gets a pointer to packet's info, and a connection-row
 *
 *	Returns true if packet has the OPPOSITE direction to that of the
 * 			connection row,
 * 			false otherwise.
 **/
static bool packet_fits_opp_conn_row(log_row_t* pckt_lg_info, connection_row_t* row){
	
	if (pckt_lg_info == NULL || row == NULL){
		printk(KERN_ERR "In packet_fits_opp_conn_row(), function got NULL argument(s).\n");
		return false;
	}
	
	return ( (pckt_lg_info->src_ip == row->dst_ip) &&
			 (pckt_lg_info->src_port == row->dst_port) &&
			 (pckt_lg_info->dst_ip == row->src_ip) &&
			 (pckt_lg_info->dst_port == row->src_port) );
}

/**
 *	Passes over g_connections_list in search of connection-rows that are
 * 	relevant to pckt_lg_info's data.
 *
 *	Updates:
 *		1. ptr_relevant_conn_row: to point at the relevant, same direction,
 * 		 connection-row, or NULL if none was found.
 * 		2. ptr_relevant_opposite_conn_row: to point at the relevant
 * 		 OPPOSITE direction connection-row, or NULL if none was found.
 * 
 **/
static void search_relevant_rows(log_row_t* pckt_lg_info,
		connection_row_t** ptr_relevant_conn_row,
		connection_row_t** ptr_relevant_opposite_conn_row)
{
	struct list_head *pos, *q;
	connection_row_t* temp_row;
	*ptr_relevant_conn_row = NULL;
	*ptr_relevant_opposite_conn_row = NULL;

	if (pckt_lg_info == NULL) {
		printk(KERN_ERR "In search_relevant_rows(), function got NULL argument.\n");
		return;
	}

	list_for_each_safe(pos, q, &g_connections_list){
		
		//Check if we've already found both.
		if ((*ptr_relevant_conn_row != NULL) && 
			(*ptr_relevant_opposite_conn_row != NULL))
		{ 
			return;
		}
		
		temp_row = list_entry(pos, connection_row_t, list);
		
		//If a row is too old - deletes it and continues to next row:
		if(is_row_timedout(temp_row)){
#ifdef CONN_DEBUG_MODE
			printk(KERN_INFO "Found an old row in connection-list, about to delete it. Its details:\n");
			print_conn_row(temp_row);
#endif
			delete_specific_row_by_list_node(pos);
			continue;
		}
		
		if ( packet_fits_conn_row(pckt_lg_info, temp_row) &&
			 (*ptr_relevant_conn_row == NULL) )
		{
#ifdef CONN_DEBUG_MODE
			printk(KERN_INFO "Found matching row in connection-list. Its details:\n");
			print_conn_row(temp_row);
#endif
			*ptr_relevant_conn_row = temp_row;
			continue; //To next connection-row
		}
		 
		if ( packet_fits_opp_conn_row(pckt_lg_info, temp_row) &&
			 (*ptr_relevant_opposite_conn_row == NULL) )
		{
#ifdef CONN_DEBUG_MODE
			printk(KERN_INFO "Found an OPPOSITE matching row in connection-list. Its details:\n");
			print_conn_row(temp_row);
#endif
			*ptr_relevant_opposite_conn_row = temp_row;
		}
		
	}

}


/**
 *	Gets a pointer to a packet's log_row_t, 
 *	adds a relevant NEW connection-row (SYN/SYN_ACK) to g_connections_list:
 *	
 *	@pckt_lg_info - holds packet's information
 *	@is_syn_packet - If true, connection's state would be: TCP_STATE_SYN_SENT  
 *					 If false, connection's state would be: TCP_STATE_SYN_RCVD
 * 
 *	Returns true on success, false if any error occured.
 *
 **/
bool add_new_connection_row(log_row_t* pckt_lg_info, bool is_syn_packet){
	
	connection_row_t* new_conn = NULL;
	
	if(pckt_lg_info == NULL){
		printk(KERN_ERR "In function add_new_connection_row(), function got NULL argument");
		return false;
	}
	
	//Allocates memory for connection-row:
    if((new_conn = kmalloc(sizeof(connection_row_t),GFP_ATOMIC)) == NULL){
		printk(KERN_ERR "Failed allocating space for new connection row.\n");
		return false;
	}
	memset(new_conn, 0, sizeof(connection_row_t)); 
	
	new_conn->src_ip = pckt_lg_info->src_ip;
	new_conn->src_port = pckt_lg_info-> src_port;
	new_conn->dst_ip = pckt_lg_info->dst_ip;
	new_conn->dst_port = pckt_lg_info->dst_port;
	new_conn->timestamp = pckt_lg_info->timestamp;
	
	//TCP_STATE_SYN_SENT when it's a (first) SYN packet,
	//TCP_STATE_SYN_RCVD when it's a (first) SYN-ACK packet:
	new_conn->tcp_state = (is_syn_packet ? TCP_STATE_SYN_SENT : TCP_STATE_SYN_RCVD);	

	INIT_LIST_HEAD(&(new_conn->list));
	
	list_add(&(new_conn->list), &g_connections_list);
	return true;
}

/**
 *	Gets a pointer to a SYN-ACK packet's log_row_t, 
 *	and 2 pointers to relevant connection rows (if any).
 *	Checks if that connection already have SYN-packet connection-row,
 *	and if so - adds a relevant new connection to g_connections_list.
 *
 *	@pckt_lg_info - the information about the packet we check
 *	@relevant_conn_row - a connection-row with the same IPs & ports,
 * 						might be NULL if no such was found
 *	@relevant_opposite_conn_row - a connection-row with the opposite side
 * 						IPs & ports, might be NULL if no such was found
 * 
 *	Updates:	1. pckt_lg_info->action
 * 				2. pckt_lg_info->reason
 * 
 *	Returns true on success, false if any error occured.
 *	
 *	NOTE:	1. If returned false, user should handle values of:
 * 				pckt_lg_info->action, pckt_lg_info->reason!
 * 			2. A valid SYN_ACK packet will have relevant_conn_row==NULL
 * 				and relevant_opposite_conn_row!=NULL.
 **/
bool handle_SYN_ACK_packet(log_row_t* pckt_lg_info, 
		connection_row_t* relevant_conn_row,
		connection_row_t* relevant_opposite_conn_row )
{
	
	if(pckt_lg_info == NULL){
		printk(KERN_ERR "In handle_SYN_ACK_packet(), function got NULL argument.\n");
		return false;
	}
	
	if ( (relevant_opposite_conn_row == NULL) || (relevant_conn_row != NULL))
	{
	//Means no prior SYN packet found OR
	//A prior, same direction connection was found: so drop this packet.
		pckt_lg_info->action = NF_DROP;
		pckt_lg_info->reason = REASON_NO_MATCHING_TCP_CONNECTION;
	} 
	else //relevant_opposite_conn_row!=NULL  and relevant_conn_row==NULL
	{ 	
		//Make sure prior connection is SYN:
		if (relevant_opposite_conn_row->tcp_state == TCP_STATE_SYN_SENT){
			//Add new SYN-ACK connection-row:
			if (!add_new_connection_row(pckt_lg_info, false)){
				//Errors already printed in add_new_connection_row()
				return false; 
			}
			pckt_lg_info->action = NF_ACCEPT;
			pckt_lg_info->reason = REASON_FOUND_MATCHING_TCP_CONNECTION;
			
		} else {
			//Never supposed to get here:
			printk(KERN_ERR "In handle_SYN_ACK_packet, previous connection row isn't TCP_STATE_SYN_SENT.\n");
			return false;
		}
			
	}
	
	return true;
}


 /**
 *	Gets a pointer to a OTHER (ACK bit and some other
 *  [non SYN-bit nor FIN-bit] is on) packet's log_row_t,
 *	and 2 pointers to relevant connection rows (if any).
 *	Checks if that packet suits current TCP state - means it has relevant
 *  connection-rows, and if so - updates those rows accordingly.
 *
 *	@pckt_lg_info - the information about the packet we check
 *	@relevant_conn_row - a connection-row with the same IPs & ports,
 * 						might be NULL if no such was found
 *	@relevant_opposite_conn_row - a connection-row with the opposite side
 * 						IPs & ports, might be NULL if no such was found
 * 
 *	Updates:	1. pckt_lg_info->action
 * 				2. pckt_lg_info->reason
 * 
 *	Returns true on success, false if any error occured.
 *	
 *	NOTE:	1. If returned false, user should handle values of:
 * 				pckt_lg_info->action, pckt_lg_info->reason!
 * 			2. A valid OTHER packet has specific tcp_states, 
 * 				see documentation below. 
 **/
bool handle_OTHER_tcp_packet(log_row_t* pckt_lg_info, 
		connection_row_t* relevant_conn_row,
		connection_row_t* relevant_opposite_conn_row )
{
	if(pckt_lg_info == NULL){
		printk(KERN_ERR "In handle_OTHER_tcp_packet(), function got NULL argument.\n");
		return false;
	}
	
	//There are only 4 cases in which OTHER packet is relevant to the connection,
	//in all 4 cases both sides of the connection are NOT NULL:
	if (relevant_conn_row != NULL && relevant_opposite_conn_row != NULL){
		
		//First 3 valid cases are when packet is:
		//	1. The last ack of the 3-way-handshake(syn, syn-ack, *ack*)
		//	2. The first ack sent from "server"s side, AFTER finising
		//		the 3-way-handshake.
		//	3. An ordinary ack between established connection:
		if( ((relevant_conn_row->tcp_state == TCP_STATE_SYN_SENT) &&
			(relevant_opposite_conn_row->tcp_state == TCP_STATE_SYN_RCVD))
			||	  
			((relevant_conn_row->tcp_state == TCP_STATE_SYN_RCVD) &&
			(relevant_opposite_conn_row->tcp_state == TCP_STATE_ESTABLISHED))
			||
			((relevant_conn_row->tcp_state == TCP_STATE_ESTABLISHED) &&
			(relevant_opposite_conn_row->tcp_state == TCP_STATE_ESTABLISHED)) )
		{
			//Next line won't change anything if both states were ESTABLISHED:
			relevant_conn_row->tcp_state = TCP_STATE_ESTABLISHED;
			relevant_conn_row->timestamp = pckt_lg_info->timestamp;
			pckt_lg_info->action = NF_ACCEPT;
			pckt_lg_info->reason = REASON_FOUND_MATCHING_TCP_CONNECTION;
			return true;
		} 
		
		//The fourth valid case is when:
		//	4. This packet is the last ack of a tcp connection:
		else if ((relevant_conn_row->tcp_state == TCP_STATE_FIN_WAIT_2) &&
			(relevant_opposite_conn_row->tcp_state == TCP_STATE_LAST_ACK))
		{
			relevant_conn_row->tcp_state = TCP_STATE_TIME_WAIT;
			relevant_conn_row->timestamp = pckt_lg_info->timestamp;
			pckt_lg_info->action = NF_ACCEPT;
			pckt_lg_info->reason = REASON_FOUND_MATCHING_TCP_CONNECTION;
			return true;
		}
	}
	
	pckt_lg_info->action = NF_DROP;
	pckt_lg_info->reason = REASON_NO_MATCHING_TCP_CONNECTION;
	return true;
	
}

 /**
 *	Gets a pointer to a RESET packet's log_row_t,
 *	and 2 pointers to relevant connection rows (if any).
 *	Checks if that packet suits current TCP state - that it has relevant
 *  connection-rows, and if so - 
 *	DELETES those rows accordingly and let the packet pass
 *
 *	@pckt_lg_info - the information about the packet we check
 *	@relevant_conn_row - a connection-row with the same IPs & ports,
 * 						might be NULL if no such was found
 *	@relevant_opposite_conn_row - a connection-row with the opposite side
 * 						IPs & ports, might be NULL if no such was found
 * 
 *	Updates:	1. pckt_lg_info->action
 * 				2. pckt_lg_info->reason
 * 				3. deletes relevant rows if packet is valid (to 
 * 				   reset the TCP connection)
 * 
 *	Returns true on success, false if any error occured.
 *	
 *	NOTE: If returned false, user should handle values of:
 * 		  pckt_lg_info->action, pckt_lg_info->reason!
 
 **/
bool handle_RESET_tcp_packet(log_row_t* pckt_lg_info, 
		connection_row_t* relevant_conn_row,
		connection_row_t* relevant_opposite_conn_row)
{
	if(pckt_lg_info == NULL){
		printk(KERN_ERR "In handle_RESET_tcp_packet(), function got NULL argument.\n");
		return false;
	}
	
	if( ((relevant_conn_row) && (relevant_opposite_conn_row))
		||
		((relevant_conn_row) && 
		(relevant_conn_row->tcp_state == TCP_STATE_SYN_SENT))
		||
		((relevant_opposite_conn_row) &&
		(relevant_opposite_conn_row->tcp_state == TCP_STATE_SYN_SENT)) )
	{
		//Delete rows:
		if (relevant_conn_row){
			delete_specific_row_by_conn_ptr(relevant_conn_row);
		}
		if (relevant_opposite_conn_row){
			delete_specific_row_by_conn_ptr(relevant_opposite_conn_row);
		}
		
		pckt_lg_info->action = NF_ACCEPT;
		pckt_lg_info->reason = REASON_FOUND_MATCHING_TCP_CONNECTION;
		return true;
	}
	
	//Packet's not relevant for tcp connection:
	pckt_lg_info->action = NF_DROP;
	pckt_lg_info->reason = REASON_NO_MATCHING_TCP_CONNECTION;
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
 * 
 *	NOTE: if returned false, take care of pckt_lg_info->action, pckt_lg_info->reason!
 **/
bool check_tcp_packet(log_row_t* pckt_lg_info, tcp_packet_t tcp_pckt_type){
	
	connection_row_t* relevant_conn_row = NULL;
	connection_row_t* relevant_opposite_conn_row = NULL;
		
	if(pckt_lg_info == NULL){
		printk(KERN_ERR "In function check_tcp_packet(), function got NULL argument.\n");
		return false;
	}

	search_relevant_rows(pckt_lg_info, &relevant_conn_row,
			&relevant_opposite_conn_row);
	
	switch (tcp_pckt_type){	
		
		case(TCP_SYN_PACKET):
			printk(KERN_ERR "In function check_tcp_packet(), function got SYN packet info.\n");
			return false;
			
		case(TCP_SYN_ACK_PACKET):
			return ( handle_SYN_ACK_packet(pckt_lg_info,
					relevant_conn_row, relevant_opposite_conn_row) );
		
		case(TCP_FIN_PACKET):
			//TODO::
			break;
		
		case(TCP_OTHER_PACKET):
			return( handle_OTHER_tcp_packet(pckt_lg_info, 
					relevant_conn_row, relevant_opposite_conn_row) );
		
		case(TCP_RESET_PACKET):
			//TODO::
			break;

		case(TCP_INVALID_PACKET):
			pckt_lg_info->action = NF_DROP;
			pckt_lg_info->reason = REASON_ILLEGAL_VALUE;
			return true;
			
		default: //TCP_ERROR_PACKET
			return false;
	}

}
