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
bool add_new_connection(log_row_t* syn_pckt_lg_info){
	///TODO::
}
