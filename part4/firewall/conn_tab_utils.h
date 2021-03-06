#ifndef _CONN_TAB_UTILS_H_
#define _CONN_TAB_UTILS_H_

#include "fw.h"

#define TIMEOUT_SECONDS (25)
#define MAX_STRLEN_OF_TCP_PACKET_TYPE (13)
#define MAX_STRLEN_OF_TCP_STATE (11)

//Connection-row format:
//"<src ip> <source port> <dst ip> <dest port> <tcp_state> <timestamp> <fake src ip> <fake source port> <fake dst ip> <fake dest port> <fake_tcp_state>'\n'"
//+12 for: 10 spaces(' '), 1 end-of line('\n'), 1 null-terminator('\0'): 
#define MAX_STRLEN_OF_CONN_ROW_FORMAT (MAX_STRLEN_OF_ULONG + 6*MAX_STRLEN_OF_BE32 + 4*MAX_STRLEN_OF_BE16 + 12)

//Adding new FTP-Data connection row format is:
//<src ip> <source port> <dst ip> <dest port>'\n'
//+5 for: 3 spaces, 1 end-of-line, 1 null terminator
#define MAX_STRLEN_OF_WRITE_FTP_CONN_ROW (2*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16+5)
#define MIN_STRLEN_OF_WRITE_FTP_CONN_ROW (2+2+5)

//Enum that helps "folding" up stages, 
//used when: 1. initiating device stopped because of some error 
//			 2. device is destroyed.
enum c_state_to_fold {
	C_UNREG_DES,
	C_DEVICE_DES,
	C_ALL_DES
};

connection_row_t* add_first_SYN_connection(log_row_t* syn_pckt_lg_info, struct sk_buff* skb);
bool check_tcp_packet(log_row_t* pckt_lg_info, tcp_packet_t tcp_pckt_type);
void search_relevant_rows(log_row_t* pckt_lg_info,
		connection_row_t** ptr_relevant_conn_row,
		connection_row_t** ptr_relevant_opposite_conn_row);
void handle_outer_tcp_packet(struct sk_buff* skb, struct tcphdr* tcp_hdr);
void delete_all_conn_rows(void);
int init_conn_tab_device(struct class* fw_class);
void destroy_conn_tab_device(struct class* fw_class);

#endif /* _CONN_TAB_UTILS_H_ */
