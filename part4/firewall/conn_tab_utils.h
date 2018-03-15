#ifndef _CONN_TAB_UTILS_H_
#define _CONN_TAB_UTILS_H_

#include "fw.h"

#define TIMEOUT_SECONDS (90)//TODO:: change to 25
#define MAX_STRLEN_OF_TCP_PACKET_TYPE (13)
#define MAX_STRLEN_OF_TCP_STATE (11)

//Connection-row format:
//"<src ip> <source port> <dst ip> <dest port> <tcp_state> <timestamp> <fake src ip> <fake source port> <fake dst ip> <fake dest port>'\n'"
//+11 for: 9 spaces(' '), 1 end-of line('\n'), 1 null-terminator('\0'): 
#define MAX_STRLEN_OF_CONN_ROW_FORMAT (MAX_STRLEN_OF_ULONG + 5*MAX_STRLEN_OF_BE32 + 4*MAX_STRLEN_OF_BE16 + 11)

//Enum that helps "folding" up stages, 
//used when: 1. initiating device stopped because of some error 
//			 2. device is destroyed.
enum c_state_to_fold {
	C_UNREG_DES,
	C_DEVICE_DES,
	C_ALL_DES
};

connection_row_t* add_first_SYN_connection(log_row_t* syn_pckt_lg_info);
bool check_tcp_packet(log_row_t* pckt_lg_info, tcp_packet_t tcp_pckt_type);
int init_conn_tab_device(struct class* fw_class);
void destroy_conn_tab_device(struct class* fw_class);

#endif /* _CONN_TAB_UTILS_H_ */
