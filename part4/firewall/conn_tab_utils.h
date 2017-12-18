#ifndef _CONN_TAB_UTILS_H_
#define _CONN_TAB_UTILS_H_

#include "fw.h"

#define TIMEOUT_SECONDS (25)
#define MAX_STRLEN_OF_TCP_PACKET_TYPE (13)
#define MAX_STRLEN_OF_TCP_STATE (11)

bool add_first_SYN_connection(log_row_t* syn_pckt_lg_info);
bool check_tcp_packet(log_row_t* pckt_lg_info, tcp_packet_t tcp_pckt_type);

#endif /* _CONN_TAB_UTILS_H_ */
