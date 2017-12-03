#ifndef LOG_UTILS_H
#define LOG_UTILS_H

#include "fw.h"
#define NUM_OF_FIELDS_IN_LOF_ROW_T (10)

void print_log_row(log_row_t* logrowPtr, int logrow_num);
bool init_log_row(struct sk_buff* skb, log_row_t* ptr_pckt_lg_info,
		unsigned char hooknumber, ack_t* ack, direction_t* direction,
		const struct net_device* in, const struct net_device* out);

#endif /* LOG_UTILS_H */
