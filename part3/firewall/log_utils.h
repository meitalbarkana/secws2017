#ifndef _LOG_UTILS_H_
#define _LOG_UTILS_H_

#include "fw.h"

#define NUM_OF_FIELDS_IN_LOF_ROW_T (10)

/**
 * LOGROW format:
 * <timestamp> <protocol> <action> <hooknum> <src ip> <dst ip> <source port> <dest port> <reason> <count>'\n'. 
 * Therefore:
 * 
 * NOTE: MAX_STRLEN_OF_LOGROW_FORMAT includes '\n' and spaces (thats why I added NUM_OF_FIELDS_IN_LOF_ROW_T)
 **/
#define MAX_STRLEN_OF_LOGROW_FORMAT (MAX_STRLEN_OF_ULONG + 3*MAX_STRLEN_OF_U8 + 4*MAX_STRLEN_OF_BE32 + 2*MAX_STRLEN_OF_BE16 + NUM_OF_FIELDS_IN_LOF_ROW_T)

/** Each field is at least 1 character long + spaces and '\n': **/
#define MIN_LOGROW_FORMAT_LEN (2*NUM_OF_FIELDS_IN_LOF_ROW_T) 

//Enum that helps "folding" up stages, 
//used when: - initiating device stopped because of some error 
//			 - device is destroyed.
enum l_state_to_fold {
	L_UNREG_DES,
	L_DEVICE_DES,
	L_FIRST_FILE_DES,
	L_ALL_DES
};


void print_log_row(log_row_t* logrowPtr);
bool init_log_row(struct sk_buff* skb, log_row_t** ptr_ptr_pckt_lg_info,
		unsigned char hooknumber, ack_t* ack, direction_t* direction,
		const struct net_device* in, const struct net_device* out);
bool insert_row(log_row_t* row);
int init_log_device(struct class* fw_class);
void destroy_log_device(struct class* fw_class);
#endif /* _LOG_UTILS_H_ */
