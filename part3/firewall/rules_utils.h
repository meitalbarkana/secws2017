#ifndef RULES_UTILS_H
#define RULES_UTILS_H
#include "fw.h"

#define MAX_NUM_OF_RULES (50)

/** Constants for printing & formatting: **/
#define MAX_LEN_RULE_NAME (20) //Including null-terminator byte 
#define NUM_OF_FIELDS_IN_RULE_T (13)
#define NUM_OF_FIELDS_IN_FORMAT (11)
#define MAX_STRLEN_OF_BE32 (10)	//MAX_U_INT = 2^32-1 = 4294967295, 10 digits
#define MAX_STRLEN_OF_BE16 (5)	//MAX_U_SHORT = 2^16-1 = 65535, 5 digits
#define MAX_STRLEN_OF_U8 (3)	//MAX_U_CHAR = 2^8-1 = 255, 3 digits
#define MAX_STRLEN_OF_D (10)	//as in MAX_U_INT...
/*******************************/

#define FW_ON 1
#define FW_OFF 0

 /** Constants for formatting rule data send by / to user**/
/** NBR_xxx stands for Number of Bytes for Rule field xxx **/
#define NBR_NAME (20)			// names will be no longer than 20 chars(includes null-terminator) = 20 bytes
#define	NBR_DIRECTION (32)		// sizeof(direction_t)
#define	NBR_SRC_IP (32)			// sizeof(__be32)
#define	NBR_SRC_PREFIX_SIZE (8)	// sizeof(__u8)
#define	NBR_DST_IP (32)			// sizeof(__be32)
#define	NBR_DST_PREFIX_SIZE (8)	// sizeof(__u8)
#define	NBR_SRC_PORT (16)		// sizeof(__be16)  
#define	NBR_DST_PORT (16)		// sizeof(__be16)
#define	NBR_PROTOCOL (8)		// sizeof(__u8)
#define	NBR_ACK	(32)			// sizeof(ack_t)
#define	NBR_ACTION (8) 			// sizeof(__u8)
#define NBR_FULL_RULE (NBR_NAME+NBR_DIRECTION+NBR_SRC_IP+NBR_SRC_PREFIX_SIZE+NBR_DST_IP+NBR_DST_PREFIX_SIZE+NBR_SRC_PORT+NBR_DST_PORT+NBR_PROTOCOL+NBR_ACK+NBR_ACTION)

enum src_or_dst_t {
	SRC,
	DST
}

#endif /* RULES_UTILS_H */
