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

enum src_or_dst_t {
	SRC,
	DST
}

#endif /* RULES_UTILS_H */
