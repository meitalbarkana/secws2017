#ifndef HOOK_UTILS_H
#define HOOK_UTILS_H

#include "rules_utils.h"
#include "log_utils.h"

//Enum that helps "folding" up stages, 
//used when: - registrating hooks stopped because of some error 
//			 - all hooks should be unregistered (destroying device).
//TODO:: change names....
enum hooked_nfhos {
	FROM_FW_H = 1,
	OTHERS_H = 2,
	INCOMING_IPV6_H = 3,
	OUTGOING_IPV6_H = 4,
	ALL_H = 5
};

#endif /* HOOK_UTILS_H */
