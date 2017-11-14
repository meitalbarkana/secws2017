#include "fw.h"
#define MAX_LEN_OF_NAME_RULE 19 //since rule_t.rule_name is of length 20, including 

/**
 * Based on Reuven Plevinsky's sysfs_example that can be found in: http://course.cs.tau.ac.il//secws17/lectures/ 
 * And on: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 **/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meital Bar-Kana Swissa");


bool get_rule_name(const char* str){ //TODO:: delete
	return (strnlen(str, MAX_LEN_OF_NAME_RULE+2) <= MAX_LEN_OF_NAME_RULE);
}

direction_t translate_str_to_direction(const char* str){//TODO:: delete
	if((strcmp(str, "in") == 0) || (strcmp(str, "IN") == 0)){
		return DIRECTION_IN;
	}
	if((strcmp(str, "out") == 0) || (strcmp(str, "OUT") == 0)){
		return DIRECTION_OUT;
	}
	if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0)){
		return DIRECTION_ANY;
	}
	
	return DIRECTION_ERROR;
}

static int __init my_init_func(void){
	//TODO:: DELETE THIS! it's just a TESER
	char str[] ="any" ;
	direction_t dt = translate_str_to_direction(str);
	if(dt == DIRECTION_ERROR){
		printk(KERN_INFO "dt is error\n");
	} else if (dt == DIRECTION_ANY) {
		printk(KERN_INFO "dt is \"any\"\n");
	} else if (dt == DIRECTION_IN) {
		printk(KERN_INFO "dt is \"in\"\n");
	} else if (dt == DIRECTION_OUT) {
		printk(KERN_INFO "dt is \"out\"\n");
	}
	
	char str2[] ="ANY" ;
	direction_t dt2 = translate_str_to_direction(str2);
	if(dt2 == DIRECTION_ERROR){
		printk(KERN_INFO "dt2 is error\n");
	} else if (dt2 == DIRECTION_ANY) {
		printk(KERN_INFO "dt2 is \"any\"\n");
	} else if (dt2 == DIRECTION_IN) {
		printk(KERN_INFO "dt2 is \"in\"\n");
	} else if (dt2 == DIRECTION_OUT) {
		printk(KERN_INFO "dt2 is \"out\"\n");
	}
	
	if (get_rule_name("1sdfg67jk012sdfghj90")){
		printk(KERN_INFO "1sdfg67jk012sdfghj90 is indeed a name for a rule\n");
	} else {
		printk(KERN_INFO "1sdfg67jk012sdfghj90 is NOT a name for a rule\n");
	}
	
	if (get_rule_name("mmmmtnnnntbbbbtvvvv")){
		printk(KERN_INFO "mmmmtnnnntbbbbtvvvv is indeed a name for a rule\n");
	} else {
		printk(KERN_INFO "mmmmtnnnntbbbbtvvvv is NOT a name for a rule\n");
	}
	
	if (get_rule_name("gggggjjjjjhhhhhh12w4r6y8u0123456789")){
		printk(KERN_INFO "gggggjjjjjhhhhhh12w4r6y8u0123456789 is indeed a name for a rule\n");
	} else {
		printk(KERN_INFO "gggggjjjjjhhhhhh12w4r6y8u0123456789 is NOT a name for a rule\n");
	}
	
	return 0;

}

static void __exit my_exit_func(void){
	printk(KERN_INFO "Module fw has left the building!\n");
}

module_init(my_init_func);
module_exit(my_exit_func);
