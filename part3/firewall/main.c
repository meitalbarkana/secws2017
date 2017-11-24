#include "main.h"

/**
 * Based on Reuven Plevinsky's sysfs_example that can be found in: http://course.cs.tau.ac.il//secws17/lectures/ 
 * And on: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 **/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meital Bar-Kana Swissa");

static int __init my_init_func(void){
	//Test:
	//char* str;
	rule_t* all_rules_table[MAX_NUM_OF_RULES];
	all_rules_table[0] = get_rule_from_string("telnet1 out 10.0.1.1/24 any TCP >1023 23 any accept", all_rules_table);
	
	if (all_rules_table[0] != NULL){
		printk(KERN_INFO "**********Rule created successfully!\n");
		str = get_rule_as_str(all_rules_table[0]);
		if (str != NULL){
			printk(KERN_INFO "Rule as string is:\n");
			printk(KERN_INFO "%s\n",str);
			kfree(str);
		} else {
			printk(KERN_INFO "________________Couldn't convert rule to string :( \n");
		}
		kfree(all_rules_table[0]);
	} else {
		printk(KERN_INFO "________________Creating rule failed!\n");
	}
	//END OF Test
	
	
	//TODO:: fill...
	//printk(KERN_INFO "Module firewall started!\n"); //TODO:: delete this :)
	
	return 0;
}

static void __exit my_exit_func(void){
	printk(KERN_INFO "Module firewall has left the building!\n"); //TODO:: delete this :)
}

module_init(my_init_func);
module_exit(my_exit_func);
