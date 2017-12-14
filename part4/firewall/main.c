#include "main.h"

/**
 * Based on Reuven Plevinsky's sysfs_example that can be found in: http://course.cs.tau.ac.il//secws17/lectures/ 
 * And on: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 **/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meital Bar-Kana Swissa");

static struct class* fw_class = NULL;

/**
 * Help function that cleans up everything associated with creating our module
 * According to the state that's been given.
 **/
static void destroyFirewall(enum main_state_to_fold stateToFold){
	switch (stateToFold){
		case(M_ALL):
			unRegisterHooks();
		case(M_ALL_CHAR_DEVS):
			destroy_log_device(fw_class);
		case(M_RULE_DEV):
			destroy_rules_device(fw_class);
		case (M_CLASS):
			class_destroy(fw_class);
	}
}


static int __init my_init_func(void){
	
	//Create fw class
	fw_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(fw_class))
	{
		printk(KERN_ERR "Failed creating fw class, init module failed.\n");
		return -1;
	}
	
	if (init_rules_device(fw_class) < 0) {
		//Error msg already been printed inside init_rules_device()
		destroyFirewall(M_CLASS);
		return -1;
	}
	
	if (init_log_device(fw_class) < 0) {
		//Error msg already been printed inside init_log_device()
		destroyFirewall(M_RULE_DEV);
		return -1;
	}
	
	if (registerHooks() < 0) {
		printk(KERN_ERR "Failed registering hooks, init module failed.\n");
		destroyFirewall(M_ALL_CHAR_DEVS);
		return -1;
	}

	printk(KERN_INFO "Module firewall started successfully.\n");	

	return 0;
}


static void __exit my_exit_func(void){
	
	destroyFirewall(M_ALL);
	printk(KERN_INFO "Module firewall was removed.\n");

}

module_init(my_init_func);
module_exit(my_exit_func);
