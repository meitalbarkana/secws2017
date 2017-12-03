#include "main.h"

/**
 * Based on Reuven Plevinsky's sysfs_example that can be found in: http://course.cs.tau.ac.il//secws17/lectures/ 
 * And on: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 **/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meital Bar-Kana Swissa");

static struct class* fw_class = NULL;


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
		class_destroy(fw_class);
		return -1;
	}
	
	//TODO:: add init_log_device
	
	if (registerHooks() < 0) {
		printk(KERN_ERR "Failed registering hooks, init module failed.\n");
		destroy_rules_device(fw_class);
		class_destroy(fw_class);
		return -1;
	}

#ifdef DEBUG_MODE 
	printk(KERN_INFO "Module firewall started successfully!\n");
#endif	

	return 0;
}


static void __exit my_exit_func(void){
	
	unRegisterHooks();
	destroy_rules_device(fw_class);
	class_destroy(fw_class);
	
#ifdef DEBUG_MODE
	printk(KERN_INFO "Module firewall has left the building!\n");
#endif

}

module_init(my_init_func);
module_exit(my_exit_func);
