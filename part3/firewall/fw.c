#include "fw.h"

/**
 * Based on Reuven Plevinsky's sysfs_example that can be found in: http://course.cs.tau.ac.il//secws17/lectures/ 
 * And on: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 **/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meital Bar-Kana Swissa");

static int __init my_init_func(void){
	//TODO:: fill...
	return 0;
}

static void __exit my_exit_func(void){
	printk(KERN_INFO "Module fw has left the building!\n"); //TODO:: delete this :)
}

module_init(my_init_func);
module_exit(my_exit_func);
