#include "fw.h"
#define MAX_LEN_OF_NAME_RULE 19 //since rule_t.rule_name is of length 20, including 

/**
 * Based on Reuven Plevinsky's sysfs_example that can be found in: http://course.cs.tau.ac.il//secws17/lectures/ 
 * And on: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 **/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meital Bar-Kana Swissa");

bool is_rule_name(const char* str){ //TODO:: delete
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

//Tests translate_str_to_direction(), is_rule_name()
void tester_1(void){
	char str[] ="any" ;
	direction_t dt = translate_str_to_direction(str);
	char str2[] ="ANY" ;
	direction_t dt2 = translate_str_to_direction(str2);
	
	if(dt == DIRECTION_ERROR){
		printk(KERN_INFO "dt is error\n");
	} else if (dt == DIRECTION_ANY) {
		printk(KERN_INFO "dt is \"any\"\n");
	} else if (dt == DIRECTION_IN) {
		printk(KERN_INFO "dt is \"in\"\n");
	} else if (dt == DIRECTION_OUT) {
		printk(KERN_INFO "dt is \"out\"\n");
	}
	
	if(dt2 == DIRECTION_ERROR){
		printk(KERN_INFO "dt2 is error\n");
	} else if (dt2 == DIRECTION_ANY) {
		printk(KERN_INFO "dt2 is \"any\"\n");
	} else if (dt2 == DIRECTION_IN) {
		printk(KERN_INFO "dt2 is \"in\"\n");
	} else if (dt2 == DIRECTION_OUT) {
		printk(KERN_INFO "dt2 is \"out\"\n");
	}
	
	if (is_rule_name("1sdfg67jk012sdfghj90")){
		printk(KERN_INFO "1sdfg67jk012sdfghj90 is indeed a name for a rule\n");
	} else {
		printk(KERN_INFO "1sdfg67jk012sdfghj90 is NOT a name for a rule\n");
	}
	
	if (is_rule_name("mmmmtnnnntbbbbtvvvv")){
		printk(KERN_INFO "mmmmtnnnntbbbbtvvvv is indeed a name for a rule\n");
	} else {
		printk(KERN_INFO "mmmmtnnnntbbbbtvvvv is NOT a name for a rule\n");
	}
	
	if (is_rule_name("gggggjjjjjhhhhhh12w4r6y8u0123456789")){
		printk(KERN_INFO "gggggjjjjjhhhhhh12w4r6y8u0123456789 is indeed a name for a rule\n");
	} else {
		printk(KERN_INFO "gggggjjjjjhhhhhh12w4r6y8u0123456789 is NOT a name for a rule\n");
	}
}

bool is_ipv4_subnet_format(char* str, __be32* ipv4value, __u8* prefixLength){
	
	size_t maxFormatLen = strlen("XXX.XXX.XXX.XXX/YY"); // = 18
	size_t minFormatLen = strlen("X.X.X.X/Y"); // = 9
	size_t strLength = strnlen(str, maxFormatLen+2); //Because there's no need to check more chars than that..
	
	/** These variables are declared here only to avoid warning of:
	 * "ISO C90 forbids mixed declarations and code"
	 * (I'd put them after the first "if")
	 **/
	//Will contain "XXX" or "YY" string:
	char* currToken; 
	//Will contain the value "XXX" or "YY" represent:
	unsigned long temp = 0; 
	//Will contain the relevant multiplicand needed for calculating ip address:
	// 2^24 = 256^3 = 16,777,216 , 2^16 = 256^2 = 65536
	// 2^8 = 256^1 = 256 , 2^0 = 256^0 = 1 
	unsigned int multiplicand = 1; 
	size_t i = 0;	
	
	if ((strLength < minFormatLen) || (strLength > maxFormatLen)){
		return false;
	}

	*ipv4value = 0;
	*prefixLength = 0;

	for (i = 0; i <= 4; ++i){
		currToken = strsep(&str, "./");
		if (currToken == NULL){
			return false;
		}
		if (i == 4) { //means we're at the part of the string representing the netmask length 
			if((strict_strtoul(currToken, 10,&temp) != 0) || (temp > 32)){ //strict_strtoul() returns 0 on success
				return false;
			}
			*prefixLength = (__u8)temp;	//Safe casting, since temp <= 32
		} else { // i is 0/1/2/3
			if((strict_strtoul(currToken, 10,&temp) != 0) || (temp > 255)){
				return false;
			}
			multiplicand = 1 << (8*(3-i));
			(*ipv4value)+= multiplicand*(unsigned int)temp; //Safe casting, since temp <= 255
		}
	}
	
	//Makes sure str didn't contain any invalid characters
	currToken = strsep(&str, "./");
	if (currToken != NULL){
		return false;
	}
	
	return true;
}

//tester for is_ipv4_subnet_format()
void tester_2(void){
	
	char str0[] = "222.13..0/23";
	char str1[] = "223.1.1.7/32";
	char str2[] = "256.1.10.42/16";
	char str3[] = "81.82.70.0/07";
	char str4[] = "0x1.255.255.255/0";
	char str5[] = "8.0x11.8.8/1";
	char str6[] = "7.7.7.77/30";
	char str7[] = "111.12.13.89/17";
	char str8[] = "11.03.19.86/22";
	char str9[] = "11.12.1992.255/12";
	char* str;
	
	__be32 ipv4value = 0;
	__u8 prefixLength = 0;
	
	
	size_t index = 0;
	for (index = 0; index < 10; ++index){
		switch (index){
			case 0:
				str = str0;
				break;
			case 1:
				str = str1;
				break;
			case 2:
				str = str2;
				break;
			case 3:
				str = str3;
				break;
			case 4:
				str = str4;
				break;
			case 5:
				str = str5;
				break;
			case 6:
				str = str6;
				break;
			case 7:
				str = str7;
				break;
			case 8:
				str = str8;
				break;
			case 9:
				str = str9;
				break;
			default:
				str = "";
		}
		
		if(is_ipv4_subnet_format(str, &ipv4value, &prefixLength)){
			printk(KERN_INFO "the string: %s is in ipv4 format!\nIts ipv4 value is: %u, Its prefix length is: %u\n", str, ipv4value, prefixLength);
		} else {
			printk(KERN_INFO "the string: %s is NOT in ipv4 format :(\n", str);
		}
	}

}

static int __init my_init_func(void){
	
	//tester_1();
	tester_2();
	
	return 0;

}

static void __exit my_exit_func(void){
	printk(KERN_INFO "Module fw has left the building!\n");
}

module_init(my_init_func);
module_exit(my_exit_func);
