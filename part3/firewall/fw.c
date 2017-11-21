#include "fw.h"
#define MAX_LEN_OF_NAME_RULE 19 //since rule_t.rule_name is of length 20, including 

/**
 * Based on Reuven Plevinsky's sysfs_example that can be found in: http://course.cs.tau.ac.il//secws17/lectures/ 
 * And on: http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 **/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meital Bar-Kana Swissa");

static bool is_rule_name(const char* str){//TODO:: delete
	if (str == NULL){
		printk(KERN_ERR "function is_rule_name got NULL value\n");
		return false;
	}
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

bool is_ipv4_subnet_format(char* str, __be32* ipv4value, __u8* prefixLength){//TODO:: delete
	
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
	
	char str0[] = "%s,xyz.12.32.1";
	char str1[] = "12345678901";
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

prot_t translate_str_to_protocol(const char* str){
	
	unsigned long temp = 0; //Might be needed in case of "other" protocol
	
	//By strcmp() documentation, since we're comparing between strings with constatn length ("any","ICMP", etc.) - it's safe 
	if((strcmp(str, "icmp") == 0) || (strcmp(str, "ICMP") == 0) || (strcmp(str, "1") == 0)){
		return PROT_ICMP;
	}
	if((strcmp(str, "tcp") == 0) || (strcmp(str, "TCP") == 0) || (strcmp(str, "6") == 0)){
		return PROT_TCP;
	}
	if((strcmp(str, "udp") == 0) || (strcmp(str, "UDP") == 0) || (strcmp(str, "17") == 0)){
		return PROT_UDP;
	}
	if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0) || (strcmp(str, "143") == 0)){
		return PROT_ANY;
	}
	if ((strcmp(str, "other") == 0) || (strcmp(str, "OTHER") == 0) || (strcmp(str, "255") == 0)){
		return PROT_OTHER;
	}
	/** 
	 *  0<=protocol<=255 (since it's of type __u8), so any string representing
	 *	a number in that range (different from 1/6/17/143) will be considered as "other"
	 *	if str's length is more than 4 (3+'\0'), sure it can't represent a number in [0,255] range
	 **/
	if((strnlen(str,5) <= 3) && (strict_strtoul(str, 10,&temp) == 0) && (temp <= 255)){
		return PROT_OTHER;
	}
	
	return PROT_ERROR;
}

//Tests translate_str_to_protocol():
void tester_3(void){
	
	char str0[] = "icmp";
	char str1[] = "ICMP";
	char str2[] = "1";
	char str3[] = "tcp";
	char str4[] = "TCP";
	char str5[] = "6";
	char str6[] = "17";
	char str7[] = "UDP";
	char str8[] = "udp";
	char str9[] = "ANY";
	char str10[] = "any";
	char str11[] = "143";
	char str12[] = "255";
	char str13[] = "other";
	char str14[] = "OTHER";
	char str15[] = "32";
	char str16[] = "166";
	char str17[] = "0";
	char str18[] = "334";
	char str19[] = "./s3P";
	char* str;
	
	size_t index = 0;
	for (index = 0; index <= 19; ++index){
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
			case 10:
				str = str10;
				break;
			case 11:
				str = str11;
				break;
			case 12:
				str = str12;
				break;
			case 13:
				str = str13;
				break;
			case 14:
				str = str14;
				break;
			case 15:
				str = str15;
				break;
			case 16:
				str = str16;
				break;
			case 17:
				str = str17;
				break;
			case 18:
				str = str18;
				break;
			case 19:
				str = str19;
				break;
			default:
				str = "";
		}
		
		switch(translate_str_to_protocol(str)){
			case(PROT_ICMP):
				printk(KERN_INFO "the string: %s is ICMP\n", str);
				break;
			case(PROT_TCP):
				printk(KERN_INFO "the string: %s is TCP\n", str);
				break;
			case(PROT_UDP):
				printk(KERN_INFO "the string: %s is UDP\n", str);
				break;
			case(PROT_OTHER):
				printk(KERN_INFO "the string: %s is OTHER\n", str);
				break;
			case(PROT_ANY):
				printk(KERN_INFO "the string: %s is ANY\n", str);
				break;
			case(PROT_ERROR):
				printk(KERN_INFO "the string: %s is ERROR\n", str);
				break;
			default:
				printk(KERN_INFO "the string: %s REALLY CAUSED AN ERROR!!!!\n", str);				

		}
	}
}

static int translate_str_to_int_port_number(const char* str){//TODO:: delete this
	unsigned long temp = 0;
	if(strnlen(str,7) <= 5){ //Since the maximum valid str length is 5+1(for '\0')+1 (to make sure str isn't longer)
		if ((strcmp(str, ">1023") == 0) || (strcmp(str, "1023") == 0)) {
			return PORT_ABOVE_1023;
		}
		if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0)){
			return PORT_ANY;
		}
		if ((strict_strtoul(str, 10,&temp) == 0) && (temp <= 65535)){
			return ((int)temp); //Safe casting since 0<=temp<=65535
		}
	}
	return PORT_ERROR;
}

//Tests translate_str_to_int_port_number():
void tester_4(void){
	
	//__be16	port_num = 0;
	switch(translate_str_to_int_port_number("65700")){
			case (PORT_ERROR):
				printk(KERN_INFO "the string: 65700 is not a valid port number\n");
				break;
			case (PORT_ANY):
				printk(KERN_INFO "the string: 65700 is any port.\n");
				break;
			case(PORT_ABOVE_1023):
				printk(KERN_INFO "the string: 65700 is above port 1023.\n");
				break;
			default: //specific number
				printk(KERN_INFO "the string: 65700 is a specific number.\n");
	}
	
	switch(translate_str_to_int_port_number("435")){
			case (PORT_ERROR):
				printk(KERN_INFO "the string: 435 is not a valid port number\n");
				break;
			case (PORT_ANY):
				printk(KERN_INFO "the string: 435 is any port.\n");
				break;
			case(PORT_ABOVE_1023):
				printk(KERN_INFO "the string: 435 is above port 1023.\n");
				break;
			default: //specific number
				printk(KERN_INFO "the string: 435 is a specific number.\n");
	}
	
	switch(translate_str_to_int_port_number("any")){
			case (PORT_ERROR):
				printk(KERN_INFO "the string: any is not a valid port number\n");
				break;
			case (PORT_ANY):
				printk(KERN_INFO "the string: any is any port.\n");
				break;
			case(PORT_ABOVE_1023):
				printk(KERN_INFO "the string: any is above port 1023.\n");
				break;
			default: //specific number
				printk(KERN_INFO "the string: any is a specific number.\n");
	}
	
	switch(translate_str_to_int_port_number(">1023")){
			case (PORT_ERROR):
				printk(KERN_INFO "the string: >1023 is not a valid port number\n");
				break;
			case (PORT_ANY):
				printk(KERN_INFO "the string: >1023 is any port.\n");
				break;
			case(PORT_ABOVE_1023):
				printk(KERN_INFO "the string: >1023 is above port 1023.\n");
				break;
			default: //specific number
				printk(KERN_INFO "the string: >1023 is a specific number.\n");
	}
	
	
	switch(translate_str_to_int_port_number("1023")){
			case (PORT_ERROR):
				printk(KERN_INFO "the string: 1023 is not a valid port number\n");
				break;
			case (PORT_ANY):
				printk(KERN_INFO "the string: 1023 is any port.\n");
				break;
			case(PORT_ABOVE_1023):
				printk(KERN_INFO "the string: 1023 is above port 1023.\n");
				break;
			default: //specific number
				printk(KERN_INFO "the string: 1023 is a specific number.\n");
	}
	
	switch(translate_str_to_int_port_number("rrrrf")){
			case (PORT_ERROR):
				printk(KERN_INFO "the string: rrrrf is not a valid port number\n");
				break;
			case (PORT_ANY):
				printk(KERN_INFO "the string: rrrrf is any port.\n");
				break;
			case(PORT_ABOVE_1023):
				printk(KERN_INFO "the string: rrrrf is above port 1023.\n");
				break;
			default: //specific number
				printk(KERN_INFO "the string: rrrrf is a specific number.\n");
	}
}

static bool translate_str_to_ack(const char* str, ack_t* ack){
	if((str != NULL) && strnlen(str,5) <= 3){ //Since the maximum valid str length is 3+1(for '\0')+1 (to make sure str isn't longer)
		if ((strcmp(str, "yes") == 0) || (strcmp(str, "YES") == 0)) {
			*ack = ACK_YES;
			return true;
		}
		if((strcmp(str, "any") == 0) || (strcmp(str, "ANY") == 0)){
			*ack = ACK_ANY;
			return true;
		}
		if((strcmp(str, "no") == 0) || (strcmp(str, "NO") == 0)){
			*ack = ACK_NO;
			return true;
		}
	}
	return false;
}

static bool translate_str_to_action(const char* str, __u8* action){
	if((str != NULL) && strnlen(str,8) <= 6){ //Since the maximum valid str length is 6+1(for '\0')+1 (to make sure str isn't longer)
		if ((strcmp(str, "accept") == 0) || (strcmp(str, "ACCEPT") == 0)) {
			*action = NF_ACCEPT;
			return true;
		}
		if((strcmp(str, "drop") == 0) || (strcmp(str, "DROP") == 0)){
			*action = NF_DROP;
			return true;
		}
	}
	return false;
}

//Tests translate_str_to_ack(), translate_str_to_action():
void tester_5(void){
	__u8 action = 0;
	ack_t* ack = kmalloc(sizeof(ack_t) ,GFP_KERNEL);//TODO:: when really using it, make sure it succeeded
	if (ack == NULL) {
		printk(KERN_INFO "Allocation failed!\n");
		return;
	}
	
	if(translate_str_to_ack("ack", ack)){
		switch (*ack){
			case (ACK_ANY):
				printk(KERN_INFO "the string: ack is any.\n");
				break;
			case(ACK_YES):
				printk(KERN_INFO "the string: ack is yes.\n");
				break;
			default: //ACK_NO
				printk(KERN_INFO "the string: ack is no.\n");
		}
	} else {
		printk(KERN_INFO "the string: ack is not a valid ack!.\n");
	}
	
	if(translate_str_to_ack("YES", ack)){
		switch (*ack){
			case (ACK_ANY):
				printk(KERN_INFO "the string: YES is any.\n");
				break;
			case(ACK_YES):
				printk(KERN_INFO "the string: YES is yes.\n");
				break;
			default: //ACK_NO
				printk(KERN_INFO "the string: YES is no.\n");
		}
	} else {
		printk(KERN_INFO "the string: YES is not a valid ack!.\n");
	}
	
	if(translate_str_to_ack("no", ack)){
		switch (*ack){
			case (ACK_ANY):
				printk(KERN_INFO "the string: no is any.\n");
				break;
			case(ACK_YES):
				printk(KERN_INFO "the string: no is yes.\n");
				break;
			default: //ACK_NO
				printk(KERN_INFO "the string: no is no.\n");
		}
	} else {
		printk(KERN_INFO "the string: no is not a valid ack!.\n");
	}
	
	if(translate_str_to_ack("now", ack)){
		switch (*ack){
			case (ACK_ANY):
				printk(KERN_INFO "the string: now is any.\n");
				break;
			case(ACK_YES):
				printk(KERN_INFO "the string: now is yes.\n");
				break;
			default: //ACK_NO
				printk(KERN_INFO "the string: now is no.\n");
		}
	} else {
		printk(KERN_INFO "the string: now is not a valid ack!.\n");
	}
	
	if(translate_str_to_action("now", &action)){
		switch (action){
			case (NF_ACCEPT):
				printk(KERN_INFO "the string: now is action: ACCEPT.\n");
				break;
			default: //NF_DROP
				printk(KERN_INFO "the string: now is action: DROP.\n");
		}
	} else {
		printk(KERN_INFO "the string: now is not a valid action :( \n");
	}
	
	if(translate_str_to_action("accepti", &action)){
		switch (action){
			case (NF_ACCEPT):
				printk(KERN_INFO "the string: accepti is action: ACCEPT.\n");
				break;
			default: //NF_DROP
				printk(KERN_INFO "the string: accepti is action: DROP.\n");
		}
	} else {
		printk(KERN_INFO "the string: accepti is not a valid action :( \n");
	}
	
	if(translate_str_to_action("accept", &action)){
		switch (action){
			case (NF_ACCEPT):
				printk(KERN_INFO "the string: accept is action: ACCEPT.\n");
				break;
			default: //NF_DROP
				printk(KERN_INFO "the string: accept is action: DROP.\n");
		}
	} else {
		printk(KERN_INFO "the string: accept is not a valid action :( \n");
	}
	
	if(translate_str_to_action("DROP", &action)){
		switch (action){
			case (NF_ACCEPT):
				printk(KERN_INFO "the string: DROP is action: ACCEPT.\n");
				break;
			default: //NF_DROP
				printk(KERN_INFO "the string: DROP is action: DROP.\n");
		}
	} else {
		printk(KERN_INFO "the string: DROP is not a valid action :( \n");
	}
	
	if(translate_str_to_action("DROPi", &action)){
		switch (action){
			case (NF_ACCEPT):
				printk(KERN_INFO "the string: DROPi is action: ACCEPT.\n");
				break;
			default: //NF_DROP
				printk(KERN_INFO "the string: DROPi is action: DROP.\n");
		}
	} else {
		printk(KERN_INFO "the string: DROPi is not a valid action :( \n");
	}
	
	kfree(ack);
}


static int __init my_init_func(void){
	
	//tester_1();
	//tester_2();
	//tester_3();
	//tester_4();
	tester_5();
	return 0;

}

static void __exit my_exit_func(void){
	printk(KERN_INFO "Module fw has left the building!\n");
}

module_init(my_init_func);
module_exit(my_exit_func);
