#include "input_utils.h"

/**
 * Loads rules from file to the firewall.
 * 
 * Returns 0 on success, -1 if failed
 *	
 * Note: function prints errors, if any, to screen
 **/
static int load_rules(const char* file_path){
	
	int rules_read = read_rules_from_file(file_path);
	
	if (rules_read < 0) {
		return -1;
	}
	
	if (rules_read == 0) {
		printf ("No rules were loaded - file was empty or had no valid rules.\n Please use clear_rules if you want to delete all firewall rules.\n");
		return 0;
	}
#ifdef USER_DEBUG_MODE
	printf("Total rules from file: %d.\n",rules_read);
#endif	
	enum rules_recieved_t rrcvd = send_rules_to_fw();
	switch (rrcvd) {
		case(NO_RULE_RECIEVED):
			printf ("Failed loading rules to the firewall. Previous rules, if any, were untouched.\n");
			return -1;
		case(PARTIAL_RULE_RECIEVED):
			printf ("Some of the rules weren't loaded, use show_rules command for details of those who were loaded");
			return 0;
		default: //ALL_RULE_RECIEVED
			printf ("All %d rules sent successfully to the firewall. Use show_rules command for details of those who were loaded\n", rules_read);
			return 0;
	}
	
}

/**
 * Sends relevant activate/deactivate string to fw.
 * 
 * @to_active_state - true if we want to activate fw,
 * 					  false if we want to deactivate fw.
 * 
 * Returns 0 on success, -1 if failed
 *	
 * Note: function prints errors, if any, to screen
 **/
static int change_active_state_fw(bool to_active_state){
	int fd = open(PATH_TO_ACTIVE_ATTR,O_WRONLY); // Open device with write only permissions
	if (fd < 0){
		printf("Error accured trying to open the rules-device, error number: %d\n", errno);
		return -1;
	}
	
	char* active_stat = (to_active_state? ACTIVATE_STRING : DEACTIVATE_STRING);
	if (write(fd, active_stat, ACTIVE_STR_LEN) <= 0){
		printf("Error accured trying to change firewall's active state, error number: %d\n", errno);
		close(fd);
		return -1;
	}
	close(fd);
	if (to_active_state) {
		printf ("Sent activate string to firewall successfully. Use show_active command to get firewall status (active/inactive)\n");
	} else {
		printf ("Sent deactivate string to firewall successfully. Use show_active command to get firewall status (active/inactive)\n");
	}
	return 0;
}


/**
 *	Gets relevant activate/deactivate status from fw
 *	(reads from PATH_TO_ACTIVE_ATTR)
 * 
 *	Returns 0 on success, -1 if failed
 *	
 * Note: function prints errors, if any, to screen
 **/
static int get_active_stat(){
	
	int stat = get_fw_active_stat();
	switch (stat){
		case (1):
			printf("Firewall is active\n");
			return 0;
		case (0):
			printf("Firewall is deactivated\n");
			return 0;
		default:
			printf("Failed getting firewall's active status\n");
			return -1;
	}
}

/**
 *	Gets number of rows in fw_log
 *	(reads from PATH_TO_LOG_SIZE_ATTR)
 * 
 *	Returns 0 on success, -1 if failed
 *	
 * Note: function prints errors, if any, to screen
 **/
static int get_log_size(){
	int num = get_num_log_rows();
	if (num < 0) {
		printf("Some error occured when trying to get log size\n");
		return -1;
	}
	
	printf("Number of rows in fw_log: %d\n", num);
	
	return 0;
}

/**
 *	Helper function to print connection-table from fw nicely (human-readable)
 * 
 *	Gets buffer containing a string representing all the connection table,
 *	its rows are in format:
 *	"<src ip> <source port> <dst ip> <dest port> <tcp_state> <timestamp> <fake src ip> <fake source port> <fake dst ip> <fake dest port> <fake tcp state>'\n'"
 * 
 *	If any error happens, prints it to the screen.
 **/
static void print_conn_tab_nicely(const char* buff){
	
	if(buff == NULL){
		printf("Error: function print_conn_tab_nicely() got NULL argument,\
				couldn't print connection-table\n");
		return;		
	}
	
	printf("<src ip> <src port> <dst ip> <dst port> <tcp_state> <timestamp> <fake src ip> <fake src port> <fake dst ip> <fake dst port> <fake tcp state>\n");
	
	
	size_t ip_len_str = strlen("XXX.XXX.XXX.XXX")+1;
	
	char ip_src_str[ip_len_str];
	char ip_dst_str[ip_len_str];
	char ip_fake_src_str[ip_len_str];
	char ip_fake_dst_str[ip_len_str];

	char *str, *pStr;
	char* curr_token = NULL;
	
	//Creating a copy of buff:
	if((str = calloc((strlen(buff)+1), sizeof(char))) == NULL){
		printf("Error allocating memory for connection-table's copy inside print_conn_tab_nicely()\n");
		return;
	}
	strncpy(str, buff, strlen(buff)+1);
	pStr = str;
	
	int tcp_state, fake_tcp_state;
	long unsigned timestamp;
	unsigned int src_ip, dst_ip, fake_src_ip, fake_dst_ip;
	unsigned short src_port, dst_port, fake_src_port, fake_dst_port;
	bool flag = true;

	while  ((curr_token = strsep(&str, "\n")) != NULL){
		
		if(strlen(curr_token) == 0){
			//skip empty lines
			continue;
		}
		
		if ( (sscanf(curr_token, "%u %hu %u %hu %d %lu %u %hu %u %hu %d", &src_ip, &src_port,
				&dst_ip, &dst_port, &tcp_state, &timestamp, &fake_src_ip,
				&fake_src_port, &fake_dst_ip, &fake_dst_port, &fake_tcp_state)) < NUM_FIELDS_IN_CONN_ROW_FORMAT ) 
		{
			printf("Couldn't parse row to valid fields, continues to next row.\n");
		} else {

			flag = true;
			if (fake_src_ip == 0) {
				strcpy(ip_fake_src_str,"None");
			} else {
				flag = tran_uint_to_ipv4str(fake_src_ip, ip_fake_src_str, ip_len_str);
			}
			if (!flag){
				printf("Couldn't parse ip's, continues to next row.\n");
				continue; 
			}
			
			if (fake_dst_ip == 0){
				strcpy(ip_fake_dst_str,"None");
			} else{
				flag = tran_uint_to_ipv4str(fake_dst_ip, ip_fake_dst_str, ip_len_str);
			}
			
			if ( !(tran_uint_to_ipv4str(src_ip, ip_src_str, ip_len_str))
				|| !(tran_uint_to_ipv4str(dst_ip, ip_dst_str, ip_len_str))
				|| !flag )
			{
				printf("Couldn't parse ip's, continues to next row.\n");
				continue; //To next iteration
			}

			printf("%s\t%hu\t%s\t%hu\t%d\t%lu\t%s\t%hu\t%s\t%hu\t%d\n", ip_src_str, src_port,
				ip_dst_str, dst_port, tcp_state, timestamp, ip_fake_src_str,
				fake_src_port, ip_fake_dst_str, fake_dst_port, fake_tcp_state);
		}
	}
	
	//Free allocations:
	free(pStr);

}

/**
 *	Gets and prints connection table format
 *	(reads from PATH_TO_CONN_TAB_ATTR)
 * 
 *	Returns 0 on success, -1 if failed
 *	
 *	Note: function prints errors, if any, to screen
 **/
static int get_conn_tab(){

	char* buff;
	unsigned int p_size = (unsigned int)getpagesize();
	if ( (buff = calloc(p_size,sizeof(char))) == NULL){
		printf("Allocating buffer for getting rows from connection table failed.\n");
		return -1;
	} 
	
	// Open device with read only permissions:
	int fd = open(PATH_TO_CONN_TAB_ATTR,O_RDONLY);
	if (fd < 0){
		printf("Error occured trying to open the connection-table device for reading, error number: %d\n", errno);
		free(buff);
		return -1;
	}
	
	if (read(fd, buff, p_size) < 0){
		printf("Error occured trying to read rows from connection table, error number: %d\n", errno);
		free(buff);
		close(fd);
		return -1;
	}
	close(fd);
	
	print_conn_tab_nicely(buff);
	free(buff);

	return 0;
}


int main(int argc, char* argv[]){

	if( (argc < 2 || argc > 3) || 
		((argc == 3) && (strcmp(argv[1], STR_LOAD_RULES) != 0)) )
	{
		printf("Wrong usage, format is: <command> <path to rules file, only if cmd is load_rules>\n");
		return -1;
	} 

	if (argc == 3){ //load_rules
		if (!valid_file_path(argv[2])) {
			printf("File doesn't exist. Please try again\n");
			return -1;
		}
		return load_rules(argv[2]);
	}
	
	if (strcmp(argv[1], STR_ACTIVATE) == 0){
		return change_active_state_fw(true);
	}
	
	if (strcmp(argv[1], STR_DEACTIVATE) == 0) {
		return change_active_state_fw(false);
	}
	
	if (strcmp(argv[1],STR_GET_ACTIVE_STAT) == 0) {
		return get_active_stat();
	}

	if (strcmp(argv[1], STR_SHOW_RULES) == 0) {
		return print_all_rules_from_fw();
	}
		
	if (strcmp(argv[1], STR_CLEAR_RULES) == 0) {
		return clear_rules();
	}

	if (strcmp(argv[1], STR_SHOW_LOG) == 0) {
		return print_all_log_rows();
	}
			
	if (strcmp(argv[1], STR_CLEAR_LOG) == 0) {
		return clear_log();
	}
	
	if (strcmp(argv[1], STR_GET_LOG_SIZE) == 0) {
		return get_log_size();
	}
	
	if (strcmp(argv[1], STR_SHOW_CONN_TAB) == 0) {
		return get_conn_tab();
	}

	printf ("Invalid command.\n");
	return -1;
	
}
