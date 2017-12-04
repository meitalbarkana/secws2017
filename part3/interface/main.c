#include "input_utils.h"

/**
 * Loads rules from file to the firewall.
 * 
 * Returns 0 on success, -1 if failed
 *	
 * Note: function prints errors, if any, to screen
 **/
int load_rules(const char* file_path){
	
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
			printf ("All %d rules were loaded successfully to the firewall.\n", rules_read);
			return 0;
	}
	
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
/**	
	if (strcmp(argv[1], STR_ACTIVATE) == 0){
		return activate_fw();
	}
	
	if (strcmp(argv[1], STR_DEACTIVATE) == 0) {
		return deactivate_fw();
	}
	
	if (strcmp(argv[1], STR_SHOW_RULES) == 0) {
		return show_rules();
	}
	
	if (strcmp(argv[1], STR_CLEAR_RULES) == 0) {
		return clear_rules();
	}
	
	if (strcmp(argv[1], STR_SHOW_LOG) == 0) {
		return show_log();
	}
	
	if (strcmp(argv[1], STR_CLEAR_LOG) == 0) {
		return clear_log();
	}
**/	
	printf ("Invalid command.\n");
	return -1;
	
}
