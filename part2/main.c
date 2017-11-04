#include <stdio.h>
#include <string.h>

typedef enum {no_arg, zero_arg, invalid_arg} arg_stat;

const char* zero_string = "0";

static arg_stat check_valid_args(int argc, char* argv[]){
		if (argc > 2) {			
			return invalid_arg;
		}	
		if (argc == 2) { // We'll have to check if the argument provided is 0.
			if (strcmp(zero_string, argv[1])==0){
				return zero_arg;
			} 
			return invalid_arg;
		} 
		else { // argc == 1:
			return no_arg;
		}
}

int main(int argc, char* argv[]){
	
		switch(check_valid_args(argc,argv)){
			case no_arg:
				printf("meow, meow, MEOW!!!! no arguments:) \n");//TODO:: DELETE THIS
				break;
			case zero_arg:
				printf("Wow, we've got a zero!\n");//TODO:: DELETE THIS
				break;
			case invalid_arg:
			default:
				printf("Arguments are invalid or too many arguments were delivered: please send one argument at most\n");
				return -1;
		}
		return 0;
	
}
