#include <stdio.h>
#include <string.h>

#define BUFF_LEN 1024

typedef enum {no_arg, zero_arg, invalid_arg} arg_stat;

const char* const zero_string = "0";

static char recievedData[BUFF_LEN];

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
	
		enum arg_stat checked_args = check_valid_args(argc,argv);
		if (checked_args==invalid_arg){
			printf("Arguments are invalid or too many arguments were delivered: please send one argument at most\n");
			return -1;
		}

		// If gets here, checked_args==no_arg OR checked_args==zero_arg
		
		if (checked_args==no_arg){//should print the device status
			int fd = open("________________",O_RDONLY); //TODO:: finish this :P
			if (fd<0){
				printf("Error accured trying to open the device, error number: %d\n", errno);
				return -1;
			}
		}


		//TODO:: finish...
		return 0;
	
}
