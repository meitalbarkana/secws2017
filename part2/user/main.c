#include <stdio.h>
#include <string.h>
#include <fcntl.h> // For open()
#include <sys/types.h> // For open()
#include <sys/stat.h> // For open()
#include <errno.h>
#include <unistd.h> // For close()

#define BUFF_LEN 1024
/** PATH_TO_DEVICE is /sys/class/<name of class we defined>/<name of device we defined>/<.attr.name we defined> **/
#define PATH_TO_DEVICE "/sys/class/Sysfs_class/sysfs_class_sysfs_Device/sysfs_att"


enum arg_stat{no_arg, zero_arg, invalid_arg};

const char* const ZERO_STRING = "0";
static char recievedData[BUFF_LEN];
static char dataToPrint[BUFF_LEN*2];

/**
 *  A help function that returns an enum representing the arguments given to the program (argv[]):
 * 		no_arg = no arguments were given,
 * 		zero_arg = the argument "0" was given,
 * 		invalid_arg = some other (invalid) argument was given.	
 **/
static enum arg_stat check_valid_args(int argc, char* argv[]){
		if (argc > 2) {			
			return invalid_arg;
		}	
		if (argc == 2) { // We'll have to check if the argument provided is 0.
			if (strcmp(ZERO_STRING, argv[1])==0){
				return zero_arg;
			} 
			return invalid_arg;
		} 
		else { // argc == 1:
			return no_arg;
		}
}

/**
 * Help function that updates dataToPrint so that it will contain the updated data we want to print, according to recievedData.
 **/
 static void prepareDataToPrint(void){
	
 }

int main(int argc, char* argv[]){
	
		enum arg_stat checked_args = check_valid_args(argc,argv);
		if (checked_args==invalid_arg){
			printf("Arguments are invalid or too many arguments were delivered: please send one argument at most\n");
			return -1;
		}

		// If gets here, checked_args==no_arg OR checked_args==zero_arg
		
		if (checked_args==no_arg){//should print the device status
			int fd = open(PATH_TO_DEVICE,O_RDONLY);
			if (fd<0){
				printf("Error accured trying to open the device, error number: %d\n", errno);
				return -1;
			}
			int numOfBytesRead = read(fd, recievedData,BUFF_LEN);
			if (numOfBytesRead < 0){
				printf("Error accured trying to read from device, error number: %d\n", errno);
				close(fd);
				return -1;
			}
			printf("Data recieved from device: %s\n", recievedData);
			close(fd);
			//TODO:: complete to formatted string!
		}
		else { // checked_args==zero_arg
			printf("zero arguments, wi-hi! :)\n");
			//TODO:: finish...
		}


		
		return 0;
	
}
