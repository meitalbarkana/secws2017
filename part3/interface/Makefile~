all: main

main: input_utils.o user_fw.o
	gcc -std=c99 -Wall -Werror -pedantic-errors $^ -o $@

input_utils.o: input_utils.c input_utils.h user_fw.h
	gcc -std=c99 -Wall -Werror -pedantic-errors -c $<

user_fw.o: user_fw.h
	gcc -std=c99 -Wall -Werror -pedantic-errors -c $<

.PHONY: clean
clean:	
	rm -f *.o main

