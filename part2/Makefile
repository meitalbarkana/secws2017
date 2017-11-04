all: a.out

clean:
	rm -f main.o a.out

a.out: main.o
	gcc -std=c99 -Wall -Werror -pedantic-errors main.o -o a.out

main.o: main.c
	gcc -std=c99 -Wall -Werror -pedantic-errors -c main.c

