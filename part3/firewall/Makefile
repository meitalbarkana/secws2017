obj-m += firewall.o
firewall-objs := main.o rules_utils.o log_utils.o fw.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

