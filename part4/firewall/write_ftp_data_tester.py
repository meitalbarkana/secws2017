import socket, sys, select, Queue, string, struct, re
from httplib import HTTPResponse
from StringIO import StringIO

PATH_TO_CONN_TAB_ATTR = "/sys/class/fw/fw/conn_tab"

def read_conn_tab_to_buff():
	buff = False
	try:
		with open(PATH_TO_CONN_TAB_ATTR,'r') as f:
			buff = f.read()
			f.close()
	except EnvironmentError as e:
		print("Error, opening device for reading connection-table failed. Error details:")
		print "\t", e

	return buff

def write_new_ftp_data_to_conn_tab(src_ip, src_port, dst_ip, dst_port):
	buff = "{0} {1} {2} {3}\n".format(src_ip, src_port, dst_ip, dst_port)
	print("buff that is sent to connection table device is: {}".format(buff))#TODO:: delete this line
	print("buff length that is sent to connection table device is: {}".format(len(buff)))#TODO:: delete this line
	try:
		with open(PATH_TO_CONN_TAB_ATTR,'w') as f:
			f.write(buff)
			f.close()
	except EnvironmentError as e:
		print("Error, opening device for writing to connection-table failed. Error details:")
		print "\t", e
		return False
	return True


def start():

	print("Connection table before trying to add:")
	print(read_conn_tab_to_buff())

	if write_new_ftp_data_to_conn_tab(167837959, 20, 167837950, 55551):
		print("Successfully wrote to connection table!\nNew connection-table is:")
		print(read_conn_tab_to_buff())
	else:
		print("Failed writing to connection table! :(")

def main():
	start()

if __name__ == '__main__':
	main()