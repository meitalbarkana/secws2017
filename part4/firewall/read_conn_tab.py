#Read from fw's connection table
import String

PATH_TO_CONN_TAB_ATTR = "/sys/class/fw/fw/conn_tab"

def read_conn_tab_to_buff():

	buff = False

	with open(PATH_TO_CONN_TAB_ATTR,'r') as f:
		buff = f.read()
		f.close()

	return buff


def find_real_destination(real_src_ip, real_src_port):
	"""
	Gets real source ip & source port, 
	searches for relevant connections in fw's connection table - 
	and returns a tuple of <real_destination_ip, real_destination_source>
	"""
	conn_tab_as_str = read_conn_tab_to_buff()
	#TODO:: delete next 2 lines:
	print("Connection table is:")
	print(conn_tab_as_str)
	
	lines = conn_tab_as_str.splitlines()
	for line in lines:
		try:
			src_ip, src_port, dst_ip, dst_port, tcp_state = line.split()
			src_ip = long(src_ip)
			src_port = int(src_port)
			dst_ip = long(dst_ip)
			dst_port = int(dst_port)
			


		except:
			print("Error while trying to split lines from connection table: wrong format.")
			return False



def main():

"""
	if not conn_tab_as_str:
		print("Function returned False.")
	else:
		print("***********Connection table is:*************")
		print(conn_tab_as_str)
"""

if __name__ == '__main__':
	main()