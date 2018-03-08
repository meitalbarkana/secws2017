#Read from fw's connection table
import string, socket, struct

PATH_TO_CONN_TAB_ATTR = "/sys/class/fw/fw/conn_tab"


"""TODO:: not all states are relevant! delete the ones that aren't"""
#"State" before a connection actually begins OR after it's closed:
TCP_STATE_CLOSED = 1,
#State a server is in when waiting for a request to start a connection:
TCP_STATE_LISTEN = 2,
#State after client sent a SYN packet and is waiting for SYN-ACK reply:
TCP_STATE_SYN_SENT = 3,
#State a server is in after receiving a SYN packet and replying with its SYN-ACK reply:
TCP_STATE_SYN_RCVD = 4,
#State a connection is in after its necessary ACK packet has been received - 
# client goes into this state after receiving a SYN-ACK,
# server goes into this state after receiving the lone ACK:
TCP_STATE_ESTABLISHED = 5,
#Client's state after he sent an initial FIN packet asking for a graceful close of the TCP connection:
TCP_STATE_FIN_WAIT_1 = 6,
#Server's state after it receives an initial FIN and sends back an ACK to acknowledge the FIN:
TCP_STATE_CLOSE_WAIT = 7,
#Client's state when receiving the ACK response to its initial FIN,
# as it waits for a final FIN from server:
TCP_STATE_FIN_WAIT_2 = 8,

#Server's state when just sent the second FIN needed to gracefully
# close the TCP connection back to (initiating) client, while it waits for acknowledgment:
TCP_STATE_LAST_ACK = 9,

#State of the initiating client that received the final FIN and has sent
# an ACK to close the connection:
TCP_STATE_TIME_WAIT = 10
""""""


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


def find_real_destination(real_src_ip, real_src_port, current_fake_dst_ip, current_fake_dst_port):
	"""
	Helper function to get_remote_servers_details():
	
	@real source ip & source port as provided by "the packet" (the flow)
	@fake destination ip & port (ours!)

	searches for relevant connections in fw's connection table - 
	and returns a tuple of <real_destination_ip, real_destination_port>
	If None was found or an error occured, returns <None, None>
	"""
	conn_tab_as_str = read_conn_tab_to_buff()
	
	#TODO:: delete next 4 lines:
	print("In function find_real_destination, received arguments:")
	print("\treal_src_ip: "+str(real_src_ip)+" ("+socket.inet_ntoa(struct.pack('!I', real_src_ip))+"), real_src_port: "+str(real_src_port))
	print("\tcurrent_fake_dst_ip: "+str(current_fake_dst_ip)+" ("+socket.inet_ntoa(struct.pack('!I', current_fake_dst_ip))+"), current_fake_dst_port: "+str(current_fake_dst_port))
	print("\nConnection table is:")
	print conn_tab_as_str, "\n"
	
	if conn_tab_as_str != False:
		lines = conn_tab_as_str.splitlines()
		for line in lines:
			try:
				#Since line format is;
				#"<src ip> <source port> <dst ip> <dest port> <tcp_state> <timestamp> <fake src ip> <fake src port> <fake dst ip> <fake dst port>"
				src_ip, src_port, dst_ip, dst_port, tcp_state, timestamp,fake_src_ip, fake_src_port, fake_dst_ip, fake_dst_port  = line.split()
				src_ip = long(src_ip)
				src_port = int(src_port)
				dst_ip = long(dst_ip)
				dst_port = int(dst_port)
				tcp_state = int(tcp_state)
				timestamp = long(timestamp)
				fake_src_ip = long(fake_src_ip)
				fake_src_port = int(fake_src_port)
				fake_dst_ip = long(fake_dst_ip)
				fake_dst_port = int(fake_dst_port)

				"""
				print "src_ip: ",src_ip,", src_port: ", src_port, ", dst_ip: ", dst_ip, ", dst_port: ",dst_port, \
				", tcp_state: ", tcp_state, ", timestamp: ", timestamp,", fake_src_ip: ",fake_src_ip, \
				", fake_src_port: ", fake_src_port,", fake_dst_ip: ", fake_dst_ip, ", fake_dst_port: ",fake_dst_port,"\n"
				"""

				
				if real_src_ip == src_ip and real_src_port == src_port and \
				fake_dst_ip == current_fake_dst_ip and fake_dst_port == current_fake_dst_port:
					#TODO:: delete the first 3 lines:
					print("******Found a match! line is:******")
					print(line)
					print("***********************************")
					return (dst_ip,dst_port)

			except:
				print("Error while trying to split lines from connection table: wrong format.")
				return (None, None)
	print("No relevent row was found in connection table: connection will be ignored.")
	return (None, None)


def main():

	#TODO:: TEST, delete this:
	#10.1.2.2 = 167838210
	#10.1.2.3 = 167838211
	#find_real_destination(real_src_ip, real_src_port, current_fake_dst_ip, current_fake_dst_port):
	dst_ip, dst_port = find_real_destination(167838210, 21, 167838211, 21212)
	print "In main, returned values are:\n\tdst_ip: ", dst_ip
	print "\tdst_port: ", dst_port

if __name__ == '__main__':
	main()