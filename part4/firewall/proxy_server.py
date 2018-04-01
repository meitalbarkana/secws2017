import socket, sys, select, Queue, string, struct
from httplib import HTTPResponse
from StringIO import StringIO

PATH_TO_CONN_TAB_ATTR = "/sys/class/fw/fw/conn_tab"
LOCALHOST = ''
#TODO:: update uses of LOCALHOST to vlan1/vlan2
VLAN_1 = '10.1.1.3'
VLAN_2 = '10.1.2.3'
HTTP_LISTENING_PORT = 8080											#"Spoof" port
FTP_LISTENING_PORT_1 = 21212
FTP_LISTENING_PORT_2 = 20202
MAX_CONN = 5
MAX_BUFFER_SIZE = 8192												#=2^13. since we should block only size > 5000, 4096 isn't enough
MAX_HTTP_CONTENT_LENGTH = 5000
CONN_TIMEOUT = 25

"""NOTE: not all states are relevant"""
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
	and returns a tuple of <real_destination_ip(in string format:"x.x.x.x"), real_destination_port>
	If None was found or an error occured, returns <None, None>
	"""
	conn_tab_as_str = read_conn_tab_to_buff()
	
	#TODO:: delete next 4 lines:
	print("In function find_real_destination, received arguments:")
	print("\treal_src_ip: "+str(real_src_ip)+" ("+socket.inet_ntoa(struct.pack('!I', real_src_ip))+"), real_src_port: "+str(real_src_port))
	print("\tcurrent_fake_dst_ip: "+str(current_fake_dst_ip)+" ("+socket.inet_ntoa(struct.pack('!I', current_fake_dst_ip))+"), current_fake_dst_port: "+str(current_fake_dst_port))
	print("\nConnection table is:")
	print(conn_tab_as_str)
	
	if conn_tab_as_str != False:
		lines = conn_tab_as_str.splitlines()
		for line in lines:
			try:
				#Since line format is;
				#"<src ip> <source port> <dst ip> <dest port> <tcp_state> <timestamp> <fake src ip> <fake src port> <fake dst ip> <fake dst port> <fake_tcp_state>"
				src_ip, src_port, dst_ip, dst_port, tcp_state, timestamp,fake_src_ip, fake_src_port, fake_dst_ip, fake_dst_port, fake_tcp_state  = line.split()
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
				fake_tcp_state = int(fake_tcp_state)
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
					print("***********************************\n")
					return (socket.inet_ntoa(struct.pack('!I', dst_ip)),dst_port)

			except:
				print("Error while trying to split lines from connection table: wrong format.")
				return (None, None)
	print("No relevent row was found in connection table: connection will be ignored.")
	return (None, None)

#Credit: https://stackoverflow.com/questions/24728088/python-parse-http-response-string
class FakeSocket():
	def __init__(self, response_str):
		self._file = StringIO(response_str)
	def makefile(self, *args, **kwargs):
		return self._file


def is_valid_content_length(all_data):
	"""
	Gets HTTP data, returns:
			1. True if it has a header "content_length" and its value <= MAX_HTTP_CONTENT_LENGTH,
			2. False otherwise (includes the case were all_data doesn't contain this header)
	NOTE: USE THIS ONLY ON HTTP DATA!
	"""
	source = FakeSocket(all_data)
	response = HTTPResponse(source)
	response.begin()

	"""
	print ("headers are:")
	for h in response.getheaders():
		print (h)  # For testing alone, TODO:: delete this.
	"""
	content_len_value = int(response.getheader('content-length', -1))
	if content_len_value == -1 or content_len_value > MAX_HTTP_CONTENT_LENGTH:
		return False
	"""
	print ("content length's value is: ")
	print (content_len_value)
	print ("content length's type is: ")
	print (type(content_len_value))
	"""
	return True


def is_valid_file(file_as_str):
	"""
	Gets FTP data, returns:
			1. False if it's an .exe file
			2. True otherwise.
	NOTE: USE THIS ONLY ON FTP DATA (files)!
	"""


def get_remote_servers_details(current_connection_socket, client_address):
	"""
	Returns a tuple of (remot_addr,remote_port) according to the relevant connection (http/ftp on 20/ftp on 21)
	"""
	our_sock_ip, our_sock_port = current_connection_socket.getsockname()
	our_sock_ip_as_int = struct.unpack("!I",socket.inet_aton(our_sock_ip))[0]
	client_sock_ip_as_int = struct.unpack("!I",socket.inet_aton(client_address[0]))[0]

	#find_real_destination(real_src_ip, real_src_port, current_fake_dst_ip, current_fake_dst_port):
	(dst_ip, dst_port) = find_real_destination(client_sock_ip_as_int, client_address[1], our_sock_ip_as_int, our_sock_port)
	if dst_ip == None:
		return False
	return (dst_ip, dst_port)


def remote_connection(sock, client_address):
	"""
	Creates a connection to the relevant remote-server.
	Returns False if any error occurred.
	"""
	try:
		remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		remote_socket.settimeout(CONN_TIMEOUT)#TODO:: check if needed..
		remote_details = get_remote_servers_details(sock, client_address)
		if remote_details == False:
			print("Error: failed to extract remote-server's details.")
			return False
		else:
			print ("In remote_connection(), remote_details are: dst_ip=[{0}] dst_port=[{1}]".format(remote_details[0], remote_details[1]))#TODO:: delete, for debugging
		remote_socket.connect(remote_details)
		return remote_socket
	except Exception as e:
		print(e)
		return False

def received_from(sock, timeout):
	data = ""
	sock.settimeout(timeout)
	try:
		while True:
			data = sock.recv(MAX_BUFFER_SIZE)
			if not data:
				break
			data =+ data
	except:
		pass
	return data


def close_sock(sock, input_sockets, messages_queue):
	"""
	Closes sock and its corresponding server socket,
	deletes them from input_sockets and from messages_queue
	"""
	print ('End of connection with {}'.format(sock.getpeername()))
	relevant_server_sock = messages_queue[sock]
	input_sockets.remove(relevant_server_sock)
	input_sockets.remove(sock)

	relevant_server_sock.close()
	sock.close()

	del messages_queue[sock]
	del messages_queue[relevant_server_sock]


'''
Simple implementation of hexdump
https://gist.github.com/JonathonReinhart/509f9a8094177d050daa84efcd4486cb
'''
def hexdump(data, length=16):
	filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
	lines = []
	digits = 4 if isinstance(data, str) else 2
	for c in range(0, len(data), length):
		chars = data[c:c+length]
		hex = ' '.join(["%0*x" % (digits, (x)) for x in chars])
		printable = ''.join(["%s" % (((x) <= 127 and filter[(x)]) or '.') for x in chars])
		lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
	print(''.join(lines))


def start():
	try:
		listening_ports = [HTTP_LISTENING_PORT, FTP_LISTENING_PORT_1, FTP_LISTENING_PORT_2]
		#Initiate 6 INET, STREAMing sockets (for listening):
		server_sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for i in xrange(6)]

		for i in xrange(3):
			#server_sockets[i].setblocking(0)
			server_sockets[i].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			server_sockets[i].bind((VLAN_1, listening_ports[i]))				#Bind it to a our host and (well-known) relevant port
			server_sockets[i].listen(MAX_CONN)									#Start listening
			print('[*] Listening on {0} {1}'.format(VLAN_1, listening_ports[i]))

		for i in xrange(3):
			#server_sockets[i+3].setblocking(0)
			server_sockets[i+3].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			server_sockets[i+3].bind((VLAN_2, listening_ports[i]))				#Bind it to a our host and (well-known) relevant port
			server_sockets[i+3].listen(MAX_CONN)									#Start listening
			print('[*] Listening on {0} {1}'.format(VLAN_2, listening_ports[i]))


	except Exception, e:
		print("Error: unable to initialize listening sockets")
		print(e)
		sys.exit(2)

	output_sockets = []
	input_sockets = server_sockets
	messages_queue = {}

	try:
		while input_sockets:
			print ("In while loop, input_sockets length is: {0}, here they come:".format(len(input_sockets)))#TODO:: delete, for debugging

			for s in input_sockets:#TODO:: delete, for debugging
				a, b = s.getsockname()#TODO:: delete, for debugging
				print("s details -> ip=[{0}] port=[{1}]".format(a, b))#TODO:: delete, for debugging
				try:
					print "s peer name is: ", s.getpeername()
				except:
					print ("s in not connected.")

			ready_to_read_sockets, ready_to_write_sockets, in_error_sockets = \
				select.select(input_sockets, output_sockets, input_sockets)

			print ("[*]Ready_to_read_sockets length is: {0}".format(len(ready_to_read_sockets)))#TODO:: delete, for debugging
			print ("[*]Ready_to_write_sockets length is: {0}".format(len(ready_to_write_sockets)))#TODO:: delete, for debugging
			print ("[*]In_error_sockets length is: {0}".format(len(in_error_sockets)))#TODO:: delete, for debugging


			for sock in ready_to_read_sockets:
				print ("In for loop, ready_to_read_sockets length is: {0}".format(len(ready_to_read_sockets)))#TODO:: delete, for debugging

				if sock in server_sockets:
					
					if sock in server_sockets[0:6]:
						print("Sock is an **ORIGINAL** server socket")
					else:
						print("Sock is a LISTENING server socket!")

					iiiiiip, pppppport = sock.getsockname()#TODO:: delete, for debugging
					print ("sock is in server_sockets, its info: ip=[{0}] port=[{1}]".format(iiiiiip, pppppport))#TODO:: delete, for debugging
					try:
						print "sock peer name is: ", sock.getpeername()
					except:
						print ("sock in not connected.")

					client_connection, client_address = sock.accept()
					print('Accepted connection {0} {1}'.format(client_address[0], client_address[1]))
					remote_server = remote_connection(sock, client_address)
					if remote_server:
						#client_connection.setblocking(0)#not sure if needed :X
						input_sockets.append(client_connection)
						input_sockets.append(remote_server)
						messages_queue[client_connection] = remote_server
						messages_queue[remote_server] = client_connection
						break
					else:
						print('The connection with the remote server can\'t be established, closing connection with client: {0} {1}'.format(client_address[0], client_address[1]))
						client_connection.close()

				else:

					iiiiiip, pppppport = sock.getsockname()##TODO:: delete, for debugging
					print ("sock is NOT in server_sockets, its info: ip=[{0}] port=[{1}], trying to accept data from it.".format(iiiiiip, pppppport))#TODO:: delete, for debugging

					data = received_from(sock, 3)
					messages_queue[sock].send(data)
					if len(data) == 0:
						close_sock(sock, input_sockets, messages_queue)
						break
					else:
						print('Received {} bytes from client '.format(len(data)))
						#TODO:: delete the next row, just for testing:
						hexdump(data)

	except KeyboardInterrupt:
		print("Ending server.")
	except Exception, e:
		print(e)
		sys.exit(0)
	#finally:
	#	print("Got to \'finally\'!")
	#	sys.exit(0)


#def conn_string(conn, data, addr):

def main():
	start()

if __name__ == '__main__':
	main()