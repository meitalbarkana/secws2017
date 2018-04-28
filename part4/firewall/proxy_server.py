import socket, sys, select, Queue, string, struct, re
from httplib import HTTPResponse
from StringIO import StringIO
from executable_constants import *

PATH_TO_CONN_TAB_ATTR = "/sys/class/fw/fw/conn_tab"

VLAN_1 = '10.1.1.3'
VLAN_2 = '10.1.2.3'
HTTP_LISTENING_PORT = 8080		#"Spoof" port
FTP_LISTENING_PORT_1 = 21212
FTP_LISTENING_PORT_2 = 20202
HTTP_PORT = 80
FTP_PORT = 21
FTP_DATA_PORT = 20
MAX_CONN = 5
MAX_BUFFER_SIZE = 8192			#=2^13. since we should block only size > 5000, 4096 isn't enough
MAX_HTTP_CONTENT_LENGTH = 5000
CONN_TIMEOUT = 25


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
				
				if real_src_ip == src_ip and real_src_port == src_port and \
				fake_dst_ip == current_fake_dst_ip and fake_dst_port == current_fake_dst_port:
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


def http_has_valid_content_length(all_data):
	"""
	Gets HTTP data, returns:
			1. True if it has a header "content_length" and its value <= MAX_HTTP_CONTENT_LENGTH,
			2. False otherwise (includes the case were all_data doesn't contain this header)
	NOTE: USE THIS ONLY ON HTTP DATA!
	"""
	source = FakeSocket(all_data)
	response = HTTPResponse(source)
	response.begin()

	content_len_value = int(response.getheader('content-length', -1))
	if content_len_value == -1 or content_len_value > MAX_HTTP_CONTENT_LENGTH:
		print("Invalid (or missing) content-length header.")
		return False

	return True


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
		remote_socket.settimeout(CONN_TIMEOUT)
		remote_details = get_remote_servers_details(sock, client_address)
		if remote_details == False:
			print("Error: failed to extract remote-server's details.")
			return False
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


def close_sock(sock, input_sockets, messages_queue, close_immediately=False):
	"""
	Closes sock and its corresponding server socket,
	deletes them from input_sockets and from messages_queue.

	If close_immediately==True, sends RST packet to both sides of the connection
	(to be used when proxy got data it should block)
	"""
	if sock==None:
		return

	l_onoff = 1 
	l_linger = 0

	try:
		relevant_server_sock = messages_queue[sock]
	except:
		relevant_server_sock = None #Not supposed to get here

	if relevant_server_sock:
		if close_immediately:
			print ("Closing connection immediately with:\n1.{0}\n2.{1}".format(sock.getpeername(),relevant_server_sock.getpeername()))
		else:
			print ("End of connection with:\n1.{0}\n2.{1}".format(sock.getpeername(),relevant_server_sock.getpeername()))
		input_sockets.remove(relevant_server_sock)
		input_sockets.remove(sock)

		if close_immediately: #Send RST packets, credit: https://stackoverflow.com/a/6440364/5928769:
			if relevant_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,struct.pack('ii', l_onoff, l_linger)) != 0 :
				print("Couldn't set relevant_server_sock's SO_LINGER, closing it *might* not send RST")
			if sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger)) != 0 :
				print("Couldn't set socket's SO_LINGER, closing it *might* not send RST")
		try:
			relevant_server_sock.close()
			sock.close()
		except Exception as e:
			print("Failed closing sockets, error is: {}.".format(e))

		del messages_queue[sock]
		del messages_queue[relevant_server_sock]

	else: #relevant_server_sock == None, not supposed to get here:
		print("Couldn't find relevant_server_sock")
		if close_immediately:
			print ("Closing connection immediately with: {}".format(sock.getpeername()))
		else:
			print ("End of connection with: {}".format(sock.getpeername()))
		input_sockets.remove(sock)

		if close_immediately: #Send RST packet:
			if sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger)) != 0 :
				print("Couldn't set socket's SO_LINGER, closing it might not send RST")
		try:
			sock.close()
		except Exception as e:
			print("Failed closing sockets, error is: {}.".format(e))		
		del messages_queue[sock]


def write_new_ftp_data_to_conn_tab(src_ip, src_port, dst_ip, dst_port):
	buff = "{0} {1} {2} {3}\n".format(src_ip, src_port, dst_ip, dst_port)
	try:
		with open(PATH_TO_CONN_TAB_ATTR,'w') as f:
			f.write(buff)
			f.close()
	except EnvironmentError as e:
		print("Error, opening device for writing to connection-table failed. Error details:")
		print "\t", e
		return False
	return True


def search_for_and_handle_PORT_command(data, other_side_socket):
	print(data)
	pattern = "PORT (\d+),(\d+),(\d+),(\d+),(\d+),(\d+)"
	ip_as_int = -1

	try:
		original_server_ip_as_str, peer_port_as_int = other_side_socket.getpeername()
	except:
		print ("Couldn't extract other proxy-FTP side info")
		return False

	try:
		port_command = re.match(pattern, data)
		if port_command:
			string_ip = port_command.group(1)+"."+port_command.group(2)+"."+port_command.group(3)+"."+port_command.group(4)
			listening_port_num = int(port_command.group(5))*256 + int(port_command.group(6))
			ip_as_int = struct.unpack("!I", socket.inet_aton(string_ip))[0]
			original_server_ip_as_int = struct.unpack("!I", socket.inet_aton(original_server_ip_as_str))[0]
			if listening_port_num<0 or listening_port_num>65535:
				print("Invalid listening_port_num value({})".format(listening_port_num))
				return False
			return write_new_ftp_data_to_conn_tab(original_server_ip_as_int, FTP_DATA_PORT, ip_as_int, listening_port_num)
	except Exception, e:
		print("Not a PORT command or Couldn't parse port command, exception is:")
		print(e)

	return True


def start():
	try:
		listening_ports = [HTTP_LISTENING_PORT, FTP_LISTENING_PORT_1, FTP_LISTENING_PORT_2]
		#Initiate 6 AF_INET (IPv4) SOCK_STREAM (TCP) sockets (for listening):
		server_sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for i in xrange(6)]

		for i in xrange(3):
			server_sockets[i].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			server_sockets[i].bind((VLAN_1, listening_ports[i]))				#Bind it to a our host and (well-known) relevant port
			server_sockets[i].listen(MAX_CONN)									#Start listening
			print('[*] Listening on {0} {1}'.format(VLAN_1, listening_ports[i]))

		for i in xrange(3):
			server_sockets[i+3].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			server_sockets[i+3].bind((VLAN_2, listening_ports[i]))				#Bind it to a our host and (well-known) relevant port
			server_sockets[i+3].listen(MAX_CONN)								#Start listening
			print('[*] Listening on {0} {1}'.format(VLAN_2, listening_ports[i]))


	except Exception, e:
		print("Error: unable to initialize listening sockets")
		print(e)
		sys.exit(2)

	output_sockets = []
	input_sockets = server_sockets
	messages_queue = {}
	number_of_sever_sockets = len(server_sockets)

	try:
		while input_sockets:
			print ("\n*****************Proxy server about to call select(), input_sockets length is: {0}.*****************".format(len(input_sockets)))

			ready_to_read_sockets, ready_to_write_sockets, in_error_sockets = \
				select.select(input_sockets, output_sockets, input_sockets)

			for sock in ready_to_read_sockets:
				print("")
				m = min(number_of_sever_sockets,len(server_sockets))
				sock_ip_as_str, sock_port_as_int = sock.getsockname()
				peer_ip_as_str = ""
				peer_port_as_int = 0

				if sock in server_sockets[0:m]:
					client_connection, client_address = sock.accept()
					print('Accepted new connection {0} {1}'.format(client_address[0], client_address[1]))
					remote_server = remote_connection(sock, client_address)
					if remote_server:
						input_sockets.append(client_connection)
						input_sockets.append(remote_server)
						messages_queue[client_connection] = remote_server
						messages_queue[remote_server] = client_connection
						break
					else:
						print('The connection with the remote server can\'t be established, closing connection with client: {0} {1}'.format(client_address[0], client_address[1]))
						client_connection.close()

				else:
					print ("Trying to accept data from socket: ip=[{0}] port=[{1}].".format(sock_ip_as_str, sock_port_as_int))
					try:
						peer_ip_as_str, peer_port_as_int = sock.getpeername()
						print ("sock's peer name is: ({0},{1})".format(peer_ip_as_str, peer_port_as_int))
					except:
						print ("sock's not connected.")
					
					data = received_from(sock, 3)
					
					if len(data) == 0:
						print("Received-data's length is 0 - meaning no more data will be received from this connection. Closing it.")
						messages_queue[sock].send(data)	
						close_sock(sock, input_sockets, messages_queue)
						break

					#If gets here, len(data) > 0:
					if peer_port_as_int == HTTP_PORT:
						print("Handling data received from HTTP port(80)...")
						if http_has_valid_content_length(data):
							messages_queue[sock].send(data)
							print("Received {} VALID http bytes from remote server, passed it to inner network.".format(len(data)))
						else:
							print("Received INVALID incoming http data ({} bytes) from remote server, closing connection.".format(len(data)))
							close_sock(sock, input_sockets, messages_queue, True)

					elif peer_port_as_int == FTP_PORT:
						print("Handling data received from FTP port(21)...")
						print("Received {0} bytes of data from remote FTP (21) server, makes sure its not an executable file before sending it to inner network.".format(len(data)))
						if(is_file_executable(data)):
							print("Got executable file from FTP server! Ending connection")
							close_sock(sock, input_sockets, messages_queue, True)
						else:
							messages_queue[sock].send(data)
							print("Sent valid data ({} bytes) from FTP server to inner-network.".format(len(data)))


					elif peer_port_as_int == FTP_DATA_PORT:
						print("Handling data received from FTP-DATA port(20)...")
						print("Received {0} bytes of data from remote DATA-FTP server, makes sure its not an executable file before sending it to inner network.".format(len(data)))
						if(is_file_executable(data)):
							print("Got executable file from DATA-FTP server! Ending connection")
							close_sock(sock, input_sockets, messages_queue, True)
						else:
							messages_queue[sock].send(data)
							print("Sent valid data ({} bytes) from DATA-FTP server to inner-network.".format(len(data)))

					elif sock_port_as_int == FTP_LISTENING_PORT_1:
						print("Received data that is sent from inner network to FTP PORT (21), searching it for PORT command:")
						if search_for_and_handle_PORT_command(data, messages_queue[sock]):
							messages_queue[sock].send(data)
							print("{0} Bytes of data from inner network were sent to remote FTP(21) server.".format(len(data)))
						else:
							print("Received INVALID outgoing FTP data ({} bytes) from inner network OR an error happened. closing connection.".format(len(data)))
							close_sock(sock, input_sockets, messages_queue, True)

					else:
						messages_queue[sock].send(data)
						print("{0} Bytes of data from inner network were sent to remote server.".format(len(data)))					 

	except KeyboardInterrupt:
		print("Ending server.")
	except Exception, e:
		print(e)
		sys.exit(0)


def main():
	start()

if __name__ == '__main__':
	main()