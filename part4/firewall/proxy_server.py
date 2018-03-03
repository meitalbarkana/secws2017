import socket, sys, select, Queue
from httplib import HTTPResponse
from StringIO import StringIO


LOCALHOST = ''
HTTP_LISTENING_PORT = 8080											#"Spoof" port
FTP_LISTENING_PORT_1 = 21212
FTP_LISTENING_PORT_2 = 20202
MAX_CONN = 5
MAX_BUFFER_SIZE = 8192												#=2^13. since we should block only size > 5000, 4096 isn't enough
MAX_HTTP_CONTENT_LENGTH = 5000


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


def get_remote_servers_details(current_connection_socket):
	#TODO::
	"""
	Will return a tuple of (remot_addr,remote_port) according to the relevant connection (http/ftp on 20/ftp on 21)
	"""
	return True


def remote_connection(sock):
	"""
	Creates a connection to the relevant remote-server.
	Returns False if any error occurred.
	"""
	try:
		remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		remote_details = get_remote_servers_details(sock)
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
		#Initiate 3 INET, STREAMing sockets (for listening):
		server_sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for i in xrange(3)]
 
 		for i in xrange(3):
			server_sockets[i].setblocking(0)
			server_sockets[i].bind((LOCALHOST, listening_ports[i]))				#Bind it to a our host and (well-known) relevant port
			server_sockets[i].listen(MAX_CONN)									#Start listening
			print('[*] Listening on {0} {1}'  .format("LOCALHOST",self.listening_ports[i]))


	except Exception, e:
		print("Error: unable to initialize listening sockets")
		print(e)
		sys.exit(2)

	output_sockets = []
	input_sockets = server_sockets
	messages_queue = {}

	try:
		while input_sockets:
			print ("In while loop")

			ready_to_read_sockets, ready_to_write_sockets, in_error_sockets = \
	               select.select(input_sockets, output_sockets, input_sockets)

	        for sock in ready_to_read_sockets:
	        	if sock in server_sockets:
	        		remote_server = remote_connection(sock)
	        		if remote_server:
						client_connection, client_address = sock.accept()
						print('Accepted connection {0} {1}'.format(client_address[0], client_address[1]))
						#client_connection.setblocking(0)#not sure if needed :X
						input_sockets.append(client_connection)
						input_sockets.append(remote_server)
						messages_queue[client_connection] = remote_server
						messages_queue[remote_server] = client_connection
						break
					else:
						print('The connection with the remote server can\'t be established,')
				else:	
					data = received_from(sock, 3)
					messages_queue[sock].send(data)
					if len(data) == 0:
						close_sock(sock, input_sockets, messages_queue):
						break
					else:
						print('Received {} bytes from client '.format(len(data)))
						#TODO:: delete the next row, just for testing:
						hexdump(data)

	except KeyBoardInterrupt:
		print("Ending server.")
	except Exception, e:
		print(e)
		sys.exit(0)
	finally:
		sys.exit(0)


#def conn_string(conn, data, addr):

def main():
	start()

if __name__ == '__main__':
	main()