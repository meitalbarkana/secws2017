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


def start():
	try:
		listening_ports = [HTTP_LISTENING_PORT, FTP_LISTENING_PORT_1, FTP_LISTENING_PORT_2]
		#Initiate 3 INET, STREAMing sockets (for listening):
		server_sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for i in xrange(3)]
 
 		for i in xrange(3):
			server_sockets[i].setblocking(0)
			server_sockets[i].bind((LOCALHOST, listening_ports[i]))				#Bind it to a our host and (well-known) relevant port
			server_sockets[i].listen(MAX_CONN)									#Start listening

	except Exception, e:
		print("Error: unable to initialize listening sockets")
		print(e)
		sys.exit(2)

	output_sockets = []
	input_sockets = server_sockets
	message_queues = {}

	while input_sockets:
		print ("In while loop")

		ready_to_read_sockets, ready_to_write_sockets, in_error_sockets = \
               select.select(input_sockets, output_sockets, input_sockets)

        for sock in ready_to_read_sockets:
        	if sock in server_sockets:
				try:
					connection, client_address = http_sock.accept()
					connection.setblocking(0)
					input_sockets.append(connection)
					"""FROM HERE ITS FOR THE HTTP:"""
					data = connection.recv(MAX_BUFFER_SIZE)
					if not data:
						print("No data was received, moving on.")
					else:
						print("************************************************************************")
						print("****************************HTTP received data is:****************************")
						print(data)
						print("****************************************************************")
						print("*********Does this data contain valid content length?**********")
						print(is_valid_content_length(data))
						print("************************************************************************")
					"""TILL HERE"""	
				except Exception, e:
					print(e)
					pass
			elif sock == server_sockets[1]:	#FTP_LISTENING_PORT_1
				#TODO::
			else:	#FTP_LISTENING_PORT_2
				#TODO::

	#TODO:: change next line accordingly:	
	sock.close()


#def conn_string(conn, data, addr):

def main():
	start()

if __name__ == '__main__':
	main()