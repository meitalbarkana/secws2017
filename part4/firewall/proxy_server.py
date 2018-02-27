import socket, sys
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


def start():
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	#Initiate an INET, STREAMing socket
		sock.bind((LOCALHOST, HTTP_LISTENING_PORT))					#Bind it to a our host and (well-known) HTTP_LISTENING_PORT port
		sock.listen(MAX_CONN)										#Start listening
	except Exception, e:
		print("Error: unable to initialize listening socket")
		print(e)
		sys.exit(2)

	while True:
		try:
			#print ("In while loop")
			#sock.setblocking(0)
			conn, addr = sock.accept()
			data = conn.recv(MAX_BUFFER_SIZE)
			if not data:
				print("No data was received, moving on to next client")
			else:
				print("************************************************************************")
				print("****************************Data is:****************************")
				print(data)
				print("****************************************************************")
				#print("*********Does this data contain valid content length?**********")
				print("*********************Data as dictionary is:*********************")
				print(is_valid_content_length(data))
				print("************************************************************************")
				#start_new_thread(conn_string, (conn, data, addr))
		except Exception, e:
			#if (e == KeyboardInterrupt):
			#	print("User requested to quit, exiting.")
			#	sys.exit(1)
			print(e)
			pass
			
	sock.close()


#def conn_string(conn, data, addr):

def main():
	start()

if __name__ == '__main__':
	main()