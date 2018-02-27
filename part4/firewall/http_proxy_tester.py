import socket, sys
import httplib
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO


LOCALHOST = ''
HTTP_LISTENING_PORT = 8080											#"Spoof" port
MAX_BUFFER_SIZE = 8192												#=2^13. since we should block only size > 5000, 4096 isn't enough
MAX_HTTP_CONTENT_LENGTH = 5000


def main():

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	#Initiate an INET, STREAMing socket
		sock.settimeout(2)
	except Exception, e:
		print("Error: unable to initialize listening socket")
		print(e)
		sys.exit(2)
	"""
	try:
		f = open("../../../../tau.html","r") #"" is an HTML file
	except:
		print ("Couldn't read file, exiting")
		sys.exit(1)
	#Credit: https://stackoverflow.com/questions/10114224/how-to-properly-send-http-response-with-python-using-socket-library-only
	
	response_body = f.read()
	"""

	response_body = "WOOF!"
	response_body_raw = ''.join(response_body)

	response_headers = {
		'Content-Type': 'text/html; encoding=utf8',
		'Content-Length': len(response_body_raw),
		'Connection': 'close',
	}

	response_headers_raw = ''.join('%s: %s\n' % (k, v) for k, v in response_headers.iteritems())

	# Reply as HTTP/1.1 server, saying "HTTP OK" (code 200).
	response_proto = 'HTTP/1.1'
	response_status = '200'
	response_status_text = 'OK' # this can be random

	try :
		sock.connect((LOCALHOST, HTTP_LISTENING_PORT))
	except :
		print 'Unable to connect'
		sys.exit()


	# sending all this stuff
	sock.send('%s %s %s\n%s\n%s' % (response_proto, response_status, response_status_text, response_headers_raw, response_body_raw))

	# and closing connection, as we stated before
	sock.close()

	print("sent all data, which is:")
	print (response_proto)
	print response_status
	print response_status_text
	print(response_headers_raw)
	print()
	print(response_body_raw)

if __name__ == '__main__':
	main()