import socket, sys, time
from scapy.all import *
from thread import *

LOCALHOST = ''				#Symbolic name, meaning localhost
HTTP_LISTENING_PORT = 8000	#Spoof port
#FTP_LISTENING_PORT_1 = 21212
#FTP_LISTENING_PORT_2 = 20202
MAX_CONN = 5
MAX_BUFFER_SIZE = 8192		#=2^13. since we should block only size > 5000, 4096 isn't enough

def start():
	try:
		#Initiate socket, bind it to relevant port/s, start listening:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind((LOCALHOST, HTTP_LISTENING_PORT))
		sock.listen(MAX_CONN)
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
				print("No data was received, moving to next client")
			else:
				print("**************Data is:**************")
				print(data)
				print("************************************")
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