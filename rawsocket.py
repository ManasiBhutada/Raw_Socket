#!/usr/bin/python
# Import all the necessary libraries
import sys
import socket
from struct import *
import os
import subprocess 
import random
import re
import string
import binascii
import time

#declare global variables
global source_ip, destination_ip, myport, filename, ethernet_final, cwnd
cwnd = 1
perm_flag = 0
time1 = 1
time2 = 2

# Create IPPROTO_TCP receive socket
try:
	s1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error:
	print "The socket has not been created. Please try again"
	sys.exit()

# Create ARP receive socket to receive ARP reply 
try:
	s2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
except socket.error:
	print "The socket has not been created. Please try again"
	sys.exit()

# Create Ethernet raw socket to send Ethernet queries
try:
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
except socket.error:
	print "The socket has not been created. Please try again"
	sys.exit()

# Bind the send socket with eth0 port chosen as default port
sock.bind(('eth0', 0))

#Choose a random source port
myport = random.randint(55002,64000)

# Extract source IP and MAC address
test = "ifconfig eth0 | grep 'inet addr'| cut -d: -f2 | cut -d' ' -f1"
sip = os.popen(test)
x = sip.read()
source_ip = x.split('\n')[0]
getip = os.popen('ifconfig |grep HWaddr')
y = getip.read()
smac =  y.split()[4]
s_mac1 = smac.replace(':', '')
s_mac2 = s_mac1.decode('hex')
xyz = os.popen('ip route')
mno = xyz.read()
targetipad = mno.split()[2]

# Declare broadcast MAC address for sending Ethernet query
df = '\xff\xff\xff\xff\xff\xff'

#Declare zero MAC address to send ARP request
targetmac = '\x00\x00\x00\x00\x00\x00'
sourceip = socket.inet_aton(source_ip)
targetip = socket.inet_aton(targetipad)

# Contruct ARP frame and pack the frame
eth_hdr1 = pack('!6s', df)
eth_hdr2= pack('!6s2s', s_mac2, '\x08\x06')
arp_hdr1 = pack('!2s2s', '\x00\x01', '\x08\x00')
arp_hdr2 = pack('!1s1s','\x06', '\x04')
arp_hdr3 = pack('2s', '\x00\x01')
arp_hdr4 = pack('!6s4s6s4s', s_mac2, sourceip, targetmac, targetip)

# Contruct total frame of Ethernet including ARP request inside the frame and send the packet over Ethenret socket
total_header = eth_hdr1 + eth_hdr2 + arp_hdr1 + arp_hdr2 + arp_hdr3 +arp_hdr4
sock.send(total_header)

# Receive the ARP reply over Etehrnet socket and extract the Destination MAC Address
arp_response =  s2.recvfrom(2048)
arp_response1 = arp_response[0]
ethernet_ex = arp_response1[0:14]
ethernet_extracted = unpack('!6s6s2s', ethernet_ex)
ether = binascii.hexlify(ethernet_extracted[1])
payload = arp_response1[14:]
payload1 = binascii.hexlify(payload)
arp_hdr = arp_response1[14:42]
arp_original = unpack('!2s2s1s1s2s6s4s6s4s', arp_hdr)
op_code_recv = binascii.hexlify(arp_original[4])
dest_mac_addr = binascii.hexlify(arp_original[5])
dest_mac_addr1 = arp_original[5].encode('hex')
dest_mac_addr2 = dest_mac_addr1.decode('hex')

# Insert the destination MAC address inside the Ethernet header and pack the header
ethernet_final = pack('!6s6s2s', dest_mac_addr2, s_mac2, '\x08\x00')

# Get URL and create file name based on the entered URL
di = sys.argv[1]

# URL error handling
url_obtained = di
if ('http://' in url_obtained):
	dip = di.replace('http://', '')
else:
	print 'enter correct URL format for example# http://david.choffnes.com/classes/cs4700sp16/project4.php'
	sys.exit()
file_name = di.rsplit('/', 1)
filename = file_name[1]
if file_name[1] == '' or '.com' in file_name[1] or '.edu' in file_name[1]:
	filename = 'index.html'
dip = di.replace('http://','')
dip1 = dip.split('/')[0]

# Extract client and host data for constructing the GET request
if '.com' in di:
	dip2 = dip.split('.com')[1]
elif '.edu' in di:
	dip2 = dip.split('.edu')[1]
if dip2 == '':
	dip2 = '/'

try:
	destination_ip = socket.gethostbyname(dip1)
except socket.error:
	print 'problem in resolving the Hostname'
	sys.exit()
mypacket = ''

# Initialize the sequence number and acknowledgement number to 0
ack_next = 0 
seq_next = 0

# Create HTTP GET request
data1 = 'GET '+ dip2 +' '+ 'HTTP/1.0\r'
data2 = 'Host: '+ dip1 +'\r'
data3 = '\r\n'
userdata = "\n".join([data1, data2, data3])

# Create IP header
def myipheader():
	global source_ip, destination_ip
	ip_header_length = 5
	version = 4
	type_of_service = 0
	total_length = 20 + 20 
	ip_identification = 46352  							# Id of this packet
	flags = 0
	fragment_offset = 0
	ttl = 255									# Time to live of the packet is set at 255
	protocol = socket.IPPROTO_TCP
	check = 0									# checksum initially 0
	version_ip_header_length = (version << 4) + ip_header_length			# Fix the IP version to 4
	saddr = socket.inet_aton(source_ip)						# Convert IP string to suitable format(number)
	daddr = socket.inet_aton(destination_ip) 
	ip_header = pack('!BBHHHBBH4s4s' , version_ip_header_length, type_of_service, total_length, ip_identification, fragment_offset, ttl, protocol, check, saddr, daddr)
	ipchecksum = initchecksum(ip_header)
	ip_header = pack('!BBHHHBBH4s4s' , version_ip_header_length, type_of_service, total_length, ip_identification, fragment_offset, ttl, protocol, ipchecksum, saddr, daddr)
	return ip_header

# Create IP header for sending HTTP request
def myipheaderdata():
        global source_ip, destination_ip, userdata
        ip_header_length = 5
        version = 4
        type_of_service = 0
        total_length = 20 + 20 + len(userdata)						# Include the length of payload 
        ip_identification = 54321  							# Initialize the IP id of current packet
        flags = 0
        fragment_offset = 0
        ttl = 255
        protocol = socket.IPPROTO_TCP
        check = 0
        version_ip_header_length = (version << 4) + ip_header_length
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(destination_ip)
        ip_header = pack('!BBHHHBBH4s4s' , version_ip_header_length, type_of_service, total_length, ip_identification, fragment_offset, ttl, protocol, check, saddr, daddr)
        ipchecksum = initchecksum(ip_header)
        ip_header = pack('!BBHHHBBH4s4s' , version_ip_header_length, type_of_service, total_length, ip_identification, fragment_offset, ttl, protocol, ipchecksum, saddr, daddr)
        return ip_header

#create tcp header
def mytcpheader():
	global source_ip, destination_ip, myport
	source_port = myport   						
	dest_port = 80   							# Destination port for HTTP requests
	seq = 1001								# Allocate a sequence number to the first packet
	ack_seq = 0
	doff = 5    								# Header length in 4 byte words		
	fin = 0
	syn = 1									# Initial packet sent is SYN from client to server
	rst = 0
	psh = 0
	ack = 0
	urg = 0
	rwnd = 65535    							# Set the maximum allowed rwnd size
	check = 0								# Initial checksum is set to 0
	urgent_pointer = 0
	tcp_hlen_reserved = (doff << 4) + 0
	tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
	tcp_header1 = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, check, urgent_pointer)
	placeholder = 0 
	proto = socket.IPPROTO_TCP
	tcplength = len(tcp_header1)
	saddr = socket.inet_aton(source_ip)
	daddr = socket.inet_aton(destination_ip)

	# Create pesuedoheader to calculate TCP checksum and insert the checksum inside the TCP header. Finally, pack the TCP header
	psuedoheader1 = pack('!4s4sBBH', saddr, daddr, placeholder, proto, tcplength)
	psuedoheader = psuedoheader1 + tcp_header1
	correctchecksum = initchecksum(psuedoheader)
	tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, correctchecksum, urgent_pointer)
	return tcp_header

# Calculate the checksum of the packet using 1's compliment method
def initchecksum(mydata):
	sum = 0
	pad = ''
	if len(mydata) % 2 == 1:
		pad = '\x00'
		mydata = mydata + pad
	for i in range(0, len(mydata), 2):
		val = (ord(mydata[i]) << 8) + (ord(mydata[i+1]))
		sum = sum + val
	sum = (sum>>16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	sum = ~sum & 0xffff
	return sum
		
# Create a TCP header to send the acknowledgement to the server after receiving SYN ACK. After acknowledgement, sent the GET request
def mytcpheader2(ack_next, seq_next, dip2):
        global source_ip, destination_ip, myport, userdata
        source_port = myport   							
        dest_port = 80   						
        seq = seq_next
        ack_seq = ack_next + 1
        doff = 5    								
        fin = 0
        syn = 0
        rst = 0
        psh = 0
        ack = 1									# Set the acknowledgement bit high
        urg = 0
        rwnd = 65535    					
        check = 0								# Initial checksum
        urgent_pointer = 0
        tcp_hlen_reserved = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        tcp_header1 = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, check, urgent_pointer)
        placeholder = 0
        proto = socket.IPPROTO_TCP
        tcplength1 = len(tcp_header1)
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(destination_ip)

	# Create pesuedoheader to calculate the checksum of the TCP packet
        psuedoheader1 = pack('!4s4sBBH', saddr, daddr, placeholder, proto, tcplength1)
	psuedoheader = psuedoheader1 + tcp_header1
        correctchecksum = initchecksum(psuedoheader)			# Send the entire pseudoheader to the checksum function
        tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, correctchecksum, urgent_pointer)
        return tcp_header

# The below function will receive the data from the server and we will extract the sequence and acknowledgement number
def tcp3wayhandshake(dip2):
        global s1, sock, destination_ip, seq_next, ack_next, userdata, ethernet_final
        tcpheader = mytcpheader()
        ipheader = myipheader()
        mypacket = ethernet_final + ipheader + tcpheader
        sock.send(mypacket)
        rcvdpack = s1.recvfrom(64000)
        rcvdpack = rcvdpack[0]
        rcvd_ip_header = rcvdpack[:20]					# Unpack the IP header, a 20 byte field from the received data
        iph = unpack('!BBHHHBBH4s4s', rcvd_ip_header)
        tcplen = iph[2]
        tcp_rcvd = rcvdpack[20:tcplen]					# Unpack the TCP header
	tcph = unpack('!HHLLBBHHHHH', tcp_rcvd)
        ack_next = tcph[2]
	seq_next = tcph[3]
	ipheader2 = myipheader()
	tcpheader2 = mytcpheader2(ack_next, seq_next, dip2)
	mypacket2 = ethernet_final + ipheader2 + tcpheader2		# Build new packet containing acknowledgement with the new TCP										 header and IP header and send it via raw socket 
	sock.send(mypacket2)
	return ack_next, seq_next

# Create a new TCP header for sending data from client to the server containing HTTP GET requests
def httpGETtcpHeader(ack_next, seq_next, dip2):
	global source_ip, destination_ip, myport, userdata
        source_port = myport   						
        dest_port = 80   							
        seq = seq_next
        ack_seq = ack_next + 1
        doff = 5    							
        fin = 0
	syn = 0
        rst = 0
        psh = 1
        ack = 1
        urg = 0
        rwnd = 65535    					
        check = 0
        urgent_pointer = 0
        tcp_hlen_reserved = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        tcp_header1 = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, check, urgent_pointer)
        placeholder = 0
        proto = socket.IPPROTO_TCP
        tcplength1 = len(tcp_header1)
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(destination_ip)
	tcplength = tcplength1 + len(userdata)
        psuedoheader1 = pack('!4s4sBBH', saddr, daddr, placeholder, proto, tcplength)
	psuedoheader = psuedoheader1 + tcp_header1 + userdata
        correctchecksum = initchecksum(psuedoheader)
        tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, correctchecksum, urgent_pointer)
	updated_seq = seq + len(userdata)
        return (tcp_header, updated_seq)

# Send acknowledgement for the data we are receiving from the server
def sendackdata(seq_next,ack_recv):
	global source_ip, destination_ip, myport, userdata
        source_port = myport   					
        dest_port = 80   							
        seq = seq_next
        ack_seq = ack_recv
        doff = 5    							
        fin = 0
        syn = 0
        rst = 0
        psh = 0
        ack = 1
        urg = 0
        rwnd = 65535   
        check = 0
        urgent_pointer = 0
        tcp_hlen_reserved = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        tcp_header1 = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, check, urgent_pointer)
        placeholder = 0
        proto = socket.IPPROTO_TCP
        tcplength1 = len(tcp_header1)
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(destination_ip)
        tcplength = tcplength1 + len(userdata)
        psuedoheader1 = pack('!4s4sBBH', saddr, daddr, placeholder, proto, tcplength1)
        psuedoheader = psuedoheader1 + tcp_header1
        correctchecksum = initchecksum(psuedoheader)
        tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, correctchecksum, urgent_pointer)
        return tcp_header

# Create an output file to read and write the data received from the server
def writefile(data1):
	global filename
	with open(filename,"a") as f:
		f.write(data1)
		f.close()
		return

# Create a FIN segment to send to the server after receiving all the data from the server 
def fincreate(seq_no, ack_no):
	global source_ip, destination_ip, myport, userdata
        source_port = myport   
        dest_port = 80   
        seq = ack_no
        ack_seq = seq_no + 1
        doff = 5    
        fin = 1							# Set the fin flag high to indicate fin segment
        syn = 0
        rst = 0
        psh = 0
        ack = 1
        urg = 0
        rwnd = 65535
        check = 0
        urgent_pointer = 0
        tcp_hlen_reserved = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        tcp_header1 = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, check, urgent_pointer)
        placeholder = 0
        proto = socket.IPPROTO_TCP
        tcplength1 = len(tcp_header1)
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(destination_ip)
        psuedoheader1 = pack('!4s4sBBH', saddr, daddr, placeholder, proto, tcplength1)
        psuedoheader = psuedoheader1 + tcp_header1
        correctchecksum = initchecksum(psuedoheader)
        tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, tcp_hlen_reserved, tcp_flags, rwnd, correctchecksum, urgent_pointer)
        tcp_fin = tcp_header
	handlefin(tcp_fin)

# Send FIN+ACK to server indicating graceful closure of connection	
def handlefin(tcp_fin):
	global s1, sock, destination_ip, ethernet_final
	ipheader5 = myipheader()
	tcpheader5 = tcp_fin
	finack = ethernet_final + ipheader5 + tcpheader5
	sock.send(finack)
	rcvack = s1.recvfrom(6400)
	sys.exit()

# Remove HTTP Header information from the data received and send the data to writefile function
def http_header(data):
	global perm_flag
	if ('\r\n\r\n' in data and perm_flag == 0):
# Perform HTTP Error Handling for codes apart from 200		
		if ("HTTP/1.1 200 OK" in data or "HTTP/1.0 200 OK" in data):
			index = data.find('\r\n\r\n') + 4
			data2 = data[index:]
			perm_flag = 1
			writefile(data2)
		else:
			error_data = data.split('\r\n')[0]
			print "HTTP error has occured. The error response is : ", error_data
			sys.exit()
	elif ('\r\n\r\n' in data and perm_flag == 1):	
		index = data.find('\r\n\r\n') + 4 
		data3 = data[:index]
		writefile(data3)
		perm_flag = 2
	else:
		writefile(data)
	return

# Send the GET request to the server and received the response 
def sendGET(ack_next, seq_next, dip2):
	global s1, cwnd, sock, destination_ip, userdata, filename, ethernet_final
	tcpheader3, updated_seq = httpGETtcpHeader(ack_next, seq_next, dip2)
	ipheader3 = myipheaderdata()
	cwnd = userdata
	myGET = ethernet_final + ipheader3 + tcpheader3 + cwnd
	sock.send(myGET)
	rcvdack = s1.recvfrom(640000)
	rcvd_ack = rcvdack[0]
	rcvd_ack_ip_header = rcvd_ack[:20]
	tcp_ack_received = rcvd_ack[20:40]
	tcp_header_ack = unpack('!HHLLBBHHH', tcp_ack_received)
	expected_seq = tcp_header_ack[2] + len(rcvd_ack[40:])
	while True:							# We will keep receiving data from server using the receiver socket and process it
		rcvdhttp = s1.recvfrom(6400000)
		datarecv = rcvdhttp[0]
		# If there is some data in the tcp segment process the segment accordingly
		if len(datarecv) > 40:
			rcvdipheader = datarecv[:20]
			iphdr = unpack('!BBHHHBBH4s4s', rcvdipheader)
			tcplength = iphdr[2]
			tcpreceived = datarecv[20:40]
			tcp_header = unpack('!HHLLBBHHH', tcpreceived)
			seq_recv = tcp_header[2]
			if seq_recv == expected_seq:
				data_recv = datarecv[40:]
				http_header(data_recv)
				data_length = len(data_recv)
				seq_recv = tcp_header[2]
				expected_seq = data_length + seq_recv 
				tcpackheader = sendackdata(updated_seq, expected_seq)
				ipheader4 = myipheader()
				ip_ack = ethernet_final + ipheader4 + tcpackheader
				sock.send(ip_ack)
			else:
				continue
		# If tcp segment contains only headers(keep alives, ACKs)
		elif len(datarecv) == 40:
			rcvdipheader = datarecv[:20]
			iphdr = unpack('!BBHHHBBH4s4s', rcvdipheader)
			tcpreceived = datarecv[20:40]
			tcp_header = unpack('!HHLLBBHHH', tcpreceived)
			flag_check = tcp_header[5]
			seq_no = tcp_header[2]
			ack_no = tcp_header[3]

			# If TCP_FLAGs value is 25 gracefully close the connection
			if flag_check == 25:
				fincreate(seq_no, ack_no)
			else:
				continue
		else:
			continue
	
# Initiate TCP 3-way handshake
tcp3wayhandshake(dip2)

# Send GET request
sendGET(ack_next, seq_next, dip2)
