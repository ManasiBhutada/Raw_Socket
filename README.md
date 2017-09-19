# Raw_Socket
Goal is to write a program called rawhttpget that takes one command line parameter (a URL), downloads the associated web page or file, and saves it to the current directory. 
The command line syntax for this program is: ./rawhttpget [URL]
Created two raw sockets: one for receiving packets and one for sending packets. The receive socket must be of type SOCK_STREAM/IPPROTO_IP; the send socket must be of type SOCK_STREAM/IPPROTO_RAW. 
Created AF_PACKET raw socket instead of a SOCK_RAW/IPPROTO_RAW socket. An AF_PACKET raw socket bypasses the operating systems layer-2 stack as well at layers 3 and 4 (TCP/IP).
