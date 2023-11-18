
import ipaddress
from scapy.layers.inet import IP, TCP
from scapy.all import *
ip = input("Enter an IP address : ")

try:
    target = ipaddress.ip_address(ip)
    print("The IP address is valid!", target)
except Exception as e:
    print("the ip address is invalid ! please inter a valid address !", e)

start_port = int(input("enter an start port :"))
end_port = int(input("enter an end port :"))

if start_port >= end_port:
    print("Invalid port range. Start port must be less than end port.")
    exit()
print("Scanning" + str(target)+"for open ports!")

if start_port == end_port:
    end_port+=1

for x in range(start_port,end_port):
    packet = IP(dst=ip)/TCP(dport = x,flags='S')
    try:
        response = sr1(packet, timeout=1 , verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 'SA':
            print("Port "+str(x)+" is open !")
            sr(IP(dst=ip) / TCP(dport=int(response.sport), flags='R'), timeout=0.5, verbose=0)
        else:
            print("port " +str(x)+" is closed :")

    except Exception as e:
        print("error in targetting port" + str(x), e)


print("Scan is done !")