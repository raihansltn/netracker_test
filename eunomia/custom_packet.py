from scapy.all import Ether, IP, TCP, sendp
import time

iface = "wlan0" #your interface, change it

#This to simulate client and server ip
num_packets = 10 #number of packets sent, change this based on your preference
client_ip = "192.168.1.4" #your ip, change it
server_ip = "192.168.1.4" #the same
server_port = 1234 #customizable
delay = 1 #customizable

for i in range(num_packets):
    client_port = 1234 + i #customizable, make sure doesn't conflict between the "fake" server and client

    syn_pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags='S')
    sendp(syn_pkt, iface=iface, verbose=True)
    print(f"[{i+1}] SYN sent from {client_ip}:{client_port} to {server_ip}:{server_port}")
    time.sleep(0.2)

    #this for syn-ack
    synack_pkt = Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags='SA')
    sendp(synack_pkt, iface=iface, verbose=True)
    print(f"[{i+1}] SYN-ACK sent from {server_ip}:{server_port} to {client_ip}:{client_port}")
    time.sleep(delay)
