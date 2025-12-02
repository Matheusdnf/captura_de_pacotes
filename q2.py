from scapy.all import *
import scapy.all as scapy
from collections import Counter

packets = rdpcap("captura2.pcap")

# inicializando os contadores

src_ips = Counter()
dst_ips = Counter()
packet_tcp= Counter()
packet_udp= Counter()


# iterando pelos pacotes e contabilidando informa¸c~oes de IP
for i, packet in enumerate(packets):
    if packet.haslayer("IP"):
        src_ips[packet['IP'].src] += 1
        dst_ips[packet['IP'].dst] += 1

    if packet.haslayer("TCP"):
        packet_tcp['TCP'] += 1
        
    if packet.haslayer("UDP"):  
        packet_udp['UDP'] += 1  

    print(f"Pacote {i+1}: {packet.summary()}")


# exibindo IPs de origem e destino e suas quantidades
print("IPs de origem:")
for ip, count in src_ips.items():
    print(f"{ip}: {count} pacotes")
print("IPs de destino:")
for ip, count in dst_ips.items():
    print(f"{ip}: {count} pacotes")

for ip, count in packet_udp.items():
    print(f"{ip}: {count} pacotes udp")

for ip, count in packet_tcp.items():
    print(f"{ip}: {count} pacotes tcp")