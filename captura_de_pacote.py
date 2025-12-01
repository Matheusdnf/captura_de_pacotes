from scapy.all import *
from collections import Counter

packets = rdpcap("captura1.pcap")

# inicializando os contadores

src_ips = Counter()
dst_ips = Counter()
# iterando pelos pacotes e contabilidando informa¸c~oes de IP
for packet in packets:
    if packet.haslayer("IP"):
        src_ips[packet['IP'].src] += 1
        dst_ips[packet['IP'].dst] += 1
# exibindo IPs de origem e destino e suas quantidades
print("IPs de origem:")
for ip, count in src_ips.items():
    print(f"{ip}: {count} pacotes")
    print("IPs de destino:")

for ip, count in dst_ips.items():
    print(f"{ip}: {count} pacotes")
