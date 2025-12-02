from scapy.all import *
import scapy.all as scapy
from collections import Counter

# Função para analisar um arquivo PCAP
def analisar_pcap(arquivo):

    print(f"\n========== ANALISANDO {arquivo} ==========\n")

    packets = rdpcap(arquivo)

    # Contadores
    src_ips = Counter()
    dst_ips = Counter()

    src_ports = Counter()
    dst_ports = Counter()

    packet_tcp = Counter()
    packet_udp = Counter()

    # Iterando pelos pacotes
    for i, packet in enumerate(packets):

        if packet.haslayer("IP"):
            src_ips[packet['IP'].src] += 1
            dst_ips[packet['IP'].dst] += 1

        if packet.haslayer("TCP"):
            packet_tcp["TCP"] += 1
            src_ports[packet['TCP'].sport] += 1
            dst_ports[packet['TCP'].dport] += 1

        if packet.haslayer("UDP"):
            packet_udp["UDP"] += 1
            src_ports[packet['UDP'].sport] += 1
            dst_ports[packet['UDP'].dport] += 1

        print(f"Pacote {i+1}: {packet.summary()}")


    # Resultados
    print("\nIPs de origem:")
    for ip, count in src_ips.items():
        print(f"{ip}: {count} pacotes")

    print("\nIPs de destino:")
    for ip, count in dst_ips.items():
        print(f"{ip}: {count} pacotes")

    print("\nPortas de origem:")
    for port, count in src_ports.items():
        print(f"{port}: {count} pacotes")

    print("\nPortas de destino:")
    for port, count in dst_ports.items():
        print(f"{port}: {count} pacotes")

    print("\nPacotes UDP:")
    for key, count in packet_udp.items():
        print(f"{key}: {count}")

    print("\nPacotes TCP:")
    for key, count in packet_tcp.items():
        print(f"{key}: {count}")


# Chamando a função para os dois arquivos pedidos
analisar_pcap("captura3-1.pcap")
analisar_pcap("captura3-2.pcap")