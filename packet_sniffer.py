from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP

# Affiche les interfaces disponibles
print("Interfaces réseau disponibles :")
print(get_if_list())

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\n[+] New Packet: {ip_src} -> {ip_dst}")
        
        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"    Protocol: TCP | Source Port: {tcp_sport} -> Destination Port: {tcp_dport}")
        
        elif packet.haslayer(UDP):
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"    Protocol: UDP | Source Port: {udp_sport} -> Destination Port: {udp_dport}")
        
        else:
            print(f"    Protocol: {protocol} (Other)")

# Utiliser conf.L3socket pour contourner le besoin de Npcap à la couche 2
conf.L3socket = conf.L3socket
print("Starting packet capture...")
sniff(iface="Wi-Fi", prn=packet_callback, store=False)
