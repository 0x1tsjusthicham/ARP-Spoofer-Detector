import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface = interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        print(packet.show())

sniff("eth0")