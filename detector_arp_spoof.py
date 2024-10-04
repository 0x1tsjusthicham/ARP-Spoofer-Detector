import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface = interface, store=False, prn=process_packet)

def get_MAC(ip):
    arp_request = scapy.ARP(pdst = ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
    return answered[0][1].hwsrc

def process_packet(packet):
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            real_mac = get_MAC(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print("[-] Under Attack!")
            print(packet.show())
    except IndexError:
        pass

sniff("eth0")