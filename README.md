
# ARP Spoof Detection

This script detects ARP spoofing attacks by sniffing network traffic and comparing the real MAC address of devices with the MAC address in incoming ARP responses. If a mismatch is detected, it raises an alert.

## Prerequisites

- Python 3.x
- Scapy library

You can install the necessary dependencies by running:

```
pip install scapy
```

## How It Works

- The script sniffs ARP packets on a specified network interface.
- It extracts the real MAC address for a given IP by sending an ARP request.
- For each incoming ARP response, it compares the MAC address in the response with the real MAC address.
- If a mismatch is found, it prints an alert (`[-] Under Attack!`), indicating a potential ARP spoofing attack.

## Code Breakdown

- `get_MAC(ip)`: Sends an ARP request to the given IP address and returns the real MAC address.
- `sniff(interface)`: Sniffs network traffic on the specified interface and processes each packet.
- `process_packet(packet)`: Checks if the packet is an ARP response and compares the MAC address in the response to the real MAC address of the device.

## Usage

To run the ARP spoof detection script, use the following command:

```
sudo python3 arp_spoof_detector.py
```

Replace `"eth0"` with the network interface you want to monitor.

## Example Output

When the script detects an ARP spoofing attempt, it will print:

```
[-] Under Attack!
```

Additionally, it will print the details of the ARP packet.

## Disclaimer

This tool is intended for educational purposes only. Monitoring network traffic and detecting attacks without permission may violate legal and ethical guidelines. Always ensure you have proper authorization before using this tool on any network.
