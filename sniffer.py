from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Determine the protocol name
        proto_name = "Unknown"
        if proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        elif proto == 1:
            proto_name = "ICMP"

        print(f"\n[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {proto_name}")

        # Extract and display payload if it exists
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload)
            if payload:
                # Print readable characters, replace unreadable ones with dots
                readable_payload = ''.join([chr(b) if 32 <= b < 127 else '.' for b in payload])
                print(f"    Raw Payload (First 60 chars): {readable_payload[:60]}")

def main():
    print("*" * 50)
    print(" * Starting Basic Network Sniffer... *")
    print(" * Press Ctrl+C to stop. *")
    print("*" * 50)
    
    # sniff() loops indefinitely, capturing packets and passing them to packet_callback
    # count=0 means sniff infinitely. You can set count=10 to capture just 10 packets.
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()

