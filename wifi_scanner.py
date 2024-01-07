from tabulate import tabulate
from scapy.layers import dot11
from scapy.all import sniff
import subprocess
import re



class WifiScanner():
    def __init__(self, **kwargs):
        args = kwargs.get('args')

        self.logger = kwargs.get('logger')

        if args.all:
            self.get_wifis()
        
        if args.beacon:
            self.sniff_beacons()

    
    def get_wifis(self):
        devices = subprocess.check_output(['netsh','wlan','show','network', 'mode=bssid']) 
        devices = devices.decode('ascii')

        self.logger.log(normalize_wifis_data(devices), 'wifi-recon')
        

        return devices
    

    def sniff_beacons(self):
        sniff(prn=handle_packet, iface="Wi-Fi", store=False)
    

def normalize_wifis_data(devices):
    wifis = []
    output = re.split(r'SSID \d+ : ', devices)[1:]

    for row in output:
        info = row.split('BSSID ')
        bssids = info[1:]
        info = info[0].split(': ')

        name = info[0].split('\n')[0].strip()
        if name == '': name = 'HIDDEN NETWORK'
        type = info[1].split('\r\n')[0].strip()
        auth = info[2].split('\r\n')[0].strip()
        encr = info[3].split('\r\n')[0].strip()

        wifi = {
            "name": name,
            "type": type,
            "auth": auth,
            "encr": encr,
            "bssids": []
        }

        for bssid in bssids:
            bssid = bssid.split(': ')

            name = bssid[1].split('\r\n')[0].strip()
            sign = bssid[2].split('\r\n')[0].strip()
            type = bssid[3].split('\r\n')[0].strip()
            band = bssid[4].split('\r\n')[0].strip()
            chan = bssid[5].split('\r\n')[0].strip()

            wifi["bssids"].append({
                "name": name,
                "sign": sign,
                "type": type,
                "band": band,
                "chan": chan
            })
        
        wifis.append(wifi)

    return wifis


def handle_packet(packet):
    if packet.haslayer(dot11.Dot11Beacon):
        # Extract the MAC address of the network
        bssid = packet[dot11.Dot11].addr2
        # Get the name of it
        ssid = packet[dot11.Dot11Elt].info.decode()
        # Get the RSSI (signal strength)
        rssi = packet.dBm_AntSignal
        print(f"Network Detected: SSID: {ssid}, BSSID: {bssid}, RSSI: {rssi}")