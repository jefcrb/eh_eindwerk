from tabulate import tabulate
from scapy.layers import dot11
from scapy.all import sniff
import subprocess
import time
import re



class WifiScanner():
    def __init__(self, **kwargs):
        args = kwargs.get('args')

        self.logger = kwargs.get('logger')
        self.monitor = args.monitor

        if args.all or args.monitor:
            self.get_wifis()
        
        if args.beacon:
            self.sniff_beacons()

    
    def get_wifis(self):
        devices = subprocess.check_output(['netsh','wlan','show','network', 'mode=bssid']) 
        devices = devices.decode('ascii')

        wifis = normalize_wifis_data(devices, self.logger, self.monitor)
        
        if self.monitor:
            pass
        else:
            self.logger.log(wifis, 'wifi-recon')

        return devices
    

    def sniff_beacons(self):
        sniff(prn=handle_packet, iface="Wi-Fi", store=False)
    

def normalize_wifis_data(devices, logger, monitor = False):
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

    if not monitor:
        return wifis
    else:
        while True:
            monitor_out = []
            for wifi in wifis:
                monitor_out.append({"name": wifi["name"], "sign": max([x["sign"] for x in wifi["bssids"]])})
                logger.log(monitor_out, 'wifi-monitor')
            
            time.sleep(1)


def handle_packet(packet):
    if packet.haslayer(dot11.Dot11Beacon):
        bssid = packet[dot11.Dot11].addr2
        ssid = packet[dot11.Dot11Elt].info.decode()
        rssi = packet.dBm_AntSignal
        print(f"Netwerk gedetecteerd: SSID: [cyan]{ssid}[/cyan], BSSID: [cyan]{bssid}[/cyan], RSSI: [cyan]{rssi}[/cyan]")