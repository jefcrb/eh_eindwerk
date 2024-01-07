from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network, AddressValueError
from scapy.all import IP, ICMP, Ether, ARP, TCP, sr1, srp, sr, conf
from threading import Thread
import socket


class NetworkScanner():
    def __init__(self, **kwargs):
        args = kwargs.get('args')

        self.verbose = args.verbose
        self.logger = kwargs.get('logger')
        self.timeout = int(args.timeout)
        self.url = args.target
        self.RANGE = False
        self.get_ip(self.url)

        self.logger.log([args], 'input')

        self.ports = self.ports_parser(args.ports)
        if self.RANGE:
            self.get_hosts()

            if len(self.ports) > 0:
                self.logger.log(self.ports, 'ports_to-scan')

            for host in [host['ip'] for host in self.hosts]:
                self.stealth_scan_host(host)

            self.logger.log(self.hosts, 'hosts_ip:mac:open_ports')

        else:
            self.get_hosts()
            
            if len(self.ports) > 0:
                self.logger.log(self.ports, 'ports_to-scan')

            if self.is_host_up():
                self.stealth_scan_host(self.ip)
                self.logger.log(self.hosts, 'hosts_ip:mac:open_ports')
            else:
                self.logger.log([self.url], 'host_down')
            


    def get_ip(self, url, port = 443):
        try:
            try:
                ip_address(url)
            except:
                ip_network(url)
                self.RANGE = True
            self.ip = url
        except ValueError as e:
            self.ip = socket.getaddrinfo(url, port)[0][4][0]
            print(f"Ip adres van {url} is {self.ip}")
        except:
            raise


    def get_hosts(self):
        # creëer ethernet frame (L2) met broadcast mac en arp request
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.ip))

        # srp() voor het gebruiken van layer 2 packets (ethernet)
        answered, unanswered = srp(arp_request, timeout=self.timeout, verbose=self.verbose)

        # itereer over gevonden online hosts en zet ze in een lijst
        active_hosts = []
        for sent, received in answered:
            active_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})


        self.logger.log(active_hosts, 'hosts_ip:mac')
        self.hosts = active_hosts
        return active_hosts
    

    def is_host_up(self):
        icmp = IP(dst=self.ip)/ICMP()
        resp = sr1(icmp, timeout=self.timeout, verbose=self.verbose)

        return resp is not None
    

    def stealth_scan_port(self, target_ip, port):
        conf.verb = 0
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="S")  # S flag voor SYN
        response = sr1(ip_packet/tcp_packet, timeout=self.timeout)

        if response is not None:
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK = open poort
                    self.logger.log([port, target_ip], 'port_found')
                    # RST om connectie te sluiten
                    rst_pkt = IP(dst=target_ip)/TCP(dport=port, flags='R')
                    sr1(rst_pkt, timeout=self.timeout)
                    return True
        return False

    def stealth_scan_host(self, target_ip):
        if len(self.ports) == 0:
            return

        open_ports = []
        threads = []

        # Implementatie van multithreading om port scans sneller te maken (creëer thread voor elke poort)
        for port_range in self.ports:
            for port in range(int(port_range[0]), int(port_range[1]) + 1):
                t = Thread(target=lambda p=port: open_ports.append(p) if self.stealth_scan_port(target_ip, p) else None)
                threads.append(t)
                t.start()

        for thread in threads:
            thread.join()

        for row in self.hosts:
            if row['ip'] == target_ip:
                row['open_ports'] = open_ports

        return open_ports


    def ports_parser(self, ports):
        if ports == '':
            return []
        
        ports = ports.split(',')
        port_range = []
        for port in ports:
            if '-' in port:
                range = port.split('-')
                port_range.append([range[0], range[1]])
            else:
                port_range.append([port, port])
        
        return port_range