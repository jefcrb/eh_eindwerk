# Ethical Hacking eindwerk
Deze repo dient voor mijn python framework voor mijn EH eindwerk

Dit framework is ontwikkeld om heel wat verschillende functionaliteiten te hebben en maakt ook gebruik van inwendige technologieën om betrouwbaarheid en efficientie te verhogen

## Functionaliteit
Help output:
```
$ python main.py -h

usage: main.py [-h] [-t TIMEOUT] [-v] {network,wifi} ...

CLI voor verschillende zaken omtrent netwerken en wifi

positional arguments:
  {network,wifi}        sub-command help
    network             Scan een netwerk of host
    wifi                Scan wifi netwerken

options:
  -h, --help            show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout voor verbindingen in seconden
  -v, --verbose         Verbose output

Gemaakt door Jef Cruysberghs (https://github.com/jefcrb)
```

Er wordt gebruikgemaakt van twee subcommando's: `network` en `wifi`

#### network
Deze module focust zich op het scannen van gegeven netwerken, zoeken naar het bestaan van hosts en open poorten.
```
$ python main.py network -h

usage: main.py network [-h] -a TARGET [-p PORTS]

options:
  -h, --help            show this help message and exit
  -a TARGET, --target TARGET
                        Netwerk range of host om te scannen
  -p PORTS, --ports PORTS
                        Target ports om te scannen (bv. 1-100 1-20,50-1000)
```

Om de `network` module te gebruiken moet je altijd een target meegeven (met `-a`), dit kan een enkel ip adres zijn, een url (deze wordt automatisch omgezet naar een ip adres) of een ip range (in CIDR formaat, bv. 192.168.1.0/24). Het script zal dan ARP requests gebruiken om de status van de gegeven host(s) te krijgen. Optioneel kan je ook poorten om te scannen meegeven (`-p`), je kunt enkele ports meegeven of ranges, of combinaties, bv. `-p 22`, `-p 50-1000`, `-p 22,50-1000`

Voor het scannen van de poorten wordt er gebruik gemaakt van stealth scans en multithreading. (Stealth scan houdt in dat er geen volledige connectie met de poort wordt opgesteld maar dat we slechts een SYN packet sturen, als deze wordt beantwoord met SYN-ACK dan is de poort open)

```py
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
```

Voorbeelden:
```
python main.py network -a 192.168.1.118 -p 1-1000
```
Output:

![image](https://github.com/jefcrb/eh_eindwerk/assets/83902653/3cfc44e4-17bc-42df-a579-b6d734831c38)



```
python main.py network -a 192.168.1.0/24 -p 22
```
Output:

![image](https://github.com/jefcrb/eh_eindwerk/assets/83902653/8a490df0-678f-4f98-afc2-efe6a34c71c0)

(Logging met behulp van de rich library :) )

#### wifi
De wifi module is gericht op het sniffen van wifi packets rondom
```
usage: main.py wifi [-h] [-a] [-b] [-m]

options:
  -h, --help     show this help message and exit
  -a, --all      Scan alle wifi netwerken in de omgeving
  -b, --beacon   Sniff beacon frames in de omgeving
  -m, --monitor  Monitor de signaalsterkte van verschillende wifi netwerken
```

De `-a` flag geeft een lijst met gedetecteerde wifinetwerken met extra informatie zoals authenticatietechnologie, encryptie, signaalsterkte, BSSID's, ...
Voorbeeld:
```
python main.py wifi -a
```
Output:

![image](https://github.com/jefcrb/eh_eindwerk/assets/83902653/c1cde2c2-1bad-44a4-a263-56ce87af16fc)

De `-b` flag zal beacon frames afkomstig van access points sniffen en decoderen en in de terminal printen
De `-m` flag zal constant wifinetwerken rondom scannen en hun signaalsterkte tonen, wanneer je rondbeweegt met je apparaat zul je zien dat deze sterker of zwakker worden
