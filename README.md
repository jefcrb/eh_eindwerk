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

