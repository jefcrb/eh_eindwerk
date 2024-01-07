from rich._emoji_codes import EMOJI
from rich.markup import escape
from rich.console import Console
from datetime import datetime
from rich import print
import math
import os

del EMOJI["cd"]

console = Console(highlighter=None)

class Logger():
    def __init__(self):
        if not os.path.exists('logs'):
            os.mkdir('logs')

        #console.print("Hello, [bold magenta]World[/bold magenta]!", ":vampire:")

    
    def log(self, data, type):
        if type == 'input':
            self.log_input(data)

        if type == 'hosts_ip:mac':
            self.log_hosts(data)

        if type == 'hosts_ip:mac:open_ports':
            self.log_hosts_verbose(data)

        if type == 'port_found':
            self.log_port_found(data)

        if type == 'host_down':
            self.log_host_down(data)

        if type == 'ports_to-scan':
            self.log_ports_to_scan(data)

        if type == 'start-command':
            self.log_start_command(data)

        if type == 'wifi-recon':
            self.log_wifi_recon(data)

        if type == 'wifi-monitor':
            self.log_wifi_monitor(data)


    def log_hosts(self, data):
        console.print(f"{len(data)} online hosts gevonden:")
        for host in data:
            console.print(f"- [bold blue]%-15s %-15s[/bold blue]" % (host['ip'], host['mac']))

        with open('logs/output.txt', 'a') as f:
            f.write(f"{len(data)} online hosts gevonden:\n")
            for host in data:
                f.write(f"%-15s %-15s\n" % (host['ip'], host['mac']))


    def log_input(self, data):
        with open('logs/output.txt', 'w') as f:
            f.write(f"Input: {data[0].target}\n")
            f.write(f"Ports to scan: {data[0].ports}\n")
            f.write(f"Start time: {datetime.now()}\n\n")

    
    def log_hosts_verbose(self, data):
        if 'open_ports' not in data[0]:
            return
        
        with open('logs/output.txt', 'a') as f:
            f.write(f"\n\nResultaten port scan:\n")
            for host in data:
                if len(host.get('open_ports', [])) > 0:
                    f.write(f"\nHost %-15s MAC %-15s\n" % (host['ip'], host['mac']))
                    for port in host.get('open_ports', []):
                        f.write(f"Vond open port {port}\n")


    def log_port_found(self, data):
        console.print(f"[bold blue]Open poort![/bold blue] Poort [cyan]{data[0]}[/cyan] is open op {data[1]}")

    
    def log_host_down(self, data):
        console.print(f"[bold red]Host {data} is offline of onbereikbaar.[/bold red]")
        
        with open('logs/output.txt', 'a') as f:
            f.write(f"\n\nHost {data} is offline of onbereikbaar.\n")


    def log_ports_to_scan(self, data):
        console.print(f"\n\nPoorten te scannen:", end=' ')
        ports = []
        for port in data:
            if port[0] == port[1]:
                ports.append(f"{port[0]}")
            else:
                ports.append(f"{port[0]}-{port[1]}")

        console.print(', '.join(ports), end='\n')

    
    def log_start_command(self, data):
        console.print(f"[bold]Tool gestart om {datetime.now()} in [white]{data.command}[/white] modus[/bold]\n")

    
    def log_wifi_recon(self, data):
        width = min(os.get_terminal_size().columns, 80)
        print(width)
        for row in data:
            spacing1 = max(len(row["name"]), 4) - 2
            spacing2 = max(len(row["type"]), 4) - 2
            spacing3 = max(max(len(row["auth"]), 4) - 10, 1)

            # header
            console.print(f'\n\n[dark_grey]{"-" * width}[/dark_grey]\n> [cyan]{row["name"]}[/cyan]')
            console.print(f'\nTYPE{" " * spacing2}AUTHENTICATIE{" " * spacing3}ENCRYPTIE')
            console.print(f'[blue]{row["type"]}  {row["auth"]}   {" " * (7 * bool(row["auth"] == "Open"))}{row["encr"]}[/blue]')
            for i, bssid in enumerate(row["bssids"]):
                console.print(f'\n- BSSID {i + 1}: {bssid["name"]}\t\tSignaalsterkte: {loading_bar(bssid["sign"])} ({bssid["sign"]})')

        
    def log_wifi_monitor(self, data):
        os.system('cls' if os.name == 'nt' else 'clear')
        output = ""
        for row in data:
            output += '{:.<30} {:.<15}'.format(row["name"], loading_bar(row["sign"]))
            output += f'\t[cyan]({row["sign"]})[/cyan]\n'
        console.print(output)


def loading_bar(pct):
    pct = int(pct.replace('%', ''))
    color = ''

    if pct < 30:
        color = 'bright_red'
    elif pct < 60:
        color = 'yellow'
    elif pct < 80:
        color = 'green'
    else:
        color = 'bright_green'

    length = 6
    bar = f'[{color}]'

    for i in range(int(pct / length)):
        bar += '#'
    for i in range(int((100 - pct) / length)):
        bar += '-'

    bar += f'[/{color}]'
    return bar