from ipaddress import IPv4Address, ip_address, AddressValueError
from rich.markdown import Markdown
from urllib.parse import urlparse
from rich.console import Console
import argparse
import socket


from network_scanner import NetworkScanner
from wifi_scanner import WifiScanner
from logger import Logger

options = ['wifi', 'network']


class Main():
    def __init__(self):
        self.logger = Logger()
        self.setup_args()
        self.logger.log(self.args, 'start-command')

        if self.args.command == 'network':
            self.networker = NetworkScanner(args = self.args, logger = self.logger)
        elif self.args.command == 'wifi':
            self.wifier = WifiScanner(args = self.args, logger = self.logger)

    def setup_args(self):
        parser = argparse.ArgumentParser(description='CLI voor verschillende zaken omtrent netwerken en wifi', formatter_class=RichHelpFormatter, prog='main.py', epilog='Gemaakt door Jef Cruysberghs (https://github.com/jefcrb)')

        parser.add_argument('-t', '--timeout', help='Timeout voor verbindingen in seconden', default='5')
        parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')

        sub_parsers = parser.add_subparsers(help='sub-command help')

        parser_network = sub_parsers.add_parser('network', help='Scan een netwerk of host')
        parser_network.add_argument('-a', '--target', help='Netwerk range of host om te scannen', required=True)
        parser_network.add_argument('-p', '--ports', help='Target ports om te scannen (bv. 1-100 1-20,50-1000)', default='')
        parser_network.set_defaults(command='network')

        parser_wifi = sub_parsers.add_parser('wifi', help='Scan wifi netwerken')
        parser_wifi.add_argument('-a', '--all', help='Scan alle wifi\'s in de omgeving', action='store_true')
        parser_wifi.add_argument('-b', '--beacon', help='Sniff beacon frames in de omgeving', action='store_true')
        parser_wifi.set_defaults(command='wifi')
        
        self.args = parser.parse_args()


class RichHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog)
        self.console = Console()

    def _print_message(self, message, file=None):
        if message:
            self.console.print(Markdown(message))

    def format_help(self):
        help_str = super().format_help()
        return help_str
    


if __name__ == '__main__':
    Main()