#!/usr/bin/env python3
# Network Scanner using Python3 and ScaPy

import sys
import argparse
try:
    import scapy.all as sp
    from mac_vendor_lookup import MacLookup
except ModuleNotFoundError:
    print('Please install the dependencies: ScaPy and mac-vendor-lookup')
    print('Run: sudo python3 -m pip install mac-vendor-lookup scapy[complete]')
    sys.exit(0)


def set_arguments(p):
    # Setting options for command line arguments
    p.add_argument('-t', '--target', dest='target_ip', help='Target IP Address / Range in IPv4')


def get_arguments(p):
    # Parsing the command line arguments and returning the arguments
    arguments = p.parse_args()
    if arguments.target_ip is None:
        p.error(f'Please specify a target. Type {sys.argv[0]} -h for more info.')
    else:
        return arguments


# def scan(ip):
#     sp.arping(ip)  # Broadcasting a predefined ARP request

def scan(ip):
    # Creating an ARP request packet
    arp_req = sp.ARP(pdst=ip)
    # Creating a broadcast channel packet
    broadcast = sp.Ether(dst='ff:ff:ff:ff:ff:ff')
    # Linking the ARP request packet to the broadcast
    arp_req_broad = broadcast / arp_req
    # Sending the combined custom packet with a timeout of 1 second and accepting the response packets
    # (returns a list of two objects: answered and unaswered packets)
    answered, _ = sp.srp(arp_req_broad, timeout=1, verbose=False)
    # Extracting the IP and MAC Address from the answered packets
    clients = [{'ip': response[1].psrc, 'mac': response[1].hwsrc} for response in answered]
    return clients


def get_mac_vendor(mac):
    # Returns the MAC Vendor
    return MacLookup().lookup(mac)


def display(clients):
    # Printing the clients IP and MAC as output
    head = '\nIP\t\t\tMAC Address\t\t\tMAC Vendor'
    head += '\n' + '-' * 70
    print(head)
    for client in clients:
        print(client.get('ip'), end='\t\t')
        print(client.get('mac'), end='\t\t')
        print(get_mac_vendor(client.get('mac')))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()  # ArgumentParser() class to parse the command line arguments
    set_arguments(parser)
    # Getting the command line arguments
    args = get_arguments(parser)
    try:
        output = scan(args.target_ip)
    except PermissionError:
        print('Please run the script as root.')
        sys.exit(0)

    display(output)
