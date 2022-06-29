#!/usr/bin/env python3
# arpspoof_detector.py
"""Detecting ARP Spoofing attack using Python3 and ScaPy"""

import sys
import argparse
try:
    import scapy.all as sp
except ModuleNotFoundError:
    print('Please install the dependencies: ScaPy')
    print('Run: sudo python3 -m pip install scapy[complete]')
    sys.exit(0)


def set_arguments(p):
    # Setting options for command line arguments
    p.add_argument('-i', '--interface', dest='interface', help='Network interface to run the detector. e.g.: eth0, wlan0')


def get_arguments(p):
    # Parsing the command line arguments and returning the arguments
    arguments = p.parse_args()
    if arguments.interface is None:
        p.error(f'Please specify a network interface. Type {sys.argv[0]} -h for more info.')
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


def process_pkt(packet):
    if packet.haslayer(sp.ARP) and packet[sp.ARP].op == 2:  # check if ARP layer has 'is-at' operation
        try:
            real_mac = scan_ip(packet[sp.ARP].psrc).get('mac')  # get the real mac of gateway
            response_mac = packet[sp.ARP].hwsrc  # get the mac from the ARP response layer
            if real_mac != response_mac:
                print('[!] Network under ARP Spoof Attack')

        except IndexError:
            pass


def sniff(interface):
    print(f'[+] Running detector on network interface {interface}...')
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
