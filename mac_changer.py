#!/usr/bin/env python3
# mac_changer.py
"""MAC Address Changer using Python3 (Linux)"""

import subprocess
import argparse
import re
import sys


def set_arguments(p):
    # Setting options for command line arguments
    p.add_argument('-m', '--mac', dest='new_mac', help='Value for new MAC Address.')
    p.add_argument('-i', '--interface', dest='interface', help='Network Interface to change the MAC Address.')


def get_arguments(p):
    # Parsing the command line arguments and returning the arguments
    arguments = p.parse_args()
    if arguments.interface is None:
        p.error(f'Please specify an interface. Type {sys.argv[0]} -h for more info.')
    elif arguments.new_mac is None:
        p.error(f'Please specify a MAC Address. Type {sys.argv[0]} -h for more info.')
    else:
        return arguments


def change_mac(interface, mac):
    # Changing the mac using ifconfig hw ether command
    print('[+] Changing MAC Address on', interface, 'to', mac)
    subprocess.call(['sudo', 'ifconfig', interface, 'down'])
    subprocess.call(['sudo', 'ifconfig', interface, 'hw', 'ether', mac])
    subprocess.call(['sudo', 'ifconfig', interface, 'up'])


def get_mac(interface, p):
    # Checking if the interface can provide a mac address and is not localhost
    try:
        ifconfig_res = subprocess.check_output(['ifconfig', interface])
        current_mac = re.search(p, str(ifconfig_res))
        return current_mac.group(0)

    except AttributeError:
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()  # ArgumentParser() class to parse the command line arguments
    set_arguments(parser)
    opt = get_arguments(parser)
    # Regular Expression to check the MAC Address input
    regex = '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})'
    pattern = re.compile(regex)
    if not re.match(pattern, opt.new_mac):
        print('[-] Invalid MAC Address input.')
        sys.exit(0)

    current_mac = get_mac(opt.interface, pattern)
    # Checking if MAC is available on given interface
    if current_mac is None:
        print('[-] Cannot read MAC Address on interface', opt.interface)
        sys.exit(0)
    else:
        print('[+] Current MAC:', current_mac)

    try:
        change_mac(opt.interface, opt.new_mac)
    except PermissionError:
        print('Please run the script as root to change the MAC Address.')
        sys.exit(0)

    current_mac = get_mac(opt.interface, pattern)
    # Checking if MAC Address change was successful
    if opt.new_mac == current_mac:
        print('[+] New MAC:', current_mac)
    else:
        print('[-] Error occured while changing the MAC Address on interface', opt.interface)
