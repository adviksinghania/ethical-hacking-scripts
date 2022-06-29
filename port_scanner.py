#!/usr/bin/env python3
# port_scanner.py
"""Port Scanner using Python3"""

import argparse
import sys
import time
import socket
from datetime import datetime


def set_arguments(p):
    # Setting options for command line arguments
    p.add_argument('-i', '--ip', dest='ip', help='IPv4 address to scan the ports')


def get_arguments(p):
    # Parsing the command line arguments and returning the arguments
    arguments = p.parse_args()
    if arguments.ip is None:
        p.error(f'[!] Please specify an IP address. Type {sys.argv[0]} -h for more info.')
    else:
        return arguments


def scan_port(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)

    # returns an error indicator
    result = s.connect_ex((target, port))
    s.close()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()  # ArgumentParser() class to parse the command line arguments
    set_arguments(parser)
    opt = get_arguments(parser)
    print(f'[!] Port Scanning started at {str(datetime.now())} for target IP {opt.ip}.')
    start = time.time()
    try:
        for port in range(1, 65535):
            if scan_port(opt.ip, port) == 0:
                print(f'[+] Port {port} is open.')

    except KeyboardInterrupt:
        print('\n[-] Exitting Program...')
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
    except socket.error:
        print("\n[!] Server not responding.")
    finally:
        sys.exit(0)
