#!/usr/bin/env python3
# threaded_port_scanner.py
"""Threaded Port Scanner using Python3"""

import argparse
import sys
import socket
import time
import concurrent.futures
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
    if result == 0:
        print(f'[+] Port {port} is open.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()  # ArgumentParser() class to parse the command line arguments
    set_arguments(parser)
    opt = get_arguments(parser)
    print(f'[!] Port Scanning started at {str(datetime.now())} for target IP {opt.ip}.')
    start = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as tpe:
            for port in range(1, 65535):
                tpe.submit(scan_port, opt.ip, port)

        stop = time.time()
        print(f'Scan done in {round(stop - start, 5)}s.')

    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
    except socket.error:
        print("\n[!] Server not responding.")
    finally:
        sys.exit(0)
