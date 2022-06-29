#!/usr/bin/env python3
# dns_lookup.py
"""Searching DNS records using DNSPython"""

import sys
import dns.resolver


def main(domain):
    records = ('A', 'AAAA', 'NS', 'SOA', 'MX', 'TXT')
    for record in records:
        try:
            responses = dns.resolver.resolve(domain, record)
            print('\nRecord response: ', record)
            print('-----------------------------------')
            for response in responses:
                print(response)

            print('-----------------------------------')
        except Exception:
            pass
            #print('Cannot resolve query for record',record)
            #print('Error for obtaining record information:', e)


if __name__ == '__main__':
    try:
        main(input('Enter hostname: '))
    except KeyboardInterrupt:
        sys.exit()
