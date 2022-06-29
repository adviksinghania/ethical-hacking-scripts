#!/usr/bin/env python3
# find_user.py
"""Searching for usernames across websites using Python3."""

import time
import requests
import argparse
import sys
import concurrent.futures

# Global variable to store the count of sites searched
SEARCHED = 0


def set_arguments(p):
    # Setting options for command line arguments
    p.add_argument('-u', '--username', dest='username', help='Target username')


def get_arguments(p):
    # Parsing the command line arguments and returning the arguments
    arguments = p.parse_args()
    if arguments.username is None:
        p.error(f'Please specify a target. Type {sys.argv[0]} -h for more info.')
    else:
        return arguments


def fetch_url(url: str) -> None:
    # Making HTTP GET request to check the user exists or not.
    global SEARCHED
    res = requests.get(url, timeout=5)
    print(f'Searched {SEARCHED}/{len(user_urls)}', end='\r')
    SEARCHED += 1
    if res.status_code in RESPONSE_CODES:
        valid_users.append(url)


if __name__ == '__main__':
    # Successful HTTP Response status codes
    RESPONSE_CODES = {200, 201, 202, 203, 206, 300, 301, 302, 303, 307, 308}

    parser = argparse.ArgumentParser()  # ArgumentParser() class to parse the command line arguments
    set_arguments(parser)
    # Getting the command line arguments
    args = get_arguments(parser)

    # Reading file to make a tuple of website URLS
    with open('sites.txt', 'r') as file:
        URLS = tuple(map(lambda x: x.strip(), file.readlines()))

    # Adding username at the end of each URL
    user_urls = [i + args.username for i in URLS]
    valid_users = []
    start = time.time()

    # Multithreading to make asynchronous requests to the URLS
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(user_urls)) as tpe:
        for url in user_urls:
            tpe.submit(fetch_url, url)

    stop = time.time()
    if len(valid_users) != 0:
        for name in filter(None, valid_users):
            print(name)

        print(f'\nFOUND: {len(valid_users)} possible usernames, Time Taken: {round(stop - start, 5)}s.')
    else:
        print("No valid usernames found.")
