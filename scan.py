#!/usr/bin/env python
import subprocess
import dns.resolver
import dns.zone
import dns.query
import tldextract
import requests
import argparse
import random
import socket
import string
import signal
import time
import json
import sys
import os

from contextlib import contextmanager

GITHUB_MAX_SIZE = 99614720

ROOT_NAMESERVER_LIST = [
    "e.root-servers.net.",
    "h.root-servers.net.",
    "l.root-servers.net.",
    "i.root-servers.net.",
    "a.root-servers.net.",
    "d.root-servers.net.",
    "c.root-servers.net.",
    "b.root-servers.net.",
    "j.root-servers.net.",
    "k.root-servers.net.",
    "g.root-servers.net.",
    "m.root-servers.net.",
    "f.root-servers.net.",
]

GLOBAL_DNS_CACHE = {
    "A": {},
    "NS": {},
    "CNAME": {},
    "SOA": {},
    "WKS": {},
    "PTR": {},
    "MX": {},
    "TXT": {},
    "RP": {},
    "AFSDB": {},
    "SRV": {},
    "A6": {},
}

RECORD_MAP = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    11: 'WKS',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    17: 'RP',
    18: 'AFSDB',
    33: 'SRV',
    38: 'A6',
}

# http://stackoverflow.com/a/287944/1195812
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class DNSTool:
    def __init__( self, verbose = True ):
        self.verbose = verbose
        self.domain_cache = {}

    def get_base_domain( self, hostname ):
        ''' Little extra parsing to accurately return a TLD string '''
        url = "http://" + hostname.lower()
        tld = tldextract.extract( url )
        if tld.suffix == '':
            return tld.domain
        else:
            return "%s.%s" % ( tld.domain, tld.suffix )

    def statusmsg( self, msg, mtype = 'status' ):
        '''
        Status messages
        '''
        if self.verbose:
            if mtype == 'status':
                print('[ STATUS ] ' + msg)
            elif mtype == 'warning':
                print(bcolors.WARNING + '[ WARNING ] ' + msg + bcolors.ENDC)
            elif mtype == 'error':
                print(bcolors.FAIL + '[ ERROR ] ' + msg + bcolors.ENDC)
            elif mtype == 'success':
                print(bcolors.OKGREEN + '[ SUCCESS ] ' + msg + bcolors.ENDC)

    def typenum_to_name( self, num ):
        '''
        Turn DNS type number into it's corresponding DNS record name
        e.g. 5 => CNAME, 1 => A
        '''
        if num in RECORD_MAP:
            return RECORD_MAP[ num ]
        return "UNK"

    @contextmanager
    def time_limit( self, seconds ):
        '''
        Timeout handler to hack around a bug in dnspython with AXFR not obeying it's timeouts 
        '''
        def signal_handler(signum, frame):
            raise Exception("TIMEOUT")
        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)

    def get_nameserver_list( self, domain ):
        self.statusmsg(f'Grabbing nameserver list for {domain}')

        if domain in GLOBAL_DNS_CACHE['NS']:
            return GLOBAL_DNS_CACHE['NS'][domain]

        '''
        Query the list of authoritative nameservers for a domain

        It is important to query all of these as it only takes one misconfigured server to give away the zone.
        '''
        try:
            answers = dns.resolver.resolve(domain, 'NS')
        except dns.resolver.NXDOMAIN:
            self.statusmsg( "NXDOMAIN - domain name doesn't exist", 'error' )
            return []
        except dns.resolver.NoNameservers:
            self.statusmsg( "No nameservers returned!", 'error' )
            return []
        except dns.exception.Timeout:
            self.statusmsg( "Nameserver request timed out (wat)", 'error' )
            return []
        except dns.resolver.NoAnswer:
            self.statusmsg( "No answer", 'error' )
            return []
        except dns.name.EmptyLabel:
            return []
        nameservers = []
        for rdata in answers:
            nameservers.append( str( rdata ) )

        nameservers.sort()

        GLOBAL_DNS_CACHE['NS'][domain] = nameservers

        return nameservers

    def parse_tld(self, domain):
        '''
        Parse DNS CNAME external pointer to get the base domain (stolen from moloch's source code, sorry buddy)
        '''
        tld = tldextract.extract(f'http://{domain}') # Hack to get parse_tld to work with us
        if tld.suffix == '':
            return tld.domain
        else:
            return f'{tld.domain}.{tld.suffix}'

    def get_root_tlds( self ):
        self.statusmsg( "Grabbing IANA's list of TLDs...")
        response = requests.get( "https://data.iana.org/TLD/tlds-alpha-by-domain.txt", )
        lines = response.text.split( "\n" )
        return [line.strip().lower() for line in lines if line and "#" not in line]

def get_json_from_file(filename):
    with open(filename, 'r') as fd:
        ret = json.load(fd)

    return ret

def write_to_json( filename, json_serializable_dict ):
    with open(filename, 'w') as fd:
        json.dump(json_serializable_dict, fd)

def get_root_tld_dict( from_cache=True ):
    if from_cache:
        return get_json_from_file('cache/tld_dict.json')

    dnstool = DNSTool()
    tlds = dnstool.get_root_tlds()
    root_map = {}
    for tld in tlds:
        root_map[ tld ] = dnstool.get_nameserver_list(
            tld + ".",
        )
    write_to_json(
        'cache/tld_dict.json',
        root_map
    )
    return root_map

def pprint( input_dict ):
    '''
    Prints dicts in a JSON pretty sort of way
    '''
    print(
        json.dumps(
            input_dict, sort_keys=True, indent=4, separators=(',', ': ')
        )
    )

def write_dig_output( hostname, nameserver, dig_output, is_gzipped ):
    if hostname == ".":
        hostname = "root"

    hostname = hostname.rstrip('.')

    dir_path = f'archives/{hostname}/'

    if not os.path.exists( dir_path ):
        os.makedirs( dir_path )

    filename = f'{dir_path}{nameserver}zone'

    with open(filename, 'w') as fd:
        fd.write(dig_output)

    if is_gzipped:
        with subprocess.Popen(['gzip', '-f', filename], stdout=subprocess.PIPE) as proc:
            output = proc.stdout.read()

def get_dig_axfr_output( hostname, nameserver ):
    with subprocess.Popen([
        'dig', 'AXFR', hostname, f'@{nameserver}', '+noall', '+answer', '+noidnout', '+onesoa', '+time=15'
    ], stdout=subprocess.PIPE) as proc:
        output = proc.stdout.read()

    return output.decode()

def zone_transfer_succeeded( zone_data ):
    if not zone_data:
        return False

    for s in [
        "Transfer failed.",
        "failed: connection refused.",
        "communications error",
        "failed: network unreachable.",
        "failed: host unreachable.",
        "connection timed out; no servers could be reached",
    ]:
        if s in zone_data:
            return False

    return True

def main():
    dnstool = DNSTool()

    zone_transfer_enabled_list = []

    for root_ns in ROOT_NAMESERVER_LIST:
        zone_data = get_dig_axfr_output(
            ".",
            root_ns,
        )

        if zone_transfer_succeeded( zone_data ):
            zone_transfer_enabled_list.append({
                "nameserver": root_ns,
                "hostname": "."
            })

            do_gzip = len(zone_data) > GITHUB_MAX_SIZE # Max github file size.
            write_dig_output(
                ".",
                root_ns,
                zone_data,
                do_gzip,
            )

    tlds = dnstool.get_root_tlds()

    for tld in tlds:
        full_tld = tld + "."

        nameservers = dnstool.get_nameserver_list(
            full_tld
        )

        for nameserver in nameservers:
            zone_data = get_dig_axfr_output(
                full_tld,
                nameserver,
            )

            if zone_transfer_succeeded( zone_data ):
                zone_transfer_enabled_list.append({
                    "nameserver": nameserver,
                    "hostname": tld,
                })

                do_gzip = len( zone_data ) > GITHUB_MAX_SIZE # Max github file size.
                write_dig_output(
                    full_tld,
                    nameserver,
                    zone_data,
                    do_gzip,
                )

    # Create markdown file of zone-transfer enabled nameservers
    with open('transferable_zones.md', 'w') as fd:
        fd.write('# List of TLDs & Roots With Zone Transfers Currently Enabled\n\n')
        for zone_status in zone_transfer_enabled_list:
            zone_name = zone_status['hostname']
            zone_dir_name = 'root' if zone_name == '.' else zone_name
            nameserver = zone_status['nameserver']

            fd.write(f'* `{zone_name}` via `{nameserver}`: [Click here to view zone data.](archives/{zone_dir_name}/{nameserver}zone)\n')


if __name__ == '__main__':
    main()
