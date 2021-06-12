#!/usr/bin/env python3

import argparse 
import dns.resolver
import netaddr 
import json

resolver = dns.resolver

def parse_args():
    parser = argparse.ArgumentParser(description='grabs the domain or file from the user.')
    parser.add_argument(
        '-f',
        '--file',
        dest = 'file')
    parser.add_argument(
        '-d',
        '--domain',
        dest = 'domain')
   
    return parser.parse_args()
    

def read_file(filename: str) -> list:
    with open(filename, "r") as f:
        domains = f.readlines()
    return [d.strip() for d in domains]


def query(domain: str, record: str):
    try:
        return resolver.resolve(domain,record)
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None


def query_spf(domain: str) -> str:
    q = query(domain,'TXT')
    if not q:
        return ""
    for txtd in q.rrset:
        if 'v=spf1' == txtd.strings[0].decode('utf-8').split()[0]:
            return txtd.strings[0].decode('utf-8')

    return ""


def query_mx(domain: str) -> dict:
    q = query(domain,'mx')
    if not q:
        return {}
    return {mx.exchange: {
            "preference": mx.preference, 
            "records": query_a(mx.exchange), 
        } for mx in q.rrset}


def query_a(domain: str) -> list:
    q = query(domain,'a')
    if not q:
        return []
    return [netaddr.IPAddress(record.address) for record in q.rrset]


def parse_mech_a(s: str):
    pass

def parse_mech_mx(s: str):
    pass

def parse_mech_ptr(s: str):
    pass

def parse_mech_include(s: str):
    pass


def parse_spf(spf: str):
    """
    this function will parse out the spf records to each mechinism 
    """
    fields = spf.split()
    for f in fields:
        i = f.split(':')
        if len(i) == 1:
            if i[0][0] in ["-", '~', '?']:
                continue
            elif i[0][0] == '+':
                #explicit mechanism pass
                pass
            else:
                #this implicit mechnism pass
                pass    
    return fields
   
def process_domain(domain:str )-> dict:
    result = {}
    result["spf"] = query_spf(domain)

    return result
    
def main():
    args = parse_args()
    if args.file:
        domains = read_file(args.file)
    elif args.domain:
        domains = [args.domain]
    else:
        raise SystemExit("please supply -f or -d")

    results = {d: process_domain(d) for d in domains}
    print(json.dumps(results, indent=4, sort_keys = True))


if __name__ == "__main__":
    main()

