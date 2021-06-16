#!/usr/bin/env python3

import argparse 
import dns.resolver, dns.reversename
import netaddr 
import json
from typing import Tuple

resolver = dns.resolver

def extract_qualifier(f: str) -> Tuple[str,str]: 
    if f.startswith('-'):
        return "Fail", f[1:]
    elif f.startswith('~'):
        return "SoftFail", f[1:]
    elif f.startswith("?"):
       return  "Neutral", f[1:]
    elif f.startswith("+"):
        return "Pass", f[1:]
    else:
        return "Pass", f

def process_mech_all(m: dict, domain: str) -> dict:
    return {"value": "all"}

def process_mech_ip4(m: dict, domain: str) -> dict:
    try:
        net = netaddr.IPNetwork(m["value"])
    except netaddr.core.AddrFormatError:
        return {"error": f"Malformed Network Address: {m['value']}"}
    return {"network_size": net.size, "network": str(net)}

def process_mech_ip6(m: dict, domain: str) -> dict:
    try:
        net = netaddr.IPNetwork(m["value"])
    except netaddr.core.AddrFormatError:
        return {"error": f"Malformed Network Address: {m['value']}"}
    return {"network_size": net.size,"network": str(net)}

def process_mech_a(m: dict, domain: str) -> dict:
    value = m["value"] or domain
    prefix = m["prefix"] or ""
    return {"records": query_a(value)}

def process_mech_mx(m: dict, domain: str) -> dict:
    value = m["value"] or domain
    prefix = m["prefix"] or ""
    return query_mx(value)

def process_mech_ptr(m: dict, domain: str) -> dict:
    return m

def process_mech_exists(m: dict, domain: str) -> dict:
    return m

def process_mech_include(m: dict, domain: str)-> dict:
    return process_domain(m["value"])


def process_mech_exp(m: dict, domain: str) -> dict:
    return m

def process_mech_redirect(m: dict, domain: str) -> dict:
    return process_domain(m["value"])

def process_unknown_mechanism(m: dict, domain: str) -> dict:
    return {"error": f"Unknown mechanism: {m['mechanism']}"}

mechanism_map = {
     "all": process_mech_all, 
     "ip4": process_mech_ip4, 
     "ip6": process_mech_ip6,
     "a": process_mech_a,
     "mx": process_mech_mx,
     "ptr": process_mech_ptr,
     "exists": process_mech_exists,
     "include": process_mech_include,
     "exp": process_mech_exp, 
     "redirect": process_mech_redirect
}

def parse_args():
    parser = argparse.ArgumentParser(description='grabs the domain or file from the user.')#grabs the arguements from the user
    parser.add_argument(
        '-f',#adds f as an arguement
        '--file',#adds file as an arguement
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
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,dns.resolver.NXDOMAIN):
        return None


def query_spf(domain: str) -> str:
    q = query(domain,'TXT')
    if not q:
        return ""
    for txtd in q.rrset:
        if txtd.strings[0].decode('utf-8').split()[0] == 'v=spf1':
            return txtd.strings[0].decode('utf-8').lower()

    return ""


def query_mx(domain: str) -> dict:
    q = query(domain,'mx')
    if not q:
        return {}
    return {str(mx.exchange): {
            "preference": mx.preference, 
            "records": query_a(mx.exchange), 
        } for mx in q.rrset}


def query_a(domain: str) -> list:
    q = query(domain,'a')
    if not q:
        return []
    return [str(netaddr.IPAddress(record.address)) for record in q.rrset]


def query_ptr(ipaddr: str) -> str:
    n = dns.reversename.from_address(ipaddr)
    q = query(n, 'ptr')
    if not q:
        return ""
    return q.rrset[0].target.to_unicode()


def parse_spf(spf: str):
    """
    this function will parse out the spf records to each mechinism 
    """
    fields = spf.split()
    results = []
    for f in fields[1:]:
        r = {"original": f}
        if '=' in f:
            r["mechanism"] = f.split('=')[0]
            r["value"] = f.split('=')[1]
            continue
        r["qualifier"], f = extract_qualifier(f)
        r["mechanism"] = f.split('/')[0].split(':')[0]
        r["prefix"] = f.split('/')[1] if '/' in f else ""
        r["value"] = f.split(':', 1)[1] if ':' in f else ""
        results.append(r)
    return results

def summarize_networks(d: dict) -> dict:
    """
    Take a dict containing networks as input
    Determine if network is ipv4 or ipv6
    Determine total count of addresses for the whole dict e.g. 
        networks = []
        networks.append(IPNetwork('127.0.0.1/8'))
        size = sum([n.size for n in networks])
    Determine total unique count of addresses for the whole dict e.g. 
        unique_size = IPSet(networks).size
    """
    pass

def process_domain(domain:str )-> dict:
    result = {"spf": query_spf(domain)}
    if not result["spf"]:
        return
    parsed_fields = parse_spf(result["spf"])
    for f in parsed_fields:
        result[str(f["original"])] = {"qualifier": f["qualifier"]} 
        handler = mechanism_map.get(f["mechanism"], process_unknown_mechanism)
        r = handler(f, domain)
        result["summary"] = summarize_networks(r)
        if isinstance(r, dict):
            for k,v in r.items():
                result[f["original"]][str(k)] = v
        

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
    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()

