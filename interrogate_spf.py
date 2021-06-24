#!/usr/bin/env python3

import argparse 
import dns.resolver, dns.reversename
import netaddr 
import json
from typing import Tuple

resolver = dns.resolver

def extract_qualifier(f: str) -> Tuple[str,str]: 
    """
    takes in the a domain for an spf record and finds  and sets its qualifer by looking at the first character of the string and comparing it with
    the qualifiers and removes the qualifier out of the string
    """
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
    """sets the value to all"""
    return {"value": "all"}

def process_mech_ip4(m: dict, domain: str) -> dict:
    """ process's an ip4 address taking in a dictionary containing the address and returns the network size and the address

    """
    try:
        net = netaddr.IPNetwork(m["value"]) ###^###
    except netaddr.core.AddrFormatError:
        return {"error": f"Malformed Network Address: {m['value']}"}
    return {"network_size": net.size, "network": str(net)}

def process_mech_ip6(m: dict, domain: str) -> dict:
    """
        process's an ip6 adress taking in a dictionary containing the address and returns the network size and address in string form
    """
    try:
        net = netaddr.IPNetwork(m["value"])
    except netaddr.core.AddrFormatError:
        return {"error": f"Malformed Network Address: {m['value']}"}
    return {"network_size": net.size,"network": str(net)}

def process_mech_a(m: dict, domain: str) -> dict:
    """
        this function takes in a dictionary containing an a record,  then returns the query results of the record.
    """
    value = m["value"] or domain
    prefix = m["prefix"] or ""## 
    return {"records": query_a(value)}

def process_mech_mx(m: dict, domain: str) -> dict:
    """
        this function takes in a dictionary containing a record, and returns the results of query_mx of value.
    """
    value = m["value"] or domain
    prefix = m["prefix"] or ""
    return query_mx(value)

def process_mech_ptr(m: dict, domain: str) -> dict:
    return m

def process_mech_exists(m: dict, domain: str) -> dict:
    return m

def process_mech_include(m: dict, domain: str)-> dict:
    """
        this method handles the include mechanism,  it takes in a dictionary containing the include and returns the results of process_domain on the address
    
    """
    return process_domain(m["value"])


def process_mech_exp(m: dict, domain: str) -> dict:
    return m

def process_mech_redirect(m: dict, domain: str) -> dict:
    return process_domain(m["value"])

def process_unknown_mechanism(m: dict, domain: str) -> dict:
    """
        this method is called if we get an unknown mechanism and returns an error
    """
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
    """ 
    this function sets up the file or domain arguements so we can tell what the user is giving us 
    """
    parser = argparse.ArgumentParser(description='grabs the domain or file from the user.')#grabs the arguements from the user
    parser.add_argument(
        '-f',#adds f as an arguement
        '--file',#adds file as an arguement
        dest = 'file')
    parser.add_argument(
        '-d',
        '--domain',
        dest = 'domain')
    parser.add_argument(
        '-o',
        '--output',
        dest = 'output'
    )
   
    return parser.parse_args()
    

def read_file(filename: str) -> list:
    """deals with a file, reading it and returning a list of domains"""
    with open(filename, "r") as f:
        domains = f.readlines()
    return [d.strip() for d in domains]


def query(domain: str, record: str):
    """calls resolver.resolve to actually query the domain"""
    try:
        return resolver.resolve(domain,record)
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,dns.resolver.NXDOMAIN):
        return None


def query_spf(domain: str) -> str:
    """
    takes in a domain as a string and trys to find a spf with a query, if it finds one it returns the spf record if not returns an empty string.
    """
    q = query(domain,'TXT')
    if not q:
        return ""
    for txtd in q.rrset:
        if txtd.strings[0].decode('utf-8').split()[0] == 'v=spf1':
            return txtd.strings[0].decode('utf-8').lower()

    return ""


def query_mx(domain: str) -> dict:
    """
        this function handles the mx mechanism, it takes in a string containg the mx record and returns a dictionary containing the results of query_a on the mx records
    """
    q = query(domain,'mx')
    if not q:
        return {}
    return {str(mx.exchange): {
            "preference": mx.preference, 
            "records": query_a(mx.exchange), 
        } for mx in q.rrset}


def query_a(domain: str) -> list:
    """
        this function queries the a record, it takes in a string containing the a record and returns a list of address 
    """
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
    """
    this method takes in a domain as a string, grabs the strings spf record if it has one, sets its qualifier has it parse to the correct mechanism functions then it has some
    magic i dont understand.
    """
    result = {"spf": query_spf(domain)}
    if not result["spf"]:
        return
    parsed_fields = parse_spf(result["spf"])
    for f in parsed_fields:
        result[str(f["original"])] = {"qualifier": f["qualifier"]} 
        handler = mechanism_map.get(f["mechanism"], process_unknown_mechanism)#does handler have a .size?
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
    if args.output:
        out_file = open("output.json", 'w')
        with open(args.output, 'w') as out_file:
             json.dump(results,out_file, indent = 4  )
        out_file.close()
    else:
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()

