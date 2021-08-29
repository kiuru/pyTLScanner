#!/usr/bin/env python

import nmap
from pymongo import MongoClient
from pprint import pprint
import tldextract
import copy
import argparse
import re

client = MongoClient('mongodb://localhost:27017/')
db = client['jyu_tls_research']
collection = db['nmap']

def scan():
    hosts_collection = db['hosts']
    entries = hosts_collection.find({},{"address":1})
    hosts = [e.get("address") for e in entries]
    hosts = list(set(hosts)) # Remove duplicate ip addresses
    
    for counter, host in enumerate(hosts):
        print("counter: %s\thost: %s" % (counter,host))
        run_scan(host)

def run_scan(host):
    nm = nmap.PortScanner()
    #nm.scan(host, '80,443,8080', '-n')
    nm.scan(host, '80,443', '-n -Pn')
    for host in nm.all_hosts():
        host2 = copy.deepcopy(nm[host])
        for x in nm[host]["tcp"]:
            del host2["tcp"][x]
            host2["tcp"][str(x)] = nm[host]["tcp"][x]
        collection.insert_one(host2)
    
    # for host in nm.all_hosts():
    #     print('----------------------------------------------------')
    #     print('Host : %s (%s)' % (host, nm[host].hostname()))
    #     print('State : %s' % nm[host].state())
    #     for proto in nm[host].all_protocols():
    #         print('----------')
    #         print('Protocol : %s' % proto)

    #     lport = nm[host][proto].keys()
    #     for port in lport:
    #         print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

def empty_scan_results():
    collection.delete_many({})

def get_result_by_ip():
    entries = collection.find({ "$or": [ { "tcp.80.state":"open"}, {"tcp.443.state":"open"} ] }, {"addresses":1, "tcp.80.state":1, "tcp.443.state":1})
    for entry in entries:
        print('address: %s    \tport: 80\tstate : %s' % (entry["addresses"]["ipv4"], entry["tcp"]["80"]["state"]))
        print('address: %s    \tport: 443\tstate : %s' % (entry["addresses"]["ipv4"], entry["tcp"]["443"]["state"]))

def get_addresses_with_open_https_port():
    entries = collection.find({"tcp.443.state":"open"}, {"addresses":1, "tcp.443.state":1})
    addresses = []
    for entry in entries:
        addresses.append(entry["addresses"]["ipv4"])
    return addresses

def get_addresses_with_open_http_port():
    entries = collection.find({"tcp.80.state":"open"}, {"addresses":1, "tcp.80.state":1})
    addresses = []
    for entry in entries:
        addresses.append(entry["addresses"]["ipv4"])
    return addresses

def update_mongodb_host_list():
    """Update MongoDB's hosts collection from the current domains.txt and hosts.txt files.
    - Host's domain must be found in the domains.txt
    - Host must be assigned to some ip address
    """
    from models.host import Host
    
    collection = db['hosts']
    collection.delete_many({})
    domains = get_domains_from_anubis_file()
    host_list = get_hosts_from_anubis_file()
    for x in host_list:
        line = x.replace('\n','')
        split = line.split(': ')
        domain = split[0]
        address = split[1]
        host = Host(domain, address)
        if is_valid_domain(domains, domain):
            collection.insert_one(host.__dict__)

def get_domains_from_anubis_file():
    domains = open('data/domains.txt', 'r').readlines()
    domains = [i.replace('\n','') for i in domains] # Remove \n character from every end of line
    return domains
    # The same list can be find from MongoDB
    #companies = get_listed_companies_from_cache('helsinki', 0, 500, False)
    #domain_list = []
    #for company in companies:
    #    ext_domain = tldextract.extract(company.website)
    #    domain = ext_domain.domain + "." + ext_domain.suffix
    #    domain_list.append(domain)
    #domain_list = list(set(domain_list))
    #return domain_list

def get_hosts_from_anubis_file():
    file = open('data/anubis_result.txt', 'r').readlines()
    file = [i.replace('\n','') for i in file] # Remove \n character from every end of line
    host_list = []
    for line in file:
        if re.compile(r':').search(line) and not re.compile(r'Subdomain search took').search(line) and not re.compile(r'Working on target').search(line):
            split = line.split(': ')
            address = split[1]
            if address:
                host_list.append(line)
    
    return host_list

def is_valid_domain(domains, subdomain):
    """Check is subdomain's main domain (std + tld) in the domain list (domains.txt)

    Args:
        domains (list): List of valid domains
        subdomain (list): List of target subdomains

    Returns:
        Boolean: True/False
    """
    tldextract_domain = tldextract.extract(subdomain)
    if tldextract_domain.domain + "." + tldextract_domain.suffix in domains:
        return True
    else:
        return False

def get_result_by_host():
    collection = db['hosts']
    entries = collection.find({"address": {"$ne":""}})
    
    open_https_addresses = get_addresses_with_open_https_port()
    open_http_addresses = get_addresses_with_open_http_port()

    open = 0
    open_https = 0
    open_http = 0
    open_http_and_https = 0
    closed = 0
    for entry in entries:
        if entry["address"] in open_https_addresses and entry["address"] in open_http_addresses:
            print('OPEN   - address: %s  \tdomain: %s \t' % (entry["address"], entry["domain"]))
            open=open+1
            open_http_and_https=open_http_and_https+1
        if entry["address"] in open_https_addresses:
            print('OPEN   - address: %s  \tdomain: %s \t' % (entry["address"], entry["domain"]))
            open=open+1
            open_https=open_https+1
        if entry["address"] in open_http_addresses:
            print('OPEN   - address: %s  \tdomain: %s \t' % (entry["address"], entry["domain"]))
            open=open+1
            open_http=open_http+1
        else:
            print('CLOSED - address: %s  \tdomain: %s \t' % (entry["address"], entry["domain"]))
            closed=closed+1
    print('Result: Open: %s, Closed: %s' % (open, closed))
    print('Open http: %s, Open https: %s, Open both: %s' % (open_http, open_https, open_http_and_https))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='pyTLScanner - Nmap scanner')
    parser.add_argument('--scan', action="store_true", dest="scan", help="Scan hosts")
    parser.add_argument('--empty-results', action="store_true", dest="empty_results", help="Empty old scan results")
    parser.add_argument('--result-ip', action="store_true", dest="result_by_ip", help="Get results by ip address")
    parser.add_argument('--result-host', action="store_true", dest="result_by_host", help="Get results by host")
    parser.add_argument('--update-db', action="store_true", dest="update_db", help="Update MongoDB from domains.txt and hosts.txt")
    args = parser.parse_args()

    if args.update_db:
        update_mongodb_host_list()
    if args.empty_results:
        empty_scan_results()
    if args.scan:
        scan()
    if args.result_by_ip:
        get_result_by_ip()
    if args.result_by_host:
        get_result_by_host()
    
    client.close()

