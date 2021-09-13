#!/usr/bin/env python

from pytlscanner import resultsFromCache
from pytlscanner import sslyze_scan
from get_listed_companies import get_listed_companies, get_listed_companies_from_cache
from pymongo import MongoClient
import time
from argumentparser import args
from pprint import pprint
from dataclasses import asdict
import json
import sslyze
from sslyze import ScanCommand
import requests
import copy

from datetime import datetime

client = MongoClient('mongodb://localhost:27017/')

def run_ssllabs_scan(market, debug, marketfrom, marketto):
    db = client['jyu_tls_research']
    collection = db['ssllabs_'+market]

    companies = get_listed_companies(market, marketfrom, marketto)
    for company in companies:
        result = resultsFromCache(company.website, debug)
        status = result["status"]
        pprint(result)
        # {'errors': [{'message': 'State: SHUT_DOWN Operation: class com.hazelcast.map.impl.operation.GetOperation'}]}
        # {"errors":[{"message":"Running at full capacity. Please try again later."}]}

        while status != 'READY':
            result = resultsFromCache(company.website, debug)
            status = result["status"]
            print(company.website, status)
            time.sleep(3)
        
        company.ssllabs_result = result
        #collection.insert_one(result)
        collection.insert_one(company.__dict__)

    client.close()

def run_sslyze_scan(market, debug, marketfrom, marketto):
    """Run SSLyze scanner against selected market's websites

    Args:
        market ([type]): Target market (e.g. helsinki)
        debug ([type]): Debug SSLyze
        marketfrom (int, optional): [description]. Defaults to 0.
        marketto (int, optional): [description]. Defaults to 0.
    """
    db = client['jyu_tls_research']
    collection = db['sslyze_'+market]
    hosts = get_all_hosts(db)
    open_https_addresses = get_addresses_with_open_https_port(db)

    for index, host in enumerate(hosts):
        if host['address'] in open_https_addresses:
            domain = host['domain']
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{current_time} \t index: {index} \t domain: {domain}")
            scanner_results = scan(domain, debug)
            for scan_result in scanner_results:
                result_as_json = json.loads(json.dumps(asdict(scan_result), cls=sslyze.JsonEncoder))
                result_as_json2 = copy.deepcopy(result_as_json)

                for i_deploy, deploy in enumerate(result_as_json2['scan_commands_results']['certificate_info']['certificate_deployments']):
                    if 'ocsp_response' in deploy and deploy['ocsp_response'] is not None:
                        del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['ocsp_response']['serial_number']
                    if 'received_certificate_chain' in deploy:
                        for i_cert, certs in enumerate(deploy['received_certificate_chain']):
                            del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['received_certificate_chain'][i_cert]['serial_number']
                            del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['received_certificate_chain'][i_cert]['public_key']['rsa_n']
                            del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['received_certificate_chain'][i_cert]['public_key']['ec_x']
                            del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['received_certificate_chain'][i_cert]['public_key']['ec_y']
                        if 'path_validation_results' in deploy:
                            for i_path, path in enumerate(deploy['path_validation_results']):
                                if 'verified_certificate_chain' in path and path['verified_certificate_chain'] is not None:
                                    for i_chain, chain in enumerate(path['verified_certificate_chain']):
                                        del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['path_validation_results'][i_path]['verified_certificate_chain'][i_chain]['serial_number']
                                        del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['path_validation_results'][i_path]['verified_certificate_chain'][i_chain]['public_key']['rsa_n']
                                        del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['path_validation_results'][i_path]['verified_certificate_chain'][i_chain]['public_key']['ec_x']
                                        del result_as_json['scan_commands_results']['certificate_info']['certificate_deployments'][i_deploy]['path_validation_results'][i_path]['verified_certificate_chain'][i_chain]['public_key']['ec_y']
                
                #pprint(result_as_json)
                collection.insert_one(result_as_json)

    client.close()

def scan(host, debug):
    scan_commands={
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.TLS_1_3_EARLY_DATA,
        #ScanCommand.HEARTBLEED,
        #ScanCommand.ROBOT,
        ScanCommand.ELLIPTIC_CURVES,
        ScanCommand.HTTP_HEADERS,
        ScanCommand.TLS_COMPRESSION,
        #ScanCommand.TLS_FALLBACK_SCSV,
        #ScanCommand.OPENSSL_CCS_INJECTION,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.SESSION_RESUMPTION,
        #ScanCommand.SESSION_RESUMPTION_RATE,
    }
    return sslyze_scan(host, scan_commands, debug)

def redirect_to_https(host):
    r = requests.get("http://"+host, allow_redirects=True)
    #r = requests.head("http://"+host, allow_redirects=True)
    if 'https://' in r.url:
        return True
    else:
        return False

def get_all_hosts(db):
    collection = db['hosts']
    entries = collection.find({"address": {"$ne":""}})
    hosts = []
    for entry in entries:
        hosts.append(entry)
    entries.close()
    return hosts

def get_addresses_with_open_https_port(db):
    collection = db['nmap']
    entries = collection.find({"tcp.443.state":"open"}, {"addresses":1, "tcp.443.state":1})
    addresses = []
    for entry in entries:
        addresses.append(entry["addresses"]["ipv4"])
    entries.close()
    return addresses

if __name__ == '__main__':
    run_sslyze_scan(args.market, args.debug, int(args.companiesfrom), int(args.companiesto))
    