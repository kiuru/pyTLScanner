#!/usr/bin/env python

from pytlscanner import resultsFromCache
from pytlscanner import sslyze_scan
from get_listed_companies import get_listed_companies, get_listed_companies_from_cache
from pymongo import MongoClient
import time
from argumentparser import args
from pprint import pprint
import sys
from dataclasses import asdict
import json
import sslyze
from sslyze import ScanCommand

from datetime import datetime

def run_ssllabs_scan(market, debug, marketfrom, marketto):
    client = MongoClient('mongodb://localhost:27017/')
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
    client = MongoClient('mongodb://localhost:27017/')
    db = client['jyu_tls_research']
    collection = db['sslyze_'+market]

    companies = get_listed_companies_from_cache(market, marketfrom, marketto)
    scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.TLS_1_3_EARLY_DATA,
            ScanCommand.HEARTBLEED,
            ScanCommand.ROBOT,
            ScanCommand.ELLIPTIC_CURVES,
            ScanCommand.HTTP_HEADERS,
            ScanCommand.TLS_COMPRESSION,
            ScanCommand.TLS_FALLBACK_SCSV,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.SESSION_RENEGOTIATION,
            ScanCommand.SESSION_RESUMPTION,
            #ScanCommand.SESSION_RESUMPTION_RATE,
        }
    for company in companies:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{current_time} {company.website}")
        scanner_results = sslyze_scan(company.website.replace('http://',''), scan_commands, debug)
        for scan_result in scanner_results:
            result_as_json = json.loads(json.dumps(asdict(scan_result), cls=sslyze.JsonEncoder))
            company.sslyze_result = result_as_json
            pprint(result_as_json)
            collection.insert_one(company.__dict__)

    client.close()

if __name__ == '__main__':
    #run_ssllabs_scan(args.market, args.debug, int(args.companiesfrom), int(args.companiesto))
    run_sslyze_scan(args.market, args.debug, int(args.companiesfrom), int(args.companiesto))
    