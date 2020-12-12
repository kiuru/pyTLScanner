#!/usr/bin/env python

from pytlscanner import resultsFromCache
from get_listed_companies import get_listed_companies
from pymongo import MongoClient
import time
from argumentparser import args
from pprint import pprint
import sys

def run_scan(market, debug, marketfrom, marketto):
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

if __name__ == '__main__':
    run_scan(args.market, args.debug, int(args.companiesfrom), int(args.companiesto))
    