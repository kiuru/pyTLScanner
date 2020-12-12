#!/usr/bin/env python

from get_listed_companies import get_listed_companies, get_listed_companies_from_cache
import tldextract
from argumentparser import args
from pprint import pprint

def run_scan(market, debug, marketfrom, marketto):

    companies = get_listed_companies_from_cache(market, marketfrom, marketto, debug)
    domain_list = []
    for company in companies:
        ext_domain = tldextract.extract(company.website)
        domain = ext_domain.domain + "." + ext_domain.suffix
        domain_list.append(domain)
    pprint(list(set(domain_list)))

if __name__ == '__main__':
    run_scan(args.market, args.debug, int(args.companiesfrom), int(args.companiesto))
    