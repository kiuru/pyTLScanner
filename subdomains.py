#!/usr/bin/env python

from get_listed_companies import get_listed_companies_from_cache
import tldextract

def run_scan(market, debug):

    companies = get_listed_companies_from_cache(market, debug)
    domain_list = []
    for company in companies:
        ext_domain = tldextract.extract(company.website)
        domain = ext_domain.domain + "." + ext_domain.suffix
        domain_list.append(domain)

    domain_list = list(set(domain_list))
    for domain in domain_list:
        print(domain)

if __name__ == '__main__':
    run_scan('helsinki', True)
    