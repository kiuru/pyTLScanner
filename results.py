#!/usr/bin/env python

from pymongo import MongoClient
from pprint import pprint

client = MongoClient('mongodb://localhost:27018/')

recommended_ciphers = [
    'TLS_AES_128_CCM_8_SHA256',
    'TLS_AES_128_CCM_SHA256',
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_DHE_RSA_WITH_AES_128_CCM',
    'TLS_DHE_RSA_WITH_AES_128_CCM_8',
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_CCM',
    'TLS_DHE_RSA_WITH_AES_256_CCM_8',
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
]

def get_ciphersuites(tls_version):
    aggregate_match = "scan_commands_results.{}.accepted_cipher_suites".format(tls_version)
    results = client['jyu_tls_research']['view_sslyze_helsinki_no_errors'].aggregate([
        {
            '$match': {
                '$and': [
                    {
                        aggregate_match: {
                            '$exists': True,
                            '$ne': []
                        }
                    }
                ]
            }
        },
        #{
        #    '$limit': 100
        #}
    ])

    weak_hosts = []
    for result in results:
        hostname = result['server_info']['server_location']['hostname']
        cipher_suites = result['scan_commands_results'][tls_version]['accepted_cipher_suites']
        for cipher in cipher_suites:
            if not cipher['cipher_suite']['name'] in recommended_ciphers:
                #print(hostname, cipher['cipher_suite']['name'])
                weak_hosts.append(hostname)

    weak_hosts = list(set(weak_hosts))
    pprint(weak_hosts)
    print('Count: ', len(weak_hosts))
    client.close()

def get_all_hosts():
    results = client['jyu_tls_research']['view_sslyze_helsinki_no_errors'].find({},{'server_info.server_location.hostname': 1})
    hosts = []
    for result in results:
        hosts.append(result['server_info']['server_location']['hostname'])
    client.close()
    print('All hosts: ', len(hosts))
    return set(hosts)

def get_hosts_from_mongo_view(view):
    results = client['jyu_tls_research'][view].find()
    hosts = []
    for result in results:
        #print(result)
        hosts.append(result['_id'])
    client.close()
    print(view, len(hosts))
    return set(hosts)

if __name__ == '__main__':
    #get_ciphersuites('tls_1_2_cipher_suites')

    hosts = get_all_hosts()
    hosts = hosts - get_hosts_from_mongo_view('view_rec_tls_version')
    hosts = hosts - get_hosts_from_mongo_view('view_rec_cipher_suites')
    hosts = hosts - get_hosts_from_mongo_view('view_rec_tls_compression')
    hosts = hosts - get_hosts_from_mongo_view('view_rec_0RTT')
    hosts = hosts - get_hosts_from_mongo_view('view_rec_ocsp')
    hosts = hosts - get_hosts_from_mongo_view('view_rec_certificate_lifespan')
    hosts = hosts - get_hosts_from_mongo_view('view_rec_certificate_validity_period')
    hosts = hosts - get_hosts_from_mongo_view('view_rec_certificate_keysize')
    hosts = hosts - get_hosts_from_mongo_view('view_rec_hsts')
    print('Meets all recommendations: ', len(hosts))
