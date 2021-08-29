#!/usr/bin/env python

from pymongo import MongoClient
from pprint import pprint
import sslyze
from sslyze import ScanCommand

client = MongoClient('mongodb://localhost:27017/')
db = client['jyu_tls_research']
collection = db['sslyze_helsinki']

def get_support_of_ecdh():
    is_true = collection.count_documents({"sslyze_result.scan_commands_results.elliptic_curves.supports_ecdh_key_exchange":{ "$eq": True }})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.elliptic_curves.supports_ecdh_key_exchange":{ "$eq": False }})
    print("Support ECDH: " + str(is_true))
    print("Doesn't support ECDH: " + str(is_false))

def get_support_tls_compression():
    is_true = collection.count_documents({"sslyze_result.scan_commands_results.tls_compression.supports_compression":{ "$eq": True }})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.tls_compression.supports_compression":{ "$eq": False }})
    print("Support TLS compression: " + str(is_true))
    print("Doesn't support TLS compression: " + str(is_false))

def get_hsts_preload():
    is_true = collection.count_documents({"sslyze_result.scan_commands_results.http_headers.strict_transport_security_header.preload":{ "$eq": True }})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.http_headers.strict_transport_security_header.preload":{ "$eq": False }})
    print("Support HSTS preload: " + str(is_true))
    print("Doesn't support HSTS preload: " + str(is_false))

def get_heartbleed():
    is_true = collection.count_documents({"sslyze_result.scan_commands_results.heartbleed.is_vulnerable_to_heartbleed":{ "$eq": True }})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.heartbleed.is_vulnerable_to_heartbleed":{ "$eq": False }})
    print("Vulnerable to Heartbleed: " + str(is_true))
    print("Doesn't vulnerable to Heartbleed: " + str(is_false))

def get_robot():
    all = collection.count_documents({})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.robot.robot_result": {"$regex":"^NOT_VULNERABLE"} })
    print("Vulnerable to Robot: " + str((int(all)-int(is_false))))
    print("Doesn't vulnerable to Robot: " + str(is_false))

def get_openssl_ccs_injection():
    is_true = collection.count_documents({"sslyze_result.scan_commands_results.openssl_ccs_injection.is_vulnerable_to_ccs_injection":{ "$eq": True }})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.openssl_ccs_injection.is_vulnerable_to_ccs_injection":{ "$eq": False }})
    print("Vulnerable to CCS Injection: " + str(is_true))
    print("Doesn't vulnerable to CCS Injection: " + str(is_false))

def get_tls_fallback_scsv():
    is_true = collection.count_documents({"sslyze_result.scan_commands_results.tls_fallback_scsv.supports_fallback_scsv":{ "$eq": True }})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.tls_fallback_scsv.supports_fallback_scsv":{ "$eq": False }})
    print("Support TLS fallback: " + str(is_true))
    print("Doesn't support TLS fallback: " + str(is_false))

def get_session_renegation():
    is_true = collection.count_documents({"sslyze_result.scan_commands_results.session_renegotiation.accepts_client_renegotiation":{ "$eq": True }})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.session_renegotiation.accepts_client_renegotiation":{ "$eq": False }})
    print("Accepts client renegotiation: " + str(is_true))
    print("Reject client renegotiation: " + str(is_false))

def get_session_secure_renegation():
    is_true = collection.count_documents({"sslyze_result.scan_commands_results.session_renegotiation.supports_secure_renegotiation":{ "$eq": True }})
    is_false = collection.count_documents({"sslyze_result.scan_commands_results.session_renegotiation.supports_secure_renegotiation":{ "$eq": False }})
    print("Supports secure renegotiation: " + str(is_true))
    print("Doesn't support secure renegotiation: " + str(is_false))


if __name__ == '__main__':
    get_support_of_ecdh()
    get_support_tls_compression()
    get_hsts_preload()
    get_robot()
    get_heartbleed()
    get_openssl_ccs_injection()
    get_tls_fallback_scsv()
    get_session_renegation()
    get_session_secure_renegation()
    client.close()