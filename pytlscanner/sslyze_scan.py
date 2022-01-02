from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    Scanner,
    ServerScanRequest,
    ScanCommand,
)
from sslyze.errors import ConnectionToServerFailed
from pprint import pprint

def sslyze_scan(host, scan_commands, debug=False) -> None:
    # First validate that we can connect to the servers we want to scan
    servers_to_scan = []
    for hostname in [host]:
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname, 443)
        try:
            server_info = ServerConnectivityTester().perform(server_location)
            servers_to_scan.append(server_info)
        except ConnectionToServerFailed as e:
            print(f"Error connecting to {server_location.hostname}:{server_location.port}: {e.error_message}")
            return

    scanner = Scanner()

    # Then queue some scan commands for each server
    for server_info in servers_to_scan:
        server_scan_req = ServerScanRequest(
            server_info=server_info, scan_commands=scan_commands,
        )
        scanner.queue_scan(server_scan_req)
        
        if debug:
            print_results(scanner)
        
        return scanner.get_results()

def print_results(scanner):
    # Then retrieve the result of the scan commands for each server
    for server_scan_result in scanner.get_results():
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

        # Scan commands that were run with errors
        for scan_command, error in server_scan_result.scan_commands_errors.items():
            print(f"\nError when running {scan_command}:\n{error.exception_trace}")

def cipher_suites(server_scan_result, protocol):
    try:
        result = server_scan_result.scan_commands_results[eval(protocol)]
        print(f"\nAccepted cipher suites for {protocol}:")
        for accepted_cipher_suite in result.accepted_cipher_suites:
            print(f"* {accepted_cipher_suite.cipher_suite.name}")
    except KeyError:
        pass

def get_certificate_info(server_scan_result):
    try:
        certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
        print("\nCertificate info:")
        for cert_deployment in certinfo_result.certificate_deployments:
            print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain_as_pem[0]}")
    except KeyError:
        pass

def get_http_headers(server_scan_result):
    try:
        result = server_scan_result.scan_commands_results[ScanCommand.HTTP_HEADERS]
        print("\nHTTP_HEADERS info:")
        pprint(result)
    except KeyError:
        pass

def get_common(server_scan_result, scan_literal):
    try:
        ec_result = server_scan_result.scan_commands_results[eval(scan_literal)]
        print(f"\n{scan_literal} info:")
        pprint(ec_result)
    except KeyError:
        pass

if __name__ == '__main__':
    scan_commands={
            ScanCommand.CERTIFICATE_INFO
        }
    sslyze_scan("cloudflare.com", scan_commands, True)