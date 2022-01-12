# pyTLScanner

## Virtualenv

    python -m venv env
    .\env\Scripts\activate
    deactivate

## Install dependencies

- Python 3
- MongoDB

Python dependencies:
    
    pip install -r requirements.txt

Python and Nmap on Linux:

    sudo apt install nmap python3-pip python-dev libssl-dev libffi-dev

Nmap on Windows:

    https://nmap.org/download.html#windows

## Execution chain with this tool

This tool's excecution chain consists of four different steps, which are 1. get listed companies website from Nasdaq Helsinki and Yahoo API, 2. find as much as possible subdomains from these companies, 3. Port scan these subdomains to get available websites, 4. Do SSL/TLS scan with SSLyze.

### 1. Get listed companies from Nasdaq Helsinki

1. Get all listed companies ticker (aka. symbol) from Nasdaq Helsinki website

    python get_listed_companies.py

2. Get listed companies website with their ticker code from Yahooo Finance API

    python subdomains.py > data/domains.txt

### 2. Subdomain scan with Anubis

Get listed companies domains. Give a list of main domains to Anubis and it will output list of subdomains.

    anubis -pf data/domains.txt -o data/anubis_result.txt

### 3. Nmap scan

Do port scan against HTTPS default port 443.

    python nmap_scanner.py --update-db --scan

### 4. Run SSL/TLS scan with SSLyze

    python pytlscanner.py --market="helsinki"

## SSLyze mongoexport

    $fields = "server_info.server_location.hostname," +
    "scan_commands_results.certificate_info.certificate_deployments.0.received_certificate_chain.0.not_valid_before," +
    "scan_commands_results.certificate_info.certificate_deployments.0.received_certificate_chain.0.not_valid_after," +
    "scan_commands_results.certificate_info.certificate_deployments.0.received_certificate_chain.0.subject_alternative_name.dns.0," +
    "scan_commands_results.certificate_info.certificate_deployments.0.received_certificate_chain.0.public_key.algorithm," +
    "scan_commands_results.certificate_info.certificate_deployments.0.received_certificate_chain.0.public_key.key_size," +
    "scan_commands_results.certificate_info.certificate_deployments.0.received_certificate_chain.0.public_key.ec_curve_name," +
    "server_info.tls_probing_result.highest_tls_version_supported," +
    "scan_commands_results.tls_1_3_early_data.supports_early_data," +
    "scan_commands_results.elliptic_curves.supported_curves.0.name," +
    "scan_commands_results.tls_1_3_cipher_suites.accepted_cipher_suites.0.cipher_suite.name," +
    "scan_commands_results.tls_1_2_cipher_suites.accepted_cipher_suites.0.cipher_suite.name," +
    "scan_commands_results.tls_1_1_cipher_suites.accepted_cipher_suites.0.cipher_suite.name," +
    "scan_commands_results.tls_1_0_cipher_suites.accepted_cipher_suites.0.cipher_suite.name," +
    "scan_commands_results.ssl_3_0_cipher_suites.accepted_cipher_suites.0.cipher_suite.name," +
    "scan_commands_results.ssl_2_0_cipher_suites.accepted_cipher_suites.0.cipher_suite.name," +
    "scan_commands_results.tls_compression.supports_compression," +
    "scan_commands_results.session_renegotiation.supports_secure_renegotiation," +
    "scan_commands_results.session_renegotiation.is_vulnerable_to_client_renegotiation_dos," +
    "scan_commands_results.session_resumption.session_id_resumption_result," +
    "scan_commands_results.session_resumption.tls_ticket_resumption_result"
     mongoexport --host localhost:27018 --collection=sslyze_helsinki --db=jyu_tls_research --type=csv --fields=$fields --out=events.csv
