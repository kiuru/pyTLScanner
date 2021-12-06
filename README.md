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

## Run scanner

    python pytlscanner.py --market="helsinki" --limit-companies-from 0 --limit-companies-to 1

## mongoexport

    $fields = "name,employees,industry,sector,website," +
    "ssllabs_result.endpoints.0.grade," +
    "ssllabs_result.endpoints.0.details.protocols.0.version," +
    "ssllabs_result.endpoints.0.details.protocols.1.version," +
    "ssllabs_result.endpoints.0.details.protocols.2.version," +
    "ssllabs_result.endpoints.0.details.protocols.3.version," +
    "ssllabs_result.endpoints.0.details.serverSignature," +
    "ssllabs_result.endpoints.0.details.cert.issuerLabel," +
    "ssllabs_result.endpoints.0.details.key.alg," +
    "ssllabs_result.endpoints.0.details.key.size," +
    "ssllabs_result.endpoints.0.details.key.strength," +
    "ssllabs_result.endpoints.0.details.hstsPolicy.status," +
    "ssllabs_result.endpoints.0.details.hstsPolicy.header," +
    "ssllabs_result.endpoints.0.details.httpStatusCode," +
    "ssllabs_result.endpoints.0.details.httpForwarding"
    mongoexport --collection=ssllabs_helsinki --db=jyu_tls_research --type=csv --fields=$fields --out=events.csv

## Get list of domains

    python subdomains.py --market="helsinki" --limit-companies-from 0 --limit-companies-to 500 > data/domains.txt

## Subdomains scanner with Anubis

    pip install anubis-netsec
    sudo apt install nmap python3-pip python-dev libssl-dev libffi-dev

## On Windows install nmap

    https://nmap.org/download.html#windows

## Get subdomains

    for i in $(cat data/domains.txt|head -2); do anubis -tip $i -o data/domains_result; done

