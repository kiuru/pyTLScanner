# pyTLScanner

## Install dependencies

- Python 3
- MongoDB

Python dependencies:

    pip3 install -r requirements.txt

## Run scanner

    python3 pytlscanner.py --market="helsinki" --limit-companies-from 0 --limit-companies-to 1

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


## Subdomains scanner with Anubis

    pip3 install anubis-netsec
    sudo apt install nmap python3-pip python-dev libssl-dev libffi-dev

## Get domains

    for i in $(cat data/domains.txt|head -2); do anubis -tip $i -o data/domains_result; done

