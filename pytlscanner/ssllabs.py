import requests
import sys
import json
import time
import logging
from pprint import pprint

API_URL = 'https://api.ssllabs.com/api/v2/'

def requestAPI(path, payload={}):
    try:
        url = API_URL + path
        response = requests.get(url, params=payload)
        return response.json()
    except:
        e = sys.exc_info()[0]
        print("Error: %s" % e)
        pprint(response.text)

def resultsFromCache(website, debug=False, publish='off', fromCache='on', all='done'):
    if debug == True:
        logging.basicConfig(level=logging.DEBUG)
    
    path = 'analyze'
    payload = {
        'host': website,
        'publish': publish,
        'fromCache': fromCache,
        'all': all
    }
    return requestAPI(path, payload)
