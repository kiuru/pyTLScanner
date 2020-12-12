import argparse

list_of_market_choices = ["baltic", "copenhagen", "helsinki", "iceland", "stockholm", "first-north", "first-north-premier"]
parser = argparse.ArgumentParser(description='pyTLScanner')
parser.add_argument("--market", dest='market', help="Select a target market", choices=list_of_market_choices)
parser.add_argument('--limit-companies-from', action="store", dest="companiesfrom", help="From")
parser.add_argument('--limit-companies-to', action="store", dest="companiesto", help="To")
parser.add_argument('--debug', action="store_true", dest="debug", help="Debug logging")
parser.add_argument('--version', action='version', version='%(prog)s 0.1.0')
#parser.set_defaults(verbose=False)
args = parser.parse_args()
