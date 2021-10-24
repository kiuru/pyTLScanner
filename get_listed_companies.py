from bs4 import BeautifulSoup
from pymongo import MongoClient
import requests
from models.company import Company

client = MongoClient('mongodb://localhost:27017/')
db = client['jyu_tls_research']

def get_listed_companies(market, marketfrom=0, marketto=0, verbose=True):
    """Get listed companies from Nasdaq's web site

    Args:
        market ([type]): Target market (e.g. helsinki)
        marketfrom (int, optional): [description]. Defaults to 0.
        marketto (int, optional): [description]. Defaults to 0.
        verbose (bool, optional): Debug. Defaults to True.

    Returns:
        [type]: List of companies
    """
    import yfinance as yf
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }
    r = requests.get("http://www.nasdaqomxnordic.com/osakkeet/listayhtiot/"+market, headers=headers)
    soup = BeautifulSoup(r.text, 'html.parser')

    markets_suffix = {
        "DKK": ".CO",
        "EUR": ".HE",
        "ISK": ".IC",
        "SEK": ".ST",
    }

    companies = []
    #for row in soup.find(id="listedCompanies").find("tbody").find_all("tr")[0:1]:
    if marketto == 0:
        rows = soup.find(id="listedCompanies").find("tbody").find_all("tr")
    else:
        rows = soup.find(id="listedCompanies").find("tbody").find_all("tr")[marketfrom:marketto]
    for row in rows:
        cells = row.find_all("td")
        name = cells[0].get_text()
        symbol = cells[1].get_text().replace('NDA FI', 'NDA-FI') # Nordea was "NDA FI", but should be "NDA-FI"
        CCY = cells[2].get_text()
        ISIN = cells[3].get_text()
        #sector = cells[4].get_text()
        ICB = cells[5].get_text()
        if verbose == True: print(name, symbol)

        try:
            ticker = yf.Ticker(symbol + markets_suffix[CCY])
            employees = ticker.info["fullTimeEmployees"]
            industry = ticker.info["industry"]
            sector = ticker.info["sector"]
            website = ticker.info["website"]
            
            company = Company(name, symbol, CCY, ISIN, ICB, employees, industry, sector, website)
            companies.append(company)
        except KeyError as err:
            print("KeyError: " + str(err))
        except ValueError as err:
            print("ValueError: " + str(err))

    return companies

def get_listed_companies_from_cache(market, marketfrom=0, marketto=0, verbose=True):
    """Get listed companies from MongoDB

    Args:
        market ([type]): Target market (e.g. helsinki)
        marketfrom (int, optional): [description]. Defaults to 0.
        marketto (int, optional): [description]. Defaults to 0.
        verbose (bool, optional): Debug. Defaults to True.

    Returns:
        [type]: List of companies
    """
    collection = db['nasdaq_'+market]
    entries = collection.find({})
    companies = []
    for entry in entries[marketfrom:marketto]:
        company = Company(entry["name"], entry["symbol"], entry["CCY"], entry["ISIN"], entry["ICB"], entry["employees"], entry["industry"], entry["sector"], entry["website"])
        companies.append(company)
    return companies

if __name__ == '__main__':
    market = "helsinki"
    collection = db['nasdaq_'+market]

    companies = get_listed_companies(market)
    collection.delete_many({})
    for company in companies:
        collection.insert_one(company.__dict__)

    client.close()
