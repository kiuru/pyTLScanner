from bs4 import BeautifulSoup
import yfinance as yf
import requests
import sys
from models.company import Company

def get_listed_companies(market, marketfrom=0, marketto=0):
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
        print(name, symbol)

        ticker = yf.Ticker(symbol + markets_suffix[CCY])
        employees = ticker.info["fullTimeEmployees"]
        industry = ticker.info["industry"]
        sector = ticker.info["sector"]
        website = ticker.info["website"]
        
        company = Company(name, symbol, CCY, ISIN, ICB, employees, industry, sector, website)
        companies.append(company)

    return companies

if __name__ == '__main__':
    companies = get_listed_companies("helsinki", 0, 1)
    print(companies[0])
