class Company:
    name = ''
    symbol = ''
    CCY = ''
    ISIN = ''
    ICB = ''
    employees = ''
    industry = ''
    sector = ''
    website = ''
    ssllabs_result = ''

    def __init__(self, name, symbol, CCY, ISIN, ICB, employees, industry, sector, website):
        self.name = name
        self.symbol = symbol
        self.CCY = CCY
        self.ISIN = ISIN
        self.ICB = ICB
        self.employees = employees
        self.industry = industry
        self.sector = sector
        self.website = website
    
    def __str__(self):
        return "%s, %s, %s, %s, %s, %s, %s, %s, %s" % (self.name, self.symbol, self.CCY, self.ISIN, self.ICB, self.employees, self.industry, self.sector, self.website)
        