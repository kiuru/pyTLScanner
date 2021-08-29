class Host:
    domain = ''
    address = ''

    def __init__(self, domain, address):
        self.domain = domain
        self.address = address
    
    def __str__(self):
        return "%s, %s" % (self.domain, self.address)
        