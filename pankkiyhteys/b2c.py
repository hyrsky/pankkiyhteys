class Entity:
    def __init__(self, name, address, country):
        self.name = name
        self.address = address
        self.country = country

class Company(Entity):
    """Entity representing company"""

class Customer(Entity):
    """Entity representing customer"""
