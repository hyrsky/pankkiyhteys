import itertools

class Entity:
    def __init__(self, name, address, country):
        self.name = name
        self.address = address
        self.country = country

class Company(Entity):
    """Entity representing company"""

class Customer(Entity):
    """Entity representing customer"""

def reference_number(n):
    m = itertools.cycle((7, 3, 1))
    r = 0

    while n:
        r, n = r + (next(m) * (n % 10)), n // 10

    r = 10 - (r % 10)

    return n * 10 + (0 if r >= 10 else r)
