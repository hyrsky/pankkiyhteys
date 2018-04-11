import itertools


SOFTWARE_ID = 'pankkiyhteys v0.3'
""" str: Client software identifier sent to bank on each request"""


def luhn(n):
    """Luhn mod 10 checksum by Hans Peter Luhn (1896-1964)"""

    sum = 0
    while n:
        r, n = n % 100, n // 100
        z, r = r % 10, r // 10 * 2
        sum += r // 10 + r % 10 + z
    return 0 == sum % 10


def reference_number(n):
    """
    The Finnish reference number is used in domestic payments.

    The calculation of check digit is done using 7-3-1 method:
     1. The digits in the basic reference data to be verified are multiplied
        by the weights 7, 3, 1... right to left .
     2. The multiplied sums are added up
     3. The sum is subtracted from then nearest figure ending in zero.
     4. The resulting difference is the check digit, which is entered as the
        last digit in the reference number.
    """

    m = itertools.cycle((7, 3, 1))
    r = 0

    while n:
        r, n = r + (next(m) * (n % 10)), n // 10

    r = 10 - (r % 10)

    return n * 10 + (0 if r >= 10 else r)
