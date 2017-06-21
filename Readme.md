# Pankkiyhteys

Communicate with Finnish banks using python

## Getting Started

This is an experimental software. Keep in mind there might be bugs!

You need to make a contract with a bank to use web services. Currently
not all banks are supported.

## Usage

```python
from pankkiyhteys import Key, Client, Bank, Environment

with open('privkey.key', 'rb') as privkey,
    open('certificate.pem', 'rb') as certificate:
  key = Key(privkey.read(), certificate.read())

client = Client(
  '1234567890', key, bank=Bank.Osuuspankki, environment=Environment.TEST
)
```

## Testing

Install requirements and run
```
nosetests
```

Count code coverage
```
pip install nose coverage
nosetests --with-coverage --cover-html --cover-html-dir=htmlcov --cover-package=pankkiyhteys --cover-erase
```

## Todo

- [ ] Signature validation, revokation lists, etc.
- [ ] Osuuspankki implementation
- [ ] Document WS file types
- [ ] Testing
