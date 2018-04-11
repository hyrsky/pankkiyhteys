# Pankkiyhteys

Communicate with Finnish banks using python

## Getting Started

This is an experimental software. Keep in mind there will be bugs!

You need to make a contract with a bank to use web services. Currently
only Osuuspankki is supported.

## Usage

```python
from pankkiyhteys import Osuuspankki

with open('privkey.key', 'rb') as privkey,
     open('certificate.pem', 'rb') as certificate:
  key = privkey.read()
  cert = certificate.read()

client = Osuuspankki('1234567890', key, cert, environment=Environment.TEST)

print(client.get_file_list())
```

## Testing

Install requirements and run
```
nosetests
```

Count code coverage
```
pip install nose coverage
coverage run --source pankkiyhteys -m unittest
coverage report
coverage html
```
