# Pankkiyhteys

Communicate with Finnish banks using python

## Getting Started

This is an experimental software. Keep in mind there might be bugs!

You need to make a contract with a bank to use web services. Currently
not all banks are supported.

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

- [ ] API: How to load keys
- [ ] Osuuspankki implementation
- [ ] Testing
