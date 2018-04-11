from io import StringIO
from enum import Enum
from decimal import Decimal
from datetime import datetime
from collections import namedtuple


class Rahayksikko(Enum):
    EURO = 1


class Tila(Enum):
    ONNISTUNUT = 0
    TILIA_EI_LOYDY = 1
    KATE_EI_RIITA = 2
    EI_MAKSUPALVELUTILI = 3
    MAKSAJA_PERUUTTANUT = 4
    PANKKI_PERUUTTANUT = 5
    PERUUTUS_EI_KOHDISTU = 6
    VALTUUTUS_PUUTTUU = 7
    ERAPAIVAVIRHE = 8
    MUOTOVIRHE = 9


class TL:
    Row = namedtuple('Row', [
        'tilinumero', 'kirjauspv', 'maksupv',
        'arkistointitunnus', 'viite', 'nimi',
        'rahayksikko', 'nimen_lahde', 'summa',
        'oikaisutunnus', 'valitystapa', 'tila'
    ])

    def _to_decimal(self, field):
        return Decimal("{}.{}".format(field[:-2], field[-2:]))

    def _read_header(self, header):
        # Check header magic
        if header[0] != "0":
            raise ValueError("Invalid header")

        self.kirjoituspv = datetime.strptime(header[1:11], "%y%m%d%H%M")
        self.rahalaitostunnus = header[11:13]
        self.laskuttajan_tunnus = header[13:22]
        self.rahayksikko = Rahayksikko(int(header[22]))

    def _read_footer(self, footer):
        self.viitetap_kpl = int(footer[1:7])
        self.viitetap_summa = self._to_decimal(footer[7:18])
        self.viiteoik_kpl = int(footer[18:24])
        self.viiteoik_summa = self._to_decimal(footer[24:35])
        self.epaonnis_kpl = int(footer[35:41])
        self.epaonnis_summa = self._to_decimal(footer[41:52])

    def _read_row(self, line):
        self._rows.append(self.Row(
            tilinumero=line[1:15],
            kirjauspv=datetime.strptime(line[15:21], "%y%m%d").date(),
            maksupv=datetime.strptime(line[21:27], "%y%m%d").date(),
            arkistointitunnus=line[27:43],
            viite=line[43:63].lstrip('0'),
            nimi=line[63:75].replace('[', 'Ä').replace('\\', 'Ö').rstrip(),
            rahayksikko=Rahayksikko(int(line[75:76])),
            nimen_lahde=line[76:77],
            summa=self._to_decimal(line[77:87]),
            oikaisutunnus=int(line[87:88]),
            valitystapa=line[88:89],
            tila=Tila(int(line[89:90].strip() or 0))))

    def __init__(self, content):
        buffer = StringIO(content)

        self._read_header(buffer.readline())
        self._rows = []

        for line in buffer.readlines():
            # Skip empty lines
            if not line.strip():
                continue

            # Footer magic
            if line[0] == '9':
                break

            self._read_row(line)
        self._read_footer(line)

    def __getitem__(self, index):
        return self._rows[index]

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)
