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


class TapahtumaLuettelo:
    Row = namedtuple('Row', [
        'tilinumero', 'kirjauspv', 'maksupv',
        'arkistointitunnus', 'viite', 'nimi',
        'rahayksikko', 'nimen_lahde', 'summa',
        'oikaisutunnus', 'valitystapa', 'tila'
    ])

    @classmethod
    def parse(cls, content):
        with StringIO(content) as buffer:
            return cls(buffer)

    def _to_decimal(self, field):
        return Decimal("{}.{}".format(field[:-2], field[-2:]))

    def _read_footer(self, footer):
        self.viitetap_kpl += int(footer[1:7])
        self.viitetap_summa += self._to_decimal(footer[7:18])
        self.viiteoik_kpl += int(footer[18:24])
        self.viiteoik_summa += self._to_decimal(footer[24:35])
        self.epaonnis_kpl += int(footer[35:41])
        self.epaonnis_summa += self._to_decimal(footer[41:52])

    def _read_header(self, header):
        self.kirjoituspv = datetime.strptime(header[1:11], "%y%m%d%H%M")

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

    def __init__(self, buffer):
        self._rows = []
        self.viitetap_kpl = 0
        self.viiteoik_kpl = 0
        self.epaonnis_kpl = 0
        self.viitetap_summa = Decimal(0)
        self.viiteoik_summa = Decimal(0)
        self.epaonnis_summa = Decimal(0)

        for line in buffer.readlines():
            # Skip empty lines
            if not line.strip():
                continue
            # Check header magic
            elif line[0] == "0":
                self._read_header(line)
            # Footer magic
            elif line[0] == '9':
                self._read_footer(line)
            else:
                self._read_row(line)

    def __getitem__(self, index):
        return self._rows[index]

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)
