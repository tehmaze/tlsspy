from collections import OrderedDict
from datetime import datetime

from pyasn1.type import char


def parse_choice(sequence):
    item = sequence.getComponent()
    if item is None:
        return None
    else:
        return item.to_python()


def parse_directory_string(sequence):
    item = sequence.getComponent()
    if item is None:
        return None
    elif isinstance(item, char.BMPString):
        return item._value.decode('utf_16_be')
    elif isinstance(item, char.UTF8String):
        return item._value.decode('utf_8')
    else:
        return item._value


def parse_hex(sequence):
    return sequence._value.encode('hex')


def parse_name(sequence):
    return str(sequence)


def parse_general_name(sequence):
    parsed = OrderedDict()

    for x in xrange(len(sequence.componentType)):
        name = sequence.componentType[x].getName()
        value = sequence.getComponentByName(name)
        if value:
            parsed[name] = parse_name(value)

    return parsed


def parse_general_names(sequence):
    parsed = []
    for item in list(sequence):
        parsed.append(parse_general_name(item))
    return parsed


def parse_sequence_dict(sequence):
    parsed = {}
    for item in sequence:
        parsed.update(item.to_python())
    return parsed


def parse_sequence_list(sequence):
    parsed = []
    for item in sequence:
        parsed.append(item.to_python())
    return parsed


def parse_time(sequence):
    value = str(sequence.getComponent())

    if sequence.getName() == 'utcTime':
        # RFC5280 says: "For the purposes of this profile, UTCTime values
        # MUST be expressed in Greenwish Mean Time (Zulu) and MUST include
        # seconds (i.e., times are YYMMDDHHMMSSZ), even when the number of
        # seconds is zero.  Conforming systems MUST interpret the year
        # field (YY) as follows:
        #
        # Where YY is greater than or equal to 50, the year SHALL be
        # interpreted as 19YY; and
        #
        # Where YY is less than 50, the year SHALL be interpreted as 20YY."
        #
        # ... guess they have little trust in the current standard being
        # around for a longer period of time :-)
        year = int(value[:2])
        if 0 <= year < 50:
            century = '20'
        elif 50 <= year <= 99:
            century = '19'

        return datetime.strptime(century + value[:-1] + 'GMT', '%Y%m%d%H%M%S%Z')

    else:
        return datetime.strptime(value[:-1] + 'GMT', '%Y%m%d%H%M%S%Z')
