#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Paul Sladen, 2014-11-25, Seaward SSS PAT testing file format debug harness
# Hereby placed in the public domain in the hopes of improving
# electrical safety and interoperability
# Usage: ./portableappliancetest.py <input.sss>
#
# Ported to Python 3 by Angel Cascarino, 2019-02-01
#
# = PAT Testing =
# Portable Appliance Testing (PAT Inspections) are tests undertaken on
# electrical equipment before they can be used in a workplace.  A
# significant part of the test process is visual, followed by an
# electrical sanity test.  This part can be performed with a
# multi-meter, but over time dedicated test machines were created to
# automate the electrical part of the test, and to record the results
# of the visual part, plus automatically recording data and time.
#
# == Seaward ==
# Seaward appear to be one UK-based manufacturer of such devices, with
# output being in a binary format normally given the extension '.sss'.
# To date (2014-11-28) I (Paul Sladen) have only seen a single '.sss'
# file, containing 12 results, of out of which 10 contain visual
# inspection only, 2 of the results have (some) of the electrical
# tests, and 1 is a visual fail.
#
# == Stream structure ==
# The structure of the file/stream is big-endian and simple in nature.
# There is no file-header, only a stream of concatenated test records.
# Each record has a six-byte header with its payload length and
# checksum, and a number of fields/sub-records prefixed by a one-byte
# type code.  The checksum is a 16-bit summation of the payload byte
# values.  The null (zeros) values may be a protocol version number.
#
# === Visual test header ===
# The visual inspection sub-record contains several fixed-length ASCII
# string fields, date-and-time (rounded down to the minute, and with no
# timezone), and configuration/parameter "testcodes".
#
# ==== Testcodes ====
# The two 10-digit testcode appear to cover the configuration of the
# testing machine (port, voltage, current limits, enabled tests).
# The test strings are ultimately configured by the user, either by
# menus or barcode-scanning a pre-made test-code sheet, or label on
# the appliance to be tested.  Testcodes are not covered here.
#
# === Electrical test results ===
# Most test results in 16-bit fields are formed of both a one-bit
# boolean field (individual test pass/fail), while the remaining
# lower 15 bits hold a resistance value (0.01 MOhm).  Current
# measurement appears to be possibly be scaled by 0.1/16 Amps.
#
# === Free form text ===
# There is space for four 21-character free-form text strings, these
# appear to normally be used for documenting any failure reason.
# The fields are fixed-length and zero padding, leaving it unclear
# whether the final byte in each string is required to be zero.
#
# = Version 2 =
# There appears to be newer version of the format with much the same
# structure, but with the possibility of multiple results per sub-record,
# with the count being iuncluded as an additional byte between the
# result code type (F0-FE) and the 16-bit result values.
#
# = Further work =
# Currently this utility is intended as a debug class to assistant
# with understanding the format in order to allow interoperability,
# and in particular allow use of the meters on non-MS Windows
# operating systems such as Debian and Ubuntu.
#
# Suggested work for those interested, could be to:
# Add option support for newer multi-sample protocol version.
# Add option to output ASCII is same format as meter (requires example)
# Add option to output .csv

import struct
import sys
import collections
from io import BytesIO

# Code is in the main() function at the bottom.  Above are helper
# classes, and then classes for parsing the 'SSS' format itself.

# Not-invented-here Structured Database Helper class
class Sdb():
    """Structured database class, not related to 'SSS' specifically.  It is
    a helper class for describing binary databases and gets used later
    below; variants of 'sdb' have been re-used over the years on various
    file-format parsers."""
    fields = []
    field_pack_format = {int: 'I'}

    def __init__(self, endian='<'):
        self.data = collections.OrderedDict()
        self.build_format_string(endian=endian)

    def fixup(self):
        pass

    def build_format_string(self, endian):
        self.endian = endian
        type_string = ''
        for __, format_type, size in self.fields:
            if format_type == int and size == 1:
                type_string += 'B'
            elif format_type == int and size == 2:
                type_string += 'H'
            elif format_type == int and size == 4:
                type_string += 'L'
            elif format_type == str:
                type_string += str(size) + 's'
            else:
                type_string += self.field_pack_format[format_type]
        self.format_string = self.endian + type_string
        self.required_length = struct.calcsize(self.format_string)

    def unpack(self, structure):
        unpacked = list(struct.unpack(self.format_string, structure))
        for name, format_type, __ in self.fields:
            if format_type == str:
                unpacked[0] = unpacked[0].replace(b'\x00', b'').rstrip()
            self.data[name] = unpacked.pop(0)
        return self

    def headings(self):
        return [name for name, format_type, size in self.fields]

    def values(self):
        return self.data.values()

    def items_dict(self):
        dictionary = '{'
        dictionary += ', '.join(['%s:%s' % (key, value) for key, value in self.data.items()])
        dictionary += '}'
        return dictionary

    def __len__(self):
        return self.required_length

    def __str__(self):
        return str(self.data)

# This sub-class for the SSS stream-format, most
class SSS(Sdb):
    def __init__(self):
        super(SSS, self).__init__(endian='>')

    def fixup(self):
        pass

    def unpack(self, structure):
        unpacked = super(SSS, self).unpack(structure)
        unpacked.fixup()
        return self

    def rescale(self, key):
        self.data[key] = (10**-(self.data[key] >> 14)) * (self.data[key] & 0x3fff)

    def passed(self, key='pass'):
        self.data[key] = bool(self.data[key] == 1)

class SSSRecordHeader(SSS):
    fields = [('payload_length', int, 2),
              ('nulls', int, 2),
              ('checksum_header', int, 2)]

    def checksum(self, payload):
        # checksum is the sum value of all the bytes in the payload portion
        self.data['checksum_payload'] = sum(payload) & 0xffff
        match = (self.data['checksum_header'] == self.data['checksum_payload'])
        self.data['checksum_match'] = match
        return match

class SSSVisualTest(SSS):
    fields = [('id', str, 16),
              ('hour', int, 1),
              ('minute', int, 1),
              ('day', int, 1),
              ('month', int, 1),
              ('year', int, 2),
              ('site', str, 16),
              ('location', str, 16),
              ('tester', str, 11),
              ('testcode1', str, 10),
              ('testcode2', str, 11)
              ]

class SSSNoDataTest(SSS):
    fields = []

class SSSEarthResistanceTest(SSS):
    fields = [('resistance', int, 2),
              ]

    def fixup(self):
        self.rescale('resistance')

class SSSEarthResistanceTestv2(SSS):
    fields = [('current', int, 1),
              ('pass', int, 1),
              ('resistance', int, 2),
              ]

    def fixup(self):
        self.rescale('resistance')
        self.passed()

class SSSEarthInsulationTest(SSS):
    fields = [('resistance', int, 2),
              ]

    def fixup(self):
        self.rescale('resistance')
        # Note: the displayed resistance for the Earth Insulation test
        # is capped at 19.99 MOhms or 99.99 MOhms depending upon the
        # model of meter.  Internally the meters appears to treat
        # infinity as somewhere around 185 MOhms and stores the actual
        # value measured (this is needed for calibration situations).
        # For simple result reporting, the value is capped to 99.99
        # MOhms, inline which what other software (and the meter's
        # display) does.
        #self.data['resistance'] = min(99.99, 0.01 * (self.data['resistance'] & 0x7fff))

class SSSCurrentTest(SSS):
    fields = [('current', int, 2),
              ]

    def fixup(self):
        self.rescale('current')

class SSSCurrentTestv2(SSS):
    fields = [('pass', int, 1),
              ('current', int, 2),
              ]

    def fixup(self):
        self.rescale('current')
        self.passed()

class SSSEarthInsulationTestv2(SSS):
    fields = [('pass', int, 1),
              ('resistance', int, 2),
              ]

    def fixup(self):
        self.rescale('resistance')
        self.passed()

class SSSPowerLeakTest(SSS):
    fields = [('leakage', int, 2),
              ('load', int, 2),
              ]

    def fixup(self):
        # Note: The 10/16ths current (load) scaling factor was
        # obtained from a sample size of two results only, both of
        # which were the same... Caveat emptor!
        self.rescale('leakage')
        self.rescale('load')

class SSSPowerLeakTestv2(SSS):
    fields = [('pass', int, 1),
              ('leakage', int, 2),
              ('load', int, 2),
              ]

    def fixup(self):
        self.data['pass'] = bool(self.data['pass'])
        self.rescale('leakage')
        self.rescale('load')

class SSSContinuityTest(SSS):
    fields = [('resistance', int, 2),
              ]

    def fixup(self):
        self.rescale('resistance')
        # Zero appears to correspond to infinity (no connection).
        # Which at least one other output software apparently shows as
        # "(no result)", instead of a numerical value.  This reported
        # behaviour is copied here.
        if self.data['resistance'] == 0.0:
            self.data['resistance'] = '(no result)'

class SSSContinuityTestv2(SSS):
    fields = [('pass', int, 1),
              ('resistance', int, 2),
              ]

    def fixup(self):
        self.rescale('resistance')
        self.passed()
        # Zero appears to correspond to infinity (no connection).
        # Which at least one other output software apparently shows as
        # "(no result)", instead of a numerical value.  This reported
        # behaviour is copied here.
        if self.data['resistance'] == 0.0:
            self.data['resistance'] = '(no result)'

class SSSUserDataMappingTest(SSS):
    fields = [('mapping1', int, 1),
              ('mapping2', int, 1),
              ('mapping3', int, 1),
              ('mapping4', int, 1),
              ]
    mappings = {0: 'Notes',
                1: 'Asset Description',
                2: 'Asset Group',
                3: 'Make',
                4: 'Model',
                5: 'Serial No.'}

    def fixup(self):
        for key, value in list(self.data.items()):
            self.data['meaning' + key[-1]] = self.mappings[value]

class SSSRetestTest(SSS):
    fields = [('nulls', int, 1),
              ('unknown', int, 1),
              ('frequency', int, 1),
              ]

class SSSSoftwareVersionTest(SSS):
    # Serial number matches format of examples on:
    # http://www.seaward.co.uk/faqs/pat-testers/how-do-i-download-my-primetest-3xx-
    fields = [('serialnumber', str, 11),
              ('firmware1', int, 1),
              ('firmware2', int, 1),
              ('firmware3', int, 1),
              ]

class SSSUserDataTest(SSS):
    fields = [('line1', str, 21),
              ('line2', str, 21),
              ('line3', str, 21),
              ('line4', str, 21),
              ]

TESTS_VERSION_1 = {
    0x01: ('Visual Pass (01)', SSSVisualTest),
    0x02: ('Visual Fail (02)', SSSVisualTest),
    0x10: ('Unknown (10)', SSSNoDataTest),
    0xe0: ('User Data Mapping (E0)', SSSUserDataMappingTest),
    0xe1: ('Retest (E1)', SSSRetestTest),
    0xf0: ('Overall Pass (F0)', SSSNoDataTest),
    0xf1: ('Overall Fail (F1)', SSSNoDataTest),
    0xf2: ('Earth Resistance (F2)', SSSEarthResistanceTest),
    0xf3: ('Earth Insulation (F3)', SSSEarthInsulationTest),
    0xf4: ('Substitute Leakage (F4)', SSSCurrentTest),
    0xf5: ('Flash Leakage (F5)', SSSCurrentTest),
    0xf6: ('Load/Leakage (F6)', SSSPowerLeakTest),
    0xf7: ('Flash Leakage (F5)', SSSCurrentTest),
    0xf8: ('Continuity (F8)', SSSContinuityTest),
    0xfa: ('Unknown (FA)', SSSNoDataTest),
    0xfb: ('User data (FB)', SSSUserDataTest),
    0xfe: ('Software Version (FE)', SSSSoftwareVersionTest),
    0xff: ('End of Record (FF)', SSSNoDataTest),
    }

TESTS_VERSION_2 = {
    0x11: ('Visual Pass v2 (11)', SSSVisualTest),
    0x12: ('Visual Fail v2 (12)', SSSVisualTest),
    0xf2: ('Earth Resistance v2 (F2)', SSSEarthResistanceTestv2),
    0xf3: ('Earth Insulation v2 (F3)', SSSEarthInsulationTestv2),
    0xf4: ('Substitute Leakage v2 (F4)', SSSCurrentTestv2),
    0xf5: ('Flash Leakage v2 (F5)', SSSCurrentTestv2),
    0xf6: ('Load/Leakage v2 (F6)', SSSPowerLeakTestv2),
    0xf7: ('Flash Leakage v2 (F7)', SSSCurrentTestv2),
    0xf8: ('Continuity v2 (F8)', SSSContinuityTestv2),
    0xf9: ('Lead Continuity Pass (F9)', SSSNoDataTest),
    }

class SSSSyntaxError(SyntaxError):
    pass

def parse_sss(filehandle):
    record_header = SSSRecordHeader()

    while True:
        header = filehandle.read(len(record_header))
        if not header:
            break
        parse_record(filehandle, record_header, header)

def parse_record(filename, record_header, header):
    tests = TESTS_VERSION_1.copy()
    version = 1

    record_header.unpack(header)
    payload = filename.read(record_header.data['payload_length'])
    validated = record_header.checksum(payload)
    
    print('New Record', record_header.items_dict())
    if record_header.data['payload_length'] == 0:
        raise SSSSyntaxError('Zero length payload')
    if not validated:
        raise SSSSyntaxError('Checksum validation failed')

    test_type = None
    while payload and test_type != 0xff:
        test_type = payload[0]
        payload = payload[1:]
        # Add in newer-style records if detected by presence of 0x11/0x12
        if version == 1 and test_type in (0x11, 0x12):
            version += 1
            tests.update(TESTS_VERSION_2)
        current_test = tests[test_type][1]()
        # Unpack the current sub-field
        current_test.unpack(payload[:len(current_test)])
        print(tests[test_type][0], current_test.items_dict())

        # Seek past to start of next sub-field
        payload = payload[len(current_test):]
    print()

def main():
    if len(sys.argv) < 2:
        print("usage: %s [input.sss]" % sys.argv[0], file=sys.stderr)
        sys.exit(2)

    # Simplify testing/dumping by allowing multiple input files on the command-line
    for filename in sys.argv[1:]:
        print('trying "%s"' % filename)
        file = open(filename, 'rb')
        contents = file.read()
        wrapped = BytesIO(contents)
        try:
            parse_sss(wrapped)
        except (SSSSyntaxError) as message:
            print('End File {Error:"%s"}' % message)
            continue

if __name__ == '__main__':
    main()
