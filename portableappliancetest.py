#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Paul Sladen, 2014-11-25, Seaward SSS PAT testing file format debug harness
# Hereby placed in the public domain in the hopes of improving
# electrical safety and interoperability
# Usage: ./portableappliancetest.py <input.sss>
#
# Ported to Python 3 by Angel Cascarino, 2019-02-01
# Sections rewritten by Tom Dufall Jan-Feb 2019
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
import xlsxwriter
import datetime
from io import BytesIO
import logging

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
                unpacked[0] = unpacked[0].decode('utf-8')
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

def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate

def parse_sss(filehandle, output_workbook):
    records = records_gen(filehandle, SSSRecordHeader())
    record_header = SSSRecordHeader()
    record = None
    record_id = 1
    while True:
        try:
            payload = next(records)
        except StopIteration:
            # file parsing complete
            break

        parse_record(payload, record_id, output_workbook)
        record_id += 1

def records_gen(filehandle, record_header):
    # Retrieve and validate record
    while True:
        header = filehandle.read(len(record_header))
        if not header:
            # handle this in record_header.unpack in the future
            break
        record_header.unpack(header)
        if record_header.data['payload_length'] == 0:
            logging.warning('Zero length payload for a record')
            continue
        payload = filehandle.read(record_header.data['payload_length'])
        if not record_header.checksum(payload):
            logging.error('Checksum validation failed for a record')
            continue
        yield payload

@static_vars(test_id=1)
def parse_record(payload, record_id, output_workbook):
    tests = TESTS_VERSION_1.copy()
    version = 1

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

        tests_written = report_record(record_id, current_test, test_type, parse_record.test_id, output_workbook)
        parse_record.test_id += tests_written

        # Seek past to start of next sub-field
        payload = payload[len(current_test):]

@static_vars(user_notes=(0, 1, 2, 3), user_counts=[0, 0, 0, 0, 0, 0])
def report_record(record_id, current_test, test_type, test_id, output_workbook):
    record_sheet, test_sheet = output_workbook.worksheets()[:2]

    #Set up constants for easy readability further down.
    #These influence the columns that each record type writes to.
    SOFTWARE_COLUMN = 8
    RECORD_DATA_COLUMN = 1
    USER_DATA_COLUMN = 2
    RETEST_FREQ_COLUMN = 10
    ROW_ORDER_COLUMN = 11
    OPTIONAL_SHEETS_OFFSET = 2

    tests_written = 0

    data_values = list(current_test.data.values())

    if test_type in (0x01, 0x02, 0x11, 0x12, 0xfe, 0xe0, 0xe1):
        #These all modify the 'record' sheet
        if test_type == 0xfe:
            #This contains data on tester serial number and firmware version
            #Combine firmware version into one string
            firmware_version = '%d.%d.%d' % tuple(data_values[1:])
            package = [data_values[0], firmware_version]
            record_sheet.write_row(record_id, SOFTWARE_COLUMN, package)
        elif test_type == 0xe0:
            #This tells us what the User Data fields actually mean.
            report_record.user_notes = tuple(data_values[0:4])
            record_sheet.write(record_id, ROW_ORDER_COLUMN, str(report_record.user_notes))
        elif test_type == 0xe1:
            #This is the retest frequency
            record_sheet.write(record_id, RETEST_FREQ_COLUMN, data_values[2])
        else:
            #This contains data on the record itself (time, place, tester)
            #Combine date-time related fields into a timestamp
            hour, minute, day, month, year = data_values[1:6]
            timestamp = datetime.datetime(year, month, day, hour, minute)
            package = [data_values[0], timestamp, *data_values[6:]]
            record_sheet.write_row(record_id, RECORD_DATA_COLUMN, package)
        record_sheet.write(record_id, 0, record_id)
        
    elif test_type in range(0xf0, 0xfb) or test_type == 0x10:
        #All the tests have different field meanings, so we'll just combine
        test_sheet.write_row(test_id, 0, [test_id, record_id, test_type, *data_values])
        tests_written += 1

    elif test_type == 0xfb:
        #This modifies the "optional data" sheets
        #These are the User Data fields.
        #Use the mapping from the E0 test to sort into correct place.
        #Assume 1 FB test per record, and assume FB follows an E0 record
        for indx, data_value in enumerate(data_values):
            if data_value:
                target = report_record.user_notes[indx]
                report_record.user_counts[target] += 1
                sheet = output_workbook.worksheets()[target + OPTIONAL_SHEETS_OFFSET]
                sheet.write_row(report_record.user_counts[target], 0, [record_id, data_value])

    else:
        pass

    return tests_written

def initialise_output(filename):
    output_workbook = xlsxwriter.Workbook(filename + '_output.xlsx', {'default_date_format': 'yyyy-mm-ddThh:mm'})

    record_sheet = output_workbook.add_worksheet("Records")
    record_sheet.write_row('A1', ["Record ID", "Item ID", "Timestamp", "Site", "Location", "Tester", "Testcode 1", "Testcode2", "Serial No.", "Firmware Version", "Retest Freq. (Months)", "User Data Input Order"])

    test_sheet = output_workbook.add_worksheet("Tests")
    test_sheet.write_row('A1', ["Test ID", "Record ID", "Test Type", "Test Parameter 1", "Test Parameter 2", "Test Parameter 3"])

    notes_sheet = output_workbook.add_worksheet("Item Notes")
    notes_sheet.write_row('A1', ["Record ID", "Notes"])

    desc_sheet = output_workbook.add_worksheet("Item Description")
    desc_sheet.write_row('A1', ["Record ID", "Asset Description"])

    group_sheet = output_workbook.add_worksheet("Item Group")
    group_sheet.write_row('A1', ["Record ID", "Asset Group"])

    make_sheet = output_workbook.add_worksheet("Item Make")
    make_sheet.write_row('A1', ["Record ID", "Make"])

    model_sheet = output_workbook.add_worksheet("Item Model")
    model_sheet.write_row('A1', ["Record ID", "Model"])

    serialnumber_sheet = output_workbook.add_worksheet("Item Serial Number")
    serialnumber_sheet.write_row('A1', ["Record ID", "Serial Number"])

    return output_workbook

def main():
    # set level of logging that gets displayed - debug<info<warning<error<critical
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("usage: %s [input.sss]" % sys.argv[0], file=sys.stderr)
        sys.exit(2)

    # Simplify testing/dumping by allowing multiple input files on the command-line
    for filename in sys.argv[1:]:
        print('trying "%s"' % filename)
        with open(filename, 'rb') as file:
            contents = file.read()
            wrapped = BytesIO(contents)
            output_workbook = initialise_output(filename)
            try:
                parse_sss(wrapped, output_workbook)
                output_workbook.close()
            except (SSSSyntaxError) as message:
                print('End File {Error:"%s"}' % message)
                output_workbook.close()
                continue

if __name__ == '__main__':
    main()
