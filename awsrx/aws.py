#! /usr/bin/python2.7
#coding=cp850
#mcit@geus.dk
# CASSANDRA version from 22/07/2021 onwards andrew.tedstone@unifr.ch
#
#rev. 21/3/2017 - add publish_to_ftp() and implement delivery of raw Freya data to ZAMG
#rev. 13/7/2017 - allow glob-style wildcards in filename passed to publish_to_ftp
#               - implement delivery of raw CEN_T data including malformed
#               - add -8191 to the values decoded as -INF (not sure if -8190 was a typo)
#rev. 08/2/2018 - add ability to append station name if known (relies on imei2name)
#rev. 08/2/2018 - publish_to_ftp() can be set to only publish the n most recent records
#rev. 19/2/2018 - don't ask for passwords if they can be read from a file under the 
#                 user's profile on the local machine (as secure as your geus pc is...)
#               - cleaned up some try/except logic
#               - dont't cast sbd_data['imei'] from str to int
#rev. 23/2/2018 - lots of changes to implement writing the columns headers at the top 
#                 of the csv files, the info is parsed out directly from the CRBasic
#                 program running in the logger. For now it's only for human use, the 
#                 actual binary decoding still uses the ugly payload_fmt dictionary
#rev. 20/6/2018 - nicer handling of ftp errors (special thanks to GEUS IT for surprise 
#                 discontinuation of ftp.geus.dk, thus triggering the bug...)
#rev. 02/7/2018 - add shebang for python launcher to pick py27
#rev. 14/2/2019 - add ftp to UWN
#rev  18/2/2019   preconfigured next available binary format (12)
#rev  12/09/2019  added THE VERSION-3!
#     07/11/2019  added debug decoding activated by uppercase number format letters
#     08/11/2019  now error messages print the full traceback including line number
#     ??          did I fix the gps decoding at some point and forgot? It works now
#     22/09/2020  cleanup some of the unused code and outdated comments before uploading to github
# ----------------
#     22/07/2021  UniFR CASSANDRA implementation - stripped out GEUS-specific codes, 
#                 updated message body format to match Rock7 delivery, 
#                 added FS2 telemetry format.
#     15/12/2021  Cleaned up code. Moved payload_fmts to another file, created env.ini.

from sorter import sorter
from tailer import tailer

from pprint import pprint

import imaplib
from ssl import PROTOCOL_TLSv1_2
import socket
import ssl
import email
from functools import partial
import re
import os, os.path
import struct
import subprocess as sp
import time, datetime, calendar
import warnings
import base64
import getpass
import os
import ftplib
import sys
import traceback
from ConfigParser import SafeConfigParser
from glob import glob
from collections import OrderedDict
import json

from payload_fmts import *

loc = os.path.dirname(os.path.realpath(__file__))

env_setup = SafeConfigParser()
env_setup.readfp(open(os.path.join(loc, 'env.ini')))

programs_dir = env_setup.get('locations', 'programs_dir')

credentials_file = "" # this should be somewhere secure
accounts_ini = SafeConfigParser()
accounts_ini.readfp(open(os.path.join(loc, 'accounts.ini')))
#accounts_ini.read(credentials_file) #optional, contains passwords, keep private

imei_file = 'imei2name.ini'
imei_ini = SafeConfigParser()
imei_ini.readfp(open(os.path.join(loc, imei_file)))
imei_names = dict(imei_ini.items('imei_to_name'))

allowed_sender_domains = json.loads(env_setup.get('settings', 'allowed_sender_domains'))


    
def parse_cr(program):

    def parse_declaration(norm_code):
        '''
        parse const and units declarations (not variables)
        '''
        
        name_value = norm_code.replace('const', '', 1).replace('units', '', 1)
        name, value = name_value.split('=', 1)
        return name.strip(), value.strip()


    def parse_table_def(norm_code):
        '''
        parse table to extract its name, the variables names and averaging methods
        '''
        
        table_def = norm_code.replace('datatable', '', 1).strip('()')
        table_name, _ = table_def.split(',', 1)
        return table_name.strip()


    def parse_table_var(norm_code, units):
        '''
        parse variable to extract its name, number format and averaging method
        '''
        
        fmt_vars_count = {'0': 3,  #Mean horizontal wind speed, unit vector mean wind direction, and standard deviation of wind direction
                          '1': 2,  #Mean horizontal wind speed and unit vector mean wind direction
                          '2': 4,  #Mean horizontal wind speed, resultant mean wind speed, resultant mean wind direction, and standard deviation of wind direction
                          '3': 1,  #Unit vector mean wind direction # WARNING: untested/unsupported
                          '4': 2,  #Unit vector mean wind direction and standard deviation of wind direction
                          }
        
        avg_meth, rest = norm_code.split('(', 1)
        avg_meth = avg_meth.strip()
        reps, var_name, params = rest.strip(' ()').split(',', 2)
        try:
            reps = int(reps)
        except ValueError:
            reps = int(constants[reps])
                    
        if '(' in var_name:
            var_name, _ = var_name.strip(')').split('(', 1)

        if avg_meth == ('sample' or 'minimum'):
            var_type = params
            
        elif avg_meth == 'average':
            var_type, _ = params.split(',')
            
        if avg_meth == 'windvector':
            fmt = params[-1]
            vars_count = fmt_vars_count[fmt]
            if vars_count < 2: raise Warning('untested/unsupported var_count < 2')
            _, var_type, _ = params.split(',', 2)
            reps = reps * vars_count
        
        table_vars = OrderedDict()
        for n in range(1, reps+1):
            if reps > 1:
                name = '%s_%i' %(var_name, n)
            else:
                name = var_name
            if not var_name.endswith('dataterminator'):
                table_vars[name] = [avg_meth, var_type, units.get(name, '')]
            
        return table_vars


    def parse_fieldnames(norm_code):
        '''
        parse FieldNames (the otional descriptions are not supported)
        '''
        
        names = norm_code.replace('fieldnames', '', 1).strip('(" )').split(',')
        
        return names
    
    # ====================
    # for now it does not look at aliases so it can't always properly name 
    # variables and associate units. Also, turning everything lowercase for
    # ease of parsing alters the names of variables and units
    
    constants = {}
    units = {}
    tables = {}
    multiline = []
    
    with open(program) as pf:
        for ln, line in enumerate(pf):
            if "'" in line:
                code, comment = line.split("'", 1)
            else:
                code, comment = line, ''
            norm_code = code.strip().lower()  #CRBasic is case-insensitive
            
            if not multiline:
                if norm_code.startswith('const'):
                    constants.setdefault(*parse_declaration(norm_code))
                if norm_code.startswith('units'):
                    units.setdefault(*parse_declaration(norm_code))
                if norm_code.startswith('datatable'):
                    this_table_name = parse_table_def(norm_code)
                    print 'parsing', this_table_name, 'in', program
                    this_table_vars = OrderedDict()
                    multiline.append('table_def')
                    
            elif multiline[-1] == 'table_def':
                if norm_code.startswith('endtable'):
                    tables[this_table_name] = this_table_vars
                    this_table_name = None
                    this_table_vars = None
                    if multiline.pop() != 'table_def':
                        raise RuntimeError('parse error at line %i of %s'
                                           % (ln, p))
                elif any((norm_code.startswith('sample'),
                          norm_code.startswith('average'),
                          norm_code.startswith('minimum'),
                          norm_code.startswith('maximum'),
                          norm_code.startswith('windvector'))):
                    this_table_vars.update(parse_table_var(norm_code, units))
                elif norm_code.startswith('fieldnames'):
                    new_names = parse_fieldnames(norm_code)
                    old_names = this_table_vars.keys()[-len(new_names):]
                    for newn, oldn in zip(new_names, old_names):
                        this_table_vars[newn] = this_table_vars[oldn]
                        this_table_vars.pop(oldn)
                            
    binarytxformatid = int(constants['binarytxformatid'])
    return binarytxformatid, constants, units, tables


def build_headers(b, tables):
    
    msg_type = b % 5
    header = ''
    units = ''
    if msg_type == 0 or msg_type == 1:
        for tn in tables:
            if ('summer' or '60min') in tn.lower(): #it's always summer for Allan's 60 minutes
                header += ','.join(tables[tn].keys())
                units += ','.join(['%s (%s)' % (averaging, units) for
                                   averaging, vartype, units in
                                   tables[tn].values()])
                
    if msg_type == 2 or msg_type == 3:
        for tn in tables:
            if 'winter' in tn.lower():
                header += ','.join(tables[tn].keys())
                units += ','.join(['%s (%s)' % (averaging, units) for
                                               averaging, vartype, units in
                                               tables[tn].values()])
                
    if msg_type == 1 or msg_type == 3:
        for tn in tables:
            if 'instantaneous' in tn.lower():
                header += ','
                header += ','.join(tables[tn].keys())
                units += ','
                units += ','.join(['%s (%s)' % (averaging, units) for
                                               averaging, vartype, units in
                                               tables[tn].values()])

    if msg_type == 4:
        for tn in tables:
            if 'diagnostics' in tn.lower():
                header += ','.join(tables[tn].keys())
                units += ','.join(['%s (%s)' % (averaging, units) for
                                               averaging, vartype, units in
                                               tables[tn].values()])
                
    return '\n'.join((','.join((' timestamp', 'seconds_since_1990', header)),
                      ''.join(('-,', 'sec,', units)), 
                      ))  # space is for getting sorted at the top...


    
def parse_programs(programs_dir):
    
    headers = {}
    
    for p in programs_dir:
        binarytxformatid, constants, units, tables = parse_cr(p)
        for b in range(binarytxformatid * 5, binarytxformatid * 5 + 5):
            if b in headers:
                continue  #raise Warning('format %i already known' %b)
            headers[b] = build_headers(b, tables)
            #print b, headers[b]
    
    return headers



class IMAP4_TLS(imaplib.IMAP4_SSL):
    #Bring to the IMAP protocol some of the recent security improvements of
    #PEP 476, so this probably requires python 2.7.9 or even 2.7.10
    #It is perhaps still not validating the server certificate because it
    #requires an external library, so MITM is still possible.
    #
    #inspired to:
    # http://www.gossamer-threads.com/lists/python/python/1132087
    # http://blog.dornea.nu/2015/05/24/validating-and-pinning-x509-certificates


    def open(self, host, port):

        self.host = host
        self.port = port

        # Create new SSL context with most secure TLS v1.2
        # FIXME: Deprecated since version 2.7.13, use PROTOCOL_TLS | OP_NO_TLSv1_2 | OP_NO_TLSv1_1 | OP_NO_SSLv3 | OP_NO_SSLv2
        ssl_context = ssl.SSLContext(PROTOCOL_TLSv1_2)

        # Forbid downgrade to insecure SSLv2 nor SSLv3 (may be redundant)
        ssl_context.options |= ssl.OP_NO_SSLv2
        ssl_context.options |= ssl.OP_NO_SSLv3

        # Prevent CRIME and TIME attacks
        ssl_context.options |= ssl.OP_NO_COMPRESSION

        # Require that a server certificate is returned and is valid
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        ssl_context.verify_flags |= ssl.VERIFY_X509_STRICT
        #ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        #ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

        try:
            import certifi
        except ImportError:
            # load system certificates, not the best ones but always available
            ssl_context.load_default_certs()
            warnings.warn('certifi not installed, will use default system certificates')
        else:
            #load quality certificates if available (requires certifi library)
            ssl_context.load_verify_locations(certifi.where())

        #TODO: retrieve and load CRL as a PEM file (mostly useless anyways)
        #ssl_context.load_verify_locations(r"C:\Python27_64\Lib\test\revocation.crl")

        # Allow only good ciphers
        ssl_context.set_ciphers('HIGH:ECDHE:!aNULL:!RC4:!DSS')

        # Check host name
        ssl_context.check_hostname = True

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sslobj = ssl_context.wrap_socket(self.sock, server_hostname=host)
        self.sslobj.connect((host, port))

        #self.sock = socket.create_connection((host, port))
        #self.sslobj = ssl.wrap_socket(
            #self.sock,
            #self.keyfile,
            #self.certfile,
            #ssl_version=ssl_version,
        #)
        self.file = self.sslobj.makefile('rb')


class EmailMessageError(Exception): pass
class SbdMessageError(Exception): pass
class TrackerMessageError(Exception): pass
class AwsMessageError(Exception): pass
class NotEmailMessageError(ValueError): pass
class NotSbdMessageError(ValueError): pass
class NotTrackerMessageError(ValueError): pass
class NotAwsMessageError(ValueError): pass


class EmailMessage(object):

    def __init__(self, email_msg):
        self.validate_email(email_msg)
        self._email_msg = email_msg
        self.metadata = {} #this should be inherited from MimirObject
        self.metadata['email_metadata'] = NotImplemented
        self.data = {}
        self.data['email_data'] = self.parse_email()

    def validate_email(self, email_msg):
        if not isinstance(email_msg, email.message.Message):
            raise NotEmailMessageError

    def parse_email(self):
        email_data = {}
        email_data['from'] = self._email_msg.get_all('from')[0]
        email_data['to'] = self._email_msg.get_all('to')
        email_data['subject'] = self._email_msg.get_all('subject')[0]
        email_data['date'] = self._email_msg.get_all('date')[0]
        email_data['attached_filenames'] = []

        if self._email_msg.is_multipart():
            for part in self._email_msg.get_payload():
                fn = part.get_filename()
                if fn: email_data['attached_filenames'].append(fn)

        return email_data


class SbdMessage(EmailMessage):

    data_entries = {'IMEI': 'imei',
                    'MOMSN': 'momsn',
                   'Transit Time': 'session_utc',
                   'Iridium Session Status': 'session_status',
                   'Iridium CEP': 'cep_radius'
                   }

    data_decoders = {'IMEI': '_parse_int',
                     'MOMSN': '_parse_int',
                     'Transit Time': '_parse_str',
                     'Iridium Session Status': '_parse_int',
                     'Iridium CEP': '_parse_float'
                     }

    def __init__(self, sbd):
        super(SbdMessage, self).__init__(sbd)
        self.validate_sbd(sbd)
        self.data['sbd_data'] = self.parse_sbd()
        #if self.data['sbd_data']['imei'] == 300234061852400: 
            #print '!'
        pass

    def validate_sbd(self, sbd):

        sender = self.data['email_data']['from']
        # There is a trailing '>' character, remove it.
        sender_domain = sender.split('@')[1][:-1]
        if sender_domain not in allowed_sender_domains:
            raise NotSbdMessageError("'sbdservice' not in %s" % sender)
        if len(self.data['email_data']['attached_filenames']) == 0:
            warnings.warn('sbd email %s %s has no *.sbd attachment' % (self.data['email_data']['date'],
                                                                       self.data['email_data']['subject']))
        for fn in self.data['email_data']['attached_filenames']:
            root, ext = os.path.splitext(fn)
            if (ext != '.sbd') and (ext != '.bin'):
                raise NotSbdMessageError("attachment %s not .sbd" % fn)


    def parse_sbd(self):
        #print(self._email_msg.get_payload())
        if self._email_msg.is_multipart():
            #print('multipart')
        #try:
            content, attachment = self._email_msg.get_payload()
            assert not content.is_multipart() #else the decode=True on the next line makes it return None and break the rest of the parsing
            body = content.get_payload(decode=True)

        else:
            #print('not multipart')
        #except ValueError:
            content = self._email_msg.get_payload(decode=True)#[0]
            attachment = None  #sometimes an email arrives with no .sbd attached
            body = content#.get_payload(decode=True)

        sbd_data = {}
        for line in body.splitlines():
            for key, entry in self.data_entries.items():
                if key in line:
                    decoder = getattr(self, self.data_decoders[key])
                    #decoder = partial(decoder, key, (': ', ' = '))
                    sbd_data[entry] = decoder(key, (': ', ' = '), line)

        if attachment != None:
            #print('Attachment:')
            #print(attachment)
            sbd_payload = attachment.get_payload(decode=True)
            # Rock7 SBD messages do not provide message size.
            #assert len(sbd_payload) == sbd_data['message_size']
            sbd_data['payload'] = sbd_payload
            #print('Payload:', sbd_payload)
        else:
            sbd_data['payload'] = None

        return sbd_data

    @staticmethod
    def _parse_int(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        return int(val)

    @staticmethod
    def _parse_float(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        return float(val)

    @staticmethod
    def _parse_str(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        return val

    @staticmethod
    def _parse_session_status(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        status = {}
        code, descr = val.split(' - ')
        status['code'], status['description'] = int(code), descr
        return status

    @staticmethod
    def _parse_unit_location(label, seps, string):
        for s in seps:
            try:
                _, val = string.split(label + s)
            except ValueError:
                continue
            else:
                break
        tokens = val.split()
        assert tokens[0].lower() == 'lat'
        assert tokens[3].lower() == 'long'
        location = {}
        location['lat'] = float(tokens[2])
        location['long'] = float(tokens[5])
        return location


class AwsMessage(SbdMessage):

    def __init__(self, aws_sbd):
        
        super(AwsMessage, self).__init__(aws_sbd)

        self.payload_fmt, self.type_len = payload_fmt, type_len  #TODO: this must come from a YAML file

        # Win32 epoch is 1st Jan 1601 but MSC epoch is 1st Jan 1970 (MSDN gmtime docs), same as Unix epoch.
        # Neither Python nor ANSI-C explicitly specify any epoch but CPython relies on the underlying C
        # library. CRbasic instead has the SecsSince1990() function.
        UnixEpochOffset = calendar.timegm((1970, 1, 1, 0, 0, 0, 0, 1, 0)) #this should always evaluate to 0 in CPython on Win32, but anyways
        CRbasicEpochOffset = calendar.timegm((1990, 1, 1, 0, 0, 0, 0, 1, 0))
        self.EpochOffset = UnixEpochOffset + CRbasicEpochOffset

        self.validate(aws_sbd)
        self.data['aws_data'] = self.parse_aws() #TODO: when generalizing, 'aws_data' should not be hardcoded but come from some 'aws' label passed to the init or something.
        pass

    def validate(self, aws_sbd):
        if self.data['sbd_data']['payload'] == None:
            raise NotAwsMessageError('no .sbd file attached to this SBD message')
        fmt = ord(self.data['sbd_data']['payload'][0])
        if fmt not in self.payload_fmt:
            raise NotAwsMessageError('unrecognized first byte %s' %hex(ord(self.data['sbd_data']['payload'][0])))

    def parse_aws(self, external=True):

        aws_data = {}

        payload = self.data['sbd_data']['payload']

        #============== adapted from old, should be cleaned up =========================================
        DataLine = payload

        IsTooLong = False
        IsTooShort = False
        if len(DataLine) == 0: raise AwsMessageError()
        if DataLine[0].isdigit():
            print('here')
            IsKnownBinaryFormat = False
            MessageFormatNum = -9999
        else:
            MessageFormatNum = ord(DataLine[0])
            try:
                MessageFormat = self.payload_fmt[MessageFormatNum]
                IsKnownBinaryFormat = True
            except KeyError:
                IsKnownBinaryFormat = False
                UnknMsgFormNum = MessageFormatNum
            # 'Bodge' for Breithornplateau - this site has the wrong BinaryFormat set logger-side
            # Detect the site based on modem IMEI and force the payload format.
            if self.data['sbd_data']['imei'] == 300434065667190:
                IsKnownBinaryFormat = True
                if MessageFormatNum == 30:
                    MessageFormatNum = 60
                    MessageFormat = self.payload_fmt[60]
                elif MessageFormatNum == 32:
                    MessageFormatNum = 62
                    MessageFormat = self.payload_fmt[62]
                else:
                    raise ValueError('Unknown BHP format.')
            if IsKnownBinaryFormat:
                print '%s-%s (binary)' %(self.data['sbd_data']['imei'], self.data['sbd_data']['momsn']) , MessageFormat[2]
                ExpectedMsgLen = MessageFormat[3]
                BinaryMessage = DataLine[1:]
                DataLine = ''
                BytePointer = 0
                ValueBytes = []
                for ValueNum in range(0, MessageFormat[0]):
                    
                    if ValueBytes: #means we have just parsed a value so if needed add debug an always add a comma
                        if type_letter.isupper(): #then it's meant for adding debug output
                            DataLine = DataLine + self.RAWtoSTR(ValueBytes)
                        DataLine = DataLine + ','
                        ValueBytes = []
                        
                    type_letter = MessageFormat[1][ValueNum]
                    ValueBytesCount = self.type_len[type_letter.lower()]
                    
                    if type_letter.lower() == 'f':
                        try:
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GFP2toDEC(ValueBytes)
                            if Value == 8191:
                                DataLine = DataLine + "NAN"
                            elif Value == 8190:
                                DataLine = DataLine + "INF"
                            elif Value == -8190 or Value == -8191: #so, which one is correct?
                                DataLine = DataLine + "-INF"
                            else:
                                DataLine = DataLine + str(Value)
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 'l':
                        try:
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + str(Value)
                            if Value in (-2147483648, 2147450879):
                                DataLine = DataLine + "NAN"
                            else:
                                DataLine = DataLine + str(Value)
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 't':
                        try:
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(Value + self.EpochOffset)) + ',' + str(Value)
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 'g':
                        try:
                            for offset in range(0,2):                                
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            if self.GFP2toDEC(ValueBytes) == 8191: #the logger sends a 2-bytes NAN instead of a 4-bytes gps values when the gps data isn't available
                                DataLine = DataLine + "NAN,"
                                BytePointer = BytePointer + 2
                                ExpectedMsgLen -= 2 #this is to fix the expected length of the message which is shorter when 2-bytes NAN come in instead of 4-byte gps values
                                continue
                            else:
                                ValueBytes = []
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + str(Value/100.0)
                            #else:
                                #DataLine = DataLine + "NAN"
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 'n':
                        try:
                            for offset in range(0,2):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            if self.GFP2toDEC(ValueBytes) == 8191: #the logger sends a 2-bytes NAN instead of a 4-bytes gps values when the gps data isn't available
                                DataLine = DataLine + "NAN,"
                                BytePointer = BytePointer + 2
                                ExpectedMsgLen -= 2 #this is to fix the expected length of the message which is shorter when 2-bytes NAN come in instead of 4-byte gps values
                                continue
                            else:
                                ValueBytes = []
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + str(Value/100000.0)
                            #else:
                                #DataLine = DataLine + "NAN"
                        except IndexError:
                            DataLine = DataLine + '?'
                    elif type_letter.lower() == 'e':
                        try:
                            for offset in range(0,2):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            if self.GFP2toDEC(ValueBytes) == 8191: #the logger sends a 2-bytes NAN instead of a 4-bytes gps values when the gps data isn't available
                                DataLine = DataLine + "NAN,"
                                BytePointer = BytePointer + 2
                                ExpectedMsgLen -= 2 #this is to fix the expected length of the message which is shorter when 2-bytes NAN come in instead of 4-byte gps values
                                continue
                            else:
                                ValueBytes = []
                            for offset in range(0,ValueBytesCount):
                                ValueBytes.append(ord(BinaryMessage[BytePointer + offset]))
                            BytePointer = BytePointer + ValueBytesCount
                            Value = self.GLI4toDEC(ValueBytes)
                            DataLine = DataLine + str(Value/100000.0)
                            #else:
                                #DataLine = DataLine + "NAN"
                        except IndexError:
                            DataLine = DataLine + '?'
                    #if type_letter.isupper(): #then it's meant for adding debug output
                        #DataLine = DataLine + self.RAWtoSTR(ValueBytes)
                    #DataLine = DataLine + ','
                #DataLine = DataLine[:-1] # to remove the trailing comma character
        IsDiagnostics = '!D' in DataLine[-5:-3] or MessageFormatNum % 5 == 4#FIXME: the stats are wrong because we don't always go through here
        IsObservations = '!M' in DataLine[-2:] or IsKnownBinaryFormat
        IsSummer = ('!S' in DataLine and '!M' in DataLine[-2:]) or MessageFormatNum % 5 in (0, 1)
        IsWinter = ('!W' in DataLine and '!M' in DataLine[-2:]) or MessageFormatNum % 5 in (2, 3)
        IsWithInstant = '!I' in DataLine[-5:-3] or (MessageFormatNum % 5 in (1, 3) and MessageFormatNum != -9999)
        if not IsKnownBinaryFormat:
            print '%s-%s' %(self.data['sbd_data']['imei'], self.data['sbd_data']['momsn']),
            if IsDiagnostics: print '(ascii) generic diagnostic message',
            elif IsObservations and IsSummer:print '(ascii) generic summer observations message',
            elif IsObservations and not IsSummer: print '(ascii) generic winter observations message',
            else: print 'unrecognized message format',
            if IsWithInstant:
                print '(+ instant.)'
            else:
                print ''
        else:
            if len(BinaryMessage)+1 < ExpectedMsgLen:
                IsTooShort = True
            elif len(BinaryMessage)+1 > ExpectedMsgLen:
                IsTooLong = True
                
        IsMalformed = IsTooLong or IsTooShort
        if IsMalformed:
            print (''.join((chr(MessageFormatNum), BinaryMessage))).decode('cp850')
            print "  WARNING - Message malformed: expected %i bytes, found %i" %(ExpectedMsgLen, len(BinaryMessage)+1)
            print "            if binary, missing values replaced by '?' and extra values dropped"
    
        if IsMalformed and FilterMalformed:
            flag = '-F'
        elif IsDiagnostics:
            flag = '-D'
        elif IsObservations:
            flag = ''
        else: #if not diagnostics nor a properly terminated message or known binary format, then it's garbage and gets dumped here
            flag = '-X'
        
        aws_data['firstbyte_fmt'] = MessageFormatNum
        aws_data['decoded_string'] = DataLine
        aws_data['flag'] = flag
        return aws_data

    @staticmethod
    def GFP2toDEC(Bytes):
        msb = Bytes[0]
        lsb = Bytes[1]
        Csign = -2*(msb & 128)/128 + 1
        CexpM = (msb & 64)/64
        CexpL = (msb & 32)/32
        Cexp = 2*CexpM + CexpL - 3
        Cuppmant = 4096*(msb & 16)/16 + 2048*(msb & 8)/8 + 1024*(msb & 4)/4 + 512*(msb & 2)/2 + 256*(msb & 1)
        Cnum = Csign * (Cuppmant + lsb)*10**Cexp
        return Cnum

    @staticmethod
    def GLI4toDEC(Bytes):
        Csign = -2 * (Bytes[0] & 0x80) / 0x80 + 1
        byte1 = Bytes[0] & 127
        byte2 = Bytes[1]
        byte3 = Bytes[2]
        byte4 = Bytes[3]
        return Csign * byte1 * 0x01000000 + byte2 * 0x010000 + byte3 * 0x0100 + byte4
    
    @staticmethod
    def RAWtoSTR(Bytes):
        us = [unichr(byte) for byte in Bytes] #the unicode strings
        hs = ['0x{0:02X}'.format(byte) for byte in Bytes] #the hex strings
        bs = ['0b{0:08b}'.format(byte) for byte in Bytes] #the bit strings
        return '(%s = %s = %s)' %(' '.join(us), ' '.join(hs), ' '.join(bs))




def connect(host, port, user, passw):

    assert ssl.RAND_status()

    mail_server = IMAP4_TLS(host, port)

    # verify TLS is allright before disclosing login credentials
    context = mail_server.ssl().context
    assert context.check_hostname
    ssl.match_hostname(mail_server.sslobj.getpeercert(), host)

    mail_server.login(user, passw)

    return mail_server


def new_mail(mail_server, last_uid=1):

    # issue the search command of the form "SEARCH UID 42:*"
    command = '(UID {}:*)'.format(last_uid)
    result, data = mail_server.uid('search', None, command)
    messages = data[0].split()
    print 'new UIDs: %s' %data[0]

    # yield mails
    for message_uid in messages:
        # SEARCH command *always* returns at least the most
        # recent message, even if it has already been synced
        if int(message_uid) > last_uid:
            print 'fetching', message_uid
            result, data = mail_server.uid('fetch', message_uid, '(RFC822)')
            # yield raw mail body
            yield message_uid, data[0][1]


def publish_to_ftp(filename, host, user, passwd, acct='', path='.', passive=True):
    
    for fn in glob(filename):
        
        print 'publishing', filename, 'to', '/'.join((host, path))
        
        remote_fn = os.path.basename(fn)
        subdirs = path.split('/')
        
        try:
            
            ftp = ftplib.FTP(host, user, passwd, acct)
            ftp.set_pasv(passive)
        
            if path != '.':
                for dirname in subdirs:
                    try:
                        ftp.cwd(dirname)
                    except ftplib.error_perm, e:
                        ftp.mkd(dirname)
                        ftp.cwd(dirname)
            
            with open(fn, 'rb') as f_in:
                ftp.storbinary('STOR %s' %remote_fn, f_in)
        except Exception, e:
            raise e
              
        else:
            ftp.close()
    
    

def getmyawsdata(account=None, 
                 password=None, 
                 server='imap.gmail.com', 
                 port=993,
                 ):
    
    programs = glob(os.sep.join((programs_dir, '*.cr1')))
    print 'parsing %s for message formats' %', '.join(programs)
    
    #for p in programs:
    headers = parse_programs(glob(os.sep.join((programs_dir, '*.cr*'))))
    print "found definitions for %s 'first byte' formats" %', '.join([str(k) for k in sorted(headers.keys())])
    print 'AWS data from server %s, account %s' %(server, account)
    
    account = account or raw_input('account: ')
    password = password or raw_input('password: ')
    server = server or raw_input('server: ')
    port = port or raw_input('port: ')
    
    out_dir = env_setup.get('locations', 'out_dir')

    try:
        with open(os.path.join(loc, 'last_aws_uid.ini'), 'r') as last_uid_f:
            last_uid = int(last_uid_f.readline())
    except Exception:
        last_uid = 1 #
        #int(raw_input('last_aws_uid.ini not found, first UID? (deafult = 1)') or 1)

    try:
        mail_server = connect(server, port, account, password)

        #resp = mail_server.list()
        #assert resp[0].upper() == 'OK'
    
        result, data = mail_server.select(mailbox='INBOX', readonly=True)
        print 'mailbox contains %s messages' %data[0]
        
        modified_files = {}
    
        for uid, mail in new_mail(mail_server, last_uid=last_uid):
    
            message = email.message_from_string(mail)
            
            try:
                aws_msg = AwsMessage(message)
            except ValueError, e:
                print e
                continue
        
            #remembering the uid allows skipping messages certainly done already,
            #but a crash between the data save and the update of last_uid will
            #result in duplicating the last message (i.e., this does not replace
            #duplicate checking before parsing/appending, which is still TODO)
    
            out_fn = 'AWS_%s%s.txt' % (aws_msg.data['sbd_data']['imei'],
                                       aws_msg.data['aws_data']['flag'])
            out_path = os.sep.join((out_dir, out_fn))
            
            aws_name = imei_names.get(str(aws_msg.data['sbd_data']['imei']), 'UNKNOWN')
            
            #write_header = out_path not in  modified_files.keys()
            modified_files[out_path] = [aws_name, 
                                        '%s' % headers.get(aws_msg.data['aws_data']['firstbyte_fmt'], '')]
    
            with open(out_path, mode='a') as out_f:
                out_f.write('%s\n' %aws_msg.data['aws_data']['decoded_string'].encode('Latin-1'))
                #print('WRITING: ', aws_msg.data['aws_data']['decoded_string'].encode('Latin-1'))
                #if write_header:
                    #out_f.write('%s\n' % headers.get(aws_msg.data['aws_data']['firstbyte_fmt'], ''))
    
            with open(os.path.join(loc, 'last_aws_uid.ini'), 'w') as last_uid_f:
                last_uid_f.write(uid)

            
    except Exception, e:
        traceback.print_exc(file=sys.stdout)
        #print e
        
    finally:
        if 'mail_server' in locals():
            print 'closing', account
            mail_server.close()
            resp = mail_server.logout()
            assert resp[0].upper() == 'BYE'
    
    return modified_files



class LockFile(object): #TODO: could this be nicer to use as a context manager?
    
    def __init__(self, file_path=os.path.join(loc, 'lock.txt'), acquire_later=False):
        
        self.file_path = file_path
        self.lock = None
        if not acquire_later:
            self.acquire()
                  
    
    def _create_lock_file(self, file_path):
        lock = open(file_path, 'w')
        lock.write('%s owns or last owned the lock. This file is used to prevent more than one instance of the program\n'
                   'from running at the same time, which would screw up the output files. Just ignore it.'% getpass.getuser())
        lock.flush()
        return lock
    
    
    def acquire(self):
        #This is not 100.00% reliable but is good enough. The catch being that someone else may create the lock 
        #file just after open(file_path, 'r') failed for not finding it but before we manage to create it ourselves.
        #When this happens, we both end up owning the same lock (because creating a file doesn't fail if it exists).
        #However fixing this cross platform and on a network share is too much effort.
        
        try:
            open(self.file_path, 'r')
        except IOError:
            self.lock = self._create_lock_file(self.file_path)
            return True
        else:
            try:
                os.remove(self.file_path)
            except OSError:
                raise RuntimeError('lock %s already taken' %self.file_path)
            else:
                self.lock = self._create_lock_file(self.file_path)
                return True
    
    
    def release(self):
        if self.lock:
            self.lock.close()
            os.remove(self.file_path)
        return True



def main(argv):
    
    interval = env_setup.getint('settings', 'interval')
    
    try:
        lock = LockFile()

    except RuntimeError, e:
        print e
        print "somebody is already running this on the same directory, you can't nor need to"
        raw_input()
        
    else:
        print 'will fetch data every %i seconds' %interval
        
        password_aws = accounts_ini.get('aws', 'password')
        if not password_aws:
            password_aws = raw_input('password for AWS email account: ')
                        
        while interval:
            try:
                modified_files = getmyawsdata(accounts_ini.get('aws', 'account'),
                                              password_aws,
                                              accounts_ini.get('aws', 'server'),
                                              accounts_ini.getint('aws', 'port'),
                                              )
                sorter(modified_files)
                tailer(modified_files, 100, env_setup.get('locations', 'tails'))
                
            except Exception, e:
                traceback.print_exc(file=sys.stdout)
                print time.asctime(), '- restarting in 5 minutes...'
                time.sleep(300)
            else:
                print 'latest data check:', time.asctime()
                time.sleep(interval)
        
    finally: #still skipped if shell or process are killed
        lock.release()


FilterMalformed = True

for item in payload_fmt.items():
    key, val = item
    var_count, var_def, comment = val
    assert var_count == len(var_def)
    bytes_count = 0
    for var in var_def:
        bytes_count += type_len[var.lower()]
    payload_fmt[key].append(bytes_count + 1) #add the format byte


if __name__ == '__main__':
    import sys
    print 'python', sys.version
    print sys.executable
    print os.getcwdu()
    sys.exit(main(sys.argv))
