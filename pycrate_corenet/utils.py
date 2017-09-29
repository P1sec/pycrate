# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2017. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
# *
# *--------------------------------------------------------
# * File Name : pycrate_corenet/utils.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# Python built-ins libraries required
import sys
import socket
import random
import re
#import traceback
from select    import select
from threading import Thread, Lock
from random    import SystemRandom
from time      import time, sleep
from datetime  import datetime
from binascii  import hexlify, unhexlify
from struct    import unpack

# SCTP support for S1AP / RUA interfaces
try:
    import sctp
except ImportError as err:
    print('pysctp library required for CorenetServer')
    print('check on github: pysctp from philpraxis for python2, from lilydjwg for python3')
    raise(err)

# conversion function for security context
try:
    from CryptoMobile.Milenage import conv_C2, conv_C3, conv_C4, conv_C5, \
                                      conv_A2, conv_A3, conv_A4, conv_A7
except ImportError as err:
    print('CryptoMobile library required for CorenetServer')
    raise(err)

from pycrate_core.utils import *

log('CorenetServer: loading all ASN.1 and NAS modules, be patient...')
# import ASN.1 modules
# to drive eNodeB and Home-eNodeB
from pycrate_asn1dir import S1AP
# to drive Home-NodeB
from pycrate_asn1dir import HNBAP
from pycrate_asn1dir import RUA
from pycrate_asn1dir import RANAP
# to decode UE 3G and LTE radio capability
from pycrate_asn1dir import RRC3G
from pycrate_asn1dir import RRCLTE

# to drive 3G UE
from pycrate_mobile  import TS24007
from pycrate_mobile  import TS24008_IE
from pycrate_mobile  import TS24008_MM
from pycrate_mobile  import TS24008_GMM
#from pycrate_mobile  import TS24008_CC
#from pycrate_mobile  import TS24008_SM

# to drive LTE UE
#from pycrate_mobile  import TS24301_NAS
#from pycrate_mobile  import TS24301_EMM
#from pycrate_mobile  import TS24301_ESM

from pycrate_mobile  import NAS


#------------------------------------------------------------------------------#
# ASN.1 objects
#------------------------------------------------------------------------------#

# actually, all ASN.1 modules are in ASN_GLOBAL
ASN_GLOBAL = S1AP.GLOBAL.MOD

# ASN.1 PDU encoders / decoders
PDU_S1AP  = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
PDU_HNBAP = HNBAP.HNBAP_PDU_Descriptions.HNBAP_PDU
PDU_RUA   = RUA.RUA_PDU_Descriptions.RUA_PDU
PDU_RANAP = RANAP.RANAP_PDU_Descriptions.RANAP_PDU

# ASN.1 modules are not thread-safe
# objects' value will be mixed in case a thread ctxt switch occurs between 
# the fg interpreter and the bg CorenetServer loop, and both accesses the same
# ASN.1 module
LOCK_S1AP  = Lock()
LOCK_HNBAP = Lock()
LOCK_RUA   = Lock()
LOCK_RANAP = Lock()

_ACQUIRE_SLEEP = 0.0003
_ACQUIRE_TO    = 300 # in number of sleep()

def s1ap_acquire():
    if LOCK_S1AP.locked():
        # wait for the other thread to end its use of the S1AP module
        i = 0
        while LOCK_S1AP.locked():
            i += 1
            sleep(_ACQUIRE_SLEEP)
            if i == _ACQUIRE_TO:
                return False
    LOCK_S1AP.acquire()
    return True

def s1ap_release():
    LOCK_S1AP.release()

def hnbap_acquire():
    if LOCK_HNBAP.locked():
        # wait for the other thread to end its use of the HNBAP module
        i = 0
        while LOCK_HNBAP.locked():
            i += 1
            sleep(_ACQUIRE_SLEEP)
            if i == _ACQUIRE_TO:
                return False
    LOCK_HNBAP.acquire()
    return True

def hnbap_release():
    LOCK_HNBAP.release()

def rua_acquire():
    if LOCK_RUA.locked():
        # wait for the other thread to end its use of the RUA module
        i = 0
        while LOCK_RUA.locked():
            i += 1
            sleep(_ACQUIRE_SLEEP)
            if i == _ACQUIRE_TO:
                return False
    LOCK_RUA.acquire()
    return True

def rua_release():
    LOCK_RUA.release()

def ranap_acquire():
    if LOCK_RANAP.locked():
        # wait for the other thread to end its use of the RANAP module
        i = 0
        while LOCK_RANAP.locked():
            i += 1
            sleep(_ACQUIRE_SLEEP)
            if i == _ACQUIRE_TO:
                return False
    LOCK_RANAP.acquire()
    return True

def ranap_release():
    LOCK_RANAP.release()

#------------------------------------------------------------------------------#
# logging facilities
#------------------------------------------------------------------------------#

class CorenetErr(PycrateErr):
    pass

class HNBAPErr(CorenetErr):
    pass

class RUAErr(CorenetErr):
    pass

class RANAPErr(CorenetErr):
    pass


# coloured logs
TRACE_COLOR_START = '\x1b[94m'
TRACE_COLOR_END = '\x1b[0m'

# logging facility
def log(msg='', withdate=True, tostdio=False, tofile='/tmp/corenet.log'):
    msg = '[%s] %s\n' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], msg)
    if tostdio:
        print(msg[:-1])
    if tofile:
        fd = open(tofile, 'a')
        fd.write(msg)
        fd.close()


#------------------------------------------------------------------------------#
# threading facilities
#------------------------------------------------------------------------------#

# thread launcher
def threadit(f, *args, **kwargs):
    t = Thread(target=f, args=args, kwargs=kwargs)
    t.start()
    return t


#------------------------------------------------------------------------------#
# global constants
#------------------------------------------------------------------------------#

# radio access techno identifiers
RAT_UTRA  = 'UTRAN'
RAT_EUTRA = 'E-UTRAN'

# SCTP payload protocol identifiers
SCTP_PPID_HNBAP = 20
SCTP_PPID_RUA   = 19
SCTP_PPID_S1AP  = 18

# HNB / ENB protocol identifiers
PROTO_HNBAP = 'HNBAP'
PROTO_RUA   = 'RUA'
PROTO_RANAP = 'RANAP'
PROTO_S1AP  = 'S1AP'


#------------------------------------------------------------------------------#
# built-ins object copy routines
#------------------------------------------------------------------------------#

def cpdict(d):
    ret = {}
    for k in d:
        if isinstance(d[k], dict):
            ret[k] = cpdict(d[k])
        elif isinstance(d[k], list):
            ret[k] = cplist(d[k])
        else:
            ret[k] = d[k]
    return ret

def cplist(l):
    ret = []
    for e in l:
        if isinstance(e, dict):
            ret.append(cpdict(e))
        elif isinstance(e, list):
            ret.append(cplist(e))
        else:
            ret.append(e)
    return ret


#------------------------------------------------------------------------------#
# ASN.1 object handling facilities
#------------------------------------------------------------------------------#

def pythonize_name(name):
    return name.replace('-', '_')


__PLMN = TS24008_IE.PLMN()
def plmn_buf_to_str(buf):
    __PLMN.from_bytes(buf)
    return __PLMN.decode()

def plmn_str_to_buf(s):
    __PLMN.encode(s)
    return __PLMN.to_bytes()


__IMSI = TS24008_IE.ID()
def imsi_buf_to_str(buf):
    __IMSI.from_bytes(buf)
    return __IMSI.decode()[1]

def imsi_str_to_buf(s):
    __IMSI.encode(type=TS24008_IE.IDTYPE_IMSI, ident=s)
    return __IMSI.to_bytes()


def cellid_bstr_to_str(bstr):
    return hexlify(int_to_bytes(*bstr)).decode('ascii')


def print_pduies(desc):
    for ptype in ('InitiatingMessage', 'Outcome', 'SuccessfulOutcome', 'UnsuccessfulOutcome'):
        if ptype in desc():
            pdu = desc()[ptype]
            print(ptype + ':')
            done = False
            if 'protocolIEs' in pdu._cont:
                ies = pdu._cont['protocolIEs']._cont._cont['value']._const_tab
                print('  IEs:')
                IEs = []
                for ident in ies('id'):
                    try:
                        info = '  - %i: %s (%s)'\
                               % (ident,
                                  pythonize_name(ies('id', ident)['Value']._tr._name),
                                  ies('id', ident)['presence'][0].upper())
                    except:
                        info = '  - %i: [%s] (%s)'\
                               % (ident,
                                  ies('id', ident)['Value'].TYPE,
                                  ies('id', ident)['presence'][0].upper())
                    IEs.append((ident, info))
                if not IEs:
                    print('    None')
                else:
                    IEs.sort(key=lambda x:x[0])
                    print('\n'.join([x[1] for x in IEs]))
                done = True
            if 'protocolExtensions' in pdu._cont:
                ies = pdu._cont['protocolExtensions']._cont._cont['extensionValue']._const_tab
                print('  Extensions:')
                Exts = []
                for ident in ies('id'):
                    try:
                        info = '  - %i: %s (%s)'\
                               % (ident,
                                  pythonize_name(ies('id', ident)['Extension']._tr._name),
                                  ies('id', ident)['presence'][0].upper())
                    except:
                        info = '  - %i: [%s] (%s)'\
                               % (ident,
                                  pythonize_name(ies('id', ident)['Extension'].TYPE),
                                  ies('id', ident)['presence'][0].upper())
                    Exts.append((ident, info))
                if not Exts:
                    print('    None')
                else:
                    Exts.sort(key=lambda x:x[0])
                    print('\n'.join([x[1] for x in Exts]))
                done = True
            if not done:
                print('  None')


def print_nasies(nasmsg):
    # go after the header (last field: Type), and print IE type, tag if defined,
    # and name
    # WNG: Type1V (Uint4), Type2 (Uint8), Type3V(Buf) are not wrapped
    print('%s (PD %i, Type %i), IEs:' % (nasmsg._name, nasmsg['ProtDisc'](), nasmsg['Type']()))
    pay = False
    ies = False
    for f in nasmsg._content:
        if pay:
            if isinstance(f, TS24007.IE):
                ietype = f.__class__.__name__
            else:
                iebl = f.get_bl()
                if iebl == 4:
                    ietype = 'Type1V'
                elif iebl == 8:
                    ietype = 'Type2'
                else:
                    ietype = 'Type3V'
                    assert( iebl >= 16 )
            if f._trans:
                print('- %-9s : %s (T: %i)' % (ietype, f._name, f[0]()))
            else:
                print('- %-9s : %s' % (ietype, f._name))
            ies = True
        if f._name == 'Type':
            pay = True
    if not ies:
        print('  None')


#------------------------------------------------------------------------------#
# wrapping classes
#------------------------------------------------------------------------------#

# Signaling stack handler (e.g. for HNBd, ENBd, UEd)
class SigStack(object):
    pass


# Signaling procedure handler
class SigProc(object):
    pass

# See ProcProto.py for prototype classes for the various mobile network procedures
# and other Proc*.py for the procedures themselves

