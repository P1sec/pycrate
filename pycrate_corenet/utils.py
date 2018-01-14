# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.2
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
from threading import Thread, Lock, Event
from random    import SystemRandom, randint
from time      import time, sleep
from datetime  import datetime
from binascii  import hexlify, unhexlify
from struct    import pack, unpack
from socket    import AF_INET, AF_INET6, AF_PACKET, ntohl, htonl, ntohs, htons, \
                      inet_aton, inet_ntoa, inet_pton, inet_ntop

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
from pycrate_core.repr  import *
from pycrate_core.elt   import Element
Element._SAFE_STAT = True
Element._SAFE_DYN  = True

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
#
from pycrate_asn1rt.utils import get_val_at

# to drive 3G UE
from pycrate_mobile  import TS24007
from pycrate_mobile  import TS24008_IE
# CS domain
from pycrate_mobile  import TS24008_MM
from pycrate_mobile  import TS24008_CC
from pycrate_mobile  import TS24011_PPSMS
from pycrate_mobile  import TS24080_SS
# PS domain
from pycrate_mobile  import TS24008_GMM
from pycrate_mobile  import TS24008_SM
#
# to drive LTE UE
from pycrate_mobile  import TS24301_EMM
from pycrate_mobile  import TS24301_ESM
#
from pycrate_mobile  import TS24007
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
# ASN.1 modules / objects
ASN_READY_S1AP  = Event()
ASN_READY_HNBAP = Event()
ASN_READY_RUA   = Event()
ASN_READY_RANAP = Event()
ASN_READY_S1AP.set()
ASN_READY_HNBAP.set()
ASN_READY_RUA.set()
ASN_READY_RANAP.set()

ASN_ACQUIRE_TO = 0.01 # in sec

def asn_s1ap_acquire():
    if ASN_READY_S1AP.is_set():
        ASN_READY_S1AP.clear()
        return True
    else:
        ready = ASN_READY_S1AP.wait(ASN_ACQUIRE_TO)
        if not ready:
            # timeout, module is still locked
            return False
        else:
            ASN_READY_S1AP.clear()
            return True

def asn_s1ap_release():
    ASN_READY_S1AP.set()

def asn_hnbap_acquire():
    if ASN_READY_HNBAP.is_set():
        ASN_READY_HNBAP.clear()
        return True
    else:
        ready = ASN_READY_HNBAP.wait(ASN_ACQUIRE_TO)
        if not ready:
            # timeout, module is still locked
            return False
        else:
            ASN_READY_HNBAP.clear()
            return True

def asn_hnbap_release():
    ASN_READY_HNBAP.set()

def asn_rua_acquire():
    if ASN_READY_RUA.is_set():
        ASN_READY_RUA.clear()
        return True
    else:
        ready = ASN_READY_RUA.wait(ASN_ACQUIRE_TO)
        if not ready:
            # timeout, module is still locked
            return False
        else:
            ASN_READY_RUA.clear()
            return True

def asn_rua_release():
    ASN_READY_RUA.set()

def asn_ranap_acquire():
    if ASN_READY_RANAP.is_set():
        ASN_READY_RANAP.clear()
        return True
    else:
        ready = ASN_READY_RANAP.wait(ASN_ACQUIRE_TO)
        if not ready:
            # timeout, module is still locked
            return False
        else:
            ASN_READY_RANAP.clear()
            return True

def asn_ranap_release():
    ASN_READY_RANAP.set()


def decode_ue_rad_cap(buf):
    UERadCap = RRCLTE.EUTRA_InterNodeDefinitions.UERadioAccessCapabilityInformation
    try:
        UERadCap.from_uper(buf)
    except:
        return None
    uecapinfo = {}
    try:
        # ue-RadioAccessCapabilityInfo (OCTET STRING) contains UECapabilityInformation (SEQUENCE)
        radcapinfo = get_val_at(UERadCap, ('criticalExtensions',
                                           'c1',
                                           'ueRadioAccessCapabilityInformation-r8',
                                           'ue-RadioAccessCapabilityInfo',
                                           'UECapabilityInformation',
                                           'criticalExtensions',
                                           'c1',
                                           'ueCapabilityInformation-r8'))
    except:
        UERadCap._val, uecapinfo
    # decode each ueCapabilityRAT-Container
    for caprat in radcapinfo['ue-CapabilityRAT-ContainerList']:
        rattype = caprat['rat-Type'] # eutra, utra, geran-cs, geran-ps, cdma2000-1XRTT
        if rattype == 'eutra':
            UEEUTRACap = RRCLTE.EUTRA_RRC_Definitions.UE_EUTRA_Capability
            try:
                UEEUTRACap.from_uper(caprat['ueCapabilityRAT-Container'])
            except:
                uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
            else:
                uecapinfo[rattype] = UEEUTRACap._val
        elif rattype == 'utra':
            UEUTRACap  = RRC3G.PDU_definitions.InterRATHandoverInfo
            try:
                UEUTRACap.from_uper(caprat['ueCapabilityRAT-Container'])
            except:
                uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
            else:
                uecapinfo[rattype] = UEUTRACap._val
        elif rattype == 'geran-cs':
            m2, m3 = NAS.MSCm2(), NAS.Classmark_3_Value_part.clone()
            # MSCm2 || MSCm3
            try:
                m2.from_bytes(caprat['ueCapabilityRAT-Container'])
                m3.from_bytes(caprat['ueCapabilityRAT-Container'][m2.get_len():])
            except:
                uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
            else:
                uecapinfo[rattype] = (m2, m3)
        elif rattype == 'geran-ps':
            mrc = NAS.MS_RA_capability_value_part.clone()
            try:
                mrc.from_bytes(caprat['ueCapabilityRAT-Container'])
            except:
                uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
            else:
                uecapinfo[rattype] = mrc
        else:
            uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
    return UERadCap._val, uecapinfo
    
    

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
RAT_GERA  = 'GERAN'
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
# various routines
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


def get_ueseccap_null_alg():
    seccap = NAS.UESecCap(val={'EEA0': 1, 'EIA0': 1, 'UEA0': 1})
    return seccap

def get_ueseccap_null_alg_lte():
    seccap = NAS.UESecCap(val={'EEA0': 1, 'EIA0': 1})
    seccap.disable_from('UEA0')
    return seccap

def cellid_bstr_to_str(bstr):
    # 20 or 28 bits
    return hexlify(int_to_bytes(*bstr)).decode('ascii')[:-1]


def globenbid_to_hum(seq):
    return {'pLMNidentity': plmn_buf_to_str(seq['pLMNidentity']),
            'eNB-ID': (seq['eNB-ID'][0], cellid_bstr_to_str(seq['eNB-ID'][1]))}


def supptas_to_hum(seqof):
    return [{'broadcastPLMNs': [plmn_buf_to_str(plmn) for plmn in sta['broadcastPLMNs']],
             'tAC': bytes_to_uint(sta['tAC'], 16)} for sta in seqof]


def gummei_to_asn(plmnid, mmegid, mmec):
    return {'pLMN-Identity': plmn_str_to_buf(plmnid),
            'mME-Group-ID' : uint_to_bytes(mmegid, 16),
            'mME-Code'     : uint_to_bytes(mmec, 8)}
            
def served_gummei_to_asn(val):
    return {'servedGroupIDs': [uint_to_bytes(gid, 16) for gid in val['GroupIDs']],
            'servedMMECs'   : [uint_to_bytes(mmec, 8) for mmec in val['MMECs']],
            'servedPLMNs'   : [plmn_str_to_buf(plmn) for plmn in val['PLMNs']]}


def mac_aton(mac='00:00:00:00:00:00'):
    return unhexlify(mac.replace(':', ''))

def inet_aton_cn(*pdnaddr):
    if pdnaddr[0] == 1:
        # IPv4 address
        try:
            return inet_aton(pdnaddr[1])
        except:
            return pdnaddr[1]
    elif pdnaddr[0] == 2:
        # accept 64-bit IPv6 prefix / subnet or full 128-bit IPv6 address
        ipaddr = pdnaddr[1]
        if ipaddr.count(':') == 3:
            # IPv6 prefix / subnet only
            return pack('>HHHH', *map(lambda x:int(x, 16), ipaddr.split(':')))
        else:
            try:
                return inet_pton(AF_INET6, ipaddr)
            except:
                return ipaddr
    elif pdnaddr[0] == 3:
        # IPv4v6 addresses
        try:
            return inet_aton(pdnaddr[1]) + inet_aton_cn(2, pdnaddr[2])
        except:
            return pdnaddr[1]
    else:
        # unknown address type
        return pdnaddr[1]

def inet_ntoa_cn(pdntype, buf):
    if pdntype == 1:
        # IPv4 address
        return (1, inet_ntoa(buf))
    elif pdntype == 2:
        # accept 64-bit IPv6 prefix / subnet or full 128-bit IPv6 address
        if len(buf) == 8:
            return (2, '%x:%x:%x:%x' % unpack('>HHHH', buf))
        else:
            return (2, inet_ntop(AF_INET6, buf))
    elif pdntype == 3:
        return (3, inet_ntoa(buf[:4]), inet_ntoa_cn(2, buf[4:])[1])
    else:
        return (pdntype, buf)

#------------------------------------------------------------------------------#
# ASN.1 object handling facilities
#------------------------------------------------------------------------------#

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

