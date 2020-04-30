# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# * Copyright 2020. Benoit Michau. P1Sec.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
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

# SCTP support for NGAP / S1AP / HNBAP / RUA interfaces
try:
    import sctp
except ImportError as err:
    print('pysctp library required for CorenetServer')
    print('check on github: https://github.com/P1sec/pysctp')
    raise(err)

# conversion function for security context
try:
    from CryptoMobile.Milenage import conv_C2, conv_C3, conv_C4, conv_C5, \
                                      conv_A2, conv_A3, conv_A4, conv_A7
except ImportError as err:
    print('CryptoMobile library required for CorenetServer')
    print('check on github: https://github.com/P1sec/CryptoMobile')
    raise(err)

from pycrate_core.utils import *
from pycrate_core.repr  import *
from pycrate_core.elt   import Element, Envelope
from pycrate_core.base  import Buf, Uint8
Element._SAFE_STAT = True
Element._SAFE_DYN  = True

log('pycrate_corenet: loading all ASN.1 and NAS modules, be patient...')
# import ASN.1 modules
# to drive gNodeB and ng-eNodeB
from pycrate_asn1dir import NGAP
# to drive eNodeB and Home-eNodeB
from pycrate_asn1dir import S1AP
# to drive Home-NodeB
from pycrate_asn1dir import HNBAP
from pycrate_asn1dir import RUA
from pycrate_asn1dir import RANAP
# to decode UE 3G, LTE and NR radio capability
from pycrate_asn1dir import RRC3G
from pycrate_asn1dir import RRCLTE
from pycrate_asn1dir import RRCNR
# to handle SS messages
from pycrate_asn1dir import SS
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
# to drive 5G UE
from pycrate_mobile  import TS24501_FGMM
from pycrate_mobile  import TS24501_FGSM
#
from pycrate_mobile  import TS24007
from pycrate_mobile  import NAS


#------------------------------------------------------------------------------#
# ASN.1 objects
#------------------------------------------------------------------------------#

# actually, all ASN.1 modules are in ASN_GLOBAL
ASN_GLOBAL = S1AP.GLOBAL.MOD

# ASN.1 PDU encoders / decoders
PDU_NGAP  = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
PDU_S1AP  = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
PDU_HNBAP = HNBAP.HNBAP_PDU_Descriptions.HNBAP_PDU
PDU_RUA   = RUA.RUA_PDU_Descriptions.RUA_PDU
PDU_RANAP = RANAP.RANAP_PDU_Descriptions.RANAP_PDU
PDU_SS_Facility = SS.SS_Facility.Facility

# ASN.1 modules are not thread-safe
# objects' value will be mixed in case a thread ctxt switch occurs between 
# the fg interpreter and the bg CorenetServer loop, and both accesses the same
# ASN.1 modules / objects
ASN_READY_NGAP  = Event()
ASN_READY_S1AP  = Event()
ASN_READY_HNBAP = Event()
ASN_READY_RUA   = Event()
ASN_READY_RANAP = Event()
ASN_READY_NGAP.set()
ASN_READY_S1AP.set()
ASN_READY_HNBAP.set()
ASN_READY_RUA.set()
ASN_READY_RANAP.set()

ASN_ACQUIRE_TO = 0.01 # in sec

def asn_ngap_acquire():
    if ASN_READY_NGAP.is_set():
        ASN_READY_NGAP.clear()
        return True
    else:
        ready = ASN_READY_NGAP.wait(ASN_ACQUIRE_TO)
        if not ready:
            # timeout, module is still locked
            return False
        else:
            ASN_READY_NGAP.clear()
            return True

def asn_ngap_release():
    ASN_READY_NGAP.set()

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
    except Exception:
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
    except Exception:
        return UERadCap._val, uecapinfo
    # decode each ueCapabilityRAT-Container
    for caprat in radcapinfo['ue-CapabilityRAT-ContainerList']:
        rattype = caprat['rat-Type'] # eutra, utra, geran-cs, geran-ps, cdma2000-1XRTT
        if rattype == 'eutra':
            UEEUTRACap = RRCLTE.EUTRA_RRC_Definitions.UE_EUTRA_Capability
            try:
                UEEUTRACap.from_uper(caprat['ueCapabilityRAT-Container'])
            except Exception:
                uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
            else:
                uecapinfo[rattype] = UEEUTRACap._val
        elif rattype == 'utra':
            UEUTRACap  = RRC3G.PDU_definitions.InterRATHandoverInfo
            try:
                UEUTRACap.from_uper(caprat['ueCapabilityRAT-Container'])
            except Exception:
                uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
            else:
                uecapinfo[rattype] = UEUTRACap._val
        elif rattype == 'geran-cs':
            m2, m3 = NAS.MSCm2(), NAS.classmark_3_value_part.clone()
            # MSCm2 || MSCm3
            buf = caprat['ueCapabilityRAT-Container']
            if buf[0:1] != b'\x33':
                uecapinfo[rattype] = buf
            else:
                m2_len = ord(buf[1:2])
                buf_m2 = buf[2:2+m2_len]
                buf_m3 = buf[2+m2_len:]
                try:
                    m2.from_bytes(buf_m2)
                    m3.from_bytes(buf_m3)
                except Exception:
                    uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
                else:
                    uecapinfo[rattype] = (m2, m3)
        elif rattype == 'geran-ps':
            mrc = NAS.ms_ra_capability_value_part.clone()
            try:
                mrc.from_bytes(caprat['ueCapabilityRAT-Container'])
            except Exception:
                uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
            else:
                uecapinfo[rattype] = mrc
        else:
            # TODO: could be cdma2000_1XRTT
            uecapinfo[rattype] = caprat['ueCapabilityRAT-Container']
    return UERadCap._val, uecapinfo


# special handling for hiding MeasParameters reported in UERadioCapability

def _seq_to_asn1_bypass():
    return '{ -- removed for brevity -- }'


def _get_mp_from_eutra_cap():
    mp_list = []
    par = RRCLTE.EUTRA_RRC_Definitions.UE_EUTRA_Capability
    mp_list.append(par._cont['measParameters'])
    par = par._cont['nonCriticalExtension']._cont['nonCriticalExtension']._cont['nonCriticalExtension']
    mp_list.append(par._cont['measParameters-v1020'])
    par = par._cont['nonCriticalExtension']._cont['nonCriticalExtension']._cont['nonCriticalExtension']
    mp_list.append(par._cont['measParameters-v1130'])
    par = par._cont['nonCriticalExtension']._cont['nonCriticalExtension']._cont['nonCriticalExtension']
    mp_list.append(par._cont['measParameters-v11a0'])
    par = par._cont['nonCriticalExtension']
    mp_list.append(par._cont['measParameters-v1250'])
    par = par._cont['nonCriticalExtension']._cont['nonCriticalExtension']._cont['nonCriticalExtension']._cont['nonCriticalExtension']
    mp_list.append(par._cont['measParameters-v1310'])
    return mp_list


_RRCLTE_MPList = _get_mp_from_eutra_cap()
_RRCLTE_MPList_to_asn1 = [mp._to_asn1 for mp in _RRCLTE_MPList]


def meas_params_to_asn1_patch():
    for mp in _RRCLTE_MPList:
        mp._to_asn1 = _seq_to_asn1_bypass


def meas_params_to_asn1_restore():
    for i, mp in enumerate(_RRCLTE_MPList):
        mp._to_asn1 = _RRCLTE_MPList_to_asn1[i]


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
    if withdate:
        msg = '[%s] %s\n' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], msg)
    else:
        msg = msg + '\n'
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
RAT_NR    = 'NR'

# SCTP payload protocol identifiers
SCTP_PPID_HNBAP = 20
SCTP_PPID_RUA   = 19
SCTP_PPID_S1AP  = 18
SCTP_PPID_NGAP  = 60

# HNB / ENB protocol identifiers
PROTO_HNBAP = 'HNBAP'
PROTO_RUA   = 'RUA'
PROTO_RANAP = 'RANAP'
PROTO_S1AP  = 'S1AP'
PROTO_NGAP  = 'NGAP'


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

def inet_aton_cn(*pdnaddr, **kw):
    """convert a PDN / PDP address tuple to a buffer
    kw can be:
        - dom: 'PS' or 'EPS'
    """
    if pdnaddr[0] == 0:
        # PPP address
        return pdnaddr[1]
    elif pdnaddr[0] == 1:
        # IPv4 address
        try:
            return inet_aton(pdnaddr[1])
        except Exception:
            log('WNG: IPv4 address conversion error, %r' % pdnaddr[1])
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
            except Exception:
                log('WNG: IPv6 address conversion error, %r' % pdnaddr[1])
                return ipaddr
    elif pdnaddr[0] == 3:
        # IPv4v6 addresses
        if 'dom' in kw and kw['dom'] == 'EPS':
            # PDN address
            try:
                return inet_aton_cn(2, pdnaddr[2]) + inet_aton_cn(1, pdnaddr[1])
            except Exception:
                log('WNG: IPv4v6 PDN address conversion error, %r' % pdnaddr[1])
                return pdnaddr[1]
        else:
            # PDP address
            try:
                return inet_aton_cn(1, pdnaddr[1]) + inet_aton_cn(2, pdnaddr[2])
            except Exception:
                log('WNG: IPv4v6 PDP address conversion error, %r' % pdnaddr[1])
                return pdnaddr[1]
    else:
        # unknown address type
        return pdnaddr[1]

def inet_ntoa_cn(pdntype, buf, dom='EPS'):
    """convert a buffer for a given pdntype and domain to a humane-readable address
    """
    if pdntype == 0:
        # PPP address
        return (pdntype, buf)
    if pdntype == 1:
        # IPv4 address
        try:
            return (1, inet_ntoa(buf))
        except Exception:
            log('WNG: IPv4 buffer conversion error, %s' % hexlify(buf).decode('ascii'))
            return None
    elif pdntype == 2:
        # accept 64-bit IPv6 local if or full 128-bit IPv6 address
        if len(buf) == 8:
            return (2, '%x:%x:%x:%x' % unpack('>HHHH', buf))
        else:
            try:
                return (2, inet_ntop(AF_INET6, buf))
            except Exception:
                log('WNG: IPv6 buffer conversion error, %s' % hexlify(buf).decode('ascii'))
                return None
    elif pdntype == 3:
        if dom == 'EPS':
            # PDN address
            try:
                return (3, inet_ntoa(buf[8:12]), inet_ntoa_cn(2, buf[:8])[1])
            except Exception:
                log('WNG: IPv4v6 PDN buffer conversion error, %s' % hexlify(buf).decode('ascii'))
        else:
            # PDP address
            try:
                return (3, inet_ntoa(buf[:4]), inet_ntop(AF_INET6, buf[4:20]))
            except Exception:
                log('WNG: IPv4v6 PDP buffer conversion error, %s' % hexlify(buf).decode('ascii'))
    else:
        return (pdntype, buf)


# routines for dealing with structures for NGAP

def ngranid_to_hum(cho):
    """returns a 3-tuple:
    - plmn id (str)
    - node type (str)
    - node id (bit-str value, 2-tuple of int)
    """
    if cho[0] == 'globalGNB-ID':
        # std gNB-ID
        return (
            plmn_buf_to_str(cho[1]['pLMNIdentity']),
            cho[1]['gNB-ID'][0],
            cho[1]['gNB-ID'][1]
            )
    elif cho[0] == 'globalNgENB-ID':
        # std ng-eNB-ID
        return (
            plmn_buf_to_str(cho[1]['pLMNIdentity']),
            cho[1]['ngENB-ID'][0],
            cho[1]['ngENB-ID'][1]
            )
    elif cho[0] == 'globalN3IWF-ID':
        return (
            plmn_buf_to_str(cho[1]['pLMNIdentity']),
            cho[1]['n3IWF-ID'][0],
            cho[1]['n3IWF-ID'][1]
            )
    return None

def bcastplmn_to_hum(seq):
    """returns a 2-tuple:
    - plmn id (str)
    - list 1 or 2-tuple corresponding to an snssai value with SST (uint8) and an optional SD (uint24)
    """
    return (
        plmn_buf_to_str(seq['pLMNIdentity']),
        [(bytes_to_uint(snssai['s-NSSAI']['sST'], 8), bytes_to_uint(snssai['s-NSSAI']['sD'], 24)) \
            if len(snssai['s-NSSAI']) > 1 else \
         (bytes_to_uint(snssai['s-NSSAI']['sST'], 8), ) \
            for snssai in seq['tAISliceSupportList']]
        )

def supptalist_to_hum(seqof):
    """returns a list of 2-tuple, each 2-tuple is:
    - TAC (uint24, was uint16 in S1AP)
    - list of broadcasted PLMN 2-tuple (see bcastplmn_to_hum)
    """
    return [(
        bytes_to_uint(seq['tAC'], 24),
        [bcastplmn_to_hum(bcastplmn) for bcastplmn in seq['broadcastPLMNList']]) \
        for seq in seqof]

def supptalist_to_asn(supptalist):
    return [
        {'tAC': uint_to_bytes(tac, bitlen=24),
         'broadcastPLMNList': [{
            'pLMNIdentity': plmn_str_to_buf(plmn),
            'tAISliceSupportList': [
                {'s-NSSAI': {
                    'sST': uint_to_bytes(snssai[0], 8),
                    'sD' : uint_to_bytes(snssai[1], 24)}} if len(snssai) > 1 else \
                {'s-NSSAI': {
                    'sST': uint_to_bytes(snssai[0], 8)}} \
                for snssai in snssailist]
            } for (plmn, snssailist) in bcastplmnlist]}
         for (tac, bcastplmnlist) in supptalist
         ]


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
                    except Exception:
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
                    except Exception:
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
    hdr = nasmsg[0]
    if 'ProtDisc' in hdr._by_name:
        pd = hdr['ProtDisc'].get_val()
    else:
        pd = hdr[0]['ProtDisc'].get_val()
    typ = hdr['Type'].get_val()
    print('%s (PD %i, Type %i), IEs:' % (nasmsg._name, pd, typ))
    #
    if len(nasmsg._content) == 1:
        print('  None')
    else:
        for ie in nasmsg._content[1:]:
            if ie.get_trans():
                # optional IE
                print('- %-9s : %s (T: %i)'\
                      % (ie.__class__.__name__, ie._name, ie[0].get_val()))
            elif isinstance(ie, TS24007.IE):
                # mandatory IE
                print('- %-9s : %s' % (ie.__class__.__name__, ie._name))
            elif ie.get_bl() == 4:
                # uint / spare bits
                print('- %-9s : %s' % ('Type1V', 'spare'))
            else:
                assert()


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

