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
from socket    import AF_INET, AF_INET6, AF_PACKET, ntohl, htonl, ntohs, htons

# SCTP support for NGAP / S1AP / HNBAP / RUA interfaces
try:
    import sctp
except ImportError as err:
    print('pysctp library required for CorenetServer')
    print('check on github: https://github.com/P1sec/pysctp')
    raise(err)

# conversion function for security context
try:
    from CryptoMobile.conv import *
except ImportError as err:
    print('CryptoMobile library required for CorenetServer')
    print('check on github: https://github.com/P1sec/CryptoMobile')
    raise(err)

# all pycrate stuffs
from pycrate_core.utils import *
from pycrate_core.repr  import *
from pycrate_core.elt   import Element, Envelope
from pycrate_core.base  import Buf, Uint8
Element._SAFE_STAT = True
Element._SAFE_DYN  = True

from pycrate_corenet.utils_fmt  import *
from pycrate_corenet.ProcProto  import SigStack, SigProc

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


def print_nasies(nasmsg, indent=''):
    # go after the header (last field: Type), and print IE type, tag if defined,
    # and name
    # WNG: Type1V (Uint4), Type2 (Uint8), Type3V(Buf) are not wrapped
    hdr = nasmsg[0]
    if 'ProtDisc' in hdr._by_name:
        pd = hdr['ProtDisc'].get_val()
    elif 'EPD' in hdr._by_name:
        pd = hdr['EPD'].get_val()
    else:
        pd = hdr[0]['ProtDisc'].get_val()
    typ = hdr['Type'].get_val()
    print('%s%s (PD %i, Type %i), IEs:' % (indent, nasmsg._name, pd, typ))
    #
    if len(nasmsg._content) == 1:
        print('%s  None' % indent)
    else:
        for ie in nasmsg._content[1:]:
            if ie.get_trans():
                # optional IE
                print('%s- %-9s : %s (T: %i)'\
                      % (indent, ie.__class__.__name__, ie._name, ie[0].get_val()))
            elif isinstance(ie, TS24007.IE):
                # mandatory IE
                print('%s- %-9s : %s' % (indent, ie.__class__.__name__, ie._name))
            elif ie.get_bl() == 4:
                # uint / spare bits
                print('%s- %-9s : %s' % (indent, 'Type1V', 'spare'))
            else:
                assert()


def print_nasproc_docs(nasproc):
    msgcn, msgue = nasproc.Cont
    print('CN message:')
    if msgcn is None:
        print('    None')
    else:
        for m in msgcn:
            print_nasies(m(), indent='    ')
            print('    ')
    print('UE message:')
    if msgue is None:
        print('    None')
    else:
        for m in msgue:
            print_nasies(m(), indent='    ')
            print('    ')

