# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2021. Benoit Michau. P1Sec.
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
# * File Name : pycrate_corenet/utils_fmt.py
# * Created : 2021-04-01
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii  import hexlify, unhexlify
from struct    import pack, unpack
from socket    import inet_aton, inet_ntoa, inet_pton, inet_ntop

from pycrate_core.utils import *

from pycrate_mobile import TS24008_IE
from pycrate_mobile import NAS


#------------------------------------------------------------------------------#
# various formatting routines
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

def globranid_to_hum(cho):
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

def globranid_to_asn(granid):
    if granid[1] == 'gNB-ID':
        return (
            'globalGNB-ID', {
                'pLMNIdentity'  : plmn_str_to_buf(granid[0]),
                'gNB-ID'        : (granid[1], granid[2])
                }
            )
    elif granid[1] == 'n3IWF-ID':
        return (
            'globalN3IWF-ID', {
                'pLMNIdentity'  : plmn_str_to_buf(granid[0]),
                'n3IWF-ID'      : (granid[1], granid[2])
                }
            )
    else:
        return (
            'globalNgENB-ID', {
                'pLMNIdentity'  : plmn_str_to_buf(granid[0]),
                'ngENB-ID'      : (granid[1], granid[2])
                }
            )

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
    # warning: in case of duplicate TAC, this will override GNB TAC of the first one(s)
    return {
        bytes_to_uint(seq['tAC'], 24) : [
            bcastplmn_to_hum(bcastplmn) for bcastplmn in seq['broadcastPLMNList']] \
        for seq in seqof
        }

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
            } for (plmn, snssailist) in bcastplmnlist]
        } for (tac, bcastplmnlist) in sorted(supptalist.items())
        ]

def guamilist_to_hum(seqof):
    # warning: in case of duplicate PLMN, this will override AMF ID of the first one(s)
    return {
        plmn_buf_to_str(guami['gUAMI']['pLMNIdentity']): (
            guami['gUAMI']['aMFRegionID'][0],
            guami['gUAMI']['aMFSetID'][0],
            guami['gUAMI']['aMFPointer'][0]
            ) for guami in seqof
        }

def guamilist_to_asn(guamilist):
    return [
        {'gUAMI': {
            'pLMNIdentity': plmn_str_to_buf(plmn),
            'aMFRegionID' : (rid, 8),
            'aMFSetID'    : (sid, 10),
            'aMFPointer'  : (ptr, 6)
            }
        } for (plmn, (rid, sid, ptr)) in sorted(guamilist.items())
        ]

def plmnsupplist_to_hum(seqof):
    # warning: in case of duplicate PLMN, this will override S-NSSAI of the first one(s)
    return {
        plmn_buf_to_str(seq['pLMNIdentity']): [
            (bytes_to_uint(snssai['s-NSSAI']['sST'], 8), bytes_to_uint(snssai['s-NSSAI']['sD'], 24)) \
                if len(snssai['s-NSSAI']) > 1 else \
            (bytes_to_uint(snssai['s-NSSAI']['sST'], 8), ) \
                for snssai in seq['sliceSupportList']
            ]
        for seq in seqof
        }

def plmnsupplist_to_asn(plmnsupplist):
    return [
        {'pLMNIdentity': plmn_str_to_buf(plmn),
         'sliceSupportList': [
            {'s-NSSAI': {'sST': uint_to_bytes(snssai[0], 8), 'sD': uint_to_bytes(snssai[1], 24)}} if len(snssai) > 1 else \
            {'s-NSSAI': {'sST': uint_to_bytes(snssai[0], 8)}} for snssai in snssais],
        } for (plmn, snssais) in sorted(plmnsupplist.items())
        ]

def ngap_userloc_to_hum(cho):
    if cho[0] == 'userLocationInformationNR':
        # return NR-CGI and TAI
        return {
            'TAI': (
                plmn_buf_to_str(cho[1]['tAI']['pLMNIdentity']),
                bytes_to_uint(cho[1]['tAI']['tAC'], 24)
                ),
            'NR-CGI': (
                plmn_buf_to_str(cho[1]['nR-CGI']['pLMNIdentity']),
                cho[1]['nR-CGI']['nRCellIdentity']
                )
            }
    elif cho[0] == 'userLocationInformationEUTRA':
        # return EUTRA-CGI and TAI
        return {
            'TAI': (
                plmn_buf_to_str(cho[1]['tAI']['pLMNIdentity']),
                bytes_to_uint(cho[1]['tAI']['tAC'], 16)
                ),
            'EUTRA-CGI': (
                plmn_buf_to_str(cho[1]['eUTRA-CGI']['pLMNIdentity']),
                cho[1]['eUTRA-CGI']['eUTRACellIdentity']
                )
            }

def make_5g_snn(plmn_id, nid=None):
    """encodes the 5G Serving Network Name as in TS 24.501, 9.12.1
    
    plmn_id: 5 or 6 digit str
    nid: None or hexa-str
    """
    snn = b'5G:mnc%.3i.mcc%.3i.3gppnetwork.org' % (int(mccmnc[3:]), int(mccmnc[:3]))
    if nid:
        snn += ":%s" % nid.encode()
    return snn


