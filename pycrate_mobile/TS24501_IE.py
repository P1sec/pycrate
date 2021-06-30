# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2019. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS24501_IE.py
# * Created : 2019-11-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 24.501: NAS protocol for 5G
# release 16 (g20)
#------------------------------------------------------------------------------#

from pycrate_core.utils  import *
from pycrate_core.elt    import (
    Envelope, Sequence, Array, Alt,
    REPR_RAW, REPR_HEX, REPR_BIN, REPR_HD, REPR_HUM
    )
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_core.charpy import Charpy

from pycrate_ether.Ethernet     import EtherType_dict
from pycrate_ether.IP           import IPProt_dict
from pycrate_mobile.TS24008_IE  import (
    BufBCD, PLMN, GPRSTimer3, APN, TFT, TimeZoneTime,
    )
from pycrate_mobile.TS24301_IE  import (
    EPSQoS, ExtEPSQoS, APN_AMBR, ExtAPN_AMBR, NAS_KSI,
    _DDX_dict as RelAssist_DDXDict,
    )
from pycrate_mobile.TS31115     import PacketCmdSMSPP

_str_reserved = 'reserved'
_str_mnospec  = 'operator-specific'


#------------------------------------------------------------------------------#
# Security header type
# TS 24.501, 9.3.1
#------------------------------------------------------------------------------#

SecHdrType_dict = {
    0 : 'No security',
    1 : 'Integrity protected',
    2 : 'Integrity protected and ciphered',
    3 : 'Integrity protected with new 5G NAS security context',
    4 : 'Integrity protected and ciphered with new 5G NAS security context'
    }


#------------------------------------------------------------------------------#
# Access type
# TS 24.501, 9.11.2.1A
#------------------------------------------------------------------------------#

class AccessType(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('Value', bl=2, dic={1:'3GPP access', 2:'non-3GPP access'})
        )


#------------------------------------------------------------------------------#
# DNN
# TS 24.501, 9.11.2.1B
#------------------------------------------------------------------------------#

class DNN(Envelope):
    _GEN = (
        Uint8('Len'),
        APN()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)
    
    def set_val(self, val):
        if isinstance(val, str_types):
            self.encode(val)
        else:
            Envelope.set_val(self, val)
    
    def encode(self, val):
        apn_items = val.split('.')
        self['APN'].set_val(self, [{'Value': apn_item} for apn_item in apn_items])
    
    def decode(self, val):
        return '.'.join([apn_item[1] for apn_item in self['APN'].get_val()])


#------------------------------------------------------------------------------#
# Intra N1 mode NAS transparent container
# TS 24.501, 9.11.2.6
#------------------------------------------------------------------------------#

_NASCiphAlgo_dict = {
    0 : '5G encryption algorithm 5G-EA0 (null)',
    1 : '5G encryption algorithm 128-5G-EA1 (SNOW)',
    2 : '5G encryption algorithm 128-5G-EA2 (AES)',
    3 : '5G encryption algorithm 128-5G-EA3 (ZUC)',
    4 : '5G encryption algorithm 5G-EA4',
    5 : '5G encryption algorithm 5G-EA5',
    6 : '5G encryption algorithm 5G-EA6',
    7 : '5G encryption algorithm 5G-EA7'
    }

_NASIntegAlgo_dict = {
    0 : '5G integrity algorithm 5G-IA0 (null)',
    1 : '5G integrity algorithm 128-5G-IA1 (SNOW)',
    2 : '5G integrity algorithm 128-5G-IA2 (AES)',
    3 : '5G integrity algorithm 128-5G-IA3 (ZUC)',
    4 : '5G integrity algorithm 5G-IA4',
    5 : '5G integrity algorithm 5G-IA5',
    6 : '5G integrity algorithm 5G-IA6',
    7 : '5G integrity algorithm 5G-IA7'
    }


class IntraN1ModeNASTransContainer(Envelope):
    _GEN = (
        Buf('MAC', val=b'\0\0\0\0', bl=32, rep=REPR_HEX),
        Uint('CiphAlgo', bl=4, dic=_NASCiphAlgo_dict),
        Uint('IntegAlgo', bl=4, dic=_NASIntegAlgo_dict),
        Uint('spare', bl=3),
        Uint('KACF', bl=1, dic={
            0:'new KAMF has not been calculated by the network',
            1:'new KAMF has been calculated by the network'}),
        NAS_KSI(),
        Uint8('Seqn'),
        )


#------------------------------------------------------------------------------#
# S-NSSAI
# TS 24.501, 9.11.2.8
#------------------------------------------------------------------------------#

# TS 23.501, 5.15.2.2
_SST_dict = {
    1: 'eMBB',
    2: 'URLLC',
    3: 'MIoT',
    4: 'V2X',
    }


class SNSSAI(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint8('SST', dic=_SST_dict),
        Uint24('SD', rep=REPR_HEX, trans=True),
        Uint8('MappedHPLMNSST', trans=True),
        Uint24('MappedHPLMNSD', rep=REPR_HEX, trans=True)
        )
    
    def set_val(self, val):
        if isinstance(val, (tuple, list)):
            if len(val) == 1:
                self[1].set_trans(True)
                self[2].set_trans(True)
                self[3].set_trans(True)
            elif len(val) == 2:
                self[1].set_trans(False)
                self[2].set_trans(True)
                self[3].set_trans(True)
            elif len(val) == 3:
                self[1].set_trans(False)
                self[2].set_trans(False)
                self[3].set_trans(True)
            elif len(val) > 3:
                self[1].set_trans(False)
                self[2].set_trans(False)
                self[3].set_trans(False)
        elif isinstance(val, dict):
            if 'SD' in val:
                self[1].set_trans(False)
            if 'MappedHPLMNSST' in val:
                self[2].set_trans(False)
            if 'MappedHPLMNSD' in val:
                self[3].set_trans(False)
        Envelope.set_val(self, val)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        l = char.len_bit()
        if l == 8:
            self[1].set_trans(True)
            self[2].set_trans(True)
            self[3].set_trans(True)
        elif l == 32:
            self[1].set_trans(False)
            self[2].set_trans(True)
            self[3].set_trans(True)
        elif l == 40:
            self[1].set_trans(False)
            self[2].set_trans(False)
            self[3].set_trans(True)
        elif l >= 64:
            self[1].set_trans(False)
            self[2].set_trans(False)
            self[3].set_trans(False)
        Envelope._from_char(self, char)


class L_SNSSAI(Envelope):
    _name = 'SNSSAI'
    _GEN = (
        Uint8('Len'),
        SNSSAI()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = char._cur + 8*self[0].get_val()
        self[1]._from_char(char)
        char._len_bit = char_lb


#------------------------------------------------------------------------------#
# S1 mode to N1 mode NAS transparent container
# TS 24.501, 9.11.2.9
#------------------------------------------------------------------------------#

class S1ModeN1ModeNASTransContainer(Envelope):
    _GEN = (
        Buf('MAC', val=b'\0\0\0\0', bl=32, rep=REPR_HEX),
        Uint('CiphAlgo', bl=4, dic=_NASCiphAlgo_dict),
        Uint('IntegAlgo', bl=4, dic=_NASIntegAlgo_dict),
        Uint('spare', bl=1),
        Uint('NCC', bl=3),
        NAS_KSI(),
        Buf('spare', bl=16),
        )


#------------------------------------------------------------------------------#
# 5GMM capability
# TS 24.501, 9.11.3.1
#------------------------------------------------------------------------------#

class FGMMCap(Envelope):
    
    ENV_SEL_TRANS = False
    
    _name = '5GMMCap'
    _GEN = (
        Uint('SGC', bl=1),
        Uint('5G-HC-CP-CIoT', bl=1),
        Uint('N3Data', bl=1),
        Uint('5G-CP-CIoT', bl=1),
        Uint('RestrictEC', bl=1),
        Uint('LPP', bl=1),
        Uint('HOAttach', bl=1),
        Uint('S1Mode', bl=1), # end of octet 1
        Uint('RACS', bl=1),
        Uint('NSSAA', bl=1),
        Uint('5G-LCS', bl=1),
        Uint('V2XCNPC5', bl=1),
        Uint('V2XCEPC5', bl=1),
        Uint('V2X', bl=1),
        Uint('5G-UP-CIoT', bl=1),
        Uint('5GSRVCC', bl=1), # end of octet 2
        Uint('spare', bl=4),
        Uint('5G-EHC-CP-CIoT', bl=1),
        Uint('MultipleUP', bl=1),
        Uint('WUSA', bl=1),
        Uint('CAG', bl=1), # end of octet 3
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def _from_char(self, char):
        if self.get_trans():
            return
        l = char.len_bit()
        if l <= 8:
            self.disable_from(8)
        elif l <= 16:
            self.disable_from(16)
        elif l > 24:
            # enables some spare bits at the end
            self[-1]._bl = l-24
        Envelope._from_char(self, char)
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# 5GMM cause
# TS 24.501, 9.11.3.2
#------------------------------------------------------------------------------#

_FGMMCause_dict = {
    3 : 'Illegal UE',
    5 : 'PEI not accepted',
    6 : 'Illegal ME',
    7 : '5GS services not allowed',
    9 : 'UE identity cannot be derived by the network',
    10 : 'Implicitly de-registered',
    11 : 'PLMN not allowed',
    12 : 'Tracking area not allowed',
    13 : 'Roaming not allowed in this tracking area',
    15 : 'No suitable cells in tracking area',
    20 : 'MAC failure',
    21 : 'Synch failure',
    22 : 'Congestion',
    23 : 'UE security capabilities mismatch',
    24 : 'Security mode rejected, unspecified',
    26 : 'Non-5G authentication unacceptable',
    27 : 'N1 mode not allowed',
    28 : 'Restricted service area',
    31 : 'Redirection to EPC required',
    43 : 'LADN not available',
    62 : 'No network slices available',
    65 : 'Maximum number of PDU sessions reached',
    67 : 'Insufficient resources for specific slice and DNN',
    69 : 'Insufficient resources for specific slice',
    71 : 'ngKSI already in use',
    72 : 'Non-3GPP access to 5GCN not allowed',
    73 : 'Serving network not authorized',
    74 : 'Temporarily not authorized for this SNPN',
    75 : 'Permanently not authorized for this SNPN',
    76 : 'Not authorized for this CAG or authorized for CAG cells only',
    77 : 'Wireline access area not allowed',
    90 : 'Payload was not forwarded',
    91 : 'DNN not supported or not subscribed in the slice',
    92 : 'Insufficient user-plane resources for the PDU session',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non-existent or not implemented',
    98 : 'Message type not compatible with the protocol state',
    99 : 'Information element non-existent or not implemented',
    100 : 'Conditional IE error',
    101 : 'Message not compatible with the protocol state',
    111 : 'Protocol error, unspecified'
    }

class FGMMCause(Uint8):
    _name = '5GMMCause'
    _dic = _FGMMCause_dict


#------------------------------------------------------------------------------#
# 5GS DRX parameters
# TS 24.501, 9.11.3.2A
#------------------------------------------------------------------------------#

_FGSDRXParam_dict = {
    0 : 'DRX value not specified',
    1 : 'DRX cycle parameter T = 32',
    2 : 'DRX cycle parameter T = 64',
    3 : 'DRX cycle parameter T = 128',
    4 : 'DRX cycle parameter T = 256'
    }

class FGSDRXParam(Envelope):
    _name = '5GSDRXParam'
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Value', bl=4, dic=_FGSDRXParam_dict)
        )


#------------------------------------------------------------------------------#
# 5GS identity type
# TS 24.501, 9.11.3.3
#------------------------------------------------------------------------------#

_FGSIDType_dict = {
    1 : 'SUCI',
    2 : '5G-GUTI',
    3 : 'IMEI',
    4 : '5G-S-TMSI',
    5 : 'IMEISV',
    6 : 'MAC address',
    7 : 'EUI-64'
    }

class FGSIDType(Envelope):
    _name = '5GSIDType'
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=_FGSIDType_dict)
        )


#------------------------------------------------------------------------------#
# 5GS mobile identity
# TS 24.501, 9.11.3.4
#------------------------------------------------------------------------------#

FGSIDFMT_IMSI    = 0
FGSIDFMT_NSI     = 1
FGSIDFMT_GCI     = 2
FGSIDFMT_GLI     = 3

FGSIDFmt_dict    = {
    0 : 'IMSI', # 15 or 16 BCD
    1 : 'Network specific identifier', # NAI: username@domainname
    2 : 'GCI',  # NAI: username@domainname
    3 : 'GLI'   # NAI: username@domainname
    }

FGSIDTYPE_NO     = 0
FGSIDTYPE_SUPI   = 1
FGSIDTYPE_GUTI   = 2
FGSIDTYPE_IMEI   = 3
FGSIDTYPE_STMSI  = 4
FGSIDTYPE_IMEISV = 5
FGSIDTYPE_MAC    = 6
FGSIDTYPE_EUI64  = 7

FGSIDType_dict   = {
    0 : 'No identity',
    1 : 'SUCI',
    2 : '5G-GUTI',
    3 : 'IMEI',
    4 : '5G-S-TMSI',
    5 : 'IMEISV',
    6 : 'MAC address',
    7 : 'EUI-64'
    }

_ProtSchemeID_dict = {
    0 : 'Null scheme',
    1 : 'ECIES scheme profile A',
    2 : 'ECIES scheme profile B',
    3 : _str_reserved,
    4 : _str_reserved,
    5 : _str_reserved,
    6 : _str_reserved,
    7 : _str_reserved,
    8 : _str_reserved,
    9 : _str_reserved,
    10 : _str_reserved,
    11 : _str_reserved,
    12 : _str_mnospec,
    13 : _str_mnospec,
    14 : _str_mnospec,
    15 : _str_mnospec
    }


class SUCI_ECIESProfA(Envelope):
    # Curve25519
    _GEN = (
        Buf('ECCEphemPK', bl=256, rep=REPR_HEX),
        Buf('CipherText', rep=REPR_HEX),
        Buf('MAC', bl=64, rep=REPR_HEX)
        )
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        ct_bl = char.len_bit() - 64
        if ct_bl > 0:
            self[1]._bl = ct_bl
            self[1]._from_char(char)
            self[1]._bl = None
        self[2]._from_char(char)


class SUCI_ECIESProfB(Envelope):
    # secp256r1
    _GEN = (
        Buf('ECCEphemPK', bl=264, rep=REPR_HEX),
        Buf('CipherText', rep=REPR_HEX),
        Buf('MAC', bl=64, rep=REPR_HEX)
        )
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        ct_bl = char.len_bit() - 64
        if ct_bl > 0:
            self[1]._bl = ct_bl
            self[1]._from_char(char)
            self[1]._bl = None
        self[2]._from_char(char)


class SUCI_IMSI(Envelope):
    _GEN = (
        PLMN(),
        BufBCD('RoutingInd', bl=16),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('ProtSchemeID', bl=4, dic=_ProtSchemeID_dict),
        Uint8('HNPKID'),
        Alt('Output', GEN={
            0 : BufBCD('MSIN'),
            1 : SUCI_ECIESProfA(),
            2 : SUCI_ECIESProfB()
            },
            DEFAULT=Buf('SUCI_UnkProf', rep=REPR_HEX),
            sel=lambda self: self.get_env()[3].get_val()) 
        )


class SUCI_NAI(UTF8String):
    pass


class FGSIDSUPI(Envelope):
    _name = '5GSIDSUPI'
    _GEN = (
        Uint('spare', bl=1),
        Uint('Fmt', val=FGSIDFMT_IMSI, bl=3, dic=FGSIDFmt_dict),
        Uint('spare', bl=1),
        Uint('Type', val=FGSIDTYPE_SUPI, bl=3, dic=FGSIDType_dict),
        Alt('Value', GEN={
            0: SUCI_IMSI(),
            1: SUCI_NAI(),
            2: SUCI_NAI(),
            3: SUCI_NAI()},
            DEFAULT=Buf('SUPI_Unk', rep=REPR_HEX),
            sel=lambda self: self.get_env()[1].get_val()),
        )
# see TS 29.503, annex C, for a human-readable representation of SUPI


class FGSIDGUTI(Envelope):
    _name = '5GSIDGUTI'
    _GEN = (
        Uint('ind', val=0xf, bl=4, rep=REPR_HEX),
        Uint('spare', bl=1),
        Uint('Type', val=FGSIDTYPE_GUTI, bl=3, dic=FGSIDType_dict),
        PLMN(),
        Uint8('AMFRegionID'),
        Uint('AMFSetID', bl=10),
        Uint('AMFPtr', bl=6),
        Uint32('5GTMSI', rep=REPR_HEX)
        )


# for IMEI and IMEISV
class FGSIDDigit(Envelope):
    _GEN = (
        Uint('Digit1', val=0xF, bl=4, rep=REPR_HEX),
        Uint('Odd', bl=1),
        Uint('Type', val=FGSIDTYPE_IMEI, bl=3, dic=FGSIDType_dict),
        BufBCD('Digits', val='')
        )


class FGSIDSTMSI(Envelope):
    _name = '5GSIDSTMSI'
    _GEN = (
        Uint('ind', val=0xf, bl=4, rep=REPR_HEX),
        Uint('spare', bl=1),
        Uint('Type', val=FGSIDTYPE_STMSI, bl=3, dic=FGSIDType_dict),
        Uint('AMFSetID', bl=10),
        Uint('AMFPtr', bl=6),
        Uint32('5GTMSI', rep=REPR_HEX)
        )


class FGSIDNone(Envelope):
    _name = '5GSIDNone'
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Type', val=FGSIDTYPE_NO, bl=3, dic=FGSIDType_dict)
        )


class FGSIDMAC(Envelope):
    _name = '5GSIDMAC'
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('MAURI', bl=1),
        Uint('Type', val=FGSIDTYPE_MAC, bl=3, dic=FGSIDType_dict),
        Buf('MAC', bl=48, rep=REPR_HEX)
        )


class FGSIDEUI64(Envelope):
    _name = '5GSIDEUI64'
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Type', val=FGSIDTYPE_EUI64, bl=3, dic=FGSIDType_dict),
        Buf('EUI64', bl=64, rep=REPR_HEX)
        )


class FGSID(Envelope):
    _name = '5GSID'
    
    _ID_LUT = {
        FGSIDTYPE_NO     : FGSIDNone(),
        FGSIDTYPE_SUPI   : FGSIDSUPI(),
        FGSIDTYPE_GUTI   : FGSIDGUTI(),
        FGSIDTYPE_IMEI   : FGSIDDigit('5GSIDIMEI'),
        FGSIDTYPE_STMSI  : FGSIDSTMSI(),
        FGSIDTYPE_IMEISV : FGSIDDigit('5GSIDIMEISV', val={'Type': FGSIDTYPE_IMEISV}),
        FGSIDTYPE_MAC    : FGSIDMAC(),
        FGSIDTYPE_EUI64  : FGSIDEUI64()
        }
    
    def set_val(self, vals):
        if isinstance(vals, dict) and 'Type' in vals:
            type = vals['Type']
            del vals['Type']
            self.encode(type, **vals)
        elif isinstance(vals, (tuple, list)):
            if len(vals) >= 4 and vals[3] == FGSIDTYPE_SUPI:
                self.encode(vals[3])
            elif len(vals) >= 3 and vals[2] in (
                FGSIDTYPE_GUTI,
                FGSIDTYPE_IMEI,
                FGSIDTYPE_IMEISV,
                FGSIDTYPE_STMSI,
                FGSIDTYPE_MAC):
                self.encode(vals[2])
            elif len(vals) >= 2 and vals[1] in (FGSIDTYPE_EUI64, FGSIDTYPE_NO):
                self.encode(vals[1])
            Envelope.set_val(self, vals)
        else:
            Envelope.set_val(self, vals)
    
    def _set_content(self, type):
        if 'Type' not in self._by_name:
            # need to create the appropriate content
            for elt in self._ID_LUT[type]:
                self.append(elt.clone())
        elif self['Type'].get_val() != type:
            # need to restructure the content
            self._content.clear()
            self._by_id.clear()
            self._by_name.clear()
            for elt in self._ID_LUT[type]:
                self.append(elt.clone())
    
    def encode(self, type, **kwargs):
        """sets the 5GS mobile identity with given type
        
        The given types correspond to the following classes:
        FGSIDTYPE_NO (0)     -> FGSIDNone
        FGSIDTYPE_SUPI (1)   -> FGSIDSUPI
        FGSIDTYPE_GUTI (2)   -> FGSIDGUTI
        FGSIDTYPE_IMEI (3)   -> FGSIDDigit
        FGSIDTYPE_STMSI (4)  -> FGSIDSTMSI
        FGSIDTYPE_IMEISV (5) -> FGSIDDigit
        FGSIDTYPE_MAC (6)    -> FGSIDMAC
        FGSIDTYPE_EUI64 (7)  -> FGSIDEUI64
        """
        if not isinstance(type, integer_types) or not 0 <= type <= 7:
            raise(PycrateErr('invalid 5GS identity type: %r' % type))
        # set the appropriate content
        self._set_content(type)
        # pass the value to encode
        Envelope.set_val(self, kwargs)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # get the type and set the appropriate content
        type = char.to_uint(8) & 0x7
        self._set_content(type)
        Envelope._from_char(self, char)
        

#------------------------------------------------------------------------------#
# 5GS network feature support
# TS 24.501, 9.11.3.5
#------------------------------------------------------------------------------#

_EMC_dict = {
    0 : 'Emergency services not supported',
    1 : 'Emergency services supported in NR connected to 5GCN only',
    2 : 'Emergency services supported in E-UTRA connected to 5GCN only',
    3 : 'Emergency services supported in NR connected to 5GCN and E-UTRA connected to 5GCN'
    }

_EMF_dict = {
    0 : 'Emergency services fallback not supported',
    1 : 'Emergency services fallback supported in NR connected to 5GCN only',
    2 : 'Emergency services fallback supported in E-UTRA connected to 5GCN only',
    3 : 'Emergency services fallback supported in NR connected to 5GCN and E-UTRA connected to 5GCN'
    }


class FGSNetFeat(Envelope):
    
    ENV_SEL_TRANS = False
    
    _name = '5GSNetFeat'
    _GEN = (
        Uint('MPSI', bl=1),
        Uint('IWK_N26', bl=1),
        Uint('EMF', bl=2, dic=_EMF_dict),
        Uint('EMC', bl=2, dic=_EMC_dict),
        Uint('IMS-VoPS-N3GPP', bl=1),
	    Uint('IMS-VoPS-3GPP', bl=1), # end of octet 1
        Uint('5G-UP-CIoT', bl=1),
        Uint('5G-HC-CP-CIoT', bl=1),
        Uint('N3Data', bl=1),
        Uint('5G-IPHC-CP-CIoT', bl=1),
        Uint('RestrictEC', bl=2),
        Uint('MCSI', bl=1),
        Uint('EMCN3', bl=1), # end of octet 2
        Uint('spare', bl=5),
        Uint('5G-EHC-CP-CIoT', bl=1),
        Uint('ATS-IND', bl=1),
        Uint('5G-LCS', bl=1), # end of octet 3
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def _from_char(self, char):
        if self.get_trans():
            return
        l = char.len_bit()
        if l <= 8:
            self.disable_from('5G-UP-CIoT')
        elif l <= 16:
            self.disable_from('spare')
        elif l > 24:
            # enables some spare bits at the end
            self[-1]._bl = l-24
        Envelope._from_char(self, char)
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (element offset or name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (element offset or name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# 5GS registration result
# TS 24.501, 9.11.3.6
#------------------------------------------------------------------------------#

_FGSRegResult_dict = {
    1 : '3GPP access',
    2 : 'Non-3GPP access',
    3 : '3GPP access and non-3GPP access',
    7 : _str_reserved
    }


class FGSRegResult(Envelope):
    _name = '5GSRegResult'
    _GEN = (
        Uint('spare', bl=2),
        Uint('Emergency', bl=1),
        Uint('NSSAAPerformed', bl=1),
        Uint('SMSAllowed', bl=1),
        Uint('Value', bl=3, dic=_FGSRegResult_dict)
        )


#------------------------------------------------------------------------------#
# 5GS registration type
# TS 24.501, 9.11.3.7
#------------------------------------------------------------------------------#

_FOR_dict = {
    0 : 'No follow-on request pending',
    1 : 'Follow-on request pending'
    }

_FGSRegType_dict = {
    1 : 'initial registration',
    2 : 'mobility registration updating',
    3 : 'periodic registration updating',
    4 : 'emergency registration',
    7 : _str_reserved
    }

class FGSRegType(Envelope):
    _name = '5GSRegType'
    _GEN = (
        Uint('FOR', bl=1, dic=_FOR_dict),
        Uint('Value', bl=3, dic=_FGSRegType_dict)
        )


#------------------------------------------------------------------------------#
# 5GS tracking area identity
# TS 24.501, 9.11.3.8
#------------------------------------------------------------------------------#

class FGSTAI(Envelope):
    _name = '5GSTAI'
    _GEN = (
        PLMN(),
        Uint24('TAC', rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val())


#------------------------------------------------------------------------------#
# 5GS tracking area identity list
# TS 24.501, 9.11.3.9
#------------------------------------------------------------------------------#

_PTAIListType_dict = {
    0 : 'list of TACs belonging to one PLMN, with non-consecutive TAC values',
    1 : 'list of TACs belonging to one PLMN, with consecutive TAC values',
    2 : 'list of TAIs belonging to different PLMNs'
    }


class _PTAIList0(Envelope):
    """List of non-consecutive TACs belonging to one PLMN
    """
    
    _GEN = (
        Uint('Num', bl=5),
        PLMN(),
        Array('TACs', GEN=Uint24('TAC'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: max(0, self[2].get_num()-1))
        self[2].set_numauto(lambda: self[0].get_val()+1)
    
    def get_tai(self):
        plmn = self['PLMN'].decode()
        return set([(plmn, tac) for tac in self['TACs'].get_val()])


class _PTAIList1(Envelope):
    """List of consecutive TACs belonging to one PLMN
    """
    
    _GEN = (
        Uint('Num', bl=5),
        PLMN(),
        Uint24('TAC1'),
        )
    
    def get_tai(self):
        plmn, tac1 = self['PLMN'].decode(), self['TAC1'].get_val()
        return set([(plmn, tac1 + i) for i in range(self['Num'].get_val() + 1)])


class _PTAIList2(Envelope):
    """List of TAI belonging to different PLMNs
    """
    
    _GEN = (
        Uint('Num', bl=5),
        Sequence('TAIs', GEN=FGSTAI())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: max(0, self[1].get_num()-1))
        self[1].set_numauto(lambda: self[0].get_val()+1)
    
    def get_tai(self):
        return set([tai.decode() for tai in self['TAIs']])


class FGSPTAIList(Envelope):
    _name = '5GSPTAIList'
    _GEN = (
        Uint('spare', bl=1),
        Uint('Type', bl=2, dic=_PTAIListType_dict),
        Alt('PTAI', GEN={
            0: _PTAIList0('PTAIList0'),
            1: _PTAIList1('PTAIList1'),
            2: _PTAIList2('PTAIList2')
            },
            DEFAULT=_PTAIList1('PTAIList1'),
            sel=lambda self: self.get_env()['Type'].get_val())
        )
    
    def get_tai(self):
        return self['PTAI'].get_alt().get_tai()


class FGSTAIList(Sequence):
    _name = '5GSTAIList'
    _GEN = FGSPTAIList() 
    
    def get_tai(self):
        tai = set()
        for tl in self:
            tai.update(tl.get_tai())
        return tai


#------------------------------------------------------------------------------#
# 5GS update type
# TS 24.501, 9.11.3.9A
#------------------------------------------------------------------------------#

class FGSUpdateType(Envelope):
    _name = '5GSUpdateType'
    _GEN = (
        Uint('spare', bl=2),
        Uint('EPS-PNB-CIoT', bl=2),
        Uint('5GS-PNB-CIoT', bl=2),
        Uint('NG-RAN-RCU', bl=1),
        Uint('SMSRequested', bl=1)
        )


#------------------------------------------------------------------------------#
# Additional 5G security information
# TS 24.501, 9.11.3.12
#------------------------------------------------------------------------------#

class Add5GSecInfo(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('RINMR', bl=1, dic={
            0:'retransmission of the initial NAS message not requested',
            1:'retransmission of the initial NAS message requested'}),
        Uint('HDP', bl=1, dic={
            0:'K_AMF derivation not required',
            1:'K_AMF derivation required'})
        )


#------------------------------------------------------------------------------#
# Additional information requested
# TS 24.501, 9.11.3.12A
#------------------------------------------------------------------------------#

class AddInfoReq(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('CipherKey', bl=1, dic={
            0:'ciphering keys for ciphered broadcast assistance data not requested',
            1:'ciphering keys for ciphered broadcast assistance data requested'})
        )


#------------------------------------------------------------------------------#
# Allowed PDU session status
# TS 24.501, 9.11.3.13
#------------------------------------------------------------------------------#
# actually identical to PDU session status in .44


#------------------------------------------------------------------------------#
# Configuration update indication
# TS 24.501, 9.11.3.18
#------------------------------------------------------------------------------#

class ConfigUpdateInd(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('RED', bl=1, dic={0:'registration not requested', 1:'registration requested'}),
        Uint('ACK', bl=1, dic={0:'ACK not requested', 1:'ACK requested'})
        )


#------------------------------------------------------------------------------#
# CAG information list
# TS 24.501, 9.11.3.18A
#------------------------------------------------------------------------------#

class CAGInfo(Envelope):
    _GEN = (
        Uint8('Len'),
        PLMN(),
        Array('CAGIDList', GEN=Uint32('CAGID', rep=REPR_HEX))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 + self[2].get_len())
        self[2].set_blauto(lambda: (self[0].get_val()-3)<<3)
    
    def decode(self):
        return {
            'PLMN'      : self['PLMN'].decode(),
            'CAGIDList' : self['CAGIDList'].get_val()
            }


class CAGInfoList(Sequence):
    _GEN = CAGInfo()
    
    def decode(self):
        return [caginfo.decode() for caginfo in self]


#------------------------------------------------------------------------------#
# CIoT small data container
# TS 24.501, 9.11.3.18B
#------------------------------------------------------------------------------#

_CIoTDataType_dict = {
    0 : 'Control plane user data',
    1 : 'SMS',
    2 : 'Location services message container'
    }

_CIoTDDX_dict = {
    0 : 'No information available',
    1 : 'No further uplink or downlink data transmission subsequent to the uplink data transmission is expected',
    2 : 'Only a single downlink data transmission and no further uplink data transmission subsequent to the uplink data transmission is expected',
    3 : _str_reserved
    }


class _CIoTSmallData_CPUD(Envelope):
    _GEN = (
        Uint('DDX', bl=2, dic=_CIoTDDX_dict),
        Uint('PDUSessID', bl=3, dic={0:'No PDU session identity assigned'}),
        Buf('Data', val=b'', rep=REPR_HEX)
        )


class _CIoTSmallData_SMS(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Buf('Data', val=b'', rep=REPR_HEX)
        )


class _CIoTSmallData_LCS(Envelope):
    _GEN = (
        Uint('DDX', bl=2, dic=_CIoTDDX_dict),
        Uint('spare', bl=3),
        Uint8('AddInfoLen'),
        Buf('AddInfo', val=b'', rep=REPR_HEX),
        Buf('Data', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


class CIoTSmallDataContainer(Envelope):
    _GEN = (
        Uint('DataType', bl=3, dic=_CIoTDataType_dict),
        Alt('Cont', GEN={
            0: _CIoTSmallData_CPUD('CPUD'),
            1: _CIoTSmallData_SMS('SMS'),
            2: _CIoTSmallData_LCS('LCS'),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )


#------------------------------------------------------------------------------#
# Ciphering key data
# TS 24.501, 9.11.3.18C
#------------------------------------------------------------------------------#

class CipheringDataSet(Envelope):
    _GEN = (
        Uint16('CipheringSetID'),
        Buf('CipheringKey', bl=128, rep=REPR_HEX),
        Uint('spare', bl=3),
        Uint('C0Len', bl=5),
        Buf('C0', rep=REPR_HEX),
        Uint('spare', bl=4),
        Uint('EUTRAposSIBLen', bl=4),
        Buf('EUTRAposSIB', rep=REPR_HEX), # actually list of flags
        Uint('spare', bl=4),
        Uint('NRposSIBLen', bl=4),
        Buf('NRposSIB', rep=REPR_HEX),
        TimeZoneTime('ValidityStartTime'),
        Uint32('ValidityDuration'),
        FGSTAIList()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['C0Len'].set_valauto(lambda: self['C0'].get_len())
        self['C0'].set_blauto(lambda: self['C0Len'].get_val()<<3)
        self['EUTRAposSIBLen'].set_valauto(lambda: self['EUTRAposSIB'].get_len())
        self['EUTRAposSIB'].set_blauto(lambda: self['EUTRAposSIBLen'].get_val()<<3)
        self['NRposSIBLen'].set_valauto(lambda: self['NRposSIB'].get_len())
        self['NRposSIB'].set_blauto(lambda: self['NRposSIBLen'].get_val()<<3)


class CipheringKeyData(Sequence):
    _GEN = CipheringDataSet()


#------------------------------------------------------------------------------#
# Control plane service type
# TS 24.501, 9.11.3.18D
#------------------------------------------------------------------------------#

_CtrlPlaneServType_dict = {
    0 : 'mobile originating request',
    1 : 'mobile terminating request',
    2 : 'data',
    3 : 'unused - mobile originating request',
    4 : 'unused - mobile originating request',
    5 : 'unused - mobile originating request',
    6 : 'unused - mobile originating request',
    7 : 'unused - mobile originating request'
    }

class CtrlPlaneServiceType(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=_CtrlPlaneServType_dict)
        )


#------------------------------------------------------------------------------#
# De-registration type
# TS 24.501, 9.11.3.20
#------------------------------------------------------------------------------#

_DeregAccessType_dict = {
    1 : '3GPP access',
    2 : 'Non-3GPP access',
    3 : '3GPP access and non-3GPP access'
    }

class DeregistrationType(Envelope):
    _GEN = (
        Uint('SwitchOff', bl=1, dic={0:'normal de-registration', 1:'switch off'}),
        Uint('ReregistrationRequired', bl=1),
        Uint('AccessType', val=1, bl=2, dic=_DeregAccessType_dict)
        )


#------------------------------------------------------------------------------#
# LADN indication
# TS 24.501, 9.11.3.29
#------------------------------------------------------------------------------#

class LADNInd(Sequence):
    _GEN = DNN()
    
    def decode(self):
        return [dnn.decode() for dnn in self]


#------------------------------------------------------------------------------#
# LADN information
# TS 24.501, 9.11.3.30
#------------------------------------------------------------------------------#

class LADN(Envelope):
    _GEN = (
        DNN(),
        FGSTAIList()
        )
    
    def decode(self):
        return self['DNN'].decode(), self['5GSTAIList'].get_tai()


class LADNInfo(Sequence):
    _GEN = LADN()
    
    def decode(self):
        return [ladn.decode() for ladn in self]


#------------------------------------------------------------------------------#
# MICO indication
# TS 24.501, 9.11.3.31
#------------------------------------------------------------------------------#

class MICOInd(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('SPRTI', bl=1),
        Uint('RAAI', bl=1)
        )


#------------------------------------------------------------------------------#
# MA PDU session information
# TS 24.501, 9.11.3.31A
#------------------------------------------------------------------------------#

MAPDUSessInfo_dict = {
    1 : 'MA PDU session network upgrade is allowed'
    }


#------------------------------------------------------------------------------#
# NAS security algorithms
# TS 24.501, 9.11.3.34
#------------------------------------------------------------------------------#

class NASSecAlgo(Envelope):
    _GEN = (
        Uint('CiphAlgo', bl=4, dic=_NASCiphAlgo_dict),
        Uint('IntegAlgo', bl=4, dic=_NASIntegAlgo_dict)
        )


#------------------------------------------------------------------------------#
# Network slicing indication
# TS 24.501, 9.11.3.36
#------------------------------------------------------------------------------#

class NetSlicingInd(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('DCNI', bl=1, dic={
             0: 'requested NSSAI not created from default configured NSSAI',
             1: 'requested NSSAI created from default configured NSSAI'}),
        Uint('NSSCI', bl=1, dic={
             0: 'network slicing subscription not changed',
             1: 'network slicing subscription changed'})
        )


#------------------------------------------------------------------------------#
# NSSAI
# TS 24.501, 9.11.3.37
#------------------------------------------------------------------------------#

class NSSAI(Sequence):
    _GEN = L_SNSSAI()
    
    def decode(self):
        return [snssai[1].get_val_d() for snssai in self]


#------------------------------------------------------------------------------#
# NSSAI inclusion mode
# TS 24.501, 9.11.3.37A
#------------------------------------------------------------------------------#

class NSSAIInclMode(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('Value', bl=2, dic={0:'A', 1:'B', 2:'C', 3:'D'})
        )


#------------------------------------------------------------------------------#
# Operator-defined access category definitions
# TS 24.501, 9.11.3.38
#------------------------------------------------------------------------------#

_CriteriaType_dict = {
    0 : 'DNN',
    1 : 'OS Id + OS App Id',
    2 : 'S-NSSAI'
    }


class _CritDNNs(Envelope):
    _GEN = (
        Uint8('Cnt'),
        Array('DNNs', GEN=DNN())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


class _CritOSAppId(Envelope):
    _GEN = (
        Buf('OS_UUID', bl=128, rep=REPR_HEX),
        Uint8('LenAppId'),
        Buf('AppId')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class _CritOSAppIds(Envelope):
    _GEN = (
        Uint8('Cnt'),
        Array('OSAppIds', GEN=_CritOSAppId('OSAppId'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())

        
class _CritSNSSAI(Envelope):
    _GEN = (
        Uint8('Cnt'),
        Sequence('SNSSAIs', GEN=L_SNSSAI())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


class CriteriaComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_CriteriaType_dict),
        Alt('Crit', GEN={
            0 : _CritDNNs('CompDNN'),
            1 : _CritOSAppIds('CompOSAppId'),
            2 : _CritSNSSAI('CompNSSAI')},
            DEFAULT=Buf('CompUnk', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val()
            )
        )


class OperatorAccessCatDef(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Precedence'),
        Uint('PSAC', bl=1),
        Uint('spare', bl=2),
        Uint('AccessCatNum', bl=5),
        Uint8('LenCriteria'),
        Sequence('Criteria', GEN=CriteriaComp()),
        Envelope('StdAccessCat', GEN=(
            Uint('spare', bl=3), 
            Uint('Value', bl=5)),
            ) # optional, depends on PSAC (Presence of Std Access Cat...)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 3 + self['LenCriteria'].get_val() if self['StdAccessCat'].get_trans() \
                                   else 4 + self['LenCriteria'].get_val())
        self['LenCriteria'].set_valauto(lambda: self['Criteria'].get_len())
        self['Criteria'].set_blauto(lambda: self['LenCriteria'].get_val()<<3)
        self['StdAccessCat'].set_transauto(lambda: False if self['PSAC'].get_val() else True)


class OperatorAccessCatDefs(Sequence):
    _GEN = OperatorAccessCatDef()


#------------------------------------------------------------------------------#
# Payload container
# TS 24.501, 9.11.3.39
#------------------------------------------------------------------------------#
# see EOF


#------------------------------------------------------------------------------#
# Payload container type
# TS 24.501, 9.11.3.40
#------------------------------------------------------------------------------#

PayloadContainerType_dict = {
    1 : 'N1 SM information',
    2 : 'SMS',
    3 : 'LTE Positioning Protocol message container',
    4 : 'SOR transparent container',
    5 : 'UE policy container',
    6 : 'UE parameters update transparent container',
    7 : 'Location services message container',
    8 : 'CIoT user data container',
    15: 'Multiple payloads'
    }


#------------------------------------------------------------------------------#
# PDU session identity 2
# TS 24.501, 9.11.3.41
#------------------------------------------------------------------------------#

class PDUSessID(Uint8):
    _dic = {0: 'no PDU session ID assigned'}


#------------------------------------------------------------------------------#
# PDU session reactivation result error cause
# TS 24.501, 9.11.3.42
#------------------------------------------------------------------------------#

class PDUSessReactResultErr(Array):
    _GEN = Envelope('PDUSessErr', GEN=(
        Uint8('PSI'),
        Uint8('Cause', dic=_FGMMCause_dict))
        )


#------------------------------------------------------------------------------#
# PDU session status
# TS 24.501, 9.11.3.44
#------------------------------------------------------------------------------#

class PDUSessStat(Envelope):
    _GEN = (
        Uint('PSI_7', bl=1),
        Uint('PSI_6', bl=1),
        Uint('PSI_5', bl=1),
        Uint('PSI_4', bl=1),
        Uint('PSI_3', bl=1),
        Uint('PSI_2', bl=1),
        Uint('PSI_1', bl=1),
        Uint('PSI_0', bl=1),
        Uint('PSI_15', bl=1),
        Uint('PSI_14', bl=1),
        Uint('PSI_13', bl=1),
        Uint('PSI_12', bl=1),
        Uint('PSI_11', bl=1),
        Uint('PSI_10', bl=1),
        Uint('PSI_9', bl=1),
        Uint('PSI_8', bl=1),
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def _from_char(self, char):
        if self.get_trans():
            return
        l = char.len_bit()
        if l <= 16:
            # disable all elements after bit l
            self.disable_from(l)
        elif l > 16:
            # enables some spare bits at the end
            self[-1]._bl = l-16
        Envelope._from_char(self, char)
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# Rejected NSSAI
# TS 24.501, 9.11.3.46
#------------------------------------------------------------------------------#

_RejectedSNSSAICause_dict = {
    0 : 'S-NSSAI not available in the current PLMN or SNPN',
    1 : 'S-NSSAI not available in the current registration area',
    2 : 'Network slice specific authentication and authorization pending for the S-NSSAI'
    }

class RejectedSNSSAI(Envelope):
    _GEN = (
        Uint('Len', bl=4),
        Uint('Cause', bl=4, dic=_RejectedSNSSAICause_dict),
        SNSSAI()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[2].get_len())
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self[1]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = char._cur + 8*self[0].get_val()
        self[2]._from_char(char)
        char._len_bit = char_lb
    
    def decode(self):
        return {'Cause': self['Cause'].get_val(), 'SNSSAI': self['SNSSAI'].get_val_d()}


class RejectedNSSAI(Sequence):
    _GEN = RejectedSNSSAI()
    
    def decode(self):
        return [rej_snssai.decode() for rej_snssai in self]


#------------------------------------------------------------------------------#
# Request type
# TS 24.501, 9.11.3.47
#------------------------------------------------------------------------------#

_RequestType_dict = {
    1 : 'initial request',
    2 : 'existing PDU session',
    3 : 'initial emergency request',
    4 : 'existing emergency PDU session',
    5 : 'modification request',
    6 : 'MA PDU request',
    7 : _str_reserved
    }

class RequestType(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=_RequestType_dict)
        )


#------------------------------------------------------------------------------#
# Service area list
# TS 24.501, 9.11.3.49
#------------------------------------------------------------------------------#

class _PTAIList3(Envelope):
    """All TAI belonging to a given PLMN
    """
    _GEN = (
        Uint('Num', val=0, bl=5),
        PLMN(),
        )
    
    def get_tai(self):
        return {(self['PLMN'].decode(), None), }


_AllowedPSAList_dict = {
    0: 'TAIs in the list are in the allowed area',
    1: 'TAIs in the list are in the non-allowed area'
    }


class PSAList(Envelope):
    _GEN = (
        Uint('Allowed', bl=1, dic=_AllowedPSAList_dict),
        Uint('Type', bl=2, dic=_PTAIListType_dict),
        Alt('PTAI', GEN={
            0: _PTAIList0('PTAIList0'),
            1: _PTAIList1('PTAIList1'),
            2: _PTAIList2('PTAIList2'),
            3: _PTAIList3('PTAIList3')
            },
            DEFAULT=_PTAIList1('PTAIList3'),
            sel=lambda self: self.get_env()['Type'].get_val())
        )
    
    def get_tai(self):
        return self['PTAI'].get_alt().get_tai()


class SAList(Sequence):
    _GEN = FGSPTAIList() 
    
    def get_tai(self):
        tai = set()
        for tl in self:
            tai.update(tl.get_tai())
        return tai


#------------------------------------------------------------------------------#
# Service type
# TS 24.501, 9.11.3.50
#------------------------------------------------------------------------------#

ServiceType_dict = {
    0 : 'signalling',
    1 : 'data',
    2 : 'mobile terminated services',
    3 : 'emergency services',
    4 : 'emergency services fallback',
    5 : 'high priority access',
    6 : 'elevated signalling',
    7 : 'unused - signalling',
    8 : 'unused - signalling',
    9 : 'unused - data',
    10 : 'unused - data',
    11 : 'unused - data'
    }


#------------------------------------------------------------------------------#
# SMS indication
# TS 24.501, 9.11.3.50A
#------------------------------------------------------------------------------#

class SMSInd(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1, dic={
            0:'SMS over NAS not available',
            1:'SMS over NAS available'})
        )


#------------------------------------------------------------------------------#
# SOR transparent container
# TS 24.501, 9.11.3.51
#------------------------------------------------------------------------------#

_SORDataType_dict = {
    0: 'steering of roaming information',
    1: 'acknowledgement of successful reception of the steering of roaming information'
    }

_SORListInd_dict = {
    0: 'no change in the list of operator controlled PLMN',
    1: 'list of preferred PLMN/access technology combinations provided'
    }

_SORListType_dict = {
    0: 'secured packet',
    1: 'list of PLMN ID and access technology'
    }

_SORAck_dict = {
    0: 'Ack not requested',
    1: 'Ack requested'
    }


class SORHeader(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('ACK', bl=1, dic=_SORAck_dict),           # only for DataType 0, otherwise spare
        Uint('ListType', bl=1, dic=_SORListType_dict), # only for DataType 0, otherwise spare
        Uint('ListInd', bl=1, dic=_SORListInd_dict),   # only for DataType 0, otherwise spare
        Uint('DataType', bl=1, dic=_SORDataType_dict)
        )


class SORReq(Envelope):
    _GEN = (
        Buf('SOR_MACI_AUSF', bl=128, rep=REPR_HEX),
        Uint16('CntSOR'),
        Alt('Data', GEN={
            0: PacketCmdSMSPP(), # STK request
            1: Sequence('PLMNATList', GEN=Envelope('PLMNAT', GEN=(
                PLMN(),
                Uint16('AccessTechno')))
                )},
            sel=lambda self: self.get_env().get_env()[0][2].get_val()
            )
        )


class SORResp(Envelope):
    _GEN = (
        Buf('SOR_MACI_UE', bl=128, rep=REPR_HEX),
        )


class SORTransContainer(Envelope):
    _GEN = (
        SORHeader(),
        Alt('Cont', GEN={
            0: SORReq(),
            1: SORResp()},
            sel=lambda self: self.get_env()[0][4].get_val()
            )
        )


#------------------------------------------------------------------------------#
# UE parameters update transparent container
# TS 24.501, 9.11.3.53A
#------------------------------------------------------------------------------#

class UPUHeader(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('REG', bl=1), # only for DataType 0, otherwise spare
        Uint('ACK', bl=1), # only for DataType 0, otherwise spare
        Uint('DataType', bl=1, dic={
            0:'carries a UE parameters update list',
            1:'carries an acknowledgement of successful reception of a UE parameters update list'})
        )


class UPUComp(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('DataSetType', val=1, bl=4, dic={
            1: 'Routing indicator update data',
            2: 'Default configured NSSAI update data'}),
        Uint16('DataSetLen'),
        Alt('DataSet', GEN={
            1: PacketCmdSMSPP(), # STK request
            2: NSSAI()},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[1].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


class UPUReq(Envelope):
    _GEN = (
        Buf('UPU_MACI_AUSF', bl=128, rep=REPR_HEX),
        Uint16('CntUPU'),
        Sequence('UPUList', GEN=UPUComp())
        )


class UPUResp(Envelope):
    _GEN = (
        Buf('UPU_MACI_UE', bl=128, rep=REPR_HEX),
        )


class UPUTransContainer(Envelope):
    _GEN = (
        UPUHeader(),
        Alt('Cont', GEN={
            0: UPUReq(),
            1: UPUResp()},
            sel=lambda self: self.get_env()[0][3].get_val())
        )


#------------------------------------------------------------------------------#
# UE security capability
# TS 24.501, 9.11.3.54
#------------------------------------------------------------------------------#

class UESecCap(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('5G-EA0', bl=1),
        Uint('5G-EA1_128', bl=1),
        Uint('5G-EA2_128', bl=1),
        Uint('5G-EA3_128', bl=1),
        Uint('5G-EA4', bl=1),
        Uint('5G-EA5', bl=1),
        Uint('5G-EA6', bl=1),
        Uint('5G-EA7', bl=1),
        Uint('5G-IA0', bl=1),
        Uint('5G-IA1_128', bl=1),
        Uint('5G-IA2_128', bl=1),
        Uint('5G-IA3_128', bl=1),
        Uint('5G-IA4', bl=1),
        Uint('5G-IA5', bl=1),
        Uint('5G-IA6', bl=1),
        Uint('5G-IA7', bl=1), # end of octet 2 (mandatory part)
        Uint('EEA0', bl=1),
        Uint('EEA1_128', bl=1),
        Uint('EEA2_128', bl=1),
        Uint('EEA3_128', bl=1),
        Uint('EEA4', bl=1),
        Uint('EEA5', bl=1),
        Uint('EEA6', bl=1),
        Uint('EEA7', bl=1),
        Uint('EIA0', bl=1),
        Uint('EIA1_128', bl=1),
        Uint('EIA2_128', bl=1),
        Uint('EIA3_128', bl=1),
        Uint('EIA4', bl=1),
        Uint('EIA5', bl=1),
        Uint('EIA6', bl=1),
        Uint('EIA7', bl=1), # end of octet 4 (optional part)
        Buf('spare', val=b'', rep=REPR_HEX, trans=True)
        )
    
    def set_val(self, val):
        Envelope.set_val(self, val)
        # in case no 4G sec cap are set, we disable them
        if not any([seccap.get_val() == 1 for seccap in self._content[16:32]]):
            self.disable_from(16)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        l = char.len_bit()
        if l <= 32:
            # disable all elements after bit l
            self.disable_from(l)
        elif l > 32:
            # enables some spare bits at the end
            self[-1]._bl = l-32
        Envelope._from_char(self, char)
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]



#------------------------------------------------------------------------------#
# UE's usage setting
# TS 24.501, 9.11.3.55
#------------------------------------------------------------------------------#

class UEUsage(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('Value', bl=1, dic={0:'voice centric', 1:'data centric'})
        )


#------------------------------------------------------------------------------#
# UE status
# TS 24.501, 9.11.3.56
#------------------------------------------------------------------------------#

class UEStatus(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('N1ModeReg', bl=1, dic={
            0:'UE not in 5GMM-REGISTERED state',
            1:'UE in 5GMM-REGISTERED state'}),
        Uint('S1ModeReg', bl=1, dic={
            0:'UE not in EMM-REGISTERED state',
            1:'UE in EMM-REGISTERED state'})
        )


#------------------------------------------------------------------------------#
# Uplink data status
# TS 24.501, 9.11.3.57
#------------------------------------------------------------------------------#

class ULDataStat(PDUSessStat):
    pass


#------------------------------------------------------------------------------#
# UE radio capability ID
# TS 24.501, 9.11.3.68
#------------------------------------------------------------------------------#

class UERadioCapID(BufBCD):
    pass


#------------------------------------------------------------------------------#
# UE radio capability ID deletion indication
# TS 24.501, 9.11.3.69
#------------------------------------------------------------------------------#

_DelRequest_dict = {
    0 : 'UE radio capability ID deletion not requested',
    1 : 'Network-assigned UE radio capability IDs deletion requested'
    }

class UERadioCapIDDelInd(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('DelRequest', bl=3, dic=_DelRequest_dict)
        )


#------------------------------------------------------------------------------#
# Truncated 5G-S-TMSI configuration
# TS 24.501, 9.11.3.70
#------------------------------------------------------------------------------#

class Trunc5GSTMSIConfig(Envelope):
    _GEN = (
        Uint('TruncAMFSetID', bl=4),
        Uint('TruncAMFPtr', bl=4)
        )


#------------------------------------------------------------------------------#
# NB-N1 mode DRX parameters
# TS 24.501, 9.11.3.73
#------------------------------------------------------------------------------#

_NBN1ModeDRXParam_dict = {
    0 : 'DRX value not specified',
    1 : 'DRX cycle parameter T = 32',
    2 : 'DRX cycle parameter T = 64',
    3 : 'DRX cycle parameter T = 128',
    4 : 'DRX cycle parameter T = 256',
    5 : 'DRX cycle parameter T = 512',
    6 : 'DRX cycle parameter T = 1024',
    }

class NBN1ModeDRXParam(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=4, dic=_NBN1ModeDRXParam_dict)
        )


#------------------------------------------------------------------------------#
# Additional configuration indication
# TS 24.501, 9.11.3.74
#------------------------------------------------------------------------------#

class AddConfigInd(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('SCMR', bl=1, dic={
            0:'no additional information',
            1:'release of N1 NAS signalling connection not required'})
        )


#------------------------------------------------------------------------------#
# 5GSM capability
# TS 24.501, 9.11.4.1
#------------------------------------------------------------------------------#

class FGSMCap(Envelope):
    
    ENV_SEL_TRANS = False
    
    _name = '5GSMCap'
    _GEN = (
        Uint('TPMIC', bl=1),
        Uint('ATSSS-ST', bl=4),
        Uint('EPT-S1', bl=1),
        Uint('MH6-PDU', bl=1),
        Uint('RQoS', bl=1),
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    #def _from_char(self, char):
    #    Envelope._from_char(self, char)
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# 5GSM cause
# TS 24.501, 9.11.4.2
#------------------------------------------------------------------------------#

_FGSMCause_dict = {
    8 : 'Operator determined barring',
    23 : 'UE security capabilities mismatch', # for NAS Security Mode Reject
    24 : 'Security mode rejected, unspecified', # for NAS Security Mode Reject
    26 : 'Insufficient resources',
    27 : 'Missing or unknown DNN',
    28 : 'Unknown PDU session type',
    29 : 'User authentication or authorization failed',
    31 : 'Request rejected, unspecified',
    32 : 'Service option not supported',
    33 : 'Requested service option not subscribed',
    35 : 'PTI already in use',
    36 : 'Regular deactivation',
    38 : 'Network failure',
    39 : 'Reactivation requested',
    41 : 'Semantic error in the TFT operation',
    42 : 'Syntactical error in the TFT operation',
    43 : 'Invalid PDU session identity',
    44 : 'Semantic errors in packet filter(s)',
    45 : 'Syntactical error in packet filter(s)',
    46 : 'Out of LADN service area',
    47 : 'PTI mismatch',
    50 : 'PDU session type IPv4 only allowed',
    51 : 'PDU session type IPv6 only allowed',
    54 : 'PDU session does not exist',
    57 : 'PDU session type IPv4v6 only allowed',
    58 : 'PDU session type Unstructured only allowed',
    59 : 'Unsupported 5QI value',
    60 : 'PDU session type Ethernet only allowed',
    67 : 'Insufficient resources for specific slice and DNN',
    68 : 'Not supported SSC mode',
    69 : 'Insufficient resources for specific slice',
    70 : 'Missing or unknown DNN in a slice',
    81 : 'Invalid PTI value',
    82 : 'Maximum data rate per UE for user-plane integrity protection is too low',
    83 : 'Semantic error in the QoS operation',
    84 : 'Syntactical error in the QoS operation',
    85 : 'Invalid mapped EPS bearer identity',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non-existent or not implemented',
    98 : 'Message type not compatible with the protocol state',
    99 : 'Information element non-existent or not implemented',
    100 : 'Conditional IE error',
    101 : 'Message not compatible with the protocol state',
    111 : 'Protocol error, unspecified'
    }

class FGSMCause(Uint8):
    _name = '5GSMCause'
    _dic  = _FGSMCause_dict


#------------------------------------------------------------------------------#
# Always-on PDU session indication
# TS 24.501, 9.11.4.3
#------------------------------------------------------------------------------#

class AlwaysOnPDUSessInd(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1)
        )


#------------------------------------------------------------------------------#
# Always-on PDU session requested
# TS 24.501, 9.11.4.4
#------------------------------------------------------------------------------#

class AlwaysOnPDUSessReq(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1)
        )


#------------------------------------------------------------------------------#
# Allowed SSC mode
# TS 24.501, 9.11.4.5
#------------------------------------------------------------------------------#

class AllowedSSCMode(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('SSC3', bl=1),
        Uint('SSC2', bl=1),
        Uint('SSC1', bl=1)
        )


#------------------------------------------------------------------------------#
# Integrity protection maximum data rate
# TS 24.501, 9.11.4.7
#------------------------------------------------------------------------------#

_IntegrityProtMaxDataRate_dict = {
    0    : '64 kbps',
    1    : 'NULL',
    0xff : 'full data rate'
    }

class IntegrityProtMaxDataRate(Envelope):
    _GEN = (
        Uint8('UPUL', dic=_IntegrityProtMaxDataRate_dict),
        Uint8('UPDL', dic=_IntegrityProtMaxDataRate_dict)
        )


#------------------------------------------------------------------------------#
# Mapped EPS bearer contexts
# TS 24.501, 9.11.4.8
#------------------------------------------------------------------------------#

_EPSBearerCtxtOC_dict = {
    0 : _str_reserved,
    1 : 'Create new EPS bearer',
    2 : 'Delete new EPS bearer',
    3 : 'Modify new EPS bearer'
    }

_EPSBearerCtxtEDict_dict = {
    1 : {
        0 : 'parameters list not included',
        1 : 'parameters list included'
        },
    2 : {
        0 : 'extension of previously provided parameters list',
        1 : 'replacement of all previously provided parameters list'
        },
    3 : { # TS unclear there !
        }
    }

_EPSParamType_dict = {
    1 : 'Mapped EPS QoS parameters',
    2 : 'Mapped extended EPS QoS parameters',
    3 : 'Traffic flow template',
    4 : 'APN-AMBR',
    5 : 'Extended APN-AMBR',
    }


class EPSParam(Envelope):
    _GEN = (
        Uint8('Type', dic=_EPSParamType_dict),
        Uint8('Len'),
        Alt('Content', GEN={
            1 : EPSQoS(),
            2 : ExtEPSQoS(),
            3 : TFT(),
            4 : APN_AMBR(),
            5 : ExtAPN_AMBR()
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class EPSBearerCtxt(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('EBI', bl=4),
        Uint16('Len'),
        Uint('OpCode', bl=2, dic=_EPSBearerCtxtOC_dict),
        Uint('spare', bl=2),
        Uint('E', bl=1),
        Uint('Num', bl=3),
        Sequence('EPSParamList', GEN=EPSParam())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 1 + self['EPSParams'].get_len()) # TS does not define which length it is...
        self['E'].set_dicauto(lambda: _EPSBearerCtxtEDict_dict.get(self['OpCode'].get_val(), {}))
        self['Num'].set_valauto(lambda: self['EPSParamList'].get_num())
        self['EPSParamList'].set_numauto(lambda: self['Num'].get_val())


class MappedEPSBearerCtxt(Sequence):
    _GEN = EPSBearerCtxt()


#------------------------------------------------------------------------------#
# Maximum number of supported packet filters
# TS 24.501, 9.11.4.9
#------------------------------------------------------------------------------#
# 17 <= Value <= 1024
 
class MaxPktFilters(Envelope):
    _GEN = (
        Uint('Value', bl=11), # should be 17 <= X <= 1024
        Uint('spare', bl=5)
        )


#------------------------------------------------------------------------------#
# PDU address
# TS 24.501, 9.11.4.10
#------------------------------------------------------------------------------#

class PDUAddress(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('Type', bl=2, dic={1:'IPv4', 2:'IPv6', 3:'IPv4v6'}),
        Alt('Addr', GEN={
            1 : Buf('IPv4', bl=32, rep=REPR_HEX),
            2 : Buf('IPv6', bl=128, rep=REPR_HEX),
            3 : Envelope('IPv4v6', GEN=(
                    Buf('IPv4', bl=32, rep=REPR_HEX),
                    Buf('IPv6', bl=128, rep=REPR_HEX)))},
            DEFAULT=Buf('unk', rep=REPR_HEX),
            sel=lambda self: self.get_env()[1].get_val()
            )
        )


#------------------------------------------------------------------------------#
# PDU session type
# TS 24.501, 9.11.4.11
#------------------------------------------------------------------------------#

_PDUSessType_dict = {
    1 : 'IPv4',
    2 : 'IPv6',
    3 : 'IPv4v6',
    4 : 'Unstructured',
    5 : 'Ethernet',
    7 : _str_reserved
    }

class PDUSessType(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=_PDUSessType_dict)
        )


#------------------------------------------------------------------------------#
# QoS flow descriptions
# TS 24.501, 9.11.4.12
#------------------------------------------------------------------------------#

_UnitBitrate_dict = {
    1  : '1 Kbps',
    2  : '4 Kbps',
    3  : '16 Kbps',
    4  : '64 Kbps',
    5  : '256 kbps',
    6  : '1 Mbps',
    7  : '4 Mbps',
    8  : '16 Mbps',
    9  : '64 Mbps',
    10 : '256 Mbps',
    11 : '1 Gbps',
    12 : '4 Gbps',
    13 : '16 Gbps',
    14 : '64 Gbps',
    15 : '256 Gbps',
    16 : '1 Tbps',
    17 : '4 Tbps',
    18 : '16 Tbps',
    19 : '64 Tbps',
    20 : '256 Tbps',
    21 : '1 Pbps',
    22 : '4 Pbps',
    23 : '16 Pbps',
    24 : '64 Pbps',
    25 : '256 Pbps'
    }

_QoSFlowOC_dict = {
    1 : 'Create new QoS flow description',
    2 : 'Delete existing QoS flow description',
    3 : 'Modify existing QoS flow description'
    }

_QoSFlowE_dict = {
    1 : {
        0 : _str_reserved,
        1 : 'parameters list is included'
        },
    2 : {
        0 : 'parameters list is not included',
        1 : _str_reserved
        },
    3 : {
        0 : 'extension of previously provided parameters',
        1 : 'replacement of all previously provided parameters'
        }
    }

_QoSFlowParamType_dict = {
    1 : '5QI',
    2 : 'GFBR uplink',
    3 : 'GFBR downlink',
    4 : 'MFBR uplink',
    5 : 'MFBR downlink',
    6 : 'Averaging window',
    7 : 'EPS bearer identity'
    }


class _QoSFlowParamFBR(Envelope):
    _GEN = (
        Uint8('Unit', dic=_UnitBitrate_dict),
        Uint16('Value')
        )


class _QoSFlowParamEBI(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('EBI', bl=4),
        )


class QoSFlowParam(Envelope):
    _GEN = (
        Uint8('Type', dic=_QoSFlowParamType_dict),
        Uint8('Len'),
        Alt('Content', GEN={
            1 : Uint8('5GQI'),
            2 : _QoSFlowParamFBR('GFBR'),
            3 : _QoSFlowParamFBR('GFBR'),
            4 : _QoSFlowParamFBR('MFBR'),
            5 : _QoSFlowParamFBR('MFBR'),
            6 : Uint16('Win', desc='millisecond'),
            7 : _QoSFlowParamEBI('EBI')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class QoSFlow(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('QFI', bl=6),
        Uint('OpCode', bl=3, dic=_QoSFlowOC_dict),
        Uint('spare', bl=6), # last 5 bit of 2nd octet and 1st bit of 3rd octet
        Uint('E', bl=1),
        Uint('Num', bl=6),
        Sequence('Params', GEN=QoSFlowParam('Param'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['E'].set_dicauto(lambda: _QoSFlowE_dict[self['OpCode'].get_val()])
        self['Num'].set_valauto(lambda: self['Params'].get_num())
        self['Params'].set_numauto(lambda: self['Num'].get_val())


class QoSFlowDesc(Sequence):
    _GEN = QoSFlow()


#------------------------------------------------------------------------------#
# QoS rules
# TS 24.501, 9.11.4.13
#------------------------------------------------------------------------------#
# similar to Traffic Flow Template for PS and EPS domains
# TS 24.008, 10.5.6.12

_QoSRuleOpCode_dict = {
    0 : _str_reserved,
    1 : 'Create new QoS rule',
    2 : 'Delete existing QoS rule',
    3 : 'Modify existing QoS rule and add packet filters',
    4 : 'Modify existing QoS rule and replace all packet filters',
    5 : 'Modify existing QoS rule and delete packet filters',
    6 : 'Modify existing QoS rule without modifying packet filters',
    7 : _str_reserved
    }

_PktFilterDir_dict = {
    0 : _str_reserved,
    1 : 'downlink only',
    2 : 'uplink only',
    3 : 'bidirectional'
    }

_PktFilterCompType_dict = {
    1   : 'Match-all type',
    16  : 'IPv4 remote address type',
    17  : 'IPv4 local address type',
    33  : 'IPv6 remote address/prefix length type',
    35  : 'IPv6 local address/prefix length type',
    48  : 'Protocol identifier/Next header type',
    64  : 'Single local port type',
    65  : 'Local port range type',
    80  : 'Single remote port type',
    81  : 'Remote port range type',
    96  : 'Security parameter index type',
    112 : 'Type of service/Traffic class type',
    128 : 'Flow label type',
    129 : 'Destination MAC address type',
    130 : 'Source MAC address type',
    131 : '802.1Q C-TAG VID type',
    132 : '802.1Q S-TAG VID type',
    133 : '802.1Q C-TAG PCP/DEI type',
    134 : '802.1Q S-TAG PCP/DEI type',
    135 : 'Ethertype type'
    }


class PktFilterDel(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('ID', bl=4)
        )


class _PktFilterCompIPv4(Envelope):
    _GEN = (
        Buf('Addr', bl=32, rep=REPR_HEX),
        Buf('Mask', bl=32, rep=REPR_HEX)
        )


class _PktFilterCompIPv6(Envelope):
    _GEN = (
        Buf('Addr', bl=128, rep=REPR_HEX),
        Uint8('Pref')
        )


class _PktFilterCompPortRange(Envelope):
    _GEN = (
        Uint16('Low'),
        Uint16('High')
        )


class _PktFilterTrafficClass(Envelope):
    _GEN = (
        Uint8('Class'),
        Uint8('Mask')
        )


class _PktFilterFlowLabel(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=20, rep=REPR_HEX)
        )


class _PktFilterVID(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=12)
        )


class _PktFilterPCPDEI(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('PCP', bl=3),
        Uint('DEI', bl=1)
        )


class PktFilterComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_PktFilterCompType_dict),
        Alt('Value', GEN={
            1   : Buf('none', bl=0, rep=REPR_HEX),
            16  : _PktFilterCompIPv4('IPv4'),
            17  : _PktFilterCompIPv4('IPv4'),
            33  : _PktFilterCompIPv6('IPv6Pref'),
            35  : _PktFilterCompIPv6('IPv6Pref'),
            48  : Uint8('ProtId', dic=IPProt_dict),
            64  : Uint16('Port'),
            65  : _PktFilterCompPortRange('PortRange'),
            80  : Uint16('Port'),
            81  : _PktFilterCompPortRange('PortRange'),
            96  : Uint32('SPI', rep=REPR_HEX),
            112 : _PktFilterTrafficClass('TrafficClass'),
            128 : _PktFilterFlowLabel('FlowLabel'),
            129 : Buf('MACDest', bl=48, rep=REPR_HEX),
            130 : Buf('MACSrc', bl=48, rep=REPR_HEX),
            131 : _PktFilterVID('CTagVID'),
            132 : _PktFilterVID('STagVID'),
            133 : _PktFilterPCPDEI('CTagPCPDEI'),
            134 : _PktFilterPCPDEI('STagPCPDEI'),
            135 : Uint16('EtherType', dic=EtherType_dict)
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


class PktFilterAdd(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('Dir', bl=2, dic=_PktFilterDir_dict),
        Uint('Id', bl=4),
        Uint8('Len'),
        Sequence('PktFilter', GEN=PktFilterComp())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[3].set_valauto(lambda: self[4].get_len())
        self[4].set_blauto(lambda: self[3].get_val()<<3)


class QoSRule(Envelope):
    _GEN = (
        Uint8('ID', dic={0:'no QoS rule identifier assigned'}),
        Uint16('Len'),
        Uint('OpCode', val=1, bl=3, dic=_QoSRuleOpCode_dict),
        Uint('DQR', bl=1, dic={0:'not the default rule', 1:'default rule'}),
        Uint('NumPktFilters', bl=4),
        Sequence('PktFilterList',
            GEN=Alt('PktFilter', GEN={
                1 : PktFilterAdd(),
                2 : Buf('empty', bl=0),
                3 : PktFilterAdd(),
                4 : PktFilterAdd(),
                5 : PktFilterDel(),
                6 : Buf('empty', bl=0)},
                DEFAULT=Buf('unk', bl=0, rep=REPR_HEX),
                sel=lambda self: self.get_env().get_env()['OpCode'].get_val())
            ),
        Uint8('Precedence', trans=True), # optional
        Envelope('Flow', GEN=(
            Uint('spare', bl=1),
            Uint('Segregation', bl=2),
            Uint('QFI', bl=5)),
            trans=True) # optional
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 1 + self['PktFilterList'].get_len() + self['Precedence'].get_len() + self['Flow'].get_len())
        self[4].set_valauto(lambda: self[5].get_num())
        self[5].set_numauto(lambda: self[4].get_val())
    
    def set_val(self, vals):
        if isinstance(vals, dict):
            if 'Precedence' in vals:
                self['Precedence'].set_trans(False)
            if 'Flow' in vals:
                self['Flow'].set_trans(False)
        elif isinstance(vals, (tuple, list)):
            if len(vals) > 5:
                self['Precedence'].set_trans(False)
            if len(vals) > 6:
                self['Flow'].set_trans(False)
        Envelope.set_val(self, vals)
        
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self[1]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = char._cur + (self[1].get_val()<<3)
        if char._len_bit > char_lb:
            raise(EltErr('{0} [_from_char]: bit length overflow'.format(self._name)))
        self[2]._from_char(char)
        self[3]._from_char(char)
        self[4]._from_char(char)
        self[5]._from_char(char)
        if char.len_bit() >= 8:
            self[6].set_trans(False)
            self[6]._from_char(char)
            if char.len_bit() >= 8:
                self[7].set_trans(False)
                self[7]._from_char(char)
        char._len_bit = char_lb


class QoSRules(Sequence):
    _GEN = QoSRule()


#------------------------------------------------------------------------------#
# Session-AMBR
# TS 24.501, 9.11.4.14
#------------------------------------------------------------------------------#

class SessAMBR(Envelope):
    _GEN = (
        Uint8('DLUnit', dic=_UnitBitrate_dict),
        Uint16('DL'),
        Uint8('ULUnit', dic=_UnitBitrate_dict),
        Uint16('UL')
        )


#------------------------------------------------------------------------------#
# SM PDU DN request container
# TS 24.501, 9.11.4.15
#------------------------------------------------------------------------------#

class SMPDUDNReqContainer(Envelope):
    _GEN = (
        UTF8String('DNSpecificID'),
        )


#------------------------------------------------------------------------------#
# SSC mode
# TS 24.501, 9.11.4.16
#------------------------------------------------------------------------------#

_SSCMode_dict = {
    1 : 'mode 1',
    2 : 'mode 2',
    3 : 'mode 3',
    4 : 'unused - mode 1',
    5 : 'unused - mode 2',
    6 : 'unused - mode 3'
    }

class SSCMode(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dict=_SSCMode_dict)
        )


#------------------------------------------------------------------------------#
# Re-attempt indicator
# TS 24.501, 9.11.4.17
#------------------------------------------------------------------------------#

class ReattemptInd(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('EPLMNC', bl=1),
        Uint('RATC', bl=1)
        )


#------------------------------------------------------------------------------#
# 5GSM network feature support
# TS 24.501, 9.11.4.18
#------------------------------------------------------------------------------#

class FGSMNetFeat(Envelope):
    _name = '5GSMNetFeat'
    _GEN = (
        Uint('spare', bl=7),
        Uint('EPT-S1', bl=1),
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (element offset or name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (element offset or name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# Re-attempt indicator
# TS 24.501, 9.11.4.21
#------------------------------------------------------------------------------#

class CongestReattemptInd(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('ABO', bl=1)
        )


#------------------------------------------------------------------------------#
# Control plane only indication
# TS 24.501, 9.11.4.23
#------------------------------------------------------------------------------#

class CtrlPlaneOnlyInd(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', val=1, bl=1,
             dic={1:'PDU session can be used for control plane CIoT 5GS optimization only'})
        )


#------------------------------------------------------------------------------#
# Ethernet header compression configuration
# TS 24.501, 9.11.4.28
#------------------------------------------------------------------------------#

class EthHdrCompConfig(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('CIDLen', bl=2, dic={
            0:'Ethernet header compression not used',
            1:'7 bits',
            2:'15 bits'})
        )


#------------------------------------------------------------------------------#
# Payload container
# TS 24.501, 9.11.3.39
#------------------------------------------------------------------------------#

_PayContOptType_dict = {
    12 : 'PDU session ID',
    24 : 'Additional information',
    58 : '5GMM cause',
    37 : 'Back-off timer value',
    59 : 'Old PDU session ID',
    80 : 'Request type',
    22 : 'S-NSSAI',
    25 : 'DNN'
    }


class _PayContOpt(Envelope):
    _GEN = (
        Uint8('Type', dic=_PayContOptType_dict),
        Uint8('Len'),
        Alt('Val', GEN={
            0x12 : PDUSessID(),
            0x24 : Buf('AdditionalInfo', rep=REPR_HEX),
            0x58 : FGMMCause(),
            0x37 : GPRSTimer3('BackOffTimer'),
            0x59 : PDUSessID('OldPDUSessID'),
            0x80 : Uint8('RequestType', dic=_RequestType_dict),
            0x22 : SNSSAI(),
            0x25 : DNN(),
            0xF0 : Uint8('ReleaseAssistInd', dic=RelAssist_DDXDict),
            0xA0 : Uint8('MAPDUSessInfo', dic=MAPDUSessInfo_dict)
            },
            DEFAULT=Buf('Val'),
            sel=lambda self: self.get_env()[0].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class _PayContEntry(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('OptNum', bl=4),
        Uint('Type', bl=4, dic=PayloadContainerType_dict),
        Sequence('Opts', GEN=_PayContOpt('Opt')),
        Buf('Cont', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[3].get_len() + self[4].get_len())
        self[1].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[1].get_val())
        self[4].set_blauto(lambda: (self[0].get_val()-1-self[3].get_len())<<3)


class PayloadContainerMult(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('Entries', GEN=_PayContEntry('Entry'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


