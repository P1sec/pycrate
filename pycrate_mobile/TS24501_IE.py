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

from pycrate_mobile.TS24008_IE  import (
    BufBCD, PLMN, GPRSTimer3,
    )
from pycrate_mobile.TS24301_IE import (
    UENetCap as S1UENetCap, UESecCap as S1UESecCap,
    )

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
# DNN
# TS 24.301, 9.11.2.1A
#------------------------------------------------------------------------------#

class DNN(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('Value')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


#------------------------------------------------------------------------------#
# S-NSSAI
# TS 24.301, 9.11.2.8
#------------------------------------------------------------------------------#

class _SNSSAI_SST_MappedHSST(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint8('MappedHPLMNSST')
        )


class _SNSSAI_SST_SD(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint16('SD')
        )


class _SNSSAI_SST_SD_MappedHSST(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint16('SD'),
        Uint8('MappedHPLMNSST')
        )


class _SNSSAI_SST_SD_MappedHSSTSD(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint16('SD'),
        Uint8('MappedHPLMNSST'),
        Uint16('MappedHPLMNSD')
        )


class _SNSSAI_SST_SD_MappedHSSTSD_spare(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint16('SD'),
        Uint8('MappedHPLMNSST'),
        Uint16('MappedHPLMNSD'),
        Buf('spare', rep=REPR_HEX)
        )


class SNSSAI(Envelope):
    _GEN = (
        Uint8('Len'),
        Alt('Value', GEN={
            0 : Buf('none', bl=0),
            1 : Uint8('SST'),
            2 : _SNSSAI_SST_MappedHSST('SST_MappedHPLMNSST'),
            3 : _SNSSAI_SST_SD('SST_SD'),
            4 : _SNSSAI_SST_SD_MappedHSSTSD('SST_SD_MappedHPLMNSSTSD')},
            DEFAULT=_SNSSAI_SST_SD_MappedHSSTSD_spare('SST_SD_MappedHPLMNSSTSD_spare'),
            sel=lambda self: self.get_env()['Len'].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())


#------------------------------------------------------------------------------#
# 5GMM capability
# TS 24.301, 9.11.3.1
#------------------------------------------------------------------------------#

class FGMMCap(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('SGC', bl=1),
        Uint('5G-HC-CP-CIoT', bl=1),
        Uint('N3Data', bl=1),
        Uint('5G-CP-CIoT', bl=1),
        Uint('RestrictEC', bl=1),
        Uint('LPP', bl=1),
        Uint('HOAttach', bl=1),
        Uint('S1Mode', bl=1),
        Uint('RACS', bl=1),
        Uint('NSSAA', bl=1),
        Uint('5G-LCS', bl=1),
        Uint('V2XCNPC5', bl=1),
        Uint('V2XCEPC5', bl=1),
        Uint('V2X', bl=1),
        Uint('5G-UP-CIoT', bl=1),
        Uint('5GSRVCC', bl=1), # end of octet 2
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def _from_char(self, char):
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
# 5GMM cause
# TS 24.301, 9.11.3.2
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
    _dic = _FGMMCause_dict


#------------------------------------------------------------------------------#
# 5GS DRX parameters
# TS 24.301, 9.11.3.2A
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
# 5GS mobile identity
# TS 24.301, 9.11.3.4
#------------------------------------------------------------------------------#

FGSIDType_dict = {
    0 : 'No identity',
    1 : 'SUCI',
    2 : '5G-GUTI',
    3 : 'IMEI',
    4 : '5G-S-TMSI',
    5 : 'IMEISV',
    6 : 'MAC address'
    }

FGSIDTYPE_NO     = 0
FGSIDTYPE_SUPI   = 1
FGSIDTYPE_GUTI   = 2
FGSIDTYPE_IMEI   = 3
FGSIDTYPE_TMSI   = 4
FGSIDTYPE_IMEISV = 5
FGSIDTYPE_MAC    = 6


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
        self[0]._from_char(char)
        ct_bl = char.len_bit() - 64
        if ct_bl > 0:
            self[1]._bl = ct_bl
            self[1]._from_char(char)
            self[1]._bl = None
        self[2]._from_char(char)


class SUPI_IMSI(Envelope):
    _GEN = (
        PLMN(),
        BufBCD('RoutingInd', bl=16),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('ProtSchemeID', bl=4, dic=_ProtSchemeID_dict),
        Uint8('HNPKID'),
        Alt('Output', GEN={
            0 : BufBCD('IMSI'),
            1 : SUCI_ECIESProfA(),
            2 : SUCI_ECIESProfB()
            },
            DEFAULT=Buf('SUCI_UnkProf', rep=REPR_HEX),
            sel=lambda self: self.get_env()[2].get_val()) 
        )


class SUPI_NAI(UTF8String):
    pass


class FGSIDSUPI(Envelope):
    _name = '5GSIDSUPI'
    _GEN = (
        Uint('spare', bl=1),
        Uint('Fmt', bl=3, dic={0:'IMSI', 1:'NAI'}),
        Uint('spare', bl=1),
        Uint('Type', val=FGSIDTYPE_SUPI, bl=3, dic=FGSIDType_dict),
        Alt('Value', GEN={
            0: SUPI_IMSI(),
            1: SUPI_NAI()},
            DEFAULT=Buf('SUPI_Unk', rep=REPR_HEX),
            sel=lambda self: self.get_env()[1].get_val()),
        )


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
    _name = '5GSIDDigit'
    _GEN = (
        Uint('Digit1', val=0xF, bl=4, rep=REPR_HEX),
        Uint('Odd', bl=1),
        Uint('Type', val=FGSIDTYPE_IMEI, bl=3, dic=FGSIDType_dict),
        Buf('Digits', val=b'', rep=REPR_HEX)
        )


class FGSIDTMSI(Envelope):
    _name = '5GSIDTMSI'
    _GEN = (
        Uint('ind', val=0xf, bl=4, rep=REPR_HEX),
        Uint('spare', bl=1),
        Uint('Type', val=FGSIDTYPE_TMSI, bl=3, dic=FGSIDType_dict),
        Uint8('AMFRegionID'),
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
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Type', val=FGSIDTYPE_MAC, bl=3, dic=FGSIDType_dict),
        Buf('MAC', bl=48, rep=REPR_HEX)
        )


class FGSIDUnk(Envelope):
    _name = '5GSIDUnk'
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Type', val=FGSIDTYPE_MAC, bl=3, dic=FGSIDType_dict),
        Buf('unk', rep=REPR_HEX)
        )


class FGSID(Envelope):
    # FGSIDTYPE_NO (0) -> FGSIDNone
    # FGSIDTYPE_SUPI (1) -> FGSIDSUPI
    # FGSIDTYPE_GUTI (2) -> FGSIDGUTI
    # FGSIDTYPE_IMEI (3) -> FGSIDDigit
    # FGSIDTYPE_TMSI (4) -> FGSIDTMSI
    # FGSIDTYPE_IMEISV (5) -> FGSIDDigit
    # FGSIDTYPE_MAC (6) -> FGSIDMAC
    # (7) -> FGSIDUnk
    
    _ID_LUT = {
        FGSIDTYPE_NO     : FGSIDNone(),
        FGSIDTYPE_SUPI   : FGSIDSUPI(),
        FGSIDTYPE_GUTI   : FGSIDGUTI(),
        FGSIDTYPE_IMEI   : FGSIDDigit(),
        FGSIDTYPE_TMSI   : FGSIDTMSI(),
        FGSIDTYPE_IMEISV : FGSIDDigit(),
        FGSIDTYPE_MAC    : FGSIDMAC(),
        7                : FGSIDUnk()
        }
    
    def set_val(self, vals):
        if isinstance(vals, dict) and 'Type' in vals:
            type = vals['Type']
            del vals['Type']
            self.encode(type, **vals)
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
        FGSIDTYPE_TMSI (4)   -> FGSIDTMSI
        FGSIDTYPE_IMEISV (5) -> FGSIDDigit
        FGSIDTYPE_MAC (6)    -> FGSIDMAC
        7 (undefined)        -> FGSIDUnk
        """
        if not isinstance(type, integer_types) or not 0 <= type <= 7:
            raise(PycrateErr('invalid 5GS identity type: %r' % type))
        # set the appropriate content
        self._set_content(type)
        # pass the value to encode
        Envelope.set_val(self, kwargs)
    
    def _from_char(self, char):
        if not self.get_trans():
            # get the type and set the appropriate content
            type = char.to_uint(8) & 0x7
            self._set_content(type)
            Envelope._from_char(self, char)
        


#------------------------------------------------------------------------------#
# 5GS registration type
# TS 24.301, 9.11.3.7
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
# TS 24.301, 9.11.3.8
#------------------------------------------------------------------------------#

class FGSTAI(Envelope):
    _name = '5GSTAI'
    _GEN = (
        PLMN(),
        Uint24('TAC', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# 5GS update type
# TS 24.301, 9.11.3.9A
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
# Allowed PDU session status
# TS 24.301, 9.11.3.13
#------------------------------------------------------------------------------#

class AllowedPDUSessStat(Envelope):
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
# LADN indication
# TS 24.501, 9.11.3.29
#------------------------------------------------------------------------------#

class LADNInd(Sequence):
    _GEN = DNN()


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
    _GEN = SNSSAI()


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
            12 : PDUSessID(),
            24 : Buf('AdditionalInfo', rep=REPR_HEX),
            58 : FGMMCause(),
            37 : GPRSTimer3('BackOffTimer'),
            59 : PDUSessID('OldPDUSessID'),
            80 : Uint8('RequestType', dic=_RequestType_dict),
            22 : SNSSAI()['Value'],
            25 : Buf('DNN')
            },
            DEFAULT=Buf('Val'),
            sel=lambda self: self.get_env()[0].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
    
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        optlen  = self[1].get_val()
        char_lb = char._len_bit
        char._len_bit = char._cur + (optlen<<3)
        self[2]._from_char(char)
        char._len_bit = char_lb


class _PayContEntry(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('OptNum', bl=4),
        Uint('Type', bl=4, dic=PayloadContainerType_dict),
        Sequence('Opts', GEN=_PayContOpt('Opt')),
        Buf('Cont')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[3].get_len() + self[4].get_len())
        self[1].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[1].get_val())
        self[4].set_blauto(lambda: self[0].get_val() - 1 - self[3].get_len())


class PayloadContainer(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('Entries', GEN=_PayContEntry('Entry'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


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
        Buf('spare', rep=REPR_HEX)
        )
    
    def _from_char(self, char):
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
        Uint('N1ModeReg', bl=1, dic={0:'UE not in 5GMM-REGISTERED state', 1:'UE in 5GMM-REGISTERED state'}),
        Uint('S1ModeReg', bl=1, dic={0:'UE not in EMM-REGISTERED state', 1:'UE in EMM-REGISTERED state'})
        )


#------------------------------------------------------------------------------#
# Uplink data status
# TS 24.501, 9.11.3.57
#------------------------------------------------------------------------------#

class ULDataStat(AllowedPDUSessStat):
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


