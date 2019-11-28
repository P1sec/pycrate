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
    BufBCD, PLMN, GPRSTimer3, APN, 
    )
#from pycrate_mobile.TS24301_IE import (
#    )

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
# TS 24.501, 9.11.2.1A
#------------------------------------------------------------------------------#

class DNN(Envelope):
    _GEN = (
        Uint8('Len'),
        APN()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        #self[1].set_blauto(lambda: self[0].get_val()<<3)


#------------------------------------------------------------------------------#
# S-NSSAI
# TS 24.501, 9.11.2.8
#------------------------------------------------------------------------------#

class _SNSSAI_SST_MappedHSST(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint8('MappedHPLMNSST')
        )


class _SNSSAI_SST_SD(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint24('SD')
        )


class _SNSSAI_SST_SD_MappedHSST(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint24('SD'),
        Uint8('MappedHPLMNSST')
        )


class _SNSSAI_SST_SD_MappedHSSTSD(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint24('SD'),
        Uint8('MappedHPLMNSST'),
        Uint24('MappedHPLMNSD')
        )


class _SNSSAI_SST_SD_MappedHSSTSD_spare(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint24('SD'),
        Uint8('MappedHPLMNSST'),
        Uint24('MappedHPLMNSD'),
        Buf('spare', rep=REPR_HEX)
        )


class SNSSAI(Envelope):
    _GEN = (
        Uint8('Len'),
        Alt('Value', GEN={
            1: Uint8('SST'),
            2: _SNSSAI_SST_MappedHSST('SST_MappedHPLMNSST'),
            4: _SNSSAI_SST_SD('SST_SD'),
            5: _SNSSAI_SST_SD_MappedHSST('SST_SD_MappedHPLMNSST'),
            8: _SNSSAI_SST_SD_MappedHSSTSD('SST_SD_MappedHPLMNSSTSD')},
            DEFAULT=_SNSSAI_SST_SD_MappedHSSTSD_spare('SST_SD_MappedHPLMNSSTSD_spare'),
            sel=lambda self: self.get_env()['Len'].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())


#------------------------------------------------------------------------------#
# 5GMM capability
# TS 24.501, 9.11.3.1
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
    6 : 'MAC address'
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

class FGSNetFeat(Envelope):
    _name = '5GSNetFeat'
    _GEN = (
        Uint('MPSI', bl=1),
        Uint('IWK_N26', bl=1),
        Uint('EMF', bl=1),
        Uint('EMC', bl=3),
        Uint('IMS-VoPS-N3GPP', bl=1),
	    Uint('IMS-VoPS-3GPP', bl=1), # end of octet 1
	    Uint('5G-LCS', bl=1),
        Uint('5G-UP-CIoT', bl=1),
        Uint('5G-HC-CP-CIoT', bl=1),
        Uint('N3Data', bl=1),
        Uint('5G-CP-CIoT', bl=1),
        Uint('RestrictEC', bl=1),
        Uint('MCSI', bl=1),
        Uint('EMCN3', bl=1), # end of octet 2
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def _from_char(self, char):
        if self.get_trans():
            return
        l = char.len_bit()
        if l <= 8:
            # disable all elements after bit l
            self.disable_from('5G-LCS')
        elif l > 16:
            # enables some spare bits at the end
            self[-1]._bl = l-16
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
    _name = '5GSRegType'
    _GEN = (
        Uint('spare', bl=3),
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
# Access type
# TS 24.501, 9.11.3.11
#------------------------------------------------------------------------------#

class AccessType(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('Value', bl=2, dic={1:'3GPP access', 2:'non-3GPP access'})
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
        Uint('HDP', bl=1, dic={0:'K_AMF derivation not required', 1:'K_AMF derivation required'})
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


#------------------------------------------------------------------------------#
# LADN information
# TS 24.501, 9.11.3.30
#------------------------------------------------------------------------------#

class LADN(Envelope):
    _GEN = (
        DNN(),
        FGSTAIList()
        )


class LADNInfo(Sequence):
    _GEN = LADN()


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
# NAS security algorithms
# TS 24.501, 9.11.3.34
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
    _GEN = SNSSAI()


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
        Sequence('SNSSAIs', GEN=SNSSAI())
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
        self['StdAccessCat'].set_transauto(lambda: False if self['PSAC'].get_val() else True)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self[1]._from_char(char)
        self[2]._from_char(char)
        self[3]._from_char(char)
        self[4]._from_char(char)
        self[5]._from_char(char)
        # truncate char according to LenCriteria
        char_lb = char._len_bit
        char._len_bit = char._cur + (self[5].get_val()<<3)
        self[6]._from_char(char)
        char._len_bit = char_lb
        self[7]._from_char(char)


class OperatorAccessCatDefs(Sequence):
    _GEN = OperatorAccessCatDef()


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
        if self.get_trans():
            return
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

class RejectedSNSSAI(Envelope):
    _GEN = (
        Uint8('Len'),
        Alt('Value', GEN={
            1: Uint8('SST'),
            4: Envelope('SST_SD', GEN=(Uint8('SST'), Uint24('SD')))},
            sel=lambda self: self.get_env()['Len'].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())


class RejectedNSSAI(Sequence):
    _GEN = RejectedSNSSAI()


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
        Uint('Value', bl=1, dic={0:'SMS over NAS not available', 1:'SMS over NAS available'})
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
        Uint('ACK', bl=1, dic=_SORAck_dict),
        Uint('ListType', bl=1, dic=_SORListType_dict),
        Uint('ListInd', bl=1, dic=_SORListInd_dict),
        Uint('DataType', bl=1, dic=_SORDataType_dict)
        )


class _SORTransCont00(Envelope):
    _GEN = (
        Buf('SOR_MACI_AUSF', bl=128, rep=REPR_HEX),
        Uint16('CntSOR'),
        Buf('SecuredPkt', rep=REPR_HEX)
        )


class _SORTransCont01(Envelope):
    _GEN = (
        Buf('SOR_MACI_AUSF', bl=128, rep=REPR_HEX),
        Uint16('CntSOR'),
        Sequence('PLMNATList', GEN=Envelope('PLMNAT', GEN=(
            PLMN(),
            Uint16('AccessTechno')))
            )
        )


class _SORTransCont1(Envelope):
    _GEN = (
        Buf('SOR_MACI_UE', bl=128, rep=REPR_HEX),
        )


def get_sor_types(cont):
    hdr = cont.get_env()['SORHeader']
    return hdr['DataType'].get_val(), hdr['ListType'].get_val()
    

class SORTransparentContainer(Envelope):
    _GEN = (
        SORHeader(),
        Alt('Cont', GEN={
            (0, 0): _SORTransCont00('SORSecuredPkt'),
            (0, 1): _SORTransCont01('SORPLMNList'),
            (1, 0): _SORTransCont1('SORACK'),
            (1, 1): _SORTransCont1('SORACK')},
            sel=lambda self: get_sor_types(self)
            )
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
        Buf('spare', rep=REPR_HEX)
        )
    
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
        Uint('N1ModeReg', bl=1, dic={0:'UE not in 5GMM-REGISTERED state', 1:'UE in 5GMM-REGISTERED state'}),
        Uint('S1ModeReg', bl=1, dic={0:'UE not in EMM-REGISTERED state', 1:'UE in EMM-REGISTERED state'})
        )


#------------------------------------------------------------------------------#
# Uplink data status
# TS 24.501, 9.11.3.57
#------------------------------------------------------------------------------#

class ULDataStat(PDUSessStat):
    pass


#------------------------------------------------------------------------------#
# MA PDU session information
# TS 24.501, 9.11.3.63
#------------------------------------------------------------------------------#

MAPDUSessInfo_dict = {
    1 : 'MA PDU session network upgrade is allowed'
    }


#------------------------------------------------------------------------------#
# CAG information list
# TS 24.501, 9.11.3.64
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
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self[1]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = char._cur + self[0].get_val() - 3
        self[2]._from_char(char)
        char._len_bit = char_lb


class CAGInfoList(Sequence):
    _GEN = CAGInfo()


#------------------------------------------------------------------------------#
# Control plane service type
# TS 24.501, 9.11.3.65
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
# CIoT small data container
# TS 24.501, 9.11.3.67
#------------------------------------------------------------------------------#

_CIoTDataType_dict = {
    1 : 'Control plane user data',
    2 : 'SMS'
    }

_CIoTDDX_dict = {
    0 : 'No information available',
    1 : 'No further uplink or downlink data transmission subsequent to the uplink data transmission is expected',
    2 : 'Only a single downlink data transmission and no further uplink data transmission subsequent to the uplink data transmission is expected',
    3 : _str_reserved
    }


class CIoTSmallDataContainer(Envelope):
    _GEN = (
        Uint('DataType', bl=3, dic=_CIoTDataType_dict),
        Uint('DDX', bl=2, dic=_CIoTDDX_dict),
        Uint('PDUSessID', bl=3, dic={0:'No PDU session identity assigned'}),
        Buf('Data', rep=REPR_HEX)
        )


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


