# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
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
# * File Name : pycrate_mobile/TS24301_IE.py
# * Created : 2017-06-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 24.301: NAS protocol for EPS
# release 13 (da0)
#------------------------------------------------------------------------------#

from binascii import unhexlify

from pycrate_core.utils  import *
from pycrate_core.elt    import Envelope, Sequence, Array, REPR_RAW, REPR_HEX, \
     REPR_BIN, REPR_HD, REPR_HUM
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_core.charpy import Charpy

from pycrate_mobile.MCC_MNC    import MNC_dict
from pycrate_mobile.TS24008_IE import TFT, PLMN, encode_bcd, decode_bcd

#------------------------------------------------------------------------------#
# For Supplementary Services, some ASN.1 structures are required
#------------------------------------------------------------------------------#

_WITH_ASN1 = True

if _WITH_ASN1:
    
    from threading       import Event
    from pycrate_asn1dir import MAP
    from pycrate_asn1rt  import wrapper
    
    ASN_MAP_READY = Event()
    ASN_MAP_READY.set()
    _ACQUIRE_TO  = 0.005
    
    def asn_map_acquire():
        if not ASN_MAP_READY.is_set():
            ASN_MAP_READY.wait(_ACQUIRE_TO)
            if not ASN_MAP_READY.is_set():
                raise(PycrateErr('unable to acquire the MAP ASN.1 module'))
        ASN_MAP_READY.clear()
    
    def asn_map_release():
        ASN_MAP_READY.set()


#------------------------------------------------------------------------------#
# Security header type
# TS 24.301, 9.3.1
#------------------------------------------------------------------------------#

SecHdrType_dict = {
    0 : 'No security',
    1 : 'Integrity protected',
    2 : 'Integrity protected and ciphered',
    3 : 'Integrity protected with new EPS security context',
    4 : 'Integrity protected and ciphered with new EPS security context',
    12 : 'Security header for SERVICE REQUEST'
    }


#------------------------------------------------------------------------------#
# EPS bearer context status
# TS 24.301, 9.9.2.1
#------------------------------------------------------------------------------#

_EPSCtxtStat_dict = {
    0 : 'BEARER CONTEXT-INACTIVE',
    1 : 'BEARER CONTEXT-ACTIVE'
    }

class EPSBearerCtxtStat(Envelope):
    _GEN = (
        Uint('EBI_7', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_6', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_5', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_4', bl=1),
        Uint('EBI_3', bl=1),
        Uint('EBI_2', bl=1),
        Uint('EBI_1', bl=1),
        Uint('EBI_0', bl=1),
        Uint('EBI_15', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_14', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_13', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_12', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_11', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_10', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_9', bl=1, dic=_EPSCtxtStat_dict),
        Uint('EBI_8', bl=1, dic=_EPSCtxtStat_dict)
        )

#------------------------------------------------------------------------------#
# Additional update result
# TS 24.301, 9.9.3.0A
#------------------------------------------------------------------------------#

_AddUpdRes_dict = {
    0 : 'no additional information',
    1 : 'CS Fallback not preferred',
    2 : 'SMS only',
    3 : 'reserved',
    }

class AddUpdateRes(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('Value', bl=2, dic=_AddUpdRes_dict),
        )


#------------------------------------------------------------------------------#
# Additional update type
# TS 24.301, 9.9.3.0B
#------------------------------------------------------------------------------#

_PNBCIoT_dict = {
    0 : 'no additional information',
    1 : 'control plane CIoT EPS optimization',
    2 : 'user plane CIoT EPS optimization',
    3 : 'reserved'
    }
_SAF_dict = {
    0: 'NAS signalling not required after completion of TAU',
    1: 'NAS signalling required after completion of TAU'
    }
_AUTV_dict = {
    1 : 'SMS only'
    }

class AddUpdateType(Envelope):
    _GEN = (
        Uint('PNB_CIoT', bl=2, dic=_PNBCIoT_dict),
        Uint('SAF', bl=1, dic=_SAF_dict),
        Uint('AUTV', bl=1, dic=_AUTV_dict)
        )


#------------------------------------------------------------------------------#
# SMS service status
# TS 24.301, 9.9.3.4B
#------------------------------------------------------------------------------#

_SMSServStat_dict = {
    0 : 'SMS services not available',
    1 : 'SMS services not available in this PLMN',
    2 : 'Network failure',
    3 : 'Congestion'
    }

class SMSServStat(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=_SMSServStat_dict)
        )


#------------------------------------------------------------------------------#
# CSFB response
# TS 24.301, 9.9.3.5
#------------------------------------------------------------------------------#

class CSFBResponse(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3,
             dic={0:'CS fallback rejected by the UE', 1:'CS fallback accepted by the UE'})
        )


#------------------------------------------------------------------------------#
# Detach type
# TS 24.301, 9.9.3.7
#------------------------------------------------------------------------------#

_EPSDetTypeMO_dict = {
    0 : 'combined EPS/IMSI detach',
    1 : 'EPS detach',
    2 : 'IMSI detach',
    3 : 'combined EPS/IMSI detach',
    4 : 'combined EPS/IMSI detach',
    5 : 'combined EPS/IMSI detach',
    6 : 'reserved',
    7 : 'reserved'
    }

_EPSDetTypeMT_dict = {
    0 : 're-attach not required',
    1 : 're-attach required',
    2 : 're-attach not required',
    3 : 'IMSI detach',
    4 : 're-attach not required',
    5 : 're-attach not required',
    6 : 'reserved',
    7 : 'reserved'
    }

class EPSDetachTypeMO(Envelope):
    _GEN = (
        Uint('SwitchOff', bl=1),
        Uint('Type', bl=3, dic=_EPSDetTypeMO_dict)
        )


class EPSDetachTypeMT(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Type', bl=3, dic=_EPSDetTypeMT_dict)
        )


#------------------------------------------------------------------------------#
# EMM cause
# TS 24.301, 9.9.3.9
#------------------------------------------------------------------------------#

_EMMCause_dict = {
    2  : 'IMSI unknown in HSS',
    3  : 'Illegal UE',
    5  : 'IMEI not accepted',
    6  : 'Illegal ME',
    7  : 'EPS services not allowed',
    8  : 'EPS services and non-EPS services not allowed',
    9  : 'UE identity cannot be derived by the network',
    10 : 'Implicitly detached',
    11 : 'PLMN not allowed',
    12 : 'Tracking Area not allowed',
    13 : 'Roaming not allowed in this tracking area',
    14 : 'EPS services not allowed in this PLMN',
    15 : 'No Suitable Cells In tracking area',
    16 : 'MSC temporarily not reachable',
    17 : 'Network failure',
    18 : 'CS domain not available',
    19 : 'ESM failure',
    20 : 'MAC failure',
    21 : 'Synch failure',
    22 : 'Congestion',
    23 : 'UE security capabilities mismatch',
    24 : 'Security mode rejected, unspecified',
    25 : 'Not authorized for this CSG',
    26 : 'Non-EPS authentication unacceptable',
    35 : 'Requested service option not authorized in this PLMN',
    39 : 'CS service temporarily not available',
    40 : 'No EPS bearer context activated',
    42 : 'Severe network failure',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non-existent or not implemented',
    98 : 'Message type not compatible with the protocol state',
    99 : 'Information element non-existent or not implemented',
    100: 'Conditional IE error',
    101: 'Message not compatible with the protocol state',
    111: 'Protocol error, unspecified'
    }

class EMMCause(Uint8):
    _dic = _EMMCause_dict


#------------------------------------------------------------------------------#
# EPS attach result
# TS 24.301, 9.9.3.10
#------------------------------------------------------------------------------#

EPSAttRes_dict = {
    1 : 'EPS only',
    2 : 'combined EPS / IMSI attach'
    }

class EPSAttachResult(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=EPSAttRes_dict)
        )


#------------------------------------------------------------------------------#
# EPS attach type
# TS 24.301, 9.9.3.11
#------------------------------------------------------------------------------#

EPSAttType_dict = {
    1 : 'EPS Attach',
    2 : 'combined EPS / IMSI attach',
    6 : 'EPS emergency attach',
    7 : 'reserved'
    }

class EPSAttachType(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=EPSAttType_dict)
        )


#------------------------------------------------------------------------------#
# EPS mobile identity
# TS 24.301, 9.9.3.12
#------------------------------------------------------------------------------#

EPSIDType_dict = {
    1 : 'IMSI',
    3 : 'IMEISV',
    6 : 'GUTI'
    }

IDTYPE_IMSI   = 1
IDTYPE_IMEISV = 3
IDTYPE_GUTI   = 6


class IDDigit(Envelope):
    _GEN = (
        Uint('Digit1', val=0xF, bl=4, rep=REPR_HEX),
        Uint('Odd', bl=1),
        Uint('Type', val=IDTYPE_IMSI, bl=3, dic=EPSIDType_dict),
        Buf('Digits', val=b'', rep=REPR_HEX)
        )


class IDGUTI(Envelope):
    _GEN = (
        Uint('Digit1', val=0xF, bl=4, rep=REPR_HEX),
        Uint('Odd', bl=1),
        Uint('Type', val=IDTYPE_GUTI, bl=3, dic=EPSIDType_dict),
        PLMN(),
        Uint16('MMEGroupID', rep=REPR_HEX),
        Uint8('MMECode', rep=REPR_HEX),
        Uint32('MTMSI', rep=REPR_HEX)
        )


class EPSID(Envelope):
    
    # during encode() / _from_char() methods
    # specific attributes are created:
    # self._IDNone  = IDNone()
    # self._IDDigit = IDDigit()
    # self._IDGUTI  = IDGUTI()
    
    def set_val(self, vals):
        if isinstance(vals, dict) and 'type' in vals and 'ident' in vals:
            self.encode(vals['type'], vals['ident'])
        else:
            Envelope.set_val(self, vals)
    
    def decode(self):
        """returns the mobile identity type and value
        """
        type = self['Type'].get_val()
        #
        if type in (IDTYPE_IMSI, IDTYPE_IMEISV):
            return (type, str(self[0].get_val()) + decode_bcd(self[3].get_val()))
        #
        elif type == IDTYPE_GUTI:
            return (type, self[3].decode(), self[4](), self[5](), self[6]())
    
    def encode(self, type, ident):
        """sets the mobile identity with given type
        
        if type is IDTYPE_IMSI or IDTYPE_IMEISV: ident must be a string of digits
        if type is IDTYPE_GUTI: ident must be a 4-tuple (PLMN -string of digits-, 
            MMEGroupID -uint16-, MMECode -uint8-, MTMSI -uint32-)
        """
        if type in (IDTYPE_IMSI, IDTYPE_IMEISV):
            if not ident.isdigit():
                raise(PycrateErr('{0}: invalid identity to encode, {1!r}'\
                      .format(self._name, ident)))
            if not hasattr(self, '_IDDigit'):
                self._IDDigit = IDDigit()
            self._content = self._IDDigit._content
            self._by_id   = self._IDDigit._by_id
            self._by_name = self._IDDigit._by_name
            self[2]._val = type
            if len(ident) % 2:
                self[1]._val = 1
            # encode digits the BCD way
            self[0]._val = int(ident[0])
            self[3]._val = encode_bcd(ident[1:])
        #
        elif type == IDTYPE_GUTI:
            if not isinstance(ident, (tuple, list)) or len(ident) != 4:
                raise(PycrateErr('{0}: invalid identity to encode, {1!r}'\
                      .format(self._name, ident)))
            if not hasattr(self, '_IDGUTI'):
                self._IDGUTI = IDGUTI()
            self._content = self._IDGUTI._content
            self._by_id   = self._IDGUTI._by_id
            self._by_name = self._IDGUTI._by_name
            self[3].set_val(ident[0])
            self[4].set_val(ident[1])
            self[5].set_val(ident[2])
            self[6].set_val(ident[3])
        #
        else:
            raise(PycrateErr('{0}: invalid identity type to encode, {1!r}'\
                  .format(self._name, ident)))
    
    def _from_char(self, char):
        if not self.get_trans():
            try:
                spare = char.get_uint(5)
                type  = char.get_uint(3)
            except CharpyErr as err:
                raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
            except Exception as err:
                raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
            #
            if type in (IDTYPE_IMSI, IDTYPE_IMEISV):
                if not hasattr(self, '_IDDigit'):
                    self._IDDigit = IDDigit()
                self._content = self._IDDigit._content
                self._by_id   = self._IDDigit._by_id
                self._by_name = self._IDDigit._by_name
                self[0]._val = spare >> 1
                self[1]._val = spare & 1
                self[2]._val = type
                self[3]._from_char(char)   
            #
            elif type == IDTYPE_GUTI:
                if not hasattr(self, '_IDGUTI'):
                    self._IDGUTI = IDGUTI()
                self._content = self._IDGUTI._content
                self._by_id   = self._IDGUTI._by_id
                self._by_name = self._IDGUTI._by_name
                self[0]._val = spare >> 1
                self[1]._val = spare & 1
                self[2]._val = type
                self[3]._from_char(char)
                self[4]._from_char(char)
                self[5]._from_char(char)
                self[6]._from_char(char)
            #
            else:
                raise(PycrateErr('{0}: invalid identity to decode, {1}'\
                      .format(self._name, type)))
    
    def repr(self):
        if not self._content:
            return Envelope.repr(self)
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        #
        type = self['Type'].get_val()
        if type in (IDTYPE_IMSI, IDTYPE_IMEISV):
            return '<%s%s%s [%s] : %s>' % (self._name, desc, trans, EPSIDType_dict[type],
                                           str(self[0].get_val()) + decode_bcd(self[3].get_val()))
        else:
            return Envelope.repr(self)
    
    __repr__ = repr


#------------------------------------------------------------------------------#
# EPS network feature support
# TS 24.301, 9.9.3.12A
#------------------------------------------------------------------------------#

class EPSNetFeat(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('CP_CIoT', desc='control plane CIoT EPS optimization', bl=1),
        Uint('ERwoPDN', desc='EMM-REGISTERED without PDN connection', bl=1),
        Uint('ESR_PS', desc='support for extended service request', bl=1),
        Uint('CS_LCS', desc='location service in CS', bl=2,
             dic={0:'no info', 1:'supported', 2:'not supported'}),
        Uint('EPC_LCS', desc='location service in EPC', bl=1),
        Uint('EMC_BS', desc='emergency bearer service in S1 mode', bl=1),
        Uint('IMS_VoPS', bl=1),
        Uint('spare', bl=4),
        Uint('EPCO', desc='extended protocol config options IE', bl=1),
        Uint('HC_CP_CIoT', desc='header compression for CP CIoT', bl=1),
        Uint('S1U_Data', desc='S1-U data transfer', bl=1),
        Uint('UP_CIoT', desc='user plane CIoT EPS optimization', bl=1)
        )
    
    def _from_char(self, char):
        if char.len_bit() < 16:
            self._set_o2_trans(True)
        Envelope._from_char(self, char)
    
    def _set_o2_trans(self, b=True):
        self[7].set_trans(b)
        self[8].set_trans(b)
        self[9].set_trans(b)
        self[10].set_trans(b)
        self[11].set_trans(b)


#------------------------------------------------------------------------------#
# EPS update result
# TS 24.301, 9.9.3.13
#------------------------------------------------------------------------------#

EPSUpdRes_dict = {
    0 : 'TA updated',
    1 : 'combined TA/LA updated',
    4 : 'TA updated and ISR activated',
    5 : 'combined TA/LA updated and ISR activated'
    }

class EPSUpdateResult(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=EPSUpdRes_dict)
        )


#------------------------------------------------------------------------------#
# EPS update type
# TS 24.301, 9.9.3.14
#------------------------------------------------------------------------------#

_EPSUpdType_dict = {
    0 : 'TA updating',
    1 : 'combined TA/LA updating',
    2 : 'combined TA/LA updating with IMSI attach',
    3 : 'periodic updating',
    4 : 'unused; shall be interpreted as "TA updating", if received by the network.',
    5 : 'unused; shall be interpreted as "TA updating", if received by the network.'
    }

class EPSUpdateType(Envelope):
    _GEN = (
        Uint('Active', bl=1,
             dic={0:'No bearer establishment requested', 1:'Bearer establishment requested'}),
        Uint('Value', bl=3, dic=_EPSUpdType_dict)
        )


#------------------------------------------------------------------------------#
# NAS key set identifier
# TS 24.301, 9.9.3.21
#------------------------------------------------------------------------------#

class NAS_KSI(Envelope):
    _GEN = (
        Uint('TSC', bl=1, dic={0:' native security context', 1:'mapped security context'}),
        Uint('Value', bl=3, dic={7:'no key available'})
        )


#------------------------------------------------------------------------------#
# NAS security algorithms
# TS 24.301, 9.9.3.23
#------------------------------------------------------------------------------#

_NASCiphAlgo_dict = {
    0 : 'EPS encryption algorithm EEA0 (null)',
    1 : 'EPS encryption algorithm 128-EEA1 (SNOW)',
    2 : 'EPS encryption algorithm 128-EEA2 (AES)',
    3 : 'EPS encryption algorithm 128-EEA3 (ZUC)',
    4 : 'EPS encryption algorithm EEA4',
    5 : 'EPS encryption algorithm EEA5',
    6 : 'EPS encryption algorithm EEA6',
    7 : 'EPS encryption algorithm EEA7'
    }

_NASIntegAlgo_dict = {
    0 : 'EPS integrity algorithm EIA0 (null)',
    1 : 'EPS integrity algorithm 128-EIA1 (SNOW)',
    2 : 'EPS integrity algorithm 128-EIA2 (AES)',
    3 : 'EPS integrity algorithm 128-EIA3 (ZUC)',
    4 : 'EPS integrity algorithm EIA4',
    5 : 'EPS integrity algorithm EIA5',
    6 : 'EPS integrity algorithm EIA6',
    7 : 'EPS integrity algorithm EIA7'
    }

class NASSecAlgo(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('CiphAlgo', bl=3, dic=_NASCiphAlgo_dict),
        Uint('spare', bl=1),
        Uint('IntegAlgo', bl=3, dic=_NASIntegAlgo_dict)
        )


#------------------------------------------------------------------------------#
# Paging identity
# TS 24.301, 9.9.3.25A
#------------------------------------------------------------------------------#

class PagingIdentity(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('Value', bl=1, dic={0:'IMSI', 1:'TMSI'})
        )


#------------------------------------------------------------------------------#
# Extended EMM cause
# TS 24.301, 9.9.3.26A
#------------------------------------------------------------------------------#

class ExtEMMCause(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('EPSOptimInfo', bl=1),
        Uint('EUTRANAllowed', bl=1)
        )


#------------------------------------------------------------------------------#
# Service type
# TS 24.301, 9.9.3.27
#------------------------------------------------------------------------------#

EMMServType_dict = {
    0 : 'mobile originating CS fallback or 1xCS fallback',
    1 : 'mobile terminating CS fallback or 1xCS fallback',
    2 : 'mobile originating CS fallback emergency call or 1xCS fallback emergency call',
    3 : 'unused; shall be interpreted as "mobile originating CS fallback or 1xCS fallback", if received by the network',
    4 : 'unused; shall be interpreted as "mobile originating CS fallback or 1xCS fallback", if received by the network',
    8 : 'packet services via S1',
    9 : 'unused; shall be interpreted as "packet services via S1", if received by the network',
    10 : 'unused; shall be interpreted as "packet services via S1", if received by the network',
    11 : 'unused; shall be interpreted as "packet services via S1", if received by the network'
    }


#------------------------------------------------------------------------------#
# Tracking area identity
# TS 24.301, 9.9.3.32
#------------------------------------------------------------------------------#

class TAI(Envelope):
    _GEN = (
        PLMN(),
        Uint16('TAC', rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val())


#------------------------------------------------------------------------------#
# Tracking area identity list
# TS 24.301, 9.9.3.33
#------------------------------------------------------------------------------#

_PTAIListType_dict = {
    0 : 'list of TACs belonging to one PLMN, with non-consecutive TAC values',
    1 : 'list of TACs belonging to one PLMN, with consecutive TAC values',
    2 : 'list of TAIs belonging to different PLMNs'
    }

class _PartialTAIList(Envelope):
    # dummy wrapping class
    pass


class PartialTAIList0(_PartialTAIList):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Type', bl=2, dic=_PTAIListType_dict),
        Uint('Num', bl=5), # WNG: the msbit of Num should stay null
        PLMN(),
        Array('TACValues', GEN=Uint16('TAC'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: max(0, self[4].get_num()-1))
        self[4].set_numauto(lambda: self[2].get_val()+1)


class PartialTAIList1(_PartialTAIList):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Type', val=1, bl=2, dic=_PTAIListType_dict),
        Uint('Num', bl=5), # WNG: the msbit of Num should stay null
        PLMN(),
        Uint16('TAC0'),
        )


class PartialTAIList2(_PartialTAIList):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Type', val=2, bl=2, dic=_PTAIListType_dict),
        Uint('Num', bl=5), # WNG: the msbit of Num should stay null
        Sequence('TAIValues', GEN=TAI())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: max(0, self[3].get_num()-1))
        self[3].set_numauto(lambda: self[2].get_val()+1)


class TAIList(Envelope):

    _PTaiListLUT = {
        0 : PartialTAIList0,
        1 : PartialTAIList1,
        2 : PartialTAIList2
        }
    
    # use an empty generator
    # concrete PartialTAIList0/1/2 will be setup during decoding / encoding
    _ptail2 = None
    _GEN = ()
    
    def set_val(self, vals):
        self.clear()
        if self._ptail2 is not None:
            del self._ptail2
        if vals is None:
            return
        for ptail in vals:
            self._set_ptail(ptail)
    
    def _set_ptail(self, ptail):
        if isinstance(ptail, (tuple, list)):
            try:
                PTaiL = self._PTaiListLUT[ptail[1]](val=ptail)
            except Exception as err:
                raise(PycrateErr('{0}: unable to set partial TAI list value, {1}'\
                      .format(self._name, err)))
        elif isinstance(ptail, dict):
            try:
                PTaiL = self._PTaiListLUT[ptail['Type']](val=ptail)
            except Exception as err:
                raise(PycrateErr('{0}: unable to set partial TAI list value, {1}'\
                      .format(self._name, err)))
        else:
            raise(PycrateErr('{0}: unable to set partial TAI list value, {1}'\
                  .format(self._name, ptail)))
        self.append(PTaiL)
    
    def encode(self, vals):
        """sets the list of TAI values (PLMN, TAC) after grouping them into 
        PartialTAIList0/1/2 structures
        
        Args:
            vals: list/tuple of 2-tuple (PLMN, TAC(s))
                PLMN: str of digits
                TAC(s): uint16, or list/tuple of uint16, or range within uint16
        
        Returns:
            None
        """
        self.clear()
        if self._ptail2 is not None:
            del self._ptail2
        for tai in vals:
            if isinstance(tai[1], range):
                # this only works in Python3
                # in Python2, range is a function which returns a list
                self.append(PartialTAIList1(val={'PLMN':tai[0],
                                                 'TAC0':tai[1].start,
                                                 'Num' :tai[1].stop-tai[1].start}))
            elif isinstance(tai[1], (tuple, list)):
                self.append(PartialTAIList0(val={'PLMN':tai[0],
                                                 'TACValues':tai[1]}))
            else:
                if self._ptail2 and self._ptail2[3].get_num() < 16:
                    # extend the existing PartialTAIList2
                    self._ptail2.set_val({'TAIValues': {self._ptail2[3].get_num(): tai}})
                else:
                    self._ptail2 = PartialTAIList2(val={'TAIValues': [tai]})
                    self.append(self._ptail2)
    
    def decode(self):
        """returns the list of TAI values (PLMN, TAC) packed within
        PartialTAIList0/1/2 structures
        
        Args:
            None
        
        Returns:
            TAIList: list/tuple of 2-tuple (PLMN, TAC(s))
                PLMN: str of digits
                TAC(s): uint16, list/tuple or uint16, or range within uint16
        """
        ret = []
        for ptl in self:
            ptl_type = ptl['Type']()
            if ptl_type == 0:
                ret.append( (ptl['PLMN'].decode(), ptl['TACValues']()) )
            elif ptl_type == 1:
                tac0 = ptl['TAC0']()
                ret.append( (ptl['PLMN'].decode(), range(tac0, tac0+ptl['Num']()+1)) )
            else:
                ret.extend( [(v['PLMN'].decode(), v['TAC']()) for v in ptl['TAIValues']] )
        return ret
    
    def _from_char(self, char):
        self.clear()
        if self._ptail2 is not None:
            del self._ptail2
        while char.len_bit() >= 24 :
            ptl_type = char.to_uint(3) & 0b11
            if ptl_type == 0:
                ptl = PartialTAIList0()
            elif ptl_type == 1:
                ptl = PartialTAIList1()
            elif ptl_type == 2:
                ptl = PartialTAIList2()
                self._ptail2 = ptl
            else:
                raise(PycrateErr('invalid Partial TAI List type: %i' % ptl_type))
            ptl._from_char(char)
            self.append(ptl)


#------------------------------------------------------------------------------#
# UE network capability
# TS 24.301, 9.9.3.34
#------------------------------------------------------------------------------#

class UENetCap(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
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
        Uint('EIA7', bl=1), # end of octet 2 (mandatory part)
        Uint('UEA0', bl=1),
        Uint('UEA1', bl=1),
        Uint('UEA2', bl=1),
        Uint('UEA3', bl=1),
        Uint('UEA4', bl=1),
        Uint('UEA5', bl=1),
        Uint('UEA6', bl=1),
        Uint('UEA7', bl=1), # end of octet 3
        Uint('UCS2', bl=1),
        Uint('UIA1', bl=1),
        Uint('UIA2', bl=1),
        Uint('UIA3', bl=1),
        Uint('UIA4', bl=1),
        Uint('UIA5', bl=1),
        Uint('UIA6', bl=1),
        Uint('UIA7', bl=1), # end of octet 4
        Uint('ProSe_dd', bl=1),
        Uint('ProSe', bl=1),
        Uint('H245_ASH', bl=1),
        Uint('ACC_CSFB', bl=1),
        Uint('LPP', bl=1),
        Uint('LCS', bl=1),
        Uint('X1_SRVCC', bl=1),
        Uint('NF', bl=1), # end of octet 5
        Uint('ePCO', bl=1),
        Uint('HC_CP_CIoT', bl=1),
        Uint('ERw_oPDN', bl=1),
        Uint('S1U_data', bl=1),
        Uint('UP_CIoT', bl=1),
        Uint('CP_CIoT', bl=1),
        Uint('ProSe_relay', bl=1),
        Uint('ProSe_dc', bl=1), # end of octet 6
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('MultiDRB', bl=1), # end of octet 7
        Buf('spare', val=b'', rep=REPR_HEX) # from 0 to 6 bytes
        )
    
    def _from_char(self, char):
        l = char.len_bit()
        if l <= 56:
            # disable all elements after bit l
            self.disable_from(l)
        elif l > 56:
            # enables some spare bits at the end
            self[-1]._bl = l-56
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
# UE security capability
# TS 24.301, 9.9.3.36
#------------------------------------------------------------------------------#

class UESecCap(Envelope):
    _GEN = (
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
        Uint('EIA7', bl=1), # end of octet 2 (mandatory part)
        Uint('UEA0', bl=1),
        Uint('UEA1', bl=1),
        Uint('UEA2', bl=1),
        Uint('UEA3', bl=1),
        Uint('UEA4', bl=1),
        Uint('UEA5', bl=1),
        Uint('UEA6', bl=1),
        Uint('UEA7', bl=1), # end of octet 3
        Uint('spare', bl=1),
        Uint('UIA1', bl=1),
        Uint('UIA2', bl=1),
        Uint('UIA3', bl=1),
        Uint('UIA4', bl=1),
        Uint('UIA5', bl=1),
        Uint('UIA6', bl=1),
        Uint('UIA7', bl=1), # end of octet 4
        Uint('spare', bl=1),
        Uint('GEA1', bl=1),
        Uint('GEA2', bl=1),
        Uint('GEA3', bl=1),
        Uint('GEA4', bl=1),
        Uint('GEA5', bl=1),
        Uint('GEA6', bl=1),
        Uint('GEA7', bl=1) # end of octet 5
        )
    
    def _from_char(self, char):
        l = char.len_bit()
        if l <= 40:
            # disable all elements after bit l
            self.disable_from(l)
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
# SS Code
# TS 24.301, 9.9.3.39
#------------------------------------------------------------------------------#
# derived from the MAP-SS-Code ASN.1 module from TS 29.002, d40

_MAPSSCode_dict = {
    0 : 'allSS',
    16 : 'allLineIdentificationSS',
    17 : 'clip',
    18 : 'clir',
    19 : 'colp',
    20 : 'colr',
    21 : 'mci',
    24 : 'allNameIdentificationSS',
    25 : 'cnap',
    32 : 'allForwardingSS',
    33 : 'cfu',
    40 : 'allCondForwardingSS',
    41 : 'cfb',
    42 : 'cfnry',
    43 : 'cfnrc',
    36 : 'cd',
    48 : 'allCallOfferingSS',
    49 : 'ect',
    50 : 'mah',
    64 : 'allCallCompletionSS',
    65 : 'cw',
    66 : 'hold',
    67 : 'ccbs-A',
    68 : 'ccbs-B',
    69 : 'mc',
    80 : 'allMultiPartySS',
    81 : 'multiPTY',
    96 : 'allCommunityOfInterest-SS',
    97 : 'cug',
    112 : 'allChargingSS',
    113 : 'aoci',
    114 : 'aocc',
    128 : 'allAdditionalInfoTransferSS',
    129 : 'uus1',
    130 : 'uus2',
    131 : 'uus3',
    144 : 'allBarringSS',
    145 : 'barringOfOutgoingCalls',
    146 : 'baoc',
    147 : 'boic',
    148 : 'boicExHC',
    153 : 'barringOfIncomingCalls',
    154 : 'baic',
    155 : 'bicRoam',
    240 : 'allPLMN-specificSS',
    241 : 'plmn-specificSS-1',
    242 : 'plmn-specificSS-2',
    243 : 'plmn-specificSS-3',
    244 : 'plmn-specificSS-4',
    245 : 'plmn-specificSS-5',
    246 : 'plmn-specificSS-6',
    247 : 'plmn-specificSS-7',
    248 : 'plmn-specificSS-8',
    249 : 'plmn-specificSS-9',
    250 : 'plmn-specificSS-A',
    251 : 'plmn-specificSS-B',
    252 : 'plmn-specificSS-C',
    253 : 'plmn-specificSS-D',
    254 : 'plmn-specificSS-E',
    255 : 'plmn-specificSS-F',
    160 : 'allCallPrioritySS',
    161 : 'emlpp',
    176 : 'allLCSPrivacyException',
    177 : 'universal',
    178 : 'callSessionRelated',
    179 : 'callSessionUnrelated',
    180 : 'plmnoperator',
    181 : 'serviceType',
    192 : 'allMOLR-SS',
    193 : 'basicSelfLocation',
    194 : 'autonomousSelfLocation',
    195 : 'transferToThirdParty'
    }

class SSCode(Uint8):
    _dic = _MAPSSCode_dict


#------------------------------------------------------------------------------#
# LCS indicator
# TS 24.301, 9.9.3.40
#------------------------------------------------------------------------------#

class LCSInd(Uint8):
    _dic = {1: 'MT-LR'}


#------------------------------------------------------------------------------#
# LCS client identity
# TS 24.301, 9.9.3.41
#------------------------------------------------------------------------------#
# derived from the MAP-LCS-DataTypes ASN.1 module from TS 29.002, d40

if _WITH_ASN1:
    
    LCSClientId = wrapper.gen_ber_wrapper(MAP.MAP_LCS_DataTypes.LCS_ClientID,
                                          asn_map_acquire,
                                          asn_map_release)

else:
    
    class LCSClientId(Buf):
        _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Generic message container type
# TS 24.301, 9.9.3.42
#------------------------------------------------------------------------------#

_GenericContType_dict = {
    1 : 'LTE Positioning Protocol (LPP) message container',
    2 : 'Location services message container'
    }

class GenericContType(Uint8):
    _dic = _GenericContType_dict


#------------------------------------------------------------------------------#
# GUTI type
# TS 24.301, 9.9.3.45
#------------------------------------------------------------------------------#

class GUTIType(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1, dic={0:'native GUTI', 1:'mapped GUTI'})
        )


#------------------------------------------------------------------------------#
# Control plane service type
# TS 24.301, 9.9.3.47
#------------------------------------------------------------------------------#

_CPServType_dict = {
    0 : 'mobile originating request',
    1 : 'mobile terminating request'
    }

class CPServiceType(Envelope):
    _GEN = (
        Uint('Active', bl=1,
             dic={0:'No bearer establishment requested', 1:'Bearer establishment requested'}),
        Uint('Value', bl=3, dic=_CPServType_dict)
        )


#------------------------------------------------------------------------------#
# APN aggregate maximum bit rate
# TS 24.301, 9.9.4.2
#------------------------------------------------------------------------------#

class APN_AMBR(Envelope):
    _GEN = (
        Uint8('DL'),
        Uint8('UL'),
        Uint8('DLExt', trans=True),
        Uint8('ULExt', trans=True),
        Uint8('DLExt2', trans=True),
        Uint8('ULExt2', trans=True)
        )
    
    def set_val(self, vals):
        # in case extended values are set, make them non-transparent
        if vals is None:
            self['DLExt'].set_trans(True)
            self['ULExt'].set_trans(True)
            self['DLExt2'].set_trans(True)
            self['ULExt2'].set_trans(True)
        elif isinstance(vals, (tuple, list)):
            if len(vals) == 6:
                self['DLExt'].set_trans(False)
                self['ULExt'].set_trans(False)
                self['DLExt2'].set_trans(False)
                self['ULExt2'].set_trans(False)
            elif len(vals) == 4:
                self['DLExt'].set_trans(False)
                self['ULExt'].set_trans(False)
        elif isinstance(vals, dict):
            if 'DLExt2' in vals or 'ULExt2' in vals:
                self['DLExt'].set_trans(False)
                self['ULExt'].set_trans(False)
                self['DLExt2'].set_trans(False)
                self['ULExt2'].set_trans(False)
            elif 'DLExt' in vals or 'ULExt' in vals:
                self['DLExt'].set_trans(False)
                self['ULExt'].set_trans(False)
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        # in case long-enough buffer is available, make extended fields non-transparent
        l = char.len_byte()
        if l == 6:
            self['DLExt'].set_trans(False)
            self['ULExt'].set_trans(False)
            self['DLExt2'].set_trans(False)
            self['ULExt2'].set_trans(False)
        elif l == 4:
            self['DLExt'].set_trans(False)
            self['ULExt'].set_trans(False)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# EPS quality of service
# TS 24.301, 9.9.4.3
#------------------------------------------------------------------------------#

class EPSQoSBitrate(Envelope):
    _GEN = (
        Uint8('MaxULBitrate'),
        Uint8('MaxDLBitrate'),
        Uint8('GuaranteedULBitrate'),
        Uint8('GuaranteedDLBitrate')
        )


class EPSQoSBitrateExt(Envelope):
    _GEN = (
        Uint8('MaxULBitrate'),
        Uint8('MaxDLBitrate'),
        Uint8('GuaranteedULBitrate'),
        Uint8('GuaranteedDLBitrate')
        )


class EPSQoSBitrateExt2(Envelope):
    _GEN = (
        Uint8('MaxULBitrate'),
        Uint8('MaxDLBitrate'),
        Uint8('GuaranteedULBitrate'),
        Uint8('GuaranteedDLBitrate')
        )


class EPSQoS(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint8('QCI'),
        EPSQoSBitrate(trans=True),
        EPSQoSBitrateExt(trans=True),
        EPSQoSBitrateExt2(trans=True)
        )
    
    def set_val(self, vals):
        # in case extended values are set, make them non-transparent
        if vals is None:
            self['EPSQoSBitrate'].set_trans(True)
            self['EPSQoSBitrateExt'].set_trans(True)
            self['EPSQoSBitrateExt2'].set_trans(True)
        elif isinstance(vals, (tuple, list)):
            if len(vals) == 4:
                self['EPSQoSBitrate'].set_trans(False)
                self['EPSQoSBitrateExt'].set_trans(False)
                self['EPSQoSBitrateExt2'].set_trans(False)
            elif len(vals) == 3:
                self['EPSQoSBitrate'].set_trans(False)
                self['EPSQoSBitrateExt'].set_trans(False)
            elif len(vals) == 2:
                self['EPSQoSBitrate'].set_trans(False)
        elif isinstance(vals, dict):
            if 'EPSQoSBitrateExt2' in vals:
                self['EPSQoSBitrate'].set_trans(False)
                self['EPSQoSBitrateExt'].set_trans(False)
                self['EPSQoSBitrateExt2'].set_trans(False)
            elif 'EPSQoSBitrateExt' in vals:
                self['EPSQoSBitrate'].set_trans(False)
                self['EPSQoSBitrateExt'].set_trans(False)
            elif 'EPSQoSBitrate' in vals:
                self['EPSQoSBitrate'].set_trans(False)
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        # in case long-enough buffer is available, make extended fields non-transparent
        l = char.len_byte()
        if l == 13:
            self['EPSQoSBitrate'].set_trans(False)
            self['EPSQoSBitrateExt'].set_trans(False)
            self['EPSQoSBitrateExt2'].set_trans(False)
        elif l == 9:
            self['EPSQoSBitrate'].set_trans(False)
            self['EPSQoSBitrateExt'].set_trans(False)
        elif l == 5:
            self['EPSQoSBitrate'].set_trans(False)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# ESM cause
# TS 24.301, 9.9.4.4
#------------------------------------------------------------------------------#

_ESMCause_dict = {
    8 : 'Operator Determined Barring',
    26 : 'Insufficient resources',
    27 : 'Missing or unknown APN',
    28 : 'Unknown PDN type',
    29 : 'User authentication failed',
    30 : 'Request rejected by Serving GW or PDN GW',
    31 : 'Request rejected, unspecified',
    32 : 'Service option not supported',
    33 : 'Requested service option not subscribed',
    34 : 'Service option temporarily out of order',
    35 : 'PTI already in use',
    36 : 'Regular deactivation',
    37 : 'EPS QoS not accepted',
    38 : 'Network failure',
    39 : 'Reactivation requested',
    41 : 'Semantic error in the TFT operation',
    42 : 'Syntactical error in the TFT operation',
    43 : 'Invalid EPS bearer identity',
    44 : 'Semantic errors in packet filter(s)',
    45 : 'Syntactical errors in packet filter(s)',
    46 : 'Unused (see NOTE 2)',
    47 : 'PTI mismatch',
    49 : 'Last PDN disconnection not allowed',
    50 : 'PDN type IPv4 only allowed',
    51 : 'PDN type IPv6 only allowed',
    52 : 'Single address bearers only allowed',
    53 : 'ESM information not received',
    54 : 'PDN connection does not exist',
    55 : 'Multiple PDN connections for a given APN not allowed',
    56 : 'Collision with network initiated request',
    59 : 'Unsupported QCI value',
    60 : 'Bearer handling not supported',
    65 : 'Maximum number of EPS bearers reached',
    66 : 'Requested APN not supported in current RAT and PLMN combination',
    81 : 'Invalid PTI value',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non-existent or not implemented',
    98 : 'Message type not compatible with the protocol state',
    99 : 'Information element non-existent or not implemented',
    100 : 'Conditional IE error',
    101 : 'Message not compatible with the protocol state',
    111 : 'Protocol error, unspecified',
    112 : 'APN restriction value incompatible with active EPS bearer context'
    }

class ESMCause(Uint8):
    _dic = _ESMCause_dict


#------------------------------------------------------------------------------#
# ESM information transfer flag
# TS 24.301, 9.9.4.5
#------------------------------------------------------------------------------#

_ESMInfoTransfer_dict = {
    0 : 'security protected ESM information transfer not required',
    1 : 'security protected ESM information transfer required'
    }

class ESMInfoTransferFlag(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1, dic=_ESMInfoTransfer_dict)
        )


#------------------------------------------------------------------------------#
# PDN address
# TS 24.301, 9.9.4.9
#------------------------------------------------------------------------------#

PDNType_dict = {
    1 : 'IPv4',
    2 : 'IPv6',
    3 : 'IPv4v6',
    4 : 'non IP'
    }

class PDNAddr(Envelope):
    _AddrBlLUT = {1:32, 2:64, 3:96} 
    _GEN = (
        Uint('spare', bl=5),
        Uint('Type', val=1, bl=3, dic=PDNType_dict),
        Buf('Addr', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_blauto(lambda: self._AddrBlLUT.get(self[1].get_val(), None))


#------------------------------------------------------------------------------#
# Traffic flow aggregate description
# TS 24.301, 9.9.4.15
#------------------------------------------------------------------------------#
# same format as Trafic Flow Template

class TFAggregate(TFT):
    pass


#------------------------------------------------------------------------------#
# Remote UE context list
# TS 24.301, 9.9.4.20
#------------------------------------------------------------------------------#
# Proximity Services (ProSe) feature

_RemUEIDType_dict = {
    1 : 'Encrypted IMSI',
    2 : 'IMSI',
    3 : 'MSISDN',
    4 : 'IMEI',
    5 : 'IMEISV',
    }

class RemUEIDEncIMSI(Envelope):
    _GEN = (
        Uint('Digit1', bl=4, rep=REPR_HEX),
        Uint('Odd', bl=1),
        Uint('Type', val=1, bl=3, dic=_RemUEIDType_dict),
        Buf('EncIMSI', val=b'', rep=REPR_HEX)
        )

class RemUEIDDigit(Envelope):
    _GEN = (
        Uint('Digit1', bl=4, rep=REPR_HEX),
        Uint('Odd', bl=1),
        Uint('Type', val=2, bl=3, dic=_RemUEIDType_dict),
        Buf('Digits', val=b'', rep=REPR_HEX)
        )

class RemoteUEID(Envelope):
    
    # during encode() / _from_char() processing
    # specific attributes are created:
    # self._IDDigit   = RemUEIDDigit()
    # self._IDEncIMSI = RemUEIDEncIMSI()
    
    def set_val(self, vals):
        if isinstance(vals, dict) and 'type' in vals and 'ident' in vals:
            self.encode(vals['type'], vals['ident'])
        else:
            Envelope.set_val(self, vals)
    
    def decode(self):
        """returns the remote UE mobile identity type and value
        """
        type = self['Type'].get_val()
        if type == 1:
            # encrypted IMSI
            return (type, self[3].to_bytes())
        
        elif type in (2, 3, 4, 5):
            # digits
            return (type, str(self[0].get_val()) + decode_bcd(self[3].get_val()))
        
        else:
            return (type, None)
    
    def encode(self, type=2, ident=None):
        """sets the remote UE mobile identity with given type
        
        if type is 1 (encrypted IMSI): ident must be an uint32
        if type is 2 (IMSI), 3 (MSISDN), 4 (IMEI) or 5 (IMEISV): ident must be a 
            string of digits
        """
        if type == 1:
            if not hasattr(self, '_IDEncIMSI'):
                self._IDEncIMSI = RemUEIDEncIMSI()
            self._content = self._IDNone._content
            self._by_id   = self._IDNone._by_id
            self._by_name = self._IDNone._by_name
            self[3].set_val(ident)
        
        elif type in (2, 3, 4, 5):
            if not ident.isdigit():
                raise(PycrateErr('{0}: invalid identity to encode, {1!r}'\
                      .format(self._name, ident)))
            if not hasattr(self, '_IDDigit'):
                self._IDDigit = RemUEIDDigit()
            self._content = self._IDDigit._content
            self._by_id   = self._IDDigit._by_id
            self._by_name = self._IDDigit._by_name
            self[2]._val = type
            if len(ident) % 2:
                self[1]._val = 1
            # encode digits the BCD way
            self[0]._val = int(ident[0])
            self[3]._val = encode_bcd(ident[1:])
    
    def _from_char(self, char):
        if not self.get_trans():
            try:
                spare = char.get_uint(5)
                type  = char.get_uint(3)
            except CharpyErr as err:
                raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
            except Exception as err:
                raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
            #
            if type == 1:
                if not hasattr(self, '_IDEncIMSI'):
                    self._IDEncIMSI = RemUEIDEncIMSI()
                self._content = self._IDTemp._content
                self._by_id   = self._IDTemp._by_id
                self._by_name = self._IDTemp._by_name
                self[0]._val = spare >> 1
                self[1]._val = spare & 1
                self[3]._from_char(char)
            #
            elif type in (2, 3, 4, 5):
                if not hasattr(self, '_IDDigit'):
                    self._IDDigit = RemUEIDDigit()
                self._content = self._IDDigit._content
                self._by_id   = self._IDDigit._by_id
                self._by_name = self._IDDigit._by_name
                self[0]._val = spare >> 1
                self[1]._val = spare & 1
                self[2]._val = type
                self[3]._from_char(char)   
    
    def repr(self):
        if not self._content:
            return Envelope.repr(self)
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        #
        type = self['Type'].get_val()
        #
        if type == 1:
            if self[3]._rep in (REPR_RAW, REPR_HUM):
                t_repr = repr(self[3].get_val())
            elif self[3]._rep == REPR_HEX:
                t_repr = '0x' + self[3].hex()
            elif self[3].rep == REPR_BIN:
                t_repr = '0b' + self[3].bin()
            else:
                t_repr = ''
            return '<%s%s%s [Encrypted IMSI] : %s>' % (self._name, desc, trans, t_repr)
        elif type in (2, 3, 4, 5):
            return '<%s%s%s [%s] : %s>' % (self._name, desc, trans, _RemUEIDType_dict[type],
                                           str(self[0].get_val()) + decode_bcd(self[3].get_val()))  
        else:
            return Envelope.repr(self)
    
    __repr__ = repr


class RemoteUECtxt(Envelope):
    _AddrBlLUT = {1:4, 2:8} 
    _GEN = (
        Uint8('Len'),
        Uint8('Num'),
        Sequence('RemoteUEIDs', GEN=RemoteUEID()),
        Uint('spare', bl=5),
        Uint('AddrType', bl=3, dic=PDNType_dict),
        Buf('AddrInfo', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 2+self[2].get_len()+self[5].get_len())
        self[1].set_valauto(self[2].get_num)
        self[2].set_numauto(self[1].get_val)
        self[5].set_blauto(lambda: self._AddrBlLUT.get(self[4](), None))


class RemoteUECtxtList(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('RemoteUECtxts', GEN=RemoteUECtxt())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self[1].get_num)
        self[1].set_numauto(self[0].get_val)


#------------------------------------------------------------------------------#
# PKMF address
# TS 24.301, 9.9.4.21
#------------------------------------------------------------------------------#
# Proximity Services (ProSe) feature

class PKMFAddr(Envelope):
    _AddrBlLUT = {1:32, 2:128} 
    _GEN = (
        Uint('spare', bl=5),
        Uint('Type', val=1, bl=3, dic={1:'IPv4', 2:'IPv6'}),
        Buf('Addr', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_blauto(lambda: self._AddrBlLUT.get(self[1](), None))


#------------------------------------------------------------------------------#
# Header compression configuration
# TS 24.301, 9.9.4.22
#------------------------------------------------------------------------------#

_HdrCompConfPType_dict = {
    0 : '0x0000 (No Compression)',
    1 : '0x0002 (UDP/IP)',
    2 : '0x0003 (ESP/IP)',
    3 : '0x0004 (IP)',
    4 : '0x0006 (TCP/IP)',
    5 : '0x0102 (UDP/IP)',
    6 : '0x0103 (ESP/IP)',
    7 : '0x0104 (IP)'
    }

class HdrCompConfig(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('P0x0104', bl=1),
        Uint('P0x0103', bl=1),
        Uint('P0x0102', bl=1),
        Uint('P0x0006', bl=1),
        Uint('P0x0004', bl=1),
        Uint('P0x0003', bl=1),
        Uint('P0x0002', bl=1),
        Uint16('MAX_CID'),
        Uint8('ParamsType', dic=_HdrCompConfPType_dict, trans=True),
        Buf('ParamsContainer', trans=True, rep=REPR_HEX)
        )
    
    def set_val(self, vals):
        if vals is None:
            self[9].set_trans(True)
            self[10].set_trans(True)
        elif isinstance(vals, (tuple, list)) and len(vals) >= 10:
            self[9].set_trans(False)
            self[10].set_trans(False)
        elif isinstance(vals, dict) and 'ParamsType' in vals:
            self[9].set_trans(False)
            self[10].set_trans(False)
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        if char.get_len() >= 4:
            self[9].set_trans(False)
            self[10].set_trans(False)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# Control plane only indication
# TS 24.301, 9.9.4.23
#------------------------------------------------------------------------------#

_CPOI_dict = {
    0 : 'PDN connection can be used with user plane radio bearer(s)',
    1 : 'PDN connection can be used for control plane CIoT EPS optimization only'
    }

class CPOnlyInd(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1, dic=_CPOI_dict)
        )


#------------------------------------------------------------------------------#
# Release assistance indication
# TS 24.301, 9.9.4.25
#------------------------------------------------------------------------------#

_DDX_dict = {
    0 : 'No information available',
    1 : 'No further uplink or downlink data transmission subsequent to the uplink data transmission is expected',
    2 : 'Only a single downlink data transmission and no further uplink data transmission subsequent to the uplink data transmission is expected',
    3 : 'reserved'
    }

class ReleaseAssistInd(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('DDX', bl=2, dic=_DDX_dict)
        )

#------------------------------------------------------------------------------#
# Header compression configuration status
# TS 24.301, 9.9.4.27
#------------------------------------------------------------------------------#

_HdrCompConfigStat_dict = {
    0 : 'header compression config used',
    1 : 'header compression config not used'
    }

class HdrCompConfigStat(Envelope):
    _GEN = (
        Uint('EBI_7', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_6', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_5', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_4', bl=1),
        Uint('EBI_3', bl=1),
        Uint('EBI_2', bl=1),
        Uint('EBI_1', bl=1),
        Uint('EBI_0', bl=1),
        Uint('EBI_15', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_14', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_13', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_12', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_11', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_10', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_9', bl=1, dic=_HdrCompConfigStat_dict),
        Uint('EBI_8', bl=1, dic=_HdrCompConfigStat_dict)
        )


#------------------------------------------------------------------------------#
# Serving PLMN rate control
# TS 24.301, 9.9.4.28
#------------------------------------------------------------------------------#

class ServingPLMNRateCtrl(Uint16):
    _desc = 'maximum ESM data transport messages with user data per 6 min'
    _dic  = {0xFFFF: 'not restricted'}

