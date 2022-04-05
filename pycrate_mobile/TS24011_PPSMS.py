# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_mobile/TS24011_PPSMS.py
# * Created : 2017-10-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'SMS_CP',
    'SMS_RP',
    #
    'CP_DATA',
    'CP_ACK',
    'CP_ERROR',
    #
    'PPSMSCPTypeClasses',
    'get_ppsmscp_msg_instances',
    #
    'RPOriginatorAddress',
    'RPDestinationAddress',
    #
    'RP_DATA_MO',
    'RP_DATA_MT',
    'RP_ACK_MO',
    'RP_ACK_MT',
    'RP_ERROR_MO',
    'RP_ERROR_MT',
    'RP_SMMA',
    #
    'PPSMSRPTypeClasses',
    'get_ppsmsrp_msg_instances'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.011: Point-to-Point (PP) Short Message Service (SMS)
# support on mobile radio interface
# release 13 (d40)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007     import *
from .TS24008_IE  import BufBCD, _BCDType_dict, _NumPlan_dict
from .TS23040_SMS import *


class SMS_CP(Layer3):
    """parent class for all SMS CP messages
    """
    pass


class SMS_RP(Layer3):
    """parent class for all SMS RP messages
    """
    pass


#------------------------------------------------------------------------------#
# CP‑messages
# TS 24.011, section 8.1
#------------------------------------------------------------------------------#

_SMSPP_CP_dict = {
    1 : 'SMS CP-DATA',
    4 : 'SMS CP-ACK',
    16: 'SMS CP-ERROR'
    }

class CPHeader(Envelope):
    _GEN = (
        TIPD(val={'ProtDisc': 9}),
        Uint8('Type', val=1, dic=_SMSPP_CP_dict),
        )


#------------------------------------------------------------------------------#
# CP‑Cause element
# TS 24.011, 8.1.4.2
#------------------------------------------------------------------------------#

_CPCause_dict = {
    17 : 'Network failure',
    22 : 'Congestion',
    81 : 'Invalid Transaction Identifier value',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non existent or not implemented',
    98 : 'Message not compatible with the short message protocol state',
    99 : 'Information element non existent or not implemented',
    111: 'Protocol error, unspecified',
    }

class CPCause(Uint8):
    _dic = _CPCause_dict


#------------------------------------------------------------------------------#
# CP‑DATA
# TS 24.011, section 7.2.1
#------------------------------------------------------------------------------#

class CP_DATA(SMS_CP):
    _GEN = (
        CPHeader(val={'Type':1}),
        Type4LV('CPUserData', val={'V':b''})
        )
    
    def _from_char(self, char):
        Layer3._from_char(self, char)
        L = self['CPUserData'][0].get_val()
        if L:
            ccur, clen = char._cur, char._len_bit
            char._cur -= 8*L
            char._len_bit = char._cur + 8*L
            mti = char.to_uint(8) & 0x7
            try:
                rp = PPSMSRPTypeClasses[mti]()
                rp._from_char(char)
            except:
                log('%s, _from_char: unable to decode RP message' % self._name)
            else:
                if char.len_bit() > 0:
                    log('%s, _from_char: incorrect decoding of RP message, %s'\
                        % (self._name, rp._name))
                else:
                    self.set_rp(rp)
            char._cur, char._len_bit = ccur, clen
    
    def set_rp(self, rp):
        cpud = self['CPUserData']
        # save the V buffer
        if cpud[1]._name == 'V':
            cpud._V  = cpud[1]
        # set the RP message like an IE
        cpud._IE = rp
        # replace V with the IE
        cpud.replace(cpud[1], rp)
        cpud[0].set_valauto(rp.get_len)


#------------------------------------------------------------------------------#
# CP‑ACK
# TS 24.011, section 7.2.2
#------------------------------------------------------------------------------#

class CP_ACK(SMS_CP):
    _GEN = (
        CPHeader(val={'Type':4}),
        )


#------------------------------------------------------------------------------#
# CP‑ERROR
# TS 24.011, section 7.2.3
#------------------------------------------------------------------------------#

class CP_ERROR(SMS_CP):
    _GEN = (
        CPHeader(val={'Type':16}),
        Type3V('CPCause', val={'V':b'\x11'}, bl={'V':8}, IE=CPCause())
        )


#------------------------------------------------------------------------------#
# PP-SMS CP dispatcher
#------------------------------------------------------------------------------#

PPSMSCPTypeClasses = {
    1 : CP_DATA,
    4 : CP_ACK,
    16: CP_ERROR
    }

def get_ppsmscp_msg_instances():
    return {k: PPSMSCPTypeClasses[k]() for k in PPSMSCPTypeClasses}


#------------------------------------------------------------------------------#
# RP‑messages
# TS 24.011, section 8.2
#------------------------------------------------------------------------------#

_RPMTI_dict = {
    0 : 'MS -> Net : RP-DATA',
    1 : 'Net -> MS : RP-DATA',
    2 : 'MS -> Net : RP-ACK',
    3 : 'Net -> MS : RP-ACK',
    4 : 'MS -> Net : RP-ERROR',
    5 : 'Net -> MS : RP-ERROR',
    6 : 'MS -> Net : RP-SMMA',
    7 : 'reserved'
    }

class RPHeader(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('MTI', bl=3, dic=_RPMTI_dict),
        Uint8('Ref')
        )


#------------------------------------------------------------------------------#
# Originator address element
# TS 24.011, section 8.2.5.1
#------------------------------------------------------------------------------#

class _RPAddress(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Type', val=1, bl=3, dic=_BCDType_dict),
        Uint('NumberingPlan', val=1, bl=4, dic=_NumPlan_dict),
        BufBCD('Num')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_blauto(lambda: 1+self['Num'].get_len())

class RPOriginatorAddress(_RPAddress):
    pass


#------------------------------------------------------------------------------#
# Destination address element
# TS 24.011, section 8.2.5.2
#------------------------------------------------------------------------------#

class RPDestinationAddress(_RPAddress):
    pass


#------------------------------------------------------------------------------#
# RP‑Cause element
# TS 24.011, section 8.2.5.4
#------------------------------------------------------------------------------#

_RPCause_dict = {
    1 : 'Unassigned (unallocated) number',
    8 : 'Operator determined barring',
    10 : 'Call barred',
    11 : 'Reserved',
    21 : 'Short message transfer rejected',
    22 : 'Memory capacity exceeded',
    27 : 'Destination out of order',
    28 : 'Unidentified subscriber',
    29 : 'Facility rejected',
    30 : 'Unknown subscriber',
    38 : 'Network out of order',
    41 : 'Temporary failure',
    42 : 'Congestion',
    47 : 'Resources unavailable, unspecified',
    50 : 'Requested facility not subscribed',
    69 : 'Requested facility not implemented',
    81 : 'Invalid short message transfer reference value',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non existent or not implemented',
    98 : 'Message not compatible with short message protocol state',
    99 : 'Information element non existent or not implemented',
    111: 'Protocol error, unspecified',
    127: 'Interworking, unspecified'
    }

class RPCause(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Value', val=41, bl=7, dic=_RPCause_dict),
        Buf('Diag', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Diag'].set_transauto(lambda: self[0]() == 1)


#------------------------------------------------------------------------------#
# RP‑DATA (Network to Mobile Station)
# TS 24.011, section 7.3.1.1
#------------------------------------------------------------------------------#

class _RP_DATA(SMS_RP):
    
    # provide a single TPDU or a dict of MTI:TPDU according to the type of RP
    TPDU = {}
    
    def _from_char(self, char):
        Layer3._from_char(self, char)
        L = self['RPUserData']['L']()
        if L:
            ccur, clen = char._cur, char._len_bit
            char._cur -= 8*L
            char._len_bit = char._cur + 8*L
            try:
                if isinstance(self.TPDU, dict):
                    mti = char.to_uint(8) & 0x3
                    tp = self.TPDU[mti]()
                else:
                    tp = self.TPDU()
                tp._from_char(char)
            except:
                log('%s, _from_char: unable to decode TP message' % self._name)
            else:
                if char.len_bit() > 0:
                    log('%s, _from_char: incorrect decoding of TP message, %s'\
                        % (self._name, tp._name))
                else:
                    self.set_tpdu(tp)
            char._cur, char._len_bit = ccur, clen
    
    def set_tpdu(self, tpdu):
        rpud = self['RPUserData']
        # save the V buffer
        if rpud[-1]._name == 'V':
            rpud._V  = rpud[-1]
        # set the RP message like an IE
        rpud._IE = tpdu
        # replace V with the IE
        rpud.replace(rpud[-1], tpdu)
        rpud['L'].set_valauto(tpdu.get_len)


class RP_DATA_MT(_RP_DATA):
    TPDU = {
        0 : SMS_DELIVER,
        2 : SMS_STATUS_REPORT
        }
    _GEN = tuple(RPHeader(val={'MTI':1})._content) + (
        Type4LV('RPOriginatorAddress', val={'V':b'\x91'}, IE=RPOriginatorAddress()),
        Type4LV('RPDestinationAddress', val={'V':b''}),
        Type4LV('RPUserData', val={'V':b''}) # < 234 bytes
        )


#------------------------------------------------------------------------------#
# RP‑DATA (Mobile Station to Network)
# TS 24.011, section 7.3.1.2
#------------------------------------------------------------------------------#

class RP_DATA_MO(_RP_DATA):
    TPDU = {
        1 : SMS_SUBMIT,
        2 : SMS_COMMAND
        }
    _GEN = tuple(RPHeader(val={'MTI':0})._content) + (
        Type4LV('RPOriginatorAddress', val={'V':b''}),
        Type4LV('RPDestinationAddress', val={'V':b'\x91'}, IE=RPDestinationAddress()),
        Type4LV('RPUserData', val={'V':b''}) # < 234 bytes
        )


#------------------------------------------------------------------------------#
# RP‑SMMA
# TS 24.011, section 7.3.2
#------------------------------------------------------------------------------#

class RP_SMMA(SMS_RP):
    _GEN = tuple(RPHeader(val={'MTI':6})._content)


#------------------------------------------------------------------------------#
# RP‑ACK
# TS 24.011, section 7.3.3
#------------------------------------------------------------------------------#

class RP_ACK_MT(_RP_DATA):
    TPDU = SMS_SUBMIT_REPORT_RP_ACK
    _GEN = tuple(RPHeader(val={'MTI':3})._content) + (
        Type4TLV('RPUserData', val={'T':0x41, 'V':b''}),
        )


class RP_ACK_MO(_RP_DATA):
    TPDU = SMS_DELIVER_REPORT_RP_ACK
    _GEN = tuple(RPHeader(val={'MTI':2})._content) + (
        Type4TLV('RPUserData', val={'T':0x41, 'V':b''}),
        )


#------------------------------------------------------------------------------#
# RP‑ERROR
# TS 24.011, section 7.3.4
#------------------------------------------------------------------------------#

class RP_ERROR_MT(_RP_DATA):
    TPDU = SMS_SUBMIT_REPORT_RP_ERROR
    _GEN = tuple(RPHeader(val={'MTI':5})._content) + (
        Type4LV('RPCause', val={'V':b'\0'}, IE=RPCause()),
        Type4TLV('RPUserData', val={'T':0x41, 'V':b''}),
        )


class RP_ERROR_MO(_RP_DATA):
    TPDU = SMS_DELIVER_REPORT_RP_ERROR
    _GEN = tuple(RPHeader(val={'MTI':4})._content) + (
        Type4LV('RPCause', val={'V':b'\0'}, IE=RPCause()),
        Type4TLV('RPUserData', val={'T':0x41, 'V':b''}),
        )


#------------------------------------------------------------------------------#
# PP-SMS RP dispatcher
#------------------------------------------------------------------------------#

PPSMSRPTypeClasses = {
    0 : RP_DATA_MO,
    1 : RP_DATA_MT,
    2 : RP_ACK_MO,
    3 : RP_ACK_MT,
    4 : RP_ERROR_MO,
    5 : RP_ERROR_MT,
    6 : RP_SMMA,
    }

def get_ppsmsrp_msg_instances():
    return {k: PPSMSRPTypeClasses[k]() for k in PPSMSRPTypeClasses}

