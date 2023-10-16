# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
# *
# * Copyright 2023. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/SIGTRANParams.py
# * Created : 2023-01-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'M3UATag',
    'M3UAPrmDispatcher',
    'M3UAMsgDispatcher',
    'M3UA_ERR',
    'M3UA_NTFY',
    'M3UA_DATA',
    'M3UA_DUNA',
    'M3UA_DAVA',
    'M3UA_DAUD',
    'M3UA_SCON',
    'M3UA_DUPU',
    'M3UA_DRST',
    'M3UA_ASPUp',
    'M3UA_ASPDown',
    'M3UA_BEAT',
    'M3UA_ASPUpAck',
    'M3UA_ASPDownAck',
    'M3UA_BEATAck',
    'M3UA_ASPAct',
    'M3UA_ASPInact',
    'M3UA_ASPActAck',
    'M3UA_ASPInactAck',
    'M3UA_REGREQ',
    'M3UA_REGRSP',
    'M3UA_DEREGREQ',
    'M3UA_DEREGRSP',
    'parse_M3UA',
    'ERR_M3UA_BUF_TOO_SHORT',
    'ERR_M3UA_BUF_INVALID',
    'ERR_M3UA_TYPE_NONEXIST',
    'ERR_M3UA_MAND_PRM_MISS',
    ]


from enum   import IntEnum
from struct import unpack

from pycrate_core.utils  import *
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.charpy import *

from pycrate_mobile.SIGTRAN import (
    Param  as SIGTRANParam,
    Params as SIGTRANParams,
    Header as SIGTRANHeader,
    SIGTRAN,
    )

#------------------------------------------------------------------------------#
# Specific classes for M3UA Parameters
#------------------------------------------------------------------------------#

class M3UADecErr(PycrateErr):
    pass


class Param(SIGTRANParam):
    """M3UA parameter's structure, as defined in RFC 4666, section 3
    """
    # When a Dispatcher is defined, it is used:
    # - at encoding: for setting the specific parameter structure compliant to the RFC
    # - at decoding: for further decoding each parameter according to its specific structure from the RFC
    _Dispatch = {}
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 4+self[2].get_len())
        if not hasattr(self[2], '_bl') or self[2]._bl is None:
            self[2].set_blauto( lambda: 8*max(0, self[1].get_val()-4))
        self[3].set_valauto(lambda: (-self[1].get_val()%4) * self._pad)
        self[3].set_blauto( lambda: 8*(-self[1].get_val()%4))
    
    def _init_val_attr(self):
        if isinstance(self[2], Buf):
            self._val_raw = self[2]
            self._val_cls = None
        else:
            self._val_raw = None
            self._val_cls = self[2]
    
    def _set_val_raw(self):
        if not hasattr(self, '_val_raw'):
            self._init_val_attr()
        if self._val_raw is None:
            self._val_raw = Buf('Val', val=b'', rep=REPR_HEX)
            self._val_raw.set_blauto(lambda: 8*max(0, self[1].get_val()-4))
        if self[2] != self._val_raw:
            self.replace(self[2], self._val_raw)
    
    def _set_val_cls(self):
        if not hasattr(self, '_val_cls'):
            self._init_val_attr()
        tag = self[0].get_val()
        if self._Dispatch and tag in self._Dispatch \
        and (self._val_cls is None or tag != self._val_cls._Tag):
            # set the structure name to the Param() top level, so that the internal
            # structure of Param stays uniform
            self._val_cls = self._Dispatch[tag]('Val')
            self._name = self._val_cls.__class__.__name__
            if not hasattr(self._val_cls, '_bl') or self._val_cls._bl is None:
                self._val_cls.set_blauto( lambda: 8*max(0, self[1].get_val()-4))
        if self._val_cls is not None and self[2] != self._val_cls:
            self.replace(self[2], self._val_cls)
    
    def _set_tag_val(self, tag, val):
        if tag is not None:
            self[0].set_val(tag)
        if isinstance(val, bytes_types):
            self._set_val_raw()
            self[2].set_val(val)
        else:
            self._set_val_cls()
            if val:
                self[2].set_val(val)
    
    # set_val() method can be used with both type of values for Val:
    # - bytes, assigned to the Buf raw object
    # - dedicated type, assigned to the dedicated parameter structure
    def set_val(self, val):
        if isinstance(val, (tuple, list)) and 3 <= len(val) <= 4:
            self._set_tag_val(val[0], val[2])
            self[1].set_val(val[1])
            if len(val) == 4:
                self[3].set_val(val[3])
        elif isinstance(val, dict):
            if 'Val' in val:
                val = dict(val)
                if 'Tag' in val:
                    self._set_tag_val(val['Tag'], val['Val'])
                    del val['Tag']
                else:
                    self._set_tag_val(None, val['Val'])
                del val['Val']
                if val:
                    Envelope.set_val(self, val)
            else:
                Envelope.set_val(self, val)
                self._set_val_cls()
        else:
            Envelope.set_val(self, val)
    
    # _from_char() method attempts to decode Val with the dedicated parameter structure
    # and fallbacks to the Buf raw object if failing with the former.
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self[1]._from_char(char)
        # 1st try decoding with the structured Data
        char_cur = char._cur
        self._set_val_cls()
        try:
            self[2]._from_char(char)
        except PycrateErr:
            # 2nd try decoding as raw Data
            char._cur = char_cur
            self._set_val_raw()
            self[2]._from_char(char)
        # this is to enable the decoding of some SIGTRAN implementations
        # were padding of the last parameter is omitted
        if char.len_bit():
            self[3]._from_char(char)
        elif self[3].get_len():
            self[3].set_trans(True)


class Params(SIGTRANParams):
    """Sequence of M3UA parameters' specific structures, as defined in RFC 4666, section 3
    """
    _GEN = Param()
    
    # this is to raise in case not all mandatory parameters are set in the sequence
    VERIF_MAND = True
    # this is to always add mandatory parameters, even if not set appropriately
    _SET_MAND  = True
    
    # Layout is used to provide the specific layout of the sequence of parameters' tag
    # Mand is used to only list mandatory parameters' tag
    _Layout = None
    _Mand   = set()
    # It is then used
    # - at encoding: for setting a default sequence of parameters compliant to the RFC
    # - at decoding: for checking the global compliance of the sequence of parameters to the RFC
    
    def __init__(self, *args, **kwargs):
        Sequence.__init__(self, *args, **kwargs)
        if 'val' not in kwargs:
            self.init_prms(wopt=False)
    
    def set_val(self, vals):
        Sequence.set_val(self, vals)
        if self._SET_MAND:
            # ensure at least all mandatory IEs are there
            mand = set(self._Mand)
            for prm in self._content:
                mand.discard( prm[0].get_val() )
            for tag in mand:
                self.add_prm(tag)
                if isinstance(self[-1], Params):
                    self[-1].init_prms(wopt=False)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        #
        if self._content:
            # reinitialize the Sequence to an empty one
            self.clear()
        # decode the sequence of IEs, whatever they are
        Sequence._from_char(self, char)
        #
        # eventually verify mandatory IE
        if self.VERIF_MAND:
            mand = set(self._Mand)
            for prm in self:
                mand.discard( prm[0].get_val() )
            if mand:
                raise(M3UADecErr('{0}: missing mandatory parameter(s), {1}'\
                      .format(self._name, ', '.join(map(str, mand)))))
    
    def add_prm(self, tag, val=None):
        """add the parameter of given `tag` and sets the value `val` (None, raw bytes 
        buffer or structured data) into its data part
        """
        self.append( self._tmpl.clone() )
        self._content[-1]._set_tag_val(tag, val)
    
    def rem_prm(self, tag):
        """remove the parameter of given `tag`
        """
        for prm in self._content[::-1]:
            if prm[0].get_val() == tag:
                self._content.remove(prm)
                break
    
    def init_prms(self, wopt=False):
        """re-initialize all parameters that are mandatory,
        adding optional ones if `wopt` is set
        
        This is called recursively on all parameters which are sequence of parameters 
        themselves, too.
        """
        # clear the content first
        self.clear()
        # init all mandatory IEs
        for tag, rule in self._Layout.items():
            if rule[0:1] == 'M':
                self.add_prm(tag)
                if isinstance(self[-1], Params):
                    self[-1].init_prms(wopt)
            elif wopt:
                self.add_prm(tag)
                if isinstance(self[-1], Params):
                    self[-1].init_prms(wopt)
    
    def get_prm_first(self, tag):
        """return the first parameter corresponding to the provided `tag', or None
        """
        for prm in self._content:
            if prm[0].get_val() == tag:
                return prm[2]
        return None
    
    def get_prm_list(self, tag):
        """return the list of parameter(s) corresponding to the provided `tag' 
        """
        ret = []
        for prm in self._content:
            if prm[0].get_val() == tag:
                ret.append(prm[2])
        return ret
    
    def chk_comp(self):
        """check the compliance of the sequence of parameters against the list of mandatory
        parameters and the potential presence of unexpected ones
        
        return 2 sets
            1st contains the missing mandatory parameters' tag
            2nd contains the unexpected (neither mandatory, nor optional) parameters' tag
        """
        # check the sequence of M3UA parameters against the Layout
        mand = set(self._Mand)
        unex = set()
        for prm in self:
            tag = prm[0].get_val()
            if tag in mand:
                mand.remove(tag)
            elif tag not in self._Layout:
                unex.add(tag)
        return mand, unex


def _get_mand_prm(layout):
    mand = set()
    for tag, rule in layout.items():
        if rule[0:1] == 'M':
            mand.add(tag)
    return mand


#------------------------------------------------------------------------------#
# All parameters defined in RFC 4666
#------------------------------------------------------------------------------#

class M3UATag(IntEnum):
    # 3.3.1
    NetworkAppearance   = 0x0200
    RoutingContext      = 0x0006
    ProtocolData        = 0x0210
    CorrelationId       = 0x0013
    # 3.4.1
    AffectedPC          = 0x0012
    InfoString          = 0x0004
    # 3.4.4
    ConcernedDPC        = 0x0206
    CongestionInd       = 0x0205
    # 3.4.5
    UserCause           = 0x0204
    # 3.5.1
    ASPId               = 0x0011
    # 3.5.5
    HeartbeatData       = 0x0009
    # 3.6.1
    RoutingKey          = 0x0207
    LocalRKId           = 0x020a
    TrafficModeType     = 0x000b
    DPC                 = 0x020b
    SIs                 = 0x020c
    OPCList             = 0x020e
    # 3.6.2
    RegResult           = 0x0208
    RegStatus           = 0x0212
    # 3.6.4
    DeregResult         = 0x0209
    DeregStatus         = 0x0213
    # 3.8.1
    ErrorCode           = 0x000c
    DiagnosticInfo      = 0x0007
    # 3.8.2
    Status              = 0x000d


class NetworkAppearance(Uint8):
    _Tag = M3UATag.NetworkAppearance


class RoutingContext(Array):
    _Tag = M3UATag.RoutingContext
    _GEN = Uint32('RC')


class ProtocolData(Envelope):
    _Tag = M3UATag.ProtocolData
    _GEN = (
        Uint32('OPC'),
        Uint32('DPC'),
        Uint8('SI'),
        Uint8('NI'),
        Uint8('MP'),
        Uint8('SLS'),
        Buf('Data', rep=REPR_HEX)
        )


class CorrelationId(Uint32):
    _Tag = M3UATag.CorrelationId


class AffectedPC(Sequence):
    _Tag = M3UATag.AffectedPC
    _GEN = Envelope('APC', GEN=(
        Uint8('Mask'),
        Uint24('PC')
        ))


class InfoString(String):
    _Tag = M3UATag.InfoString


class ConcernedDPC(Uint32):
    _Tag = M3UATag.ConcernedDPC


class CongestionInd(Uint32):
    _Tag = M3UATag.CongestionInd


class UserCause(Envelope):
    _Tag = M3UATag.UserCause
    _GEN = (
        Uint16('Cause', dic={
            0 : 'Unknown',
            1 : 'Unequipped Remote User',
            2 : 'Inaccessible Remote User'}),
        Uint16('User', val=3, dic={
            3 : 'SCCP',
            4 : 'TUP',
            5 : 'ISUP',
            6 : 'DUP',
            7 : 'Reserved',
            8 : 'MTP Testing User Part',
            9 : 'Broadband ISDN User Part',
            10: 'Satellite ISDN User Part',
            11: 'Signal Processing Network Element User Part',
            12: 'AAL type 2 Signalling',
            13: 'BICC',
            14: 'Gateway Control Protocol',
            })
        )


class ASPId(Uint32):
    _Tag = M3UATag.ASPId


class HeartbeatData(Buf):
    _repr = REPR_HEX
    _Tag  = M3UATag.HeartbeatData


class LocalRKId(Uint32):
    _Tag = M3UATag.LocalRKId


class TrafficModeType(Uint32):
    _Tag = M3UATag.TrafficModeType
    _dic = {
        1 : 'Override',
        2 : 'Loadshare',
        3 : 'Broadcast',
        }
    DEFAULT_VAL = 1


class DPC(Envelope):
    _Tag = M3UATag.DPC
    _GEN = (
        Uint8('Mask'),
        Uint24('PC')
        )


class SIs(Array):
    _Tag = M3UATag.SIs
    _GEN = Uint8('SI')


class OPCList(Sequence):
    _Tag = M3UATag.OPCList
    _GEN = Envelope('OPC', GEN=(
        Uint8('Mask'),
        Uint24('PC')
        ))


class RoutingKey(Params):
    _Tag    = M3UATag.RoutingKey
    # this Layout needs to stay ordered, which is not supported with the current runtime
    _Layout = {
        M3UATag.LocalRKId         : 'M',
        M3UATag.RoutingContext    : 'O',
        M3UATag.TrafficModeType   : 'O',
        M3UATag.DPC               : 'M+',
        M3UATag.NetworkAppearance : 'O',
        M3UATag.SIs               : 'O+',
        M3UATag.OPCList           : 'O+',
        # [DPC, SIs, OPCList] group may be repeated, pattern which is not verified with
        # the current runtime
        }
    _Mand   = _get_mand_prm(_Layout)


# RFC 4666, 3.6.2, Registration Response (REG RSP)

class RegStatus(Uint32):
    _Tag = M3UATag.RegStatus
    _dic = {
        0: "Successfully Registered",
        1: "Error - Unknown",
        2: "Error - Invalid DPC",
        3: "Error - Invalid Network Appearance",
        4: "Error - Invalid Routing Key",
        5: "Error - Permission Denied",
        6: "Error - Cannot Support Unique Routing",
        7: "Error - Routing Key not Currently Provisioned",
        8: "Error - Insufficient Resources",
        9: "Error - Unsupported RK parameter Field",
        10: "Error - Unsupported/Invalid Traffic Handling Mode",
        11: "Error - Routing Key Change Refused",
        12: "Error - Routing Key Already Registered",
        }


class RegResult(Params):
    _Tag    = M3UATag.RegResult
    _Layout = {
        M3UATag.LocalRKId       : 'M',
        M3UATag.RegStatus       : 'M',
        M3UATag.RoutingContext  : 'M',
        }
    _Mand   = _get_mand_prm(_Layout)


class DeregStatus(Uint32):
    _Tag = M3UATag.DeregStatus
    _dic = {
        0 : 'Successfully Deregistered',
        1 : 'Error - Unknown',
        2 : 'Error - Invalid Routing Context',
        3 : 'Error - Permission Denied',
        4 : 'Error - Not Registered',
        5 : 'Error - ASP Currently Active for Routing Context',
        }


class DeregResult(Params):
    _Tag    = M3UATag.DeregResult
    _Layout = {
        M3UATag.RoutingContext  : 'M',
        M3UATag.DeregStatus     : 'M',
        }
    _Mand   = _get_mand_prm(_Layout)


# RFC 4666, 3.8.1, Error

class ErrorCode(Uint32):
    _Tag = M3UATag.ErrorCode
    _dic = {
        0x01: "Invalid Version",
        0x02: "Not Used in M3UA",
        0x03: "Unsupported Message Class",
        0x04: "Unsupported Message Type",
        0x05: "Unsupported Traffic Mode Type",
        0x06: "Unexpected Message",
        0x07: "Protocol Error",
        0x08: "Not Used in M3UA",
        0x09: "Invalid Stream Identifier",
        0x0a: "Not Used in M3UA",
        0x0b: "Not Used in M3UA",
        0x0c: "Not Used in M3UA",
        0x0d: "Refused - Management Blocking",
        0x0e: "ASP Identifier Required",
        0x0f: "Invalid ASP Identifier",
        0x10: "Not Used in M3UA",
        0x11: "Invalid Parameter Value",
        0x12: "Parameter Field Error",
        0x13: "Unexpected Parameter",
        0x14: "Destination Status Unknown",
        0x15: "Invalid Network Appearance",
        0x16: "Missing Parameter",
        0x17: "Not Used in M3UA",
        0x18: "Not Used in M3UA",
        0x19: "Invalid Routing Context",
        0x1a: "No Configured AS for ASP",
        }
    DEFAULT_VAL = 7


class DiagnosticInfo(Buf):
    _repr = REPR_HEX
    _Tag  = M3UATag.DiagnosticInfo


# RFC 4666, 3.8.2, Notify

_StatAS_dict = {
    1 : 'Reserved',
    2 : 'AS-INACTIVE',
    3 : 'AS-ACTIVE',
    4 : 'AS-PENDING',
    }

_StatOther_dict = {
    1 : 'Insufficient ASP Resources Active in AS',
    2 : 'Alternate ASP Active',
    3 : 'ASP Failure',
    }


class Status(Envelope):
    _Tag = M3UATag.Status
    _GEN = (
        Uint16('Type', val=1, dic={1: 'AS State Change', 2: 'Other'}),
        Uint16('Info', val=2)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_dicauto(lambda: _StatAS_dict if self[0].get_val() == 1 else _StatOther_dict)


#------------------------------------------------------------------------------#
# Global M3UA parameter dispatcher and message class generator
#------------------------------------------------------------------------------#

# Associate the specific M3UA parameter's structures to their tag within the Param
# class dispatcher

M3UAPrmDispatcher = {
    M3UATag.NetworkAppearance : NetworkAppearance,
    M3UATag.RoutingContext    : RoutingContext,
    M3UATag.ProtocolData      : ProtocolData,
    M3UATag.CorrelationId     : CorrelationId,
    M3UATag.AffectedPC        : AffectedPC,
    M3UATag.InfoString        : InfoString,
    M3UATag.ConcernedDPC      : ConcernedDPC,
    M3UATag.CongestionInd     : CongestionInd,
    M3UATag.ASPId             : ASPId,
    M3UATag.HeartbeatData     : HeartbeatData,
    M3UATag.RoutingKey        : RoutingKey,
    M3UATag.LocalRKId         : LocalRKId,
    M3UATag.TrafficModeType   : TrafficModeType,
    M3UATag.DPC               : DPC,
    M3UATag.SIs               : SIs,
    M3UATag.OPCList           : OPCList,
    M3UATag.RegResult         : RegResult,
    M3UATag.RegStatus         : RegStatus,
    M3UATag.DeregResult       : DeregResult,
    M3UATag.DeregStatus       : DeregStatus,
    M3UATag.ErrorCode         : ErrorCode,
    M3UATag.DiagnosticInfo    : DiagnosticInfo,
    M3UATag.Status            : Status,
    }

Param._Dispatch = M3UAPrmDispatcher


def _gen_m3ua_cls(Name, Class, Type, Prms):
    """generate the specific M3UA message class with the appropriate Class, Type
    and parameters Layout
    """
    
    class M3UAMsg(SIGTRAN):
        _GEN = (
            SIGTRANHeader('Header', val={'Class': Class, 'Type': Type}),
            Prms(hier=1)
            )
    
    M3UAMsg.__doc__  = """M3UA %s message structure
        Including the common message header and the sequence of parameters with 
        specific structures according to RFC 4666, section 3
        """ % Name
    M3UAMsg.__name__ = 'M3UA_%s' % Name
    return M3UAMsg


#------------------------------------------------------------------------------#
# M3UA message classes
#------------------------------------------------------------------------------#

# RFC 4666, 3.3.1, Payload Data Message (DATA)
class ParamsDATA(Params):
    """M3UA DATA parameters, RFC 4666, 3.3.1
    """
    _Layout = {
        M3UATag.NetworkAppearance   : 'O',
        M3UATag.RoutingContext      : 'C',
        M3UATag.ProtocolData        : 'M',
        M3UATag.CorrelationId       : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_DATA   = _gen_m3ua_cls('DATA', 1, 1, ParamsDATA)


# RFC 4666, 3.4.1, Destination Unavailable (DUNA)
class ParamsDUNA(Params):
    """M3UA DUNA parameters, RFC 4666, 3.4.1
    """
    _Layout = {
        M3UATag.NetworkAppearance   : 'O',
        M3UATag.RoutingContext      : 'C',
        M3UATag.AffectedPC          : 'M',
        M3UATag.InfoString          : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_DUNA   = _gen_m3ua_cls('DUNA', 2, 1, ParamsDUNA)


# RFC 4666, 3.4.2, Destination Available (DAVA)
class ParamsDAVA(Params):
    """M3UA DAVA parameters, RFC 4666, 3.4.2
    """
    _Layout = {
        M3UATag.NetworkAppearance   : 'O',
        M3UATag.RoutingContext      : 'C',
        M3UATag.AffectedPC          : 'M',
        M3UATag.InfoString          : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_DAVA   = _gen_m3ua_cls('DAVA', 2, 2, ParamsDAVA)


# RFC 4666, 3.4.3, Destination State Audit (DAUD)
class ParamsDAUD(Params):
    """M3UA DAUD parameters, RFC 4666, 3.4.3
    """
    _Layout = {
        M3UATag.NetworkAppearance   : 'O',
        M3UATag.RoutingContext      : 'C',
        M3UATag.AffectedPC          : 'M',
        M3UATag.InfoString          : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_DAUD   = _gen_m3ua_cls('DAUD', 2, 3, ParamsDAUD)


# RFC 4666, 3.4.4, Signalling Congestion (SCON)
class ParamsSCON(Params):
    """M3UA SCON parameters, RFC 4666, 3.4.4
    """
    _Layout = {
        M3UATag.NetworkAppearance   : 'O',
        M3UATag.RoutingContext      : 'C',
        M3UATag.AffectedPC          : 'M',
        M3UATag.ConcernedDPC        : 'O',
        M3UATag.CongestionInd       : 'O',
        M3UATag.InfoString          : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_SCON   = _gen_m3ua_cls('SCON', 2, 4, ParamsSCON)


# RFC 4666, 3.4.5, Destination User Part Unavailable (DUPU)
class ParamsDUPU(Params):
    """M3UA DUPU parameters, RFC 4666, 3.4.5
    """
    _Layout = {
        M3UATag.NetworkAppearance   : 'O',
        M3UATag.RoutingContext      : 'C',
        M3UATag.AffectedPC          : 'M',
        M3UATag.UserCause           : 'M',
        M3UATag.InfoString          : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_DUPU   = _gen_m3ua_cls('DUPU', 2, 5, ParamsDUPU)


# RFC 4666, 3.4.6, Destination Restricted (DRST)
class ParamsDRST(Params):
    """M3UA DRST parameters, RFC 4666, 3.4.6
    """
    _Layout = {
        M3UATag.NetworkAppearance   : 'O',
        M3UATag.RoutingContext      : 'C',
        M3UATag.AffectedPC          : 'M',
        M3UATag.InfoString          : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_DRST   = _gen_m3ua_cls('DRST', 2, 6, ParamsDRST)


# RFC 4666, 3.5.1, ASP Up
class ParamsASPUp(Params):
    """M3UA ASP Up parameters, RFC 4666, 3.5.1
    """
    _Layout = {
        M3UATag.ASPId       : 'O',
        M3UATag.InfoString  : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ASPUp  = _gen_m3ua_cls('ASPUp', 3, 1, ParamsASPUp)


# RFC 4666, 3.5.2, ASP Up Acknowledgement (ASP Up Ack)
class ParamsASPUpAck(Params):
    """M3UA ASP Up Ack parameters, RFC 4666, 3.5.2
    """
    _Layout = {
        M3UATag.ASPId       : 'O',
        M3UATag.InfoString  : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ASPUpAck = _gen_m3ua_cls('ASPUpAck', 3, 4, ParamsASPUpAck)


# RFC 4666, 3.5.3, ASP Down
class ParamsASPDown(Params):
    """M3UA ASP Down parameters, RFC 4666, 3.5.3
    """
    _Layout = {
        M3UATag.InfoString : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ASPDown = _gen_m3ua_cls('ASPDown', 3, 2, ParamsASPDown)


# RFC 4666, 3.5.4, ASP Down Acknowledgement (ASP Down Ack)
class ParamsASPDownAck(Params):
    """M3UA ASP Down Ack parameters, RFC 4666, 3.5.4
    """
    _Layout = {
        M3UATag.InfoString : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ASPDownAck = _gen_m3ua_cls('ASPDownAck', 3, 5, ParamsASPDownAck)


# RFC 4666, 3.5.5, Heartbeat (BEAT)
class ParamsBEAT(Params):
    """M3UA BEAT parameters, RFC 4666, 3.5.5
    """
    _Layout = {
        M3UATag.HeartbeatData : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_BEAT   = _gen_m3ua_cls('BEAT', 3, 3, ParamsBEAT)


# RFC 4666, 3.5.6, Heartbeat Acknowledgement (BEAT Ack)
class ParamsBEATAck(Params):
    """M3UA BEAT Ack parameters, RFC 4666, 3.5.6
    """
    _Layout = {
        M3UATag.HeartbeatData : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_BEATAck = _gen_m3ua_cls('BEATAck', 3, 6, ParamsBEATAck)


# RFC 4666, 3.6.1, Registration Request (REG REQ)
class ParamsREGREQ(Params):
    """M3UA REG REQ parameters, RFC 4666, 3.6.1
    """
    _Layout = {
        M3UATag.RoutingKey : 'M+',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_REGREQ = _gen_m3ua_cls('REGREQ', 9, 1, ParamsREGREQ)


# RFC 4666, 3.6.2, Registration Response (REG RSP)
class ParamsREGRSP(Params):
    """M3UA REG RSP parameters, RFC 4666, 3.6.2
    """
    _Layout = {
        M3UATag.RegResult : 'M+',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_REGRSP = _gen_m3ua_cls('REGRSP', 9, 2, ParamsREGRSP)


# RFC 4666, 3.6.3, Deregistration Request (DEREG REQ)
class ParamsDEREGREQ(Params):
    """M3UA DEREG REQ parameters, RFC 4666, 3.6.3
    """
    _Layout = {
        M3UATag.RoutingContext : 'M',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_DEREGREQ = _gen_m3ua_cls('DEREGREQ', 9, 3, ParamsDEREGREQ)


# RFC 4666, 3.6.4, Deregistration Response (DEREG RSP)
class ParamsDEREGRSP(Params):
    """M3UA DEREG RSP parameters, RFC 4666, 3.6.4
    """
    _Layout = {
        M3UATag.DeregResult : 'M+',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_DEREGRSP = _gen_m3ua_cls('DEREGRSP', 9, 4, ParamsDEREGRSP)


# RFC 4666, 3.7.1, ASP Active
class ParamsASPAct(Params):
    """M3UA ASP Active parameters, RFC 4666, 3.7.1
    """
    _Layout = {
        M3UATag.TrafficModeType : 'O',
        M3UATag.RoutingContext  : 'O',
        M3UATag.InfoString      : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ASPAct = _gen_m3ua_cls('ASPAct', 4, 1, ParamsASPAct)


# RFC 4666, 3.7.2, ASP Active Acknowledgement (ASP Active Ack)
class ParamsASPActAck(Params):
    """M3UA ASP Active Ack parameters, RFC 4666, 3.7.2
    """
    _Layout = {
        M3UATag.TrafficModeType : 'O',
        M3UATag.RoutingContext  : 'O',
        M3UATag.InfoString      : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ASPActAck = _gen_m3ua_cls('ASPActAck', 4, 3, ParamsASPActAck)


# RFC 4666, 3.7.3, ASP Inactive
class ParamsASPInact(Params):
    """M3UA ASP Inactive parameters, RFC 4666, 3.7.3
    """
    _Layout = {
        M3UATag.RoutingContext  : 'O',
        M3UATag.InfoString      : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ASPInact = _gen_m3ua_cls('ASPInact', 4, 2, ParamsASPInact)


# RFC 4666, 3.7.4, ASP Inactive Acknowledgement (ASP Inactive Ack)
class ParamsASPInactAck(Params):
    """M3UA ASP Inactive Ack parameters, RFC 4666, 3.7.4
    """
    _Layout = {
        M3UATag.RoutingContext  : 'O',
        M3UATag.InfoString      : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ASPInactAck = _gen_m3ua_cls('ASPInactAck', 4, 4, ParamsASPInactAck)


# RFC 4666, 3.8.1, Error
class ParamsERR(Params):
    """M3UA Error parameters, RFC 4666, 3.8.1
    """
    _Layout = {
        M3UATag.ErrorCode           : 'M',
        M3UATag.RoutingContext      : 'C',
        M3UATag.NetworkAppearance   : 'C',
        M3UATag.AffectedPC          : 'C',
        M3UATag.DiagnosticInfo      : 'C',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_ERR    = _gen_m3ua_cls('ERR', 0, 0, ParamsERR)


# RFC 4666, 3.8.2, Notify
class ParamsNTFY(Params):
    """M3UA Notify parameters, RFC 4666, 3.8.2
    """
    _Layout = {
        M3UATag.Status          : 'M',
        M3UATag.ASPId           : 'C',
        M3UATag.RoutingContext  : 'O',
        M3UATag.InfoString      : 'O',
        }
    _Mand   = _get_mand_prm(_Layout)

M3UA_NTFY = _gen_m3ua_cls('NTFY', 0, 1, ParamsNTFY)


#------------------------------------------------------------------------------#
# M3UA parser
#------------------------------------------------------------------------------#

# SIGTRAN Class / Type dispatcher to M3UA message classes
M3UAMsgDispatcher = {
    (0, 0) : M3UA_ERR,
    (0, 1) : M3UA_NTFY,
    (1, 1) : M3UA_DATA,
    (2, 1) : M3UA_DUNA,
    (2, 2) : M3UA_DAVA,
    (2, 3) : M3UA_DAUD,
    (2, 4) : M3UA_SCON,
    (2, 5) : M3UA_DUPU,
    (2, 6) : M3UA_DRST,
    (3, 1) : M3UA_ASPUp,
    (3, 2) : M3UA_ASPDown,
    (3, 3) : M3UA_BEAT,
    (3, 4) : M3UA_ASPUpAck,
    (3, 5) : M3UA_ASPDownAck,
    (3, 6) : M3UA_BEATAck,
    (4, 1) : M3UA_ASPAct,
    (4, 2) : M3UA_ASPInact,
    (4, 3) : M3UA_ASPActAck,
    (4, 4) : M3UA_ASPInactAck,
    (9, 1) : M3UA_REGREQ,
    (9, 2) : M3UA_REGRSP,
    (9, 3) : M3UA_DEREGREQ,
    (9, 4) : M3UA_DEREGRSP
    }


# error code at decoding
ERR_M3UA_BUF_TOO_SHORT = 1
ERR_M3UA_BUF_INVALID   = 2
ERR_M3UA_TYPE_NONEXIST = 3
ERR_M3UA_MAND_PRM_MISS = 4

def parse_M3UA(buf):
    """parses the buffer `buf' for M3UA message and returns a 2-tuple:
    - M3UA message structure, or None if parsing failed
    - parsing error code, 0 if parsing succeeded, > 0 otherwise
    """
    if len(buf) < 8:
        return None, ERR_M3UA_BUF_TOO_SHORT
    vers, _, cls, typ = unpack('>BBBB', buf[:4])
    if vers != 1 or (cls, typ) not in M3UAMsgDispatcher:
        return None, ERR_M3UA_TYPE_NONEXIST
    Msg = M3UAMsgDispatcher[(cls, typ)]()
    try:
        Msg.from_bytes(buf)
    except M3UADecErr:
        Params.VERIF_MAND = False
        Msg = Msg.__class__()
        try:
            Msg.from_bytes(buf)
            Params.VERIF_MAND = True
        except Exception:
            Params.VERIF_MAND = True
            return None, ERR_M3UA_BUF_INVALID
        else:
            return Msg, ERR_M3UA_MAND_PRM_MISS
    else:
        return Msg, 0

