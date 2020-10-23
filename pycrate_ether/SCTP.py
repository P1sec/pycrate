# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate 
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1Sec.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be usefu,
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
# * File Name : pycrate_ether/SCTP.py
# * Created : 2020-02-03
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii   import *
from struct     import pack
try:
    #raise(ImportError)
    # try to import external LGPL CRC32C Python module
    # https://github.com/ICRAR/crc32c
    from crc32c import crc32c as _crc32c
    def crc32c_cs(buf):
        """Return computed CRC-32c checksum"""
        return pack('<I', _crc32c(buf))
    
except ImportError:
    # define an internal CRC32C processing here
    from array import array as _array
    _crc32c_table = (
        0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F,
        0x35F1141C, 0x26A1E7E8, 0xD4CA64EB, 0x8AD958CF, 0x78B2DBCC,
        0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27,
        0x5E133C24, 0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
        0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384, 0x9A879FA0,
        0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC,
        0xBC267848, 0x4E4DFB4B, 0x20BD8EDE, 0xD2D60DDD, 0xC186FE29,
        0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
        0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E,
        0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA, 0x30E349B1, 0xC288CAB2,
        0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59,
        0xE4292D5A, 0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
        0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595, 0x417B1DBC,
        0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0,
        0x67DAFA54, 0x95B17957, 0xCBA24573, 0x39C9C670, 0x2A993584,
        0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
        0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC,
        0x64D4CECF, 0x77843D3B, 0x85EFBE38, 0xDBFC821C, 0x2997011F,
        0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4,
        0x0F36E6F7, 0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
        0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789, 0xEB1FCBAD,
        0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1,
        0xCDBE2C45, 0x3FD5AF46, 0x7198540D, 0x83F3D70E, 0x90A324FA,
        0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
        0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD,
        0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829, 0x82F63B78, 0x709DB87B,
        0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90,
        0x563C5F93, 0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
        0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C, 0x92A8FC17,
        0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B,
        0xB4091BFF, 0x466298FC, 0x1871A4D8, 0xEA1A27DB, 0xF94AD42F,
        0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
        0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9,
        0x97BAA1BA, 0x84EA524E, 0x7681D14D, 0x2892ED69, 0xDAF96E6A,
        0xC9A99D9E, 0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81,
        0xFC588982, 0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
        0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622, 0x38CC2A06,
        0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A,
        0x1E6DCDEE, 0xEC064EED, 0xC38D26C4, 0x31E6A5C7, 0x22B65633,
        0xD0DDD530, 0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
        0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914,
        0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0, 0xD3D3E1AB, 0x21B862A8,
        0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643,
        0x07198540, 0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
        0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F, 0xE330A81A,
        0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06,
        0xC5914FF2, 0x37FACCF1, 0x69E9F0D5, 0x9B8273D6, 0x88D28022,
        0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
        0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A,
        0xC69F7B69, 0xD5CF889D, 0x27A40B9E, 0x79B737BA, 0x8BDCB4B9,
        0x988C474D, 0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052,
        0xAD7D5351
        )
    
    def _crc32c_add(crc, buf):
        buf = _array('B', buf)
        for b in buf:
            crc = (crc >> 8) ^ _crc32c_table[(crc ^ b) & 0xff]
        return crc
    
    def _crc32c_done(crc):
        tmp = ~crc & 0xffffffff
        b0 = tmp & 0xff
        b1 = (tmp >> 8) & 0xff
        b2 = (tmp >> 16) & 0xff
        b3 = (tmp >> 24) & 0xff
        crc = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        return crc
    
    def crc32c_cs(buf):
        """Return computed CRC-32c checksum"""
        return pack('>I', _crc32c_done(_crc32c_add(0xffffffff, buf)))
    

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *


#------------------------------------------------------------------------------#
# Stream Control Transmission Protocol
# IETF RFC 4960: https://tools.ietf.org/html/rfc4960
# IANA SCTP Parameters: https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# SCTP constants and dicts
#------------------------------------------------------------------------------#

# SCTP chunk types
CHK_DATA            = 0
CHK_INIT            = 1
CHK_INIT_ACK        = 2
CHK_SACK            = 3
CHK_HEARTBEAT       = 4
CHK_HEARTBEAT_ACK   = 5
CHK_ABORT           = 6
CHK_SHUTDOWN        = 7
CHK_SHUTDOWN_ACK    = 8
CHK_ERROR           = 9
CHK_COOKIE_ECHO     = 10
CHK_COOKIE_ACK      = 11
CHK_ECNE            = 12
CHK_CWR             = 13
CHK_SHUTDOWN_COMPLETE = 14
CHK_AUTH            = 15
CHK_I_DATA          = 64
CHK_ASCONF_ACK      = 128
CHK_RE_CONFIG       = 130
CHK_PAD             = 132
CHK_FORWARD_TSN     = 192
CHK_ASCONF          = 193
CHK_I_FORWARD_TSN   = 194

ChkType_dict = {
    0   : 'DATA',
    1   : 'INIT',
    2   : 'INIT ACK',
    3   : 'SACK',
    4   : 'HEARTBEAT',
    5   : 'HEARTBEAT ACK',
    6   : 'ABORT',
    7   : 'SHUTDOWN',
    8   : 'SHUTDOWN ACK',
    9   : 'ERROR',
    10  : 'COOKIE ECHO',
    11  : 'COOKIE ACK',
    12  : 'ECNE',
    13  : 'CWR',
    14  : 'SHUTDOWN COMPLETE',
    15  : 'AUTH',
    64  : 'I-DATA',
    128 : 'ASCONF-ACK',
    130 : 'RE-CONFIG',
    132 : 'PAD',
    192 : 'FORWARD TSN',
    193 : 'ASCONF',
    194 : 'I-FORWARD-TSN',
    }


# SCTP parameter types
PRM_HEARTBEAT_INFO      = 1
PRM_IPV4_ADDR           = 5
PRM_IPV6_ADDR           = 6
PRM_STATE_COOKIE        = 7
PRM_UNRECO_PRM          = 8
PRM_COOKIE_PRESERV      = 9
PRM_HOSTNAME_ADDR       = 11
PRM_SUPP_ADDR_TYPES     = 12
PRM_OUT_SSN_RESET_REQ   = 13
PRM_IN_SSN_RESET_REQ    = 14
PRM_SSN_TSN_RESET_REQ   = 15
PRM_RECONFIG_RESP       = 16
PRM_ADD_OUT_STREAMS_REQ = 17
PRM_ADD_IN_STREAMS_REQ  = 18
PRM_RESERV_ECN_CAP      = 32768
PRM_RANDOM              = 32770
PRM_CHK_LIST            = 32771
PRM_REQ_HMAC_ALG        = 32772
PRM_PAD                 = 32773
PRM_SUPP_EXT            = 32776
PRM_FWD_TSN_SUPP        = 49152
PRM_ADD_IP_ADDR         = 49153
PRM_DEL_IP_ADDR         = 49154
PRM_ERR_CAUSE_IND       = 49155
PRM_SET_PRIM_ADDR       = 49156
PRM_SUCC_IND            = 49157
PRM_ADAPT_LAYER_IND     = 49158

PrmType_dict = {
    1     : 'Heartbeat Info',
    5     : 'IPv4 Address',
    6     : 'IPv6 Address',
    7     : 'State Cookie',
    8     : 'Unrecognized Parameters',
    9     : 'Cookie Preservative',
    11    : 'Host Name Address',
    12    : 'Supported Address Types',
    13    : 'Outgoing SSN Reset Request Parameter',
    14    : 'Incoming SSN Reset Request Parameter',
    15    : 'SSN/TSN Reset Request Parameter',
    16    : 'Re-configuration Response Parameter',
    17    : 'Add Outgoing Streams Request Parameter',
    18    : 'Add Incoming Streams Request Parameter',
    32768 : 'Reserved for ECN Capable',
    32770 : 'Random',
    32771 : 'Chunk List',
    32772 : 'Requested HMAC Algorithm Parameter',
    32773 : 'Padding',
    32776 : 'Supported Extensions',
    49152 : 'Forward TSN supported',
    49153 : 'Add IP Address',
    49154 : 'Delete IP Address',
    49155 : 'Error Cause Indication',
    49156 : 'Set Primary Address',
    49157 : 'Success Indication',
    49158 : 'Adaptation Layer Indication',
    }

HMACAlg_dict = {
    1 : 'SHA-1',
    3 : 'SHA-256'
    }


# SCTP causes
CAUSE_INVALID_SID           = 1
CAUSE_MISSING_MAND_PRM      = 2
CAUSE_STALE_COOKIE_ERR      = 3
CAUSE_OUT_OF_RESOURCE       = 4
CAUSE_UNRESOLV_ADDR         = 5
CAUSE_UNRECO_CHK            = 6
CAUSE_INVALID_MAND_PRM      = 7
CAUSE_UNRECO_PRM            = 8
CAUSE_NO_USER_DATA          = 9
CAUSE_COOKIE_RECV_SHUT      = 10
CAUSE_RESTART_ASSOC_ADDR    = 11
CAUSE_USER_INIT_ABORT       = 12
CAUSE_PROTO_VIOLATION       = 13
CAUSE_REQ_DEL_LAST_IP       = 160
CAUSE_REF_RESOURCE_SHORT    = 161
CAUSE_REQ_DEL_SRC_IP        = 162
CAUSE_ILLEGAL_ASCONF_ACK    = 163
CAUSE_REF_NO_AUTH           = 164
CAUSE_UNSUPP_HMAC_ALG       = 261

CauseCode_dict = {
    1   : 'Invalid Stream Identifier',
    2   : 'Missing Mandatory Parameter',
    3   : 'Stale Cookie Error',
    4   : 'Out of Resource',
    5   : 'Unresolvable Address',
    6   : 'Unrecognized Chunk Type',
    7   : 'Invalid Mandatory Parameter',
    8   : 'Unrecognized Parameters',
    9   : 'No User Data',
    10 	: 'Cookie Received While Shutting Down',
    11 	: 'Restart of an Association with New Addresses',
    12 	: 'User Initiated Abort',
    13 	: 'Protocol Violation',
    160 : 'Request to Delete Last Remaining IP Address',
    161 : 'Operation Refused Due to Resource Shortage',
    162 : 'Request to Delete Source IP Address',
    163 : 'Association Aborted due to illegal ASCONF-ACK',
    164 : 'Request refused - no authorization',
    261 : 'Unsupported HMAC Identifier'
    }


#------------------------------------------------------------------------------#
# generic SCTP cause
#------------------------------------------------------------------------------#

# generic SCTP cause class
class SCTPCause(Envelope):
    _GEN = (
        Uint16('Code', val=CAUSE_PROTO_VIOLATION, dic=CauseCode_dict),
        Uint16('Len'),
        Buf('Info', rep=REPR_HEX),
        Buf('pad', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 4 + self[2].get_len())
        self[2].set_blauto(lambda: (self[1].get_val()-4)<<3)
        self[3].set_blauto(lambda: self._pad_len())
        self[3].set_valauto(lambda: (self._pad_len()>>3) * b'\0')
    
    def _pad_len(self):
        off = self[2].get_bl() % 32
        if off:
            return 32 - off
        else:
            return 0


# specific SCTP cause class builder
def make_cause(name, code, Info):
    
    if Info is None:
        # no specific parameter
        class SCTPCauseSpec(SCTPCause):
            _type = 1
            _name = name
            _GEN  = (
                Uint16('Code', val=code, dic=CauseCode_dict),
                Uint16('Len', val=4)
                )
            #
            def __init__(self, *args, **kwargs):
                Envelope.__init__(self, *args, **kwargs)
    #
    elif hasattr(Info, '_bl') and Info._bl is not None and Info._bl > 0:
        # basic fixed size parameter
        off = Info._bl % 32
        if off:
            class SCTPCauseSpec(SCTPCause):
                _type = 2
                _name = name
                _GEN  = (
                    Uint16('Code', val=code, dic=CauseCode_dict),
                    Uint16('Len', val=Info._bl>>3),
                    Info,
                    Buf('pad', val=((32-off)>>3)*b'\0', bl=32-off, rep=REPR_HEX)
                    )
                #
                def __init__(self, *args, **kwargs):
                    Envelope.__init__(self, *args, **kwargs)
        #
        else:
            class SCTPCauseSpec(SCTPCause):
                _type = 3
                _name = name
                _GEN  = (
                    Uint16('Type', val=code, dic=CauseCode_dict),
                    Uint16('Len', val=Info._bl>>3),
                    Info
                    )
                #
                def __init__(self, *args, **kwargs):
                    Envelope.__init__(self, *args, **kwargs)
    #
    else:
        # constructed parameter structure
        if hasattr(Info, '_blauto'):
            class SCTPCauseSpec(SCTPCause):
                _type = 4
                _name = name
                _GEN  = (
                    Uint16('Code', val=code, dic=CauseCode_dict),
                    Uint16('Len'),
                    Info,
                    Buf('pad', rep=REPR_HEX)
                    )
        #    
        else:
            class SCTPCauseSpec(SCTPCause):
                _type = 5
                _name = name
                _GEN  = (
                    Uint16('Code', val=code, dic=CauseCode_dict),
                    Uint16('Len'),
                    Info,
                    Buf('pad', rep=REPR_HEX)
                    )
                #
                def __init__(self, *args, **kwargs):
                    Envelope.__init__(self, *args, **kwargs)
                    self[1].set_valauto(lambda: 4 + self[2].get_len())
                    self[3].set_blauto(lambda: self._pad_len())
                    self[3].set_valauto(lambda: (self._pad_len()>>3) * b'\0')
    #
    return SCTPCauseSpec


class SCTPCauseAny(SCTPCause):
    """Empty envelope that gets populated only at _from_char() and set_val() calls
    where the cause code is determined
    """
    
    _GEN     = tuple()
    _lut     = {}
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
    
    def _set_cause_struct(self, code):
        Cause = self._lut.get(code, SCTPCause)()
        self._name = Cause._name
        self.extend(Cause._content)
    
    def set_val(self, vals):
        if isinstance(vals, (tuple, list)) and len(vals) >= 1:
            self._set_cause_struct(vals[0])
        elif isinstance(vals, dict) and 'Code' in vals:
            self._set_cause_struct(vals['Code'])
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        code = char.to_uint(8)
        self._set_cause_struct(code)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# generic SCTP parameter
#------------------------------------------------------------------------------#

# generic SCTP parameter class
class SCTPPrm(Envelope):
    _GEN  = (
        Uint16('Type', val=PRM_HEARTBEAT_INFO, dic=PrmType_dict),
        Uint16('Len'),
        Buf('Val', rep=REPR_HEX),
        Buf('pad', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 4 + self[2].get_len())
        self[2].set_blauto(lambda: (self[1].get_val()-4)<<3)
        self[3].set_blauto(lambda: self._pad_len())
        self[3].set_valauto(lambda: (self._pad_len()>>3) * b'\0')
    
    def _pad_len(self):
        off = self[2].get_bl() % 32
        if off:
            return 32 - off
        else:
            return 0


# specific SCTP parameter class builder
def make_prm(name, prmtype, Val):
    
    if Val is None:
        # no specific parameter structure
        class SCTPPrmSpec(SCTPPrm):
            _type = 1
            _name = name
            _GEN  = (
                Uint16('Type', val=prmtype, dic=PrmType_dict),
                Uint16('Len', val=4)
                )
            #
            def __init__(self, *args, **kwargs):
                Envelope.__init__(self, *args, **kwargs)
    #
    elif hasattr(Val, '_bl') and Val._bl is not None and Val._bl > 0:
        # basic fixed size parameter structure
        off = Val._bl % 32
        if off:
            class SCTPPrmSpec(SCTPPrm):
                _type = 2
                _name = name
                _GEN  = (
                    Uint16('Type', val=prmtype, dic=PrmType_dict),
                    Uint16('Len', val=Val._bl>>3),
                    Val,
                    Buf('pad', val=((32-off)>>3)*b'\0', bl=32-off, rep=REPR_HEX)
                    )
                #
                def __init__(self, *args, **kwargs):
                    Envelope.__init__(self, *args, **kwargs)
        #
        else:
            class SCTPPrmSpec(SCTPPrm):
                _type = 3
                _name = name
                _GEN  = (
                    Uint16('Type', val=prmtype, dic=PrmType_dict),
                    Uint16('Len', val=Val._bl>>3),
                    Val
                    )
                #
                def __init__(self, *args, **kwargs):
                    Envelope.__init__(self, *args, **kwargs)
    #
    else:
        # constructed parameter structure
        if hasattr(Val, '_blauto'):
            class SCTPPrmSpec(SCTPPrm):
                _type = 4
                _name = name
                _GEN  = (
                    Uint16('Type', val=prmtype, dic=PrmType_dict),
                    Uint16('Len'),
                    Val,
                    Buf('pad', rep=REPR_HEX)
                    )
        #    
        else:
            class SCTPPrmSpec(SCTPPrm):
                _type = 5
                _name = name
                _GEN  = (
                    Uint16('Type', val=prmtype, dic=PrmType_dict),
                    Uint16('Len'),
                    Val,
                    Buf('pad', rep=REPR_HEX)
                    )
                #
                def __init__(self, *args, **kwargs):
                    Envelope.__init__(self, *args, **kwargs)
                    self[1].set_valauto(lambda: 4 + self[2].get_len())
                    self[3].set_blauto(lambda: self._pad_len())
                    self[3].set_valauto(lambda: (self._pad_len()>>3) * b'\0')
    #
    return SCTPPrmSpec


class SCTPPrmAny(SCTPPrm):
    """Empty envelope that gets populated only at _from_char() and set_val() calls
    where the parameter type is determined
    
    A *prmset* kwargs can be passed at init to reduce the type of parameters allowed
    """
    
    _GEN    = tuple()
    _lut    = {}
    
    ENFORCE_PRMSET_DECODE = True
    ENFORCE_PRMSET_ENCODE = True
    _prmset = None
    
    def __init__(self, *args, **kwargs):
        if 'prmset' in kwargs:
            self._prmset = kwargs['prmset']
            del kwargs['prmset']
        Envelope.__init__(self, *args, **kwargs)
    
    def _set_prm_struct(self, prmtype, dec):
        if self._prmset is not None \
        and ((dec and self.ENFORCE_PRMSET_DECODE) \
          or (not dec and self.ENFORCE_PRMSET_ENCODE)) \
        and prmtype not in self._prmset:
            raise(PycrateErr('invalid SCTP parameter type: %i not in %r'\
                  % (prmtype, self._prmset)) )
        Prm = self._lut.get(prmtype, SCTPPrm)()
        self._name = Prm._name
        self.extend(Prm._content)
    
    def set_val(self, vals):
        if isinstance(vals, (tuple, list)) and len(vals) >= 1:
            self._set_prm_struct(vals[0], False)
        elif isinstance(vals, dict) and 'Type' in vals:
            self._set_prm_struct(vals['Type'], False)
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        prmtype = char.to_uint(8)
        self._set_prm_struct(prmtype, True)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# generic SCTP chunk
#------------------------------------------------------------------------------#

# generic SCTP chunk class
class SCTPChk(Envelope):
    _GEN = (
        Uint8('Type', val=CHK_DATA, dic=ChkType_dict),
        Uint8('Flags', rep=REPR_BIN),
        Uint16('Len'),
        Buf('Val', rep=REPR_HEX, hier=1),
        Buf('pad', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: 4 + self[3].get_len())
        self[3].set_blauto(lambda: (self[2].get_val()-4)<<3)
        self[4].set_blauto(lambda: self._pad_len())
        self[4].set_valauto(lambda: (self._pad_len()>>3)*b'\0')
    
    def _pad_len(self):
        off = self[3].get_bl() % 32
        if off:
            return 32 - off
        else:
            return 0


# specific SCTP chunk class builder
def make_chk(name, chktype, Val, Flags=None):
    #
    if Flags is None:
        Flags = Uint8('Flags', rep=REPR_BIN)
    else:
        assert( Flags.get_bl() == 8 )
    #
    Val.set_hier(1)
    #
    if hasattr(Val, '_bl') and Val._bl is not None and Val._bl > 0:
        # basic fixed size chunk structure
        off = Val._bl % 32
        if off:
            class SCTPChkSpec(SCTPChk):
                _type = 2
                _name = name
                _GEN  = (
                    Uint8('Type', val=chktype, dic=ChkType_dict),
                    Flags,
                    Uint16('Len', val=Val._bl>>3),
                    Val,
                    Buf('pad', val=((32-off)>>3)*b'\0', rep=REPR_HEX)
                    )
            #
            def __init__(self, *args, **kwargs):
                Envelope.__init__(self, *args, **kwargs)
        #
        else:
            class SCTPChkSpec(SCTPChk):
                _type = 3
                _name = name
                _GEN  = (
                    Uint8('Type', val=chktype, dic=ChkType_dict),
                    Flags,
                    Uint16('Len', val=Val._bl>>3),
                    Val
                    )
                #
                def __init__(self, *args, **kwargs):
                    Envelope.__init__(self, *args, **kwargs)
    #
    else:
        # constructed chunk structure
        if hasattr(Val, '_blauto'):
            class SCTPChkSpec(SCTPChk):
                _type = 4
                _name = name
                _GEN  = (
                    Uint8('Type', val=chktype, dic=ChkType_dict),
                    Flags,
                    Uint16('Len'),
                    Val,
                    Buf('pad', rep=REPR_HEX)
                    )
        #
        else:
            class SCTPChkSpec(SCTPChk):
                _type = 5
                _name = name
                _GEN  = (
                    Uint8('Type', val=chktype, dic=ChkType_dict),
                    Flags,
                    Uint16('Len'),
                    Val,
                    Buf('pad', rep=REPR_HEX)
                    )
                
                def __init__(self, *args, **kwargs):
                    Envelope.__init__(self, *args, **kwargs)
                    self[2].set_valauto(lambda: 4 + self[3].get_len())
                    self[4].set_blauto(lambda: self._pad_len())
                    self[4].set_valauto(lambda: (self._pad_len()>>3)*b'\0')
    #
    return SCTPChkSpec


class SCTPChkAny(SCTPChk):
    """Empty envelope that gets populated only at _from_char() and set_val() calls
    where the chunk type is determined
    
    A *chkset* kwargs can be passed at init to reduce the type of chunks allowed
    """
    
    _GEN    = tuple()
    _lut    = {}
    
    ENFORCE_CHKSET_DECODE = True
    ENFORCE_CHKSET_ENCODE = True
    _chkset = None
    
    def __init__(self, *args, **kwargs):
        if 'chkset' in kwargs:
            self._chkset = kwargs['chkset']
            del kwargs['chkset']
        Envelope.__init__(self, *args, **kwargs)
    
    def _set_chk_struct(self, chktype, dec):
        if self._chkset is not None \
        and ((dec and self.ENFORCE_CHKSET_DECODE) \
          or (not dec and self.ENFORCE_CHKSET_ENCODE)) \
        and chktype not in self._chkset:
            raise(PycrateErr('invalid SCTP chunk type: %i not in %r'\
                  % (chktype, self._chkset)))
        Chk = self._lut.get(chktype, SCTPChk)()
        self._name = Chk._name
        self.extend(Chk._content)
    
    def set_val(self, vals):
        if isinstance(vals, (tuple, list)) and len(vals) >= 1:
            self._set_chk_struct(vals[0], False)
        elif isinstance(vals, dict) and 'Type' in vals:
            self._set_chk_struct(vals['Type'], False)
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        chktype = char.to_uint(8)
        #chkhdr  = char.to_bytes(32)
        #chklen  = unpack('>H', chkhdr[2:4])[0]
        #print('SCTP chk type %i, chk hdr 0x%s, chk len %i, buf len %i'\
        #      % (chktype, hexlify(chkhdr).decode('ascii'), chklen, char.len_byte()))
        self._set_chk_struct(chktype, True)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# specific SCTP causes
#------------------------------------------------------------------------------#

SCTPCauseInvalidSID         = make_cause(
    name='SCTPCauseInvalidSID',
    code=CAUSE_INVALID_SID,
    Info=Uint16('SID')
    )


class _MissingMandPrm(Envelope):
    _name = 'MissingMandPrm'
    _GEN  = (
        Uint32('NumMissingPrms'),
        Array('MissingPrms', GEN=Uint16('Type', dic=PrmType_dict))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


SCTPCauseMissingMandPrm     = make_cause(
    name='SCTPCauseMissingMandPrm',
    code=CAUSE_MISSING_MAND_PRM,
    Info=_MissingMandPrm()
    )


SCTPCauseStaleCookieErr     = make_cause(
    name='SCTPCauseStaleCookieErr',
    code=CAUSE_STALE_COOKIE_ERR,
    Info=Uint32('StalenessUsec')
    )


SCTPCauseOutOfResource      = make_cause(
    name='SCTPCauseOutOfResource',
    code=CAUSE_OUT_OF_RESOURCE,
    Info=None
    )


SCTPCauseUnresolvAddr       = make_cause(
    name='SCTPCauseUnresolvAddr',
    code=CAUSE_UNRESOLV_ADDR,
    Info=SCTPPrmAny(prmset={
        PRM_IPV4_ADDR,
        PRM_IPV6_ADDR,
        PRM_HOSTNAME_ADDR})
    )


SCTPCauseUnrecoChk          = make_cause(
    name='SCTPCauseUnrecoChk',
    code=CAUSE_UNRECO_CHK,
    Info=SCTPChkAny()
    )


SCTPCauseInvalidMandPrm     = make_cause(
    name='SCTPInvalidMandPrm',
    code=CAUSE_INVALID_MAND_PRM,
    Info=None
    )


SCTPCauseUnrecoPrm          = make_cause(
    name='SCTPCauseUnrecoPrm',
    code=CAUSE_UNRECO_PRM,
    Info=SCTPPrmAny()
    )


SCTPCauseNoUserData         = make_cause(
    name='SCTPCauseNoUserData',
    code=CAUSE_NO_USER_DATA,
    Info=Uint32('TSN')
    )


SCTPCauseCookieRecvShut     = make_cause(
    name='SCTPCauseCookieRecvShut',
    code=CAUSE_COOKIE_RECV_SHUT,
    Info=None
    )


SCTPCauseRestartAssocAddr   = make_cause(
    name='SCTPCauseRestartAssocAddr',
    code=CAUSE_RESTART_ASSOC_ADDR,
    Info=Sequence('Addrs', GEN=SCTPPrmAny(prmset={
        PRM_IPV4_ADDR,
        PRM_IPV6_ADDR,
        PRM_HOSTNAME_ADDR}))
    )


SCTPCauseUserInitAbort      = make_cause(
    name='SCTPCauseUserInitAbort',
    code=CAUSE_USER_INIT_ABORT,
    Info=Buf('Reason')
    )


SCTPCauseProtoViolation     = make_cause(
    name='SCTPCauseProtoViolation',
    code=CAUSE_PROTO_VIOLATION,
    Info=Buf('Info')
    )


SCTPCauseReqDelLastIP       = make_cause(
    name='SCTPCuaseReqDelLastIP',
    code=CAUSE_REQ_DEL_LAST_IP,
    Info=SCTPPrmAny(prmset={
        PRM_DEL_IP_ADDR})
    )


SCTPCauseRefResourceShort   = make_cause(
    name='SCTPCauseRefResourceShort',
    code=CAUSE_REF_RESOURCE_SHORT,
    Info=SCTPPrmAny(prmset={
        PRM_ADD_IP_ADDR})
    )


SCTPCauseReqDelSrcIP        = make_cause(
    name='SCTPCauseReqDelSrcIP',
    code=CAUSE_REQ_DEL_SRC_IP,
    Info=SCTPPrmAny(prmset={
        PRM_DEL_IP_ADDR})
    )


SCTPCauseIllegalASCONFAck   = make_cause(
    name='SCTPCauseIllegalASCONFAck',
    code=CAUSE_ILLEGAL_ASCONF_ACK,
    Info=None
    )


SCTPCauseRefNoAuth          = make_cause(
    name='SCTPCauseRefNoAuth',
    code=CAUSE_REF_NO_AUTH,
    Info=SCTPPrmAny()
    )


SCTPCauseUnsuppHMACAlg      = make_cause(
    name='SCTPCauseUnsuppHMACAlg',
    code=CAUSE_UNSUPP_HMAC_ALG,
    Info=Uint16('HMACAlg', val=1, dic=HMACAlg_dict)
    )


SCTPCauseAny._lut = {
    CAUSE_INVALID_SID           : SCTPCauseInvalidSID,
    CAUSE_MISSING_MAND_PRM      : SCTPCauseMissingMandPrm,
    CAUSE_STALE_COOKIE_ERR      : SCTPCauseStaleCookieErr,
    CAUSE_OUT_OF_RESOURCE       : SCTPCauseOutOfResource,
    CAUSE_UNRESOLV_ADDR         : SCTPCauseUnresolvAddr,
    CAUSE_UNRECO_CHK            : SCTPCauseUnrecoChk,
    CAUSE_INVALID_MAND_PRM      : SCTPCauseInvalidMandPrm,
    CAUSE_UNRECO_PRM            : SCTPCauseUnrecoPrm,
    CAUSE_NO_USER_DATA          : SCTPCauseNoUserData,
    CAUSE_COOKIE_RECV_SHUT      : SCTPCauseCookieRecvShut,
    CAUSE_RESTART_ASSOC_ADDR    : SCTPCauseRestartAssocAddr,
    CAUSE_USER_INIT_ABORT       : SCTPCauseUserInitAbort,
    CAUSE_PROTO_VIOLATION       : SCTPCauseProtoViolation,
    CAUSE_REQ_DEL_LAST_IP       : SCTPCauseReqDelLastIP,
    CAUSE_REF_RESOURCE_SHORT    : SCTPCauseRefResourceShort,
    CAUSE_REQ_DEL_SRC_IP        : SCTPCauseReqDelSrcIP,
    CAUSE_ILLEGAL_ASCONF_ACK    : SCTPCauseIllegalASCONFAck,
    CAUSE_REF_NO_AUTH           : SCTPCauseRefNoAuth,
    CAUSE_UNSUPP_HMAC_ALG       : SCTPCauseUnsuppHMACAlg
    }


#------------------------------------------------------------------------------#
# specific SCTP parameters
#------------------------------------------------------------------------------#

SCTPPrmHeartbeatInfo    = make_prm(
    name='SCTPPrmHeartbeatInfo',
    prmtype=PRM_HEARTBEAT_INFO,
    Val=Buf('Echo', rep=REPR_HEX)
    )


SCTPPrmIPv4Addr         = make_prm(
    name='SCTPPrmIPv4Addr',
    prmtype=PRM_IPV4_ADDR,
    Val=Buf('Addr', bl=32, rep=REPR_HEX)
    )


SCTPPrmIPv6Addr         = make_prm(
    name='SCTPPrmIPv6Addr',
    prmtype=PRM_IPV6_ADDR,
    Val=Buf('Addr', bl=128, rep=REPR_HEX)
    )


SCTPPrmStateCookie      = make_prm(
    name='SCTPPrmStateCookie',
    prmtype=PRM_STATE_COOKIE,
    Val=Buf('Cookie', val=b'', rep=REPR_HEX)
    )


SCTPPrmUnrecoPrm        = make_prm(
    name='SCTPPrmUnrecoPrm',
    prmtype=PRM_UNRECO_PRM,
    Val=SCTPPrm('UnrecoPrm')
    )


SCTPPrmCookiePreserv    = make_prm(
    name='SCTPPrmCookiePreserv',
    prmtype=PRM_COOKIE_PRESERV,
    Val=Uint32('CookieLifespanIncrMsec')
    )


SCTPPrmHostnameAddr     = make_prm(
    name='SCTPPrmHostnameAddr',
    prmtype=PRM_HOSTNAME_ADDR,
    Val=NullTermStr('Hostname')
    )


SCTPPrmSuppAddrTypes    = make_prm(
    name='SCTPPrmSuppAddrTypes',
    prmtype=PRM_SUPP_ADDR_TYPES,
    Val=Array('Types', GEN=Uint16('Type', dic=PrmType_dict))
    )


class _OutSSNResetReq(Envelope):
    _name = 'OutSSNResetReq'
    _GEN  = (
        Uint32('ReconfigReqSN'),
        Uint32('ReconfigRespSN'),
        Uint32('SenderLastTSN'),
        Array('StreamNums', GEN=Uint16('StreamNum'))
        )


SCTPPrmOutSSNResetReq   = make_prm(
    name='SCTPPrmOutSSNResetReq',
    prmtype=PRM_OUT_SSN_RESET_REQ,
    Val=_OutSSNResetReq()
    )


class _InSSNResetReq(Envelope):
    _name = 'InSSNResetReq'
    _GEN  = (
        Uint32('ReconfigReqSN'),
        Array('StreamNums', GEN=Uint16('StreamNum'))
        )


SCTPPrmInSSNResetReq    = make_prm(
    name='SCTPPrmInSSNResetReq',
    prmtype=PRM_IN_SSN_RESET_REQ,
    Val=_InSSNResetReq()
    )


SCTPPrmSSNTSNResetReq   = make_prm(
    name='SCTPPrmSSNTSNResetReq',
    prmtype=PRM_SSN_TSN_RESET_REQ,
    Val=Uint32('ReconfigReqSN')
    )


_ReconfigRespRes_dict = {
    0 : 'Success - Nothing to do',
    1 : 'Success - Performed',
    2 : 'Denied',
    3 : 'Error - Wrong SSN',
    4 : 'Error - Request already in progress',
    5 : 'Error - Bad Sequence Number',
    6 : 'In progress'
    }

class _ReconfigResp(Envelope):
    _name = 'ReconfigResp'
    _GEN  = (
        Uint32('ReconfigRespSN'),
        Uint32('Res', dic=_ReconfigRespRes_dict),
        Uint32('SenderNextTSN'),
        Uint32('ReceiverNextTSN')
        )


SCTPPrmReconfigResp     = make_prm(
    name='SCTPPrmReconfigResp',
    prmtype=PRM_RECONFIG_RESP,
    Val=_ReconfigResp()
    )


class _AddOutStreamsReq(Envelope):
    _name = 'AddOutStreamsReq'
    _GEN  = (
        Uint32('ReconfigReqSN'),
        Uint16('NewStreamsNum'),
        Uint16('res')
        )


SCTPPrmAddOutStreamsReq = make_prm(
    name='SCTPPrmAddOutStreamsReq',
    prmtype=PRM_ADD_OUT_STREAMS_REQ,
    Val=_AddOutStreamsReq()
    )


class _AddInStreamsReq(Envelope):
    _name = 'AddInStreamsReq'
    _GEN  = (
        Uint32('ReconfigReqSN'),
        Uint16('NewStreamsNum'),
        Uint16('res')
        )


SCTPPrmAddInStreamsReq  = make_prm(
    name='SCTPPrmAddInStreamsReq',
    prmtype=PRM_ADD_IN_STREAMS_REQ,
    Val=_AddInStreamsReq()
    )


SCTPPrmReservECNCap     = make_prm(
    name='SCTPPrmReservECNCap',
    prmtype=PRM_RESERV_ECN_CAP,
    Val=None
    )


SCTPPrmRandom           = make_prm(
    name='SCTPPrmRandom',
    prmtype=PRM_RANDOM,
    Val=Buf('Rand', rep=REPR_HEX)
    )


SCTPPrmChkList          = make_prm(
    name='SCTPPrmChkList',
    prmtype=PRM_CHK_LIST,
    Val=Array('ChkTypes', GEN=Uint8('Type', dic=ChkType_dict))
    )


SCTPPrmReqHMACAlg       = make_prm(
    name='SCTPPrmReqHMACAlg',
    prmtype=PRM_REQ_HMAC_ALG,
    Val=Array('HMACAlgs', GEN=Uint16('HMACAlg', val=1, dic=HMACAlg_dict))
    )


SCTPPrmPad              = make_prm(
    name='SCTPPrmPad',
    prmtype=PRM_PAD,
    Val=Buf('pad', val=b'', rep=REPR_HEX)
    )


SCTPPrmSuppExt          = make_prm(
    name='SCTPPrmSuppExt',
    prmtype=PRM_SUPP_EXT,
    Val=Array('ChkTypes', GEN=Uint8('Type', dic=ChkType_dict))
    )


SCTPPrmFwdTSNSupp       = make_prm(
    name='SCTPPrmFwdTSNSupp',
    prmtype=PRM_FWD_TSN_SUPP,
    Val=None
    )


class _ASCONFIpAddr(Envelope):
    _name = 'ASCONFIpAddr'
    _GEN  = (
        Uint32('CID'),
        SCTPPrmAny(prmset={
            PRM_IPV4_ADDR,
            PRM_IPV6_ADDR})
        )


SCTPPrmAddIPAddr        = make_prm(
    name='SCTPPrmAddIPAddr',
    prmtype=PRM_ADD_IP_ADDR,
    Val=_ASCONFIpAddr()
    )


SCTPPrmDelIPAddr        = make_prm(
    name='SCTPPrmDelIPAddr',
    prmtype=PRM_DEL_IP_ADDR,
    Val=_ASCONFIpAddr()
    )


class _ErrCauseInd(Envelope):
    _name = 'ErrCauseInd'
    _GEN  = (
        Uint32('CID'),
        Sequence('Causes', GEN=SCTPCauseAny())
        )


SCTPPrmErrCauseInd      = make_prm(
    name='SCTPPrmErrCauseInd',
    prmtype=PRM_ERR_CAUSE_IND,
    Val=_ErrCauseInd()
    )


SCTPPrmSetPrimAddr      = make_prm(
    name='SCTPPrmSetPrimAddr',
    prmtype=PRM_SET_PRIM_ADDR,
    Val=_ASCONFIpAddr()
    )


SCTPPrmSuccInd          = make_prm(
    name='SCTPPrmSuccInd',
    prmtype=PRM_SUCC_IND,
    Val=Uint32('CID')
    )


SCTPPrmAdaptLayerInd    = make_prm(
    name='SCTPPrmAdaptLayerInd',
    prmtype=PRM_ADAPT_LAYER_IND,
    Val=Uint32('AdaptCodePt')
    )


# configure the look-up table of SCTPPrmAny with all specific SCTPPrm classes
SCTPPrmAny._lut = {
    PRM_HEARTBEAT_INFO      : SCTPPrmHeartbeatInfo,
    PRM_IPV4_ADDR           : SCTPPrmIPv4Addr,
    PRM_IPV6_ADDR           : SCTPPrmIPv6Addr,
    PRM_STATE_COOKIE        : SCTPPrmStateCookie,
    PRM_UNRECO_PRM          : SCTPPrmUnrecoPrm,
    PRM_COOKIE_PRESERV      : SCTPPrmCookiePreserv,
    PRM_HOSTNAME_ADDR       : SCTPPrmHostnameAddr,
    PRM_SUPP_ADDR_TYPES     : SCTPPrmSuppAddrTypes,
    PRM_OUT_SSN_RESET_REQ   : SCTPPrmOutSSNResetReq,
    PRM_IN_SSN_RESET_REQ    : SCTPPrmInSSNResetReq,
    PRM_SSN_TSN_RESET_REQ   : SCTPPrmSSNTSNResetReq,
    PRM_RECONFIG_RESP       : SCTPPrmReconfigResp,
    PRM_ADD_OUT_STREAMS_REQ : SCTPPrmAddOutStreamsReq,
    PRM_ADD_IN_STREAMS_REQ  : SCTPPrmAddInStreamsReq,
    PRM_RESERV_ECN_CAP      : SCTPPrmReservECNCap,
    PRM_RANDOM              : SCTPPrmRandom,
    PRM_CHK_LIST            : SCTPPrmChkList,
    PRM_REQ_HMAC_ALG        : SCTPPrmReqHMACAlg,
    PRM_PAD                 : SCTPPrmPad,
    PRM_SUPP_EXT            : SCTPPrmSuppExt,
    PRM_FWD_TSN_SUPP        : SCTPPrmFwdTSNSupp,
    PRM_ADD_IP_ADDR         : SCTPPrmAddIPAddr,
    PRM_DEL_IP_ADDR         : SCTPPrmDelIPAddr,
    PRM_ERR_CAUSE_IND       : SCTPPrmErrCauseInd,
    PRM_SET_PRIM_ADDR       : SCTPPrmSetPrimAddr,
    PRM_SUCC_IND            : SCTPPrmSuccInd,
    PRM_ADAPT_LAYER_IND     : SCTPPrmAdaptLayerInd
    }


#------------------------------------------------------------------------------#
# specific SCTP chunks
#------------------------------------------------------------------------------#

class _Data(Envelope):
    _GEN  = (
        Uint32('TSN'),
        Uint16('SID'),
        Uint16('SSN'),
        Uint32('PPID'),
        Buf('Data', rep=REPR_HEX)
        )


class _DataFlags(Envelope):
    _GEN  = (
        Uint('unassigned', bl=4, rep=REPR_HEX),
        Uint('I', bl=1),
        Uint('U', bl=1),
        Uint('B', bl=1),
        Uint('E', bl=1)
        )


SCTPChkData             = make_chk(
    name='SCTPChkData',
    chktype=CHK_DATA,
    Val=_Data('Val'),
    Flags=_DataFlags('Flags')
    )


class _Init(Envelope):
    _GEN = (
        Uint32('Tag', rep=REPR_HEX),
        Uint32('a_rwnd', val=65536),
        Uint16('OS'),
        Uint16('MIS'),
        Uint32('I_TSN'),
        Sequence('Prms', GEN=SCTPPrmAny(prmset={
            PRM_IPV4_ADDR,
            PRM_IPV6_ADDR,
            PRM_COOKIE_PRESERV,
            PRM_RESERV_ECN_CAP,
            PRM_HOSTNAME_ADDR,
            PRM_SET_PRIM_ADDR,
            PRM_ADAPT_LAYER_IND,
            PRM_SUPP_EXT}))
        )


SCTPChkInit             = make_chk(
    name='SCTPChkInit',
    chktype=CHK_INIT,
    Val=_Init('Val')
    )


class _InitAck(Envelope):
    _GEN = (
        Uint32('Tag', rep=REPR_HEX),
        Uint32('a_rwnd', val=65536),
        Uint16('OS'),
        Uint16('MIS'),
        Uint32('I_TSN'),
        Sequence('Prms', GEN=SCTPPrmAny(prmset={
            PRM_STATE_COOKIE,
            PRM_IPV4_ADDR,
            PRM_IPV6_ADDR,
            PRM_UNRECO_PRM,
            PRM_RESERV_ECN_CAP,
            PRM_HOSTNAME_ADDR,
            PRM_SET_PRIM_ADDR,
            PRM_ADAPT_LAYER_IND,
            PRM_SUPP_EXT}))
        )


SCTPChkInitAck          = make_chk(
    name='SCTPChkInitAck',
    chktype=CHK_INIT_ACK,
    Val=_InitAck('Val')
    )


class _SAck(Envelope):
    _GEN = (
        Uint32('CumTSNAck'),
        Uint32('Arwnd', val=65536),
        Uint16('NumGapAckBlocks'),
        Uint16('NumDupTSNs'),
        Array('GapAckBlocks', GEN=Envelope('GapAckBlock', GEN=(Uint16('Start'), Uint16('End')))),
        Array('DupTSNs', GEN=Uint32('DupTSN'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[4].get_num())
        self[3].set_valauto(lambda: self[5].get_num())
        self[4].set_numauto(lambda: self[2].get_val())
        self[5].set_numauto(lambda: self[3].get_val())


SCTPChkSAck             = make_chk(
    name='SCTPChkSAck',
    chktype=CHK_SACK,
    Val=_SAck('Val')
    )


class _Heartbeat(Envelope):
    _GEN = (
        SCTPPrmHeartbeatInfo(),
        )


SCTPChkHeartbeat        = make_chk(
    name='SCTPChkHeartbeat',
    chktype=CHK_HEARTBEAT,
    Val=_Heartbeat('Val')
    )


SCTPChkHeartbeatAck     = make_chk(
    name='SCTPChkHeartbeatAck',
    chktype=CHK_HEARTBEAT_ACK,
    Val=_Heartbeat('Val')
    )


class _AbortFlags(Envelope):
    _GEN = (
        Uint('unassigned', bl=7, rep=REPR_HEX),
        Uint('T', bl=1)
        )


SCTPChkAbort            = make_chk(
    name='SCTPChkAbort',
    chktype=CHK_ABORT,
    Val=Sequence('Val', GEN=SCTPCauseAny()),
    Flags=_AbortFlags('Flags')
    )


SCTPChkShutdown         = make_chk(
    name='SCTPChkShutdown',
    chktype=CHK_SHUTDOWN,
    Val=Envelope('Val', GEN=(Uint32('CumTSNAck'), ))
    )


SCTPChkShutdownAck      = make_chk(
    name='SCTPShkShutdownAck',
    chktype=CHK_SHUTDOWN_ACK,
    Val=Envelope('Val', GEN=tuple())
    )


SCTPChkError            = make_chk(
    name='SCTPChkError',
    chktype=CHK_ERROR,
    Val=Sequence('Val', GEN=SCTPCauseAny())
    )


SCTPChkCookieEcho       = make_chk(
    name='SCTPChkCookieEcho',
    chktype=CHK_COOKIE_ECHO,
    Val=Envelope('Val', GEN=(Buf('Cookie', val=b'abcd', rep=REPR_HEX), ))
    )


SCTPChkCookieAck        = make_chk(
    name='SCTPChkCookieAck',
    chktype=CHK_COOKIE_ACK,
    Val=Envelope('Val', GEN=tuple())
    )


SCTPChkECNE             = make_chk(
    name='SCTPChkECNE',
    chktype=CHK_ECNE,
    Val=Envelope('Val', GEN=(Uint32('LowTSNNum'), ))
    )


SCTPChkCWR              = make_chk(
    name='SCTPChkCWR',
    chktype=CHK_CWR,
    Val=Envelope('Val', GEN=(Uint32('LowTSNNum'), ))
    )


SCTPChkShutdownComplete = make_chk(
    name='SCTPChkShutdownComplete',
    chktype=CHK_SHUTDOWN_COMPLETE,
    Val=Envelope('Val', GEN=tuple()),
    Flags=_AbortFlags('Flags')
    )


class _Auth(Envelope):
    _GEN = (
        Uint16('SharedKeyId'),
        Uint16('HMACAlg', val=1, dic=HMACAlg_dict),
        Buf('HMAC', rep=REPR_HEX)
        )


SCTPChkAuth             = make_chk(
    name='SCTPChkAuth',
    chktype=CHK_AUTH,
    Val=_Auth('Val')
    )


class _IData(Envelope):
    _GEN = (
        Uint32('TSN'),
        Uint16('SID'),
        Uint16('res'),
        Uint32('MID'),
        Uint32('PPID_FSN'),
        Buf('Data', rep=REPR_HEX)
        )


SCTPChkIData            = make_chk(
    name='SCTPChkIData',
    chktype=CHK_I_DATA,
    Val=_IData('Val'),
    Flags=_DataFlags('Flags')
    )


class _ASCONF(Envelope):
    _GEN = (
        Uint32('SN'),
        Sequence('Prms', GEN=SCTPPrmAny(prmset={
            PRM_IPV4_ADDR,
            PRM_IPV6_ADDR,
            PRM_ADD_IP_ADDR,
            PRM_DEL_IP_ADDR,
            PRM_SET_PRIM_ADDR}))
        )


SCTPChkASCONF           = make_chk(
    name='SCTPChkASCONF',
    chktype=CHK_ASCONF,
    Val=_ASCONF('Val')
    )


class _ASCONFAck(Envelope):
    _GEN = (
        Uint32('SN'),
        Sequence('Prms', GEN=SCTPPrm(prmset={
            PRM_ERR_CAUSE_IND,
            PRM_SUCC_IND}))
        )


SCTPChkASCONFAck        = make_chk(
    name='SCTPChkASCONFAck',
    chktype=CHK_ASCONF_ACK,
    Val=_ASCONFAck('Val')
    )


SCTPChkReConfig         = make_chk(
    name='SCTPChkReConfig',
    chktype=CHK_RE_CONFIG,
    Val=Sequence('Val', GEN=SCTPPrmAny(prmset={
        PRM_OUT_SSN_RESET_REQ,
        PRM_IN_SSN_RESET_REQ,
        PRM_SSN_TSN_RESET_REQ,
        PRM_ADD_OUT_STREAMS_REQ,
        PRM_ADD_IN_STREAMS_REQ,
        PRM_RECONFIG_RESP})) # 1 or 2 parameters, not less, not more
    )


SCTPChkPad              = make_chk(
    name='SCTPChkPad',
    chktype=CHK_PAD,
    Val=Buf('Val', val=b'', rep=REPR_HEX)
    )


class _ForwardTSN(Envelope):
    _GEN = (
        Uint32('NewCumTSN'),
        Array('Streams', GEN=Envelope('Stream', GEN=(
            Uint16('SID'),
            Uint16('SSN'))))
        )


SCTPChkForwardTSN       = make_chk(
    name='SCTPChkForwardTSN',
    chktype=CHK_FORWARD_TSN,
    Val=_ForwardTSN('Val')
    )


class _IForwardTSN(Envelope):
    _GEN = (
        Uint32('NewCumTSN'),
        Array('Streams', GEN=Envelope('Stream', GEN=(
            Uint16('SID'),
            Uint('res', bl=15, rep=REPR_HEX),
            Uint('U', bl=1),
            Uint32('MID'))))
        )


SCTPChkIForwardTSN      = make_chk(
    name='SCTPChkIForwardTSN',
    chktype=CHK_I_FORWARD_TSN,
    Val=_IForwardTSN('Val')
    )


SCTPChkAny._lut = {
    CHK_DATA            : SCTPChkData,
    CHK_INIT            : SCTPChkInit,
    CHK_INIT_ACK        : SCTPChkInitAck,
    CHK_SACK            : SCTPChkSAck,
    CHK_HEARTBEAT       : SCTPChkHeartbeat,
    CHK_HEARTBEAT_ACK   : SCTPChkHeartbeatAck,
    CHK_ABORT           : SCTPChkAbort,
    CHK_SHUTDOWN        : SCTPChkShutdown,
    CHK_SHUTDOWN_ACK    : SCTPChkShutdownAck,
    CHK_ERROR           : SCTPChkError,
    CHK_COOKIE_ECHO     : SCTPChkCookieEcho,
    CHK_COOKIE_ACK      : SCTPChkCookieAck,
    CHK_ECNE            : SCTPChkECNE,
    CHK_CWR             : SCTPChkCWR,
    CHK_SHUTDOWN_COMPLETE : SCTPChkShutdownComplete,
    CHK_AUTH            : SCTPChkAuth,
    CHK_I_DATA          : SCTPChkIData,
    CHK_ASCONF_ACK      : SCTPChkASCONFAck,
    CHK_RE_CONFIG       : SCTPChkReConfig,
    CHK_PAD             : SCTPChkPad,
    CHK_FORWARD_TSN     : SCTPChkForwardTSN,
    CHK_ASCONF          : SCTPChkASCONF,
    CHK_I_FORWARD_TSN   : SCTPChkIForwardTSN,
    }


#------------------------------------------------------------------------------#
# SCTP packet
#------------------------------------------------------------------------------#

class SCTPHdr(Envelope):
    _CS_OFF = False # for checksum offload
    _GEN = (
        Uint16('Src'),
        Uint16('Dst'),
        Uint32('Tag', rep=REPR_HEX),
        Buf('CS', bl=32, rep=REPR_HEX) # val automated
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[3].set_valauto(lambda: self.checksum())
    
    def checksum(self):
        if self._CS_OFF:
            return b'\0\0\0\0'
        else:
            buf = pack('>HHI', self[0](), self[1](), self[2]()) + b'\0\0\0\0'
            pay = self.get_next()
            if pay is not None:
                buf += pay.to_bytes()
            return crc32c_cs(buf)


class SCTP(Envelope):
    _GEN = (
        SCTPHdr(),
        Sequence('SCTPPay', GEN=SCTPChkAny(), hier=1)
        )

