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
# * File Name : pycrate_mobile/PPP.py
# * Created : 2017-11-08
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

#------------------------------------------------------------------------------#
# IETF RFC 1661: The Point-to-Point Protocol (PPP)
# section 5: LCP packet format
#------------------------------------------------------------------------------#

# for LCP Code Configure-*         
_LCPOptType_dict = {
    1 : 'Maximum-Receive-Unit',
    2 : 'Async-Control-Character-Map',
    3 : 'Authentication-Protocol',
    4 : 'Quality-Protocol',
    5 : 'Magic-Number',
    6 : 'RESERVED',
    7 : 'Protocol-Field-Compression',
    8 : 'Address-and-Control-Field-Compression'
    }

class LCPOpt(Envelope):
    _GEN = (
        Uint8('Type', dic=_LCPOptType_dict),
        Uint8('Len'),
        Buf('Data', rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 2+self[2].get_len())
        self[2].set_blauto(lambda: max(0, 8*(self[1].get_val()-2)))

class LCPDataConf(Sequence):
    _GEN = LCPOpt()


# for LCP Code Terminate-* and Code-Reject
class LCPDataRaw(Buf):
    _rep = REPR_HEX


# for LCP Code Protocol-Reject
class LCPDataProtRej(Envelope):
    _GEN = (
        Uint16('RejectedProtocol'),
        Buf('RejectedInfo', rep=REPR_HEX)
        )


# for LCP Code Echo-* and Discard-Request
class LCPDataEcho(Envelope):
    _GEN = (
        Uint32('Magic', rep=REPR_HEX),
        Buf('Data', rep=REPR_HEX)
        )


# global LCP format
_LCPCode_dict = {
    1 : 'Configure-Request',
    2 : 'Configure-Ack',
    3 : 'Configure-Nak',
    4 : 'Configure-Reject',
    5 : 'Terminate-Request',
    6 : 'Terminate-Ack',
    7 : 'Code-Reject',
    8 : 'Protocol-Reject',
    9 : 'Echo-Request',
    10 : 'Echo-Reply',
    11 : 'Discard-Request'
    }

class LCP(Envelope):
    ENV_SEL_TRANS = False
    
    _CConf    = (1, 2, 3, 4)
    _CEcho    = (9, 10, 11)
    
    _GEN = (
        Uint8('Code', val=1, dic=_LCPCode_dict),
        Uint8('Id'),
        Uint16('Len'),
        Buf('Data')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len()+4)
        self[3].set_blauto(lambda: max(0, 8*(self[2].get_val()-4)))
    
    def _set_data(self, code):
        data = None
        if code in self._CConf:
            data = LCPDataConf('Data')
        elif code in self._CEcho:
            data = LCPDataEcho('Data')
            data[1].set_blauto(lambda: max(0, 8*(self[2].get_val()-8)))
        elif code == 8:
            data = LCPDataProtRej('Data')
            data[1].set_blauto(lambda: max(0, 8*(self[2].get_val()-6)))
        if data is not None:
            self.replace(self[3], data)
    
    def set_val(self, vals):
        code = None
        if isinstance(vals, (tuple, list)) and not isinstance(vals[-1], bytes_types):
            code = vals[0]
        elif isinstance(vals, dict) and 'Data' in vals and not isinstance(vals['Data'], bytes_types):
            try:
                code = vals['Code']
            except:
                code = 1
        if code is not None:
            self._set_data(code)
        Envelope.set_val(self, vals)
        
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        self[2]._from_char(char)
        code, data = self[0].get_val(), None
        self._set_data(code)
        self[3]._from_char(char)


#------------------------------------------------------------------------------#
# IETF RFC 1332: The PPP Internet Protocol Control Protocol (IPCP)
# NCP packet format (variant of LCP)
#------------------------------------------------------------------------------#
# + RFC1877 (DNS@, NBNS@), RFC3241 (ROHC)

# for NCP Code Configure-*         
_NCPOptType_dict = {
    1   : 'IP-Addresses',
    2   : 'IP-Compression-Protocol',
    3   : 'IP-Address',
    4   : 'Mobile-IPv4',
    129 : 'Primary DNS Server Address',
    130 : 'Primary NBNS Server Address',
    131 : 'Secondary DNS Server Address',
    132 : 'Secondary NBNS Server Address'
    }

class NCPOpt(Envelope):
    _GEN = (
        Uint8('Type', dic=_NCPOptType_dict),
        Uint8('Len'),
        Buf('Data', rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 2+self[2].get_len())
        self[2].set_blauto(lambda: max(0, 8*(self[1].get_val()-2)))

class NCPDataConf(Sequence):
    _GEN = NCPOpt()


# global NCP format
_NCPCode_dict = {
    1 : 'Configure-Request',
    2 : 'Configure-Ack',
    3 : 'Configure-Nak',
    4 : 'Configure-Reject',
    5 : 'Terminate-Request',
    6 : 'Terminate-Ack',
    7 : 'Code-Reject'
    }

class NCP(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint8('Code', val=1, dic=_NCPCode_dict),
        Uint8('Id'),
        Uint16('Len'),
        Buf('Data')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len()+4)
        self[3].set_blauto(lambda: max(0, 8*(self[2].get_val()-4)))
    
    def set_val(self, vals):
        code = None
        if isinstance(vals, (tuple, list)):
            data = vals[-1]
            if not isinstance(data, bytes_types):
                code = vals[0]
        elif isinstance(vals, dict) and 'Data' in vals:
            data = vals['Data']
            if not isinstance(data, bytes_types):
                try:
                    code = vals['Code']
                except:
                    code = 1
        if code is not None and 1 <= code <= 4:
            Data = NCPDataConf('Data')
            Data.set_num(len(data))
            self.replace(self[3], Data)
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        self[2]._from_char(char)
        code = self[0].get_val()
        if 1 <= code <= 4:
            Data = NCPDataConf('Data')
            self.replace(self[3], Data)
        self[3]._from_char(char)


#------------------------------------------------------------------------------#
# IETF RFC 1334: PPP Authentication Protocols (PAP and CHAP)
#------------------------------------------------------------------------------#

# PAP Authenticate-Request
class PAPAuthReq(Envelope):
    _GEN = (
        Uint8('PeerIDLen'),
        Buf('PeerID'),
        Uint8('PasswdLen'),
        Buf('Passwd')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: 8*self[2].get_val())


# PAP Authenticate-Ack and Authentication-Nak
class _PAPAuthMsg(Envelope):
    _GEN = (
        Uint8('MsgLen'),
        Buf('Msg')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())

class PAPAuthAck(_PAPAuthMsg):
    pass

class PAPAuthNak(_PAPAuthMsg):
    pass


# global PAP format
_PAPCode_dict = {
    1 : 'Authenticate-Request',
    2 : 'Authenticate-Ack',
    3 : 'Authenticate-Nak',
    }

class PAP(Envelope):
    _GEN = (
        Uint8('Code', val=1, dic=_PAPCode_dict),
        Uint8('Id'),
        Uint16('Len'),
        Buf('Data')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len()+4)
        self[3].set_blauto(lambda: max(0, 8*(self[2].get_val()-4)))
    
    def set_val(self, vals):
        code = None
        if isinstance(vals, (tuple, list)):
            data = vals[-1]
            if not isinstance(data, bytes_types):
                code = vals[0]
        elif isinstance(vals, dict) and 'Data' in vals:
            data = vals['Data']
            if not isinstance(data, bytes_types):
                try:
                    code = vals['Code']
                except:
                    code = 1
        if code == 1:
            self.replace(self[3], PAPAuthReq('Data'))
        elif code == 2:
            self.replace(self[3], PAPAuthAck('Data'))
        elif code == 3:
            self.replace(self[3], PAPAuthNak('Data'))
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        self[2]._from_char(char)
        code = self[0].get_val()
        if code == 1:
            self.replace(self[3], PAPAuthReq('Data'))
        elif code == 2:
            self.replace(self[3], PAPAuthAck('Data'))
        elif code == 3:
            self.replace(self[3], PAPAuthNak('Data'))
        self[3]._from_char(char)


# CHAP Challenge / Response
class _CHAPValue(Envelope):
    _GEN = (
        Uint8('ValueLen'),
        Buf('Value', rep=REPR_HEX),
        Buf('Name')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())
        # Name will be bounded thanks to the Len field in the CHAP header

class CHAPChallenge(_CHAPValue):
    pass

class CHAPResponse(_CHAPValue):
    pass


# global CHAP format
_CHAPCode_dict = {
    1 : 'Challenge',
    2 : 'Response',
    3 : 'Success',
    4 : 'Failure'
    }

class CHAP(Envelope):
    _GEN = (
        Uint8('Code', val=1, dic=_PAPCode_dict),
        Uint8('Id'),
        Uint16('Len'),
        Buf('Data')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len()+4)
        self[3].set_blauto(lambda: max(0, 8*(self[2].get_val()-4)))
    
    def set_val(self, vals):
        code = None
        if isinstance(vals, (tuple, list)):
            data = vals[-1]
            if not isinstance(data, bytes_types):
                code = vals[0]
        elif isinstance(vals, dict) and 'Data' in vals:
            data = vals['Data']
            if not isinstance(data, bytes_types):
                try:
                    code = vals['Code']
                except:
                    code = 1
        if code == 1:
            self.replace(self[3], CHAPChallenge('Data'))
        elif code == 2:
            self.replace(self[3], CHAPResponse('Data'))
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        code = self[0].get_val()
        if code == 1:
            data = CHAPChallenge('Data')
            data.from_bytes( self[3].get_val() )
            self.replace(self[3], data)
        elif code == 2:
            data = CHAPResponse('Data')
            data.from_bytes( self[3].get_val() )
            self.replace(self[3], data)
        
