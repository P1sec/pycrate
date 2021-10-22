# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
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
# * File Name : pycrate_mobile/TS38415_PDUSess.py
# * Created : 2021-10-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'PDUSessInfo'
    ]


#------------------------------------------------------------------------------#
# 3GPP TS 38.415: NG-RAN; PDU session user plane protocol
# Used within GTP-U extension header 64
# release 16 (g50)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *


#------------------------------------------------------------------------------#
# DL PDU SESSION INFORMATION (PDU Type 0)
# TS 38.415, section 5.5.2.1
#------------------------------------------------------------------------------#

PDUSessType_dict = {
    0 : 'DL',
    1 : 'UL',
    }


class DLPDUSessInfo(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('QMP', val=0, bl=1), # controls DLSndTS transparency
        Uint('SNP', val=0, bl=1), # controls DLQFISeqNum transparency
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('PPP', val=0, bl=1), # controls PPI transparency
        Uint('RQI', bl=1),
        Uint('QFI', bl=6),
        Uint('PPI', bl=3),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint64('DLSndTS'),
        Uint24('DLQFISeqNum'),
        Buf('Pad', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['PPI'].set_transauto(lambda: False if self['PPP'].get_val() else True)
        self[7].set_transauto(lambda: False if self['PPP'].get_val() else True)
        self['DLSndTS'].set_transauto(lambda: False if self['QMP'].get_val() else True)
        self['DLQFISeqNum'].set_transauto(lambda: False if self['SNP'].get_val() else True)
        self['Pad'].set_valauto(lambda: self._get_pad())
    
    def _get_pad(self):
        l = 2
        if self['PPP'].get_val():
            l += 1
        if self['QMP'].get_val():
            l += 8
        if self['SNP'].get_val():
            l += 3
        # need to account for 2 additional bytes within the GTP-U Extension Header
        return (-(2+l)%4) * b'\0'


class ULPDUSessInfo(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('QMP', val=0, bl=1),
        Uint('DLDelayInd', val=0, bl=1),
        Uint('ULDelayInd', val=0, bl=1),
        Uint('SNP', val=0, bl=1),
        Uint('N3N9DelayInd', val=0, bl=1),
        Uint('NewIEFlagInd', bl=1),
        Uint('QFI', bl=6),
        Uint64('DLSndTSRep'),
        Uint64('DLRcvTS'),
        Uint64('ULSndTS'),
        Uint32('DLDelayRes'),
        Uint32('ULDelayRes'),
        Uint24('ULQFISeqNum'),
        Uint32('N3N9DelayRes'),
        Uint8('NewIEFlags', rep=REPR_HEX),
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('D1ULPDCPDelayResInd', bl=1),
        Buf('Pad', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['DLSndTSRep'].set_transauto(lambda: False if self['QMP'].get_val() else True)
        self['DLRcvTS'].set_transauto(lambda: False if self['QMP'].get_val() else True)
        self['ULSndTS'].set_transauto(lambda: False if self['QMP'].get_val() else True)
        self['DLDelayRes'].set_transauto(lambda: False if self['DLDelayInd'].get_val() else True)
        self['ULDelayRes'].set_transauto(lambda: False if self['ULDelayInd'].get_val() else True)
        self['ULQFISeqNum'].set_transauto(lambda: False if self['SNP'].get_val() else True)
        self['N3N9DelayRes'].set_transauto(lambda: False if self['N3N9DelayInd'].get_val() else True)
        self['NewIEFlags'].set_transauto(lambda: False if self['NewIEFlagInd'].get_val() else True)
        self['spare'].set_transauto(lambda: self._get_d1ulpdcpdel_trans())
        self['D1ULPDCPDelayResInd'].set_transauto(lambda: self._get_d1ulpdcpdel_trans())
        self['Pad'].set_valauto(lambda: self._get_pad())
    
    def _get_d1ulpdcpdel_trans(self):
        if self['NewIEFlagInd'].get_val() == 0:
            return True
        elif self['NewIEFlags'].get_val() & 0x01:
            return False
        else:
            return True
    
    def _get_pad(self):
        l = 2
        if self['QMP'].get_val():
            l += 24
        if self['DLDelayInd'].get_val():
            l += 4
        if self['ULDelayInd'].get_val():
            l += 4
        if self['SNP'].get_val():
            l += 3
        if self['N3N9DelayInd'].get_val():
            l += 4
        if self['NewIEFlagInd'].get_val():
            if self['NewIEFlags'].get_val() & 0x01:
                l += 2
            else:
                l += 1
        # need to account for 2 additional bytes within the GTP-U Extension Header
        return (-(2+l)%4) * b'\0'


# TODO: investig diff with default / non-default Info struct repr
class PDUSessInfo(Envelope):
    _GEN = (
        Uint('Type', bl=4, dic=PDUSessType_dict),
        Alt('Info', GEN={
            0 : DLPDUSessInfo('DLInfo'),
            1 : ULPDUSessInfo('ULInfo'),
            },
            DEFAULT=Buf('spare', bl=12, rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val()
            )
        )

