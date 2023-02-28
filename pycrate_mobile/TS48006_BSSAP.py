# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
# *
# * Copyright 2023. Laurent Ghigonis. P1Sec.
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
# * File Name : pycrate_mobile/TS48006_BSSAP.py
# * Created : 2023-01-09
# * Authors : Laurent Ghigonis
# *--------------------------------------------------------
#*/

from enum import IntEnum
from struct import unpack

from pycrate_core.elt import Envelope, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base import *
from pycrate_core.repr import *


#------------------------------------------------------------------------------#
# BSS Application Part (BSSAP) as defined in 3GPP TS 48.006 and 3GPP TS 49.008
#------------------------------------------------------------------------------#
# Implementation notes:
# * Len has to be set manually in BSSAP_DirectTransfer and BSSAP_Management,
#   as the layer is an adaption between 2 layers, and does not *include* the upper layer (no setvalauto() in __init__())
# * procedures : TS49.008 https://www.etsi.org/deliver/etsi_ts/149000_149099/149008/09.00.00_60/ts_149008v090000p.pdf
# * protocol   : TS48.006 https://www.etsi.org/deliver/etsi_ts/148000_148099/148006/09.00.00_60/ts_148006v090000p.pdf
# * wireshark implementation : https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-bssap.c


#------------------------------------------------------------------------------#
# BSSAP header elements
#------------------------------------------------------------------------------#

class BSSAPType(IntEnum):
	BSS_MANAGEMENT  = 0x00
	DIRECT_TRANSFER = 0x01


class DistributionUnit(Envelope):
	_GEN = (
		Uint('RadioMessageGroup', bl=7),
		Uint('Discrimination', bl=1, dic={
		    BSSAPType.BSS_MANAGEMENT  : 'Not Transparent: BSSMAP',
		    BSSAPType.DIRECT_TRANSFER : 'Transparent: DTAP'}),
	)


# Service Access Point Identifier, defined in TS44.006
class BSSAP_SAPI(IntEnum):
    SIGNALING = 0
    SMS       = 3


BSSAP_SAPI_dict = {
    BSSAP_SAPI.SIGNALING: 'signaling information',
    BSSAP_SAPI.SMS:       'SMS',
    }


#------------------------------------------------------------------------------#
# BSSAP messages
#------------------------------------------------------------------------------#
# TS48.006, 9.3.2: Transfer of DTAP messages
# TS48.006, 9.3.3: Transfer of BSSMAP messages

class BSSAP(Envelope):
	_GEN = (
		DistributionUnit('DistributionUnit', val=(0, BSSAPType.DIRECT_TRANSFER)),
		Envelope('DLCI', GEN=(
			Uint('ControlChannelIdentification', bl=2, dic={
			    0: 'no further specified',
			    1: 'reserved',
			    2: 'FACCH or SDCCH',
			    3: 'SACCH'}),
			Uint('spare', bl=3),
			Uint('SAPI', bl=3, dic=BSSAP_SAPI_dict)
			)),
		Uint8('Len'),
		Buf('L3', rep=REPR_HEX)
	    )
	
	def __init__(self, *args, **kwargs):
	    Envelope.__init__(self, *args, **kwargs)
	    # DLCI only present for DIRECT_TRANSFER
	    self['DLCI'].set_transauto(lambda: not self['DistributionUnit'].get_val()[1])
	    self['Len'].set_valauto(lambda: self['L3'].get_len())
	    self['L3'].set_blauto(lambda: self['Len'].get_val()<<3)

