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
    Envelope, Sequence, Array,
    REPR_RAW, REPR_HEX, REPR_BIN, REPR_HD, REPR_HUM
    )
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_core.charpy import Charpy

from pycrate_mobile.TS24008_IE  import (
    BufBCD
    )

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
# UE status
# TS 24.501, 9.11.3.56
#------------------------------------------------------------------------------#

class UEStatus(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('N1ModeReg', bl=1),
        Uint('S1ModeReg', bl=1)
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


