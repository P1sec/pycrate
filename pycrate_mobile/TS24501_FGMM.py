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
# * File Name : pycrate_mobile/TS24501_FGMM.py
# * Created : 2019-11-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.501: NAS protocol for 5G
# release 16 (g20)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007       import *
from .TS24008_IE    import (
    AUTN,
    )
from .TS24301_IE    import (
    NAS_KSI,
    )
from .TS24501_IE    import *
#from .TS24501_FGSM  import FGSMTypeClasses

try:
    from CryptoMobile import CM
except:
    _with_cm = False
    log('warning: CryptoMobile Python module not found, unable to handle 5G NAS security')
else:
    _with_cm = True
    if hasattr(CM, 'EEA2'):
        _EIA = {
            1 : CM.EIA1,
            2 : CM.EIA2,
            3 : CM.EIA3
            }
        _EEA = {
            1 : CM.EEA1,
            2 : CM.EEA2,
            3 : CM.EEA3
            }
    else:
        _EIA = {
            1 : CM.EIA1,
            3 : CM.EIA3
            }
        _EEA = {
            1 : CM.EEA1,
            3 : CM.EEA3
            }


#------------------------------------------------------------------------------#
# 5GS Mobility Management header
# TS 24.501, section 9
#------------------------------------------------------------------------------#

# section 9.7
_FGMM_dict = {
    # registration
    65 : "Registration request",
    66 : "Registration accept",
    67 : "Registration complete",
    68 : "Registration reject",
    69 : "Deregistration request MO",
    70 : "Deregistration accept MO",
    71 : "Deregistration request MT",
    72 : "Deregistration accept MT",
    # service request
    76 : "Service request",
    77 : "Service reject",
    78 : "Service accept",
    79 : "Control plane service request",
    # common procedures
    84 : "Configuration update command",
    85 : "Configuration update complete",
    86 : "Authentication request",
    87 : "Authentication response",
    88 : "Authentication reject",
    89 : "Authentiction failure",
    90 : "Authentication result",
    91 : "Identity request",
    92 : "Identity response",
    93 : "Security mode command",
    94 : "Security mode complete",
    95 : "Security Mode reject",
    # misc
    100: "5GMM status",
    101: "Notification",
    102: "Notification response",
    103: "UL NAS transport",
    104: "DL NAS transport"
    }


class FGMMHeader(Envelope):
    _GEN = (
        Uint8('EPD', val=126, dic=ProtDisc_dict),
        Uint('spare', bl=4),
        Uint('SecHdr', bl=4, dic=SecHdrType_dict),
        Uint8('Type', val=100, dic=_FGMM_dict)
        )


#------------------------------------------------------------------------------#
# Authentication request
# TS 24.501, section 8.2.1
#------------------------------------------------------------------------------#

class FGMMAuthenticationRequest(Layer3):
    _GEN = (
        FGMMHeader(val={'Type':86}),
        Uint('spare', bl=4),
        Type1V('NAS_KSI', IE=NAS_KSI()),
        Type4LV('ABBA', val={'V':b'\0\0'}),
        Type3TV('RAND', val={'T':0x21, 'V':16*b'\0'}, bl={'V':128}),
        Type4LV('AUTN', val={'V':16*b'\0'}, IE=AUTN()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0'})
        )


#------------------------------------------------------------------------------#
# Authentication response
# TS 24.501, section 8.2.2
#------------------------------------------------------------------------------#

class FGMMAuthenticationResponse(Layer3):
    _GEN = (
        FGMMHeader(val={'Type':87}),
        Type4TLV('RES', val={'T':0x2D, 'V':16*b'\0'}),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0'})
        )


#------------------------------------------------------------------------------#
# Authentication result
# TS 24.501, section 8.2.3
#------------------------------------------------------------------------------#

class FGMMAuthenticationResult(Layer3):
    _GEN = (
        FGMMHeader(val={'Type':90}),
        Uint('spare', bl=4),
        Type1V('NAS_KSI', IE=NAS_KSI()),
        Type6LVE('EAPMsg', val={'V':b'\0\0\0\0'}),
        Type4TLV('ABBA', val={'T':0x38, 'V':b'\0\0'})
        )


#------------------------------------------------------------------------------#
# Authentication failure
# TS 24.501, section 8.2.4
#------------------------------------------------------------------------------#

class FGMMAuthenticationFailure(Layer3):
    _GEN = (
        FGMMHeader(val={'Type':89}),
        Type3V('FGMMCause', val={'V':b'\x16'}, bl={'V':8}, IE=FGMMCause()),
        Type4TLV('AUTS', val={'T':0x30, 'V':14*b'\0'})
        )


#------------------------------------------------------------------------------#
# Authentication reject
# TS 24.501, section 8.2.5
#------------------------------------------------------------------------------#

class FGMMAuthenticationReject(Layer3):
    _GEN = (
        FGMMHeader(val={'Type':88}),
        Type6LVE('EAPMsg', val={'V':b'\0\0\0\0'}),
        )




