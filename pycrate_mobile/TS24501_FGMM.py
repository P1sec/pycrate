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
    AUTN, MSCm2, SuppCodecList, ExtDRXParam,
    )
from .TS24301_IE    import (
    NAS_KSI, EPSBearerCtxtStat,
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
        Type3V('5GMMCause', val={'V':b'\x16'}, bl={'V':8}, IE=FGMMCause()),
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


#------------------------------------------------------------------------------#
# Registration request
# TS 24.501, section 8.2.6
#------------------------------------------------------------------------------#
# This is were things are getting serious...

class FGMMRegistrationRequest(Layer3):
    _GEN = (
        FGMMHeader(val={'Type':65}),
        Type1V('NAS_KSI', IE=NAS_KSI()),
        Type1V('5GSRegistrationType', IE=FGSRegType()),
        Type6LVE('5GSID', val={'V':b'\0\0\0\0'}, IE=FGSID()),
        Type1TV('NonCurrentNativeNAS_KSI', val={'T':0xC, 'V':0}, IE=NAS_KSI()),
        Type4TLV('5GMMCap', val={'T':0x10, 'V':b'\0'}, IE=FGMMCap()),
        Type4TLV('UESecCap', val={'T':0x2E, 'V':b'\0\0'}, IE=UESecCap()),
        Type4TLV('NSSAI', val={'T':0x2F, 'V':b'\0\0'}, IE=NSSAI()),
        Type3TV('TAI', val={'T':0x52, 'V':6*b'\0'}, IE=FGSTAI()),
        Type4TLV('S1UENetCap', val={'T':0x17, 'V':b'\0\0'}, IE=S1UENetCap()),
        Type4TLV('ULDataStat', val={'T':0x40, 'V':b'\0\0'}, IE=ULDataStat()),
        Type1TV('MICOInd', val={'T':0xB, 'V':0}, IE=MICOInd()),
        Type4TLV('UEStatus', val={'T':0x2B, 'V':b'\0'}, IE=UEStatus()),
        Type6TLVE('AddGUTI', val={'T':0x77, 'V':b'\xf2'+10*b'\0'}, IE=FGSID()),
        Type4TLV('AllowedPDUSessStat', val={'T':0x25, 'V':b'\0\0'}, IE=AllowedPDUSessStat()),
        Type4TLV('UEUsage', val={'T':0x18, 'V':b'\0'}, IE=UEUsage()),
        Type4TLV('5GSDRXParam', val={'T':0x51, 'V':b'\0'}, IE=FGSDRXParam()),
        Type6TLVE('EPSNASContainer', val={'T':0x70, 'V':b'\x07\0'}),
        Type6TLVE('LADNInd', val={'T':0x74, 'V':b''}, IE=LADNInd()),
        Type1TV('PayloadContainerType', val={'T':0x8, 'V':1}, dic=PayloadContainerType_dict),
        Type6TLVE('PayloadContainer', val={'T':0x7B, 'V':b'\0'}, IE=PayloadContainer()),
        Type1TV('NetSlicingInd', val={'T':0x9, 'V':0}, IE=NetSlicingInd()),
        Type4TLV('5GSUpdateType', val={'T':0x43, 'V':b'\0'}, IE=FGSUpdateType()),
        Type4TLV('MSCm2', val={'T':0x41, 'V':b'@\0\0'}, IE=MSCm2()),
        Type4TLV('SuppCodecs', val={'T':0x42, 'V':b'\0\x01\0'}, IE=SuppCodecList()),
        Type6TLVE('NASContainer', val={'T':0x71, 'V':b'\0\0'}),
        Type4TLV('EPSBearerCtxtStat', val={'T':0x60, 'V':b'\0\0'}, IE=EPSBearerCtxtStat()),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam()),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('UERadioCapID', val={'T':0x67, 'V':b'\0'}, IE=UERadioCapID()),
        )

