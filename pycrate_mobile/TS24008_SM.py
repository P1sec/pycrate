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
# * File Name : pycrate_mobile/TS24008_SM.py
# * Created : 2017-06-22
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/

__all__ = [
    'SMActivateMBMSContextAccept',
    'SMActivateMBMSContextReject',
    'SMActivateMBMSContextRequest',
    'SMActivatePDPContextAccept',
    'SMActivatePDPContextReject',
    'SMActivatePDPContextRequest',
    'SMActivateSecondaryPDPContextAccept',
    'SMActivateSecondaryPDPContextReject',
    'SMActivateSecondaryPDPContextRequest',
    'SMDeactivatePDPContextAccept',
    'SMDeactivatePDPContextRequest',
    'SMModifyPDPContextAcceptMO',
    'SMModifyPDPContextAcceptMT',
    'SMModifyPDPContextReject',
    'SMModifyPDPContextRequestMO',
    'SMModifyPDPContextRequestMT',
    'SMNotification',
    'SMRequestMBMSContextActivation',
    'SMRequestMBMSContextActivationReject',
    'SMRequestPDPContextActivation',
    'SMRequestPDPContextActivationReject',
    'SMRequestSecondaryPDPContextActivation',
    'SMRequestSecondaryPDPContextActivationReject',
    'SMStatus',
    #
    'SMTypeClasses',
    'get_sm_msg_instances'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.008: Mobile radio interface layer 3 specification
# release 13 (d90)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24008_IE import *
from .TS24007    import *

#------------------------------------------------------------------------------#
# GPRS Session Management header
# TS 24.008, section 10.1 to 10.4
#------------------------------------------------------------------------------#

# PS Mobility Management procedures dict
_PS_SM_dict = {
    65: "GPRS - Activate PDP context request",
    66: "GPRS - Activate PDP context accept",
    67: "GPRS - Activate PDP context reject",
    68: "GPRS - Request PDP context activation",
    69: "GPRS - Request PDP context activation rejection",
    70: "GPRS - Deactivate PDP context request",
    71: "GPRS - Deactivate PDP context accept",
    72: "GPRS - Modify PDP context request(Network to MS direction)",
    73: "GPRS - Modify PDP context accept (MS to network direction)",
    74: "GPRS - Modify PDP context request(MS to network direction)",
    75: "GPRS - Modify PDP context accept (Network to MS direction)",
    76: "GPRS - Modify PDP context reject",
    77: "GPRS - Activate secondary PDP context request",
    78: "GPRS - Activate secondary PDP context accept",
    79: "GPRS - Activate secondary PDP context reject",
    85: "GPRS - SM Status",
    86: "GPRS - Activate MBMS Context Request",
    87: "GPRS - Activate MBMS Context Accept",
    88: "GPRS - Activate MBMS Context Reject",
    89: "GPRS - Request MBMS Context Activation",
    90: "GPRS - Request MBMS Context Activation Reject",
    91: "GPRS - Request Secondary PDP Context Activation",
    92: "GPRS - Request Secondary PDP Context Activation Reject",
    93: "GPRS - Notification"
    }

class SMHeader(Envelope):
    _GEN = (
        TIPD(val={'ProtDisc': 10}),
        Uint8('Type', val=85, dic=_PS_SM_dict),
        )

#------------------------------------------------------------------------------#
# Activate PDP context request
# TS 24.008, section 9.5.1
#------------------------------------------------------------------------------#

class SMActivatePDPContextRequest(Layer3):
    _GEN = (
        SMHeader(val={'Type':65}),
        Type3V('NSAPI', val={'V':b'\x05'}, bl={'V':8}, IE=NSAPI()),
        Type3V('LLC_SAPI', val={'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type4LV('QoS', val={'V':11*b'\x00'}, IE=QoS()),
        Type4LV('PDPAddr', val={'V':b'\x00\x01'}, IE=PDPAddr()),
        Type4TLV('APN', val={'T':0x28, 'V':b'\0'}, IE=APN()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('ReqType', val={'T':0xA, 'V':1}, dic=RequestType_dict),
        Type1TV('DeviceProp', val={'T':0xC, 'V':0}, IE=DeviceProp()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\x00'})
        )


#------------------------------------------------------------------------------#
# Activate PDP context accept
# TS 24.008, section 9.5.2
#------------------------------------------------------------------------------#

class SMActivatePDPContextAccept(Layer3):
    _GEN = (
        SMHeader(val={'Type':66}),
        Type3V('LLC_SAPI', val={'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type4LV('QoS', val={'V':11*b'\0'}, IE=QoS()),
        Uint('spare', bl=4),
        Type1V('RadioPriority', dic=RadioPrio_dict),
        Type4TLV('PDPAddr', val={'T':0x2B, 'V':b'\0\x01'}, IE=PDPAddr()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('PacketFlowId', val={'T':0x34, 'V':b'\0'}, IE=PacketFlowId()),
        Type4TLV('SMCause', val={'T':0x39, 'V':b'\x6f'}, IE=SMCause()),
        Type1TV('ConType', val={'T':0xB, 'V':0}, dic=ConnectivityType_dict),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate PDP context reject
# TS 24.008, section 9.5.3
#------------------------------------------------------------------------------#

class SMActivatePDPContextReject(Layer3):
    _GEN = (
        SMHeader(val={'Type':67}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ReattemptInd', val={'T':0x6B, 'V':b'\0'}, IE=ReattemptInd()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate Secondary PDP Context Request
# TS 24.008, section 9.5.4
#------------------------------------------------------------------------------#

class SMActivateSecondaryPDPContextRequest(Layer3):
    _GEN = (
        SMHeader(val={'Type':77}),
        Type3V('NSAPI', val={'V':b'\x05'}, bl={'V':8}, IE=NSAPI()),
        Type3V('LLC_SAPI', val={'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type4LV('QoS', val={'V':11*b'\0'}, IE=QoS()),
        Type4LV('LinkedTI', val={'V':b'\0'}, IE=TI()),
        Type4TLV('TFT', val={'T':0x36, 'V':b'\0'}, IE=TFT()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('DeviceProp', val={'T':0xC, 'V':0}, IE=DeviceProp()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate Secondary PDP Context Accept
# TS 24.008, section 9.5.5
#------------------------------------------------------------------------------#

class SMActivateSecondaryPDPContextAccept(Layer3):
    _GEN = (
        SMHeader(val={'Type':78}),
        Type3V('LLC_SAPI', val={'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type4LV('QoS', val={'V':11*b'\0'}, IE=QoS()),
        Uint('spare', bl=4),
        Type1V('RadioPriority', dic=RadioPrio_dict),
        Type4TLV('PacketFlowId', val={'T':0x34, 'V':b'\0'}, IE=PacketFlowId()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate Secondary PDP Context Reject
# TS 24.008, section 9.5.6
#------------------------------------------------------------------------------#

class SMActivateSecondaryPDPContextReject(Layer3):
    _GEN = (
        SMHeader(val={'Type':79}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ReattemptInd', val={'T':0x6B, 'V':b'\0'}, IE=ReattemptInd()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Request PDP Context Activation
# TS 24.008, section 9.5.7
#------------------------------------------------------------------------------#

class SMRequestPDPContextActivation(Layer3):
    _GEN = (
        SMHeader(val={'Type':68}),
        Type4LV('PDPAddr', val={'V':b'\0\x01'}, IE=PDPAddr()),
        Type4TLV('APN', val={'T':0x28, 'V':b'\0'}, IE=APN()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )

#------------------------------------------------------------------------------#
# Request PDP Context Activation Rejection
# TS 24.008, section 9.5.8
#------------------------------------------------------------------------------#

class SMRequestPDPContextActivationReject(Layer3):
    _GEN = (
        SMHeader(val={'Type':69}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )

#------------------------------------------------------------------------------#
# Modify PDP context request (Network to MS direction)
# TS 24.008, section 9.5.9
#------------------------------------------------------------------------------#

class SMModifyPDPContextRequestMT(Layer3):
    _GEN = (
        SMHeader(val={'Type':72}),
        Uint('spare', bl=4),
        Type1V('RadioPriority', dic=RadioPrio_dict),
        Type3V('LLC_SAPI', val={'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type4LV('QoS', val={'V':11*b'\0'}, IE=QoS()),
        Type4TLV('PDPAddr', val={'T':0x2B, 'V':b'\0\x01'}, IE=PDPAddr()),
        Type4TLV('PacketFlowId', val={'T':0x34, 'V':b'\0'}, IE=PacketFlowId()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('TFT', val={'T':0x36, 'V':b'\0'}, IE=TFT()),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )

#------------------------------------------------------------------------------#
# Modify PDP context request (MS to Network direction)
# TS 24.008, section 9.5.10
#------------------------------------------------------------------------------#

class SMModifyPDPContextRequestMO(Layer3):
    _GEN = (
        SMHeader(val={'Type':74}),
        Type3TV('LLC_SAPI', val={'T':0x32, 'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type4TLV('QoS', val={'T':0x30, 'V':11*b'\0'}, IE=QoS()),
        Type4TLV('TFT', val={'T':0x31, 'V':b'\0'}, IE=TFT()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('DeviceProp', val={'T':0xC, 'V':0}, IE=DeviceProp()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Modify PDP Context Accept (MS to Network direction)
# TS 24.008, section 9.5.11
#------------------------------------------------------------------------------#

class SMModifyPDPContextAcceptMO(Layer3):
    _GEN = (
        SMHeader(val={'Type':73}),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )

#------------------------------------------------------------------------------#
# Modify PDP Context Accept (Network to MS direction)
# TS 24.008, section 9.5.12
#------------------------------------------------------------------------------#

class SMModifyPDPContextAcceptMT(Layer3):
    _GEN = (
        SMHeader(val={'Type':75}),
        Type4TLV('QoS', val={'T':0x30, 'V':11*b'\0'}, IE=QoS()),
        Type3TV('LLC_SAPI', val={'T':0x32, 'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type1TV('RadioPriority', val={'T':0x8, 'V':0}, IE=RadioPriority()),
        Type4TLV('PacketFlowId', val={'T':0x34, 'V':b'\0'}, IE=PacketFlowId()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )

#------------------------------------------------------------------------------#
# Modify PDP Context Reject
# TS 24.008, section 9.5.13
#------------------------------------------------------------------------------#

class SMModifyPDPContextReject(Layer3):
    _GEN = (
        SMHeader(val={'Type':76}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ReattemptInd', val={'T':0x6B, 'V':b'\0'}, IE=ReattemptInd()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )

#------------------------------------------------------------------------------#
# Deactivate PDP Context Request
# TS 24.008, section 9.5.14
#------------------------------------------------------------------------------#

class SMDeactivatePDPContextRequest(Layer3):
    _GEN = (
        SMHeader(val={'Type':70}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause()),
        Type1TV('TearDownInd', val={'T':0x9, 'V':0}, IE=TearDownInd()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('MBMSProtConfig', val={'T':0x35, 'V':b'\0'}),
        Type4TLV('T3396', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept())
        )


#------------------------------------------------------------------------------#
# Deactivate PDP Context Accept
# TS 24.008, section 9.5.15
#------------------------------------------------------------------------------#

class SMDeactivatePDPContextAccept(Layer3):
    _GEN = (
        SMHeader(val={'Type':71}),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('MBMSProtConfig', val={'T':0x35, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Request Secondary PDP Context Activation
# TS 24.008, section 9.5.15a
#------------------------------------------------------------------------------#

class SMRequestSecondaryPDPContextActivation(Layer3):
    _GEN = (
        SMHeader(val={'Type':91}),
        Type4LV('QoS', val={'V':11*b'\0'}, IE=QoS()),
        Type4LV('LinkedTI', val={'V':b'\0'}, IE=TI()),
        Type4TLV('TFT', val={'T':0x36, 'V':b'\0'}, IE=TFT()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Request Secondary PDP Context Activation Reject
# TS 24.008, section 9.5.15b
#------------------------------------------------------------------------------#

class SMRequestSecondaryPDPContextActivationReject(Layer3):
    _GEN = (
        SMHeader(val={'Type':92}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Notification
# TS 24.008, section 9.5.16a
#------------------------------------------------------------------------------#

class SMNotification(Layer3):
    _GEN = (
        SMHeader(val={'Type':93}),
        Type4LV('NotificationInd', val={'V':b'\0'}, IE=NotificationInd())
        )


#------------------------------------------------------------------------------#
# SM Status
# TS 24.008, section 9.5.21
#------------------------------------------------------------------------------#

class SMStatus(Layer3):
    _GEN = (
        SMHeader(val={'Type':85}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause())
        )

#------------------------------------------------------------------------------#
# Activate MBMS Context Request
# TS 24.008, section 9.5.22
#------------------------------------------------------------------------------#

class SMActivateMBMSContextRequest(Layer3):
    _GEN = (
        SMHeader(val={'Type':86}),
        Type3V('MBMS_NSAPI', val={'V':b'\0'}, bl={'V':8}, IE=ENSAPI()),
        Type3V('LLC_SAPI', val={'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type4LV('MBMSBearerCap', val={'V':b'\0'}, IE=MBMSBearerCap()),
        Type4LV('MCastAddr', val={'V':b'\0\x01'}, IE=PDPAddr()),
        Type4LV('APN', val={'V':b'\0'}, IE=APN()),
        Type4TLV('MBMSProtConfig', val={'T':0x35, 'V':b'\0'}),
        Type1TV('DeviceProp', val={'T':0xC, 'V':0}, IE=DeviceProp())
        )


#------------------------------------------------------------------------------#
# Activate MBMS Context Accept
# TS 24.008, section 9.5.23
#------------------------------------------------------------------------------#

class SMActivateMBMSContextAccept(Layer3):
    _GEN = (
        SMHeader(val={'Type':87}),
        Type4LV('TMGI', val={'V':b'\0\0\0'}, IE=TMGI()),
        Type3V('LLC_SAPI', val={'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type4TLV('MBMSProtConfig', val={'T':0x35, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate MBMS Context Reject
# TS 24.008, section 9.5.24
#------------------------------------------------------------------------------#

class SMActivateMBMSContextReject(Layer3):
    _GEN = (
        SMHeader(val={'Type':88}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause()),
        Type4TLV('MBMSProtConfig', val={'T':0x35, 'V':b'\0'}),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ReattemptInd', val={'T':0x6B, 'V':b'\0'}, IE=ReattemptInd())
        )


#------------------------------------------------------------------------------#
# Request MBMS Context Activation
# TS 24.008, section 9.5.25
#------------------------------------------------------------------------------#

class SMRequestMBMSContextActivation(Layer3):
    _GEN = (
        SMHeader(val={'Type':89}),
        Type3V('LinkedNSAPI', val={'V':b'\x05'}, bl={'V':8}, IE=NSAPI()),
        Type4LV('MCastAddr', val={'V':b'\0\x01'}, IE=PDPAddr()),
        Type4LV('APN', val={'V':b'\0'}, IE=APN()),
        Type4TLV('MBMSProtConfig', val={'T':0x35, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Request MBMS Context Activation Reject
# TS 24.008, section 9.5.26
#------------------------------------------------------------------------------#

class SMRequestMBMSContextActivationReject(Layer3):
    _GEN = (
        SMHeader(val={'Type':90}),
        Type3V('SMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=SMCause()),
        Type4TLV('MBMSProtConfig', val={'T':0x35, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# SM dispatchers
#------------------------------------------------------------------------------#

SMTypeClasses = {
    65: SMActivatePDPContextRequest,
    66: SMActivatePDPContextAccept,
    67: SMActivatePDPContextReject,
    68: SMRequestPDPContextActivation,
    69: SMRequestPDPContextActivationReject,
    70: SMDeactivatePDPContextRequest,
    71: SMDeactivatePDPContextAccept,
    72: SMModifyPDPContextRequestMT,
    73: SMModifyPDPContextAcceptMO,
    74: SMModifyPDPContextRequestMO,
    75: SMModifyPDPContextAcceptMT,
    76: SMModifyPDPContextReject,
    77: SMActivateSecondaryPDPContextRequest,
    78: SMActivateSecondaryPDPContextAccept,
    79: SMActivateSecondaryPDPContextReject,
    85: SMStatus,
    86: SMActivateMBMSContextRequest,
    87: SMActivateMBMSContextAccept,
    88: SMActivateMBMSContextReject,
    89: SMRequestMBMSContextActivation,
    90: SMRequestMBMSContextActivationReject,
    91: SMRequestSecondaryPDPContextActivation,
    92: SMRequestSecondaryPDPContextActivationReject,
    93: SMNotification
    }

def get_sm_msg_instances():
    return {k: SMTypeClasses[k]() for k in SMTypeClasses}

