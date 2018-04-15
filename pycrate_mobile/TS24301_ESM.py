# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
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
# * File Name : pycrate_mobile/TS24301_ESM.py
# * Created : 2017-10-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'ESMActDediEPSBearerCtxtAccept',
    'ESMActDediEPSBearerCtxtReject',
    'ESMActDediEPSBearerCtxtRequest',
    'ESMActDefaultEPSBearerCtxtAccept',
    'ESMActDefaultEPSBearerCtxtReject',
    'ESMActDefaultEPSBearerCtxtRequest',
    'ESMBearerResourceAllocReject',
    'ESMBearerResourceAllocRequest',
    'ESMBearerResourceModifReject',
    'ESMBearerResourceModifRequest',
    'ESMDataTransport',
    'ESMDeactEPSBearerCtxtAccept',
    'ESMDeactEPSBearerCtxtRequest',
    'ESMDummyMessage',
    'ESMInformationRequest',
    'ESMInformationResponse',
    'ESMModifyEPSBearerCtxtAccept',
    'ESMModifyEPSBearerCtxtReject',
    'ESMModifyEPSBearerCtxtRequest',
    'ESMNotification',
    'ESMPDNConnectivityReject',
    'ESMPDNConnectivityRequest',
    'ESMPDNDisconnectReject',
    'ESMPDNDisconnectRequest',
    'ESMRemoteUEReport',
    'ESMRemoteUEResponse',
    'ESMStatus',
    #
    'ESMTypeClasses',
    'get_esm_msg_instances'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.301: NAS protocol for EPS
# release 13 (da0)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007    import *
from .TS24008_IE import *
from .TS24301_IE import *


#------------------------------------------------------------------------------#
# EPS Session Management header
# TS 24.301, section 9
#------------------------------------------------------------------------------#

# section 9.8
_ESM_dict = {
    # default bearer
    193 : "Activate default EPS bearer context request",
    194 : "Activate default EPS bearer context accept",
    195 : "Activate default EPS bearer context reject",
    # dedicated bearer
    197 : "Activate dedicated EPS bearer context request",
    198 : "Activate dedicated EPS bearer context accept",
    199 : "Activate dedicated EPS bearer context reject",
    # bearer modification
    201 : "Modify EPS bearer context request",
    202 : "Modify EPS bearer context accept",
    203 : "Modify EPS bearer context reject",
    # bearer deactivation
    205 : "Deactivate EPS bearer context request",
    206 : "Deactivate EPS bearer context accept",
    # request PDN connectivity
    208 : "PDN connectivity request",
    209 : "PDN connectivity reject",
    # request PDN disconnection
    210 : "PDN disconnect request",
    211 : "PDN disconnect reject",
    # request bearer resource allocation
    212 : "Bearer resource allocation request",
    213 : "Bearer resource allocation reject",
    # request bearer resource modification
    214 : "Bearer resource modification request",
    215 : "Bearer resource modification reject",
    # misc
    217 : "ESM information request",
    218 : "ESM information response",
    219 : "Notification",
    220 : "ESM dummy message",
    232 : "ESM status",
    233 : "Remote UE report",
    234 : "Remote UE response",
    235 : "ESM data transport"
    }

class ESMHeader(Envelope):
    _GEN = (
        Uint('EPSBearerId', bl=4),
        Uint('ProtDisc', val=2, bl=4),
        Uint8('PTI'),
        Uint8('Type', val=232, dic=_ESM_dict)
        )


#------------------------------------------------------------------------------#
# Activate dedicated EPS bearer context accept
# TS 24.301, section 8.3.1
#------------------------------------------------------------------------------#

class ESMActDediEPSBearerCtxtAccept(Layer3):
    _GEN = (
        ESMHeader(val={'Type':198}),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate dedicated EPS bearer context reject
# TS 24.301, section 8.3.2
#------------------------------------------------------------------------------#

class ESMActDediEPSBearerCtxtReject(Layer3):
    _GEN = (
        ESMHeader(val={'Type':199}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate dedicated EPS bearer context request
# TS 24.301, section 8.3.3
#------------------------------------------------------------------------------#

class ESMActDediEPSBearerCtxtRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':197}),
        Uint('spare', bl=4),
        Type1V('LinkedEPSBearerId'),
        Type4LV('EPSQoS', val={'V':b'\x09'}, IE=EPSQoS()),
        Type4LV('TFT', val={'V':b'\0'}, IE=TFT()),
        Type4TLV('TI', val={'T':0x5D, 'V':b'\0'}, IE=TI()),
        Type4TLV('QoS', val={'T':0x30, 'V':11*b'\0'}, IE=QoS()),
        Type3TV('LLC_SAPI', val={'T':0x32, 'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type1TV('RadioPriority', val={'T':0x8, 'V':0}, IE=RadioPriority()),
        Type4TLV('PacketFlowId', val={'T':0x34, 'V':b'\0'}, IE=PacketFlowId()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate default EPS bearer context accept
# TS 24.301, section 8.3.4
#------------------------------------------------------------------------------#

class ESMActDefaultEPSBearerCtxtAccept(Layer3):
    _GEN = (
        ESMHeader(val={'Type':194}),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate default EPS bearer context reject
# TS 24.301, section 8.3.5
#------------------------------------------------------------------------------#

class ESMActDefaultEPSBearerCtxtReject(Layer3):
    _GEN = (
        ESMHeader(val={'Type':195}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Activate default EPS bearer context request
# TS 24.301, section 8.3.6
#------------------------------------------------------------------------------#

class ESMActDefaultEPSBearerCtxtRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':193}),
        Type4LV('EPSQoS', val={'V':b'\x09'}, IE=EPSQoS()),
        Type4LV('APN', val={'V':b'\0'}, IE=APN()),
        Type4LV('PDNAddr', val={'V':b'\x01\0\0\0\0',}, IE=PDNAddr()),
        Type4TLV('TI', val={'T':0x5D, 'V':b'\0'}, IE=TI()),
        Type4TLV('QoS', val={'T':0x30, 'V':11*b'\0'}, IE=QoS()),
        Type3TV('LLC_SAPI', val={'T':0x32, 'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type1TV('RadioPriority', val={'T':0x8, 'V':0}, IE=RadioPriority()),
        Type4TLV('PacketFlowId', val={'T':0x34, 'V':b'\0'}, IE=PacketFlowId()),
        Type4TLV('APN_AMBR', val={'T':0x5E, 'V':b'\0\0'}, IE=APN_AMBR()),
        Type3TV('ESMCause', val={'T':0x58, 'V':b'\0'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('ConType', val={'T':0xB, 'V':0}, dic=ConnectivityType_dict),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type4TLV('HdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=HdrCompConfig()),
        Type1TV('CPOnlyInd', val={'T':0x9, 'V':0}, IE=CPOnlyInd()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'}),
        Type4TLV('ServingPLMNRateCtrl', val={'T':0x6E, 'V':b'\0'}, IE=ServingPLMNRateCtrl())
        )


#------------------------------------------------------------------------------#
# Bearer resource allocation reject
# TS 24.301, section 8.3.7
#------------------------------------------------------------------------------#

class ESMBearerResourceAllocReject(Layer3):
    _GEN = (
        ESMHeader(val={'Type':213}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ReattemptInd', val={'T':0x6B, 'V':b'\0'}, IE=ReattemptInd()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Bearer resource allocation request
# TS 24.301, section 8.3.8
#------------------------------------------------------------------------------#

class ESMBearerResourceAllocRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':212}),
        Uint('spare', bl=4),
        Type1V('LinkedEPSBearerId'),
        Type4LV('TFAggregate', val={'V':b'\0'}, IE=TFAggregate()),
        Type4LV('EPSQoS', val={'V':b'\x09'}, IE=EPSQoS()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('DeviceProp', val={'T':0xC, 'V':0}, IE=DeviceProp()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Bearer resource modification reject
# TS 24.301, section 8.3.9
#------------------------------------------------------------------------------#

class ESMBearerResourceModifReject(Layer3):
    _GEN = (
        ESMHeader(val={'Type':215}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ReattemptInd', val={'T':0x6B, 'V':b'\0'}, IE=ReattemptInd()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Bearer resource modification request
# TS 24.301, section 8.3.10
#------------------------------------------------------------------------------#

class ESMBearerResourceModifRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':214}),
        Uint('spare', bl=4),
        Type1V('LinkedEPSBearerId'),
        Type4LV('TFAggregate', val={'V':b'\0'}, IE=TFAggregate()),
        Type4TLV('EPSQoS', val={'T':0x5B, 'V':b'\x09'}, IE=EPSQoS()),
        Type3TV('ESMCause', val={'T':0x58, 'V':b'\0'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('DeviceProp', val={'T':0xC, 'V':0}, IE=DeviceProp()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type4TLV('HdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=HdrCompConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Deactivate EPS bearer context accept
# TS 24.301, section 8.3.11
#------------------------------------------------------------------------------#

class ESMDeactEPSBearerCtxtAccept(Layer3):
    _GEN = (
        ESMHeader(val={'Type':206}),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Deactivate EPS bearer context request
# TS 24.301, section 8.3.12
#------------------------------------------------------------------------------#

class ESMDeactEPSBearerCtxtRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':205}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# ESM dummy message
# TS 24.301, section 8.3.12A
#------------------------------------------------------------------------------#

class ESMDummyMessage(Layer3):
    _GEN = (
        ESMHeader(val={'Type':220}),
        )


#------------------------------------------------------------------------------#
# ESM information request
# TS 24.301, section 8.3.13
#------------------------------------------------------------------------------#

class ESMInformationRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':217}),
        )


#------------------------------------------------------------------------------#
# ESM information response
# TS 24.301, section 8.3.14
#------------------------------------------------------------------------------#

class ESMInformationResponse(Layer3):
    _GEN = (
        ESMHeader(val={'Type':218}),
        Type4TLV('APN', val={'T':0x28, 'V':b'\0'}, IE=APN()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# ESM status
# TS 24.301, section 8.3.15
#------------------------------------------------------------------------------#

class ESMStatus(Layer3):
    _GEN = (
        ESMHeader(val={'Type':232}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause())
        )


#------------------------------------------------------------------------------#
# Modify EPS bearer context accept
# TS 24.301, section 8.3.16
#------------------------------------------------------------------------------#

class ESMModifyEPSBearerCtxtAccept(Layer3):
    _GEN = (
        ESMHeader(val={'Type':202}),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Modify EPS bearer context reject
# TS 24.301, section 8.3.17
#------------------------------------------------------------------------------#

class ESMModifyEPSBearerCtxtReject(Layer3):
    _GEN = (
        ESMHeader(val={'Type':203}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Modify EPS bearer context request
# TS 24.301, section 8.3.18
#------------------------------------------------------------------------------#

class ESMModifyEPSBearerCtxtRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':201}),
        Type4TLV('EPSQoS', val={'T':0x5B, 'V':b'\x09'}, IE=EPSQoS()),
        Type4TLV('TFT', val={'T':0x36, 'V':b'\0'}, IE=TFT()),
        Type4TLV('QoS', val={'T':0x30, 'V':11*b'\0'}, IE=QoS()),
        Type3TV('LLC_SAPI', val={'T':0x32, 'V':b'\0'}, bl={'V':8}, IE=LLC_SAPI()),
        Type1TV('RadioPriority', val={'T':0x8, 'V':0}, IE=RadioPriority()),
        Type4TLV('PacketFlowId', val={'T':0x34, 'V':b'\0'}, IE=PacketFlowId()),
        Type4TLV('APN_AMBR', val={'T':0x5E, 'V':b'\0\0'}, IE=APN_AMBR()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('WLANOffloadInd', val={'T':0xC, 'V':0}, IE=WLANOffloadAccept()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type4TLV('HdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=HdrCompConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Notification
# TS 24.301, section 8.3.18A
#------------------------------------------------------------------------------#

class ESMNotification(Layer3):
    _GEN = (
        ESMHeader(val={'Type':219}),
        Type4LV('NotificationInd', val={'V':b'\0'}, IE=NotificationInd()),
        )


#------------------------------------------------------------------------------#
# PDN connectivity reject
# TS 24.301, section 8.3.19
#------------------------------------------------------------------------------#

class ESMPDNConnectivityReject(Layer3):
    _GEN = (
        ESMHeader(val={'Type':209}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ReattemptInd', val={'T':0x6B, 'V':b'\0'}, IE=ReattemptInd()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# PDN connectivity request
# TS 24.301, section 8.3.20
#------------------------------------------------------------------------------#

class ESMPDNConnectivityRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':208}),
        Type1V('PDNType', dic=PDNType_dict),
        Type1V('RequestType', dic=RequestType_dict),
        Type1TV('ESMInfoTransferFlag', val={'T':0xD, 'V':0}, IE=ESMInfoTransferFlag()),
        Type4TLV('APN', val={'T':0x28, 'V':b'\0'}, IE=APN()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type1TV('DeviceProp', val={'T':0xC, 'V':0}, IE=DeviceProp()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type4TLV('HdrCompConfig', val={'T':0x66, 'V':b'\0\0\0'}, IE=HdrCompConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# PDN disconnect reject
# TS 24.301, section 8.3.21
#------------------------------------------------------------------------------#

class ESMPDNDisconnectReject(Layer3):
    _GEN = (
        ESMHeader(val={'Type':211}),
        Type3V('ESMCause', val={'V':b'\x6f'}, bl={'V':8}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )



#------------------------------------------------------------------------------#
# PDN disconnect request
# TS 24.301, section 8.3.22
#------------------------------------------------------------------------------#

class ESMPDNDisconnectRequest(Layer3):
    _GEN = (
        ESMHeader(val={'Type':210}),
        Uint('spare', bl=4),
        Type1V('LinkedEPSBearerId'),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Remote UE report
# TS 24.301, section 8.3.23
#------------------------------------------------------------------------------#

class ESMRemoteUEReport(Layer3):
    _GEN = (
        ESMHeader(val={'Type':233}),
        Type6TLVE('RemoteUEConnected', val={'T':0x79, 'V':b''}, IE=RemoteUECtxtList()),
        Type6TLVE('RemoteUEDisconnected', val={'T':0x7A, 'V':b''}, IE=RemoteUECtxtList()),
        Type4TLV('PKMFAddr', val={'T':0x6F, 'V':b'\0'}, IE=PKMFAddr())
        )


#------------------------------------------------------------------------------#
# Remote UE response
# TS 24.301, section 8.3.24
#------------------------------------------------------------------------------#

class ESMRemoteUEResponse(Layer3):
    _GEN = (
        ESMHeader(val={'Type':234}),
        )


#------------------------------------------------------------------------------#
# ESM DATA TRANSPORT
# TS 24.301, section 8.3.25
#------------------------------------------------------------------------------#

class ESMDataTransport(Layer3):
    _GEN = (
        ESMHeader(val={'Type':235}),
        Type6LVE('UserData', val={'V':b''}),
        Type1TV('ReleaseAssistInd', val={'T':0xD, 'V':0}, IE=ReleaseAssistInd())
        )


#------------------------------------------------------------------------------#
# ESM dispatcher
#------------------------------------------------------------------------------#

ESMTypeClasses = {
    193 : ESMActDefaultEPSBearerCtxtRequest,
    194 : ESMActDefaultEPSBearerCtxtAccept,
    195 : ESMActDefaultEPSBearerCtxtReject,
    197 : ESMActDediEPSBearerCtxtRequest,
    198 : ESMActDediEPSBearerCtxtAccept,
    199 : ESMActDediEPSBearerCtxtReject,
    201 : ESMModifyEPSBearerCtxtRequest,
    202 : ESMModifyEPSBearerCtxtAccept,
    203 : ESMModifyEPSBearerCtxtReject,
    205 : ESMDeactEPSBearerCtxtRequest,
    206 : ESMDeactEPSBearerCtxtAccept,
    208 : ESMPDNConnectivityRequest,
    209 : ESMPDNConnectivityReject,
    210 : ESMPDNDisconnectRequest,
    211 : ESMPDNDisconnectReject,
    212 : ESMBearerResourceAllocRequest,
    213 : ESMBearerResourceAllocReject,
    214 : ESMBearerResourceModifRequest,
    215 : ESMBearerResourceModifReject,
    217 : ESMInformationRequest,
    218 : ESMInformationResponse,
    219 : ESMNotification,
    220 : ESMDummyMessage,
    232 : ESMStatus,
    233 : ESMRemoteUEReport,
    234 : ESMRemoteUEResponse,
    235 : ESMDataTransport
    }

def get_esm_msg_instances():
    return {k: ESMTypeClasses[k]() for k in ESMTypeClasses}

