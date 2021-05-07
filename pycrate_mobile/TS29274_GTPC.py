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
# * File Name : pycrate_mobile/TS29274_GTPC.py
# * Created : 2019-07-16
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/


#__all__ = [
#    ]


#------------------------------------------------------------------------------#
# 3GPP TS 29.274: Evolved General Packet Radio Service (GPRS) Tunnelling Protocol 
# for Control plane (GTPv2-C)
# release 17.1.1 (h11)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from pycrate_mobile.TS29244_PFCP    import (
    BitFlags,
    FQCSID,
    _FQDN,
    TimerUnit_dict,
    _Timer,
    )
from pycrate_mobile.TS24301_IE      import (
    TAI,
    UENetCap,
    )
from pycrate_mobile.TS24008_IE      import (
    BufBCD,
    ProtConfig,
    PLMN,
    APN,
    TFT,
    RAI,
    LAI,
    DRXParam,
    VoiceDomPref,
    TimeZone,
    DLSavingTime,
    TMGI as _TMGI,
    MSCm2,
    classmark_3_value_part,
    ms_network_capability_value_part,
    SuppCodecList
    )
from pycrate_mobile.TS44018_IE      import (
    ChanNeeded,
    )
from pycrate_mobile.TS24007         import (
    Type4LV,
    TI,
    )


#------------------------------------------------------------------------------#
# GTP-C header
# TS 29.274, section 5.1
#------------------------------------------------------------------------------#

# GTP-C v2 type of messages:
# this dict may become infamous...
# TS 29.274, section 6.1
# TS 29.276, section 7.1 for S101, section 7A for S121
# TS 29.280, section 5 for Sv

GTPCType_dict = {
    # all GTP-C v2 interfaces
    0   : 'Reserved',
    1   : 'Echo Request',
    2   : 'Echo Response',
    3   : 'Version Not Supported Indication',
    # S101 (MME / HRPD), TS 29.276
    4   : 'Direct Transfer Request message', 
    5   : 'Direct Transfer Response message',
    6   : 'Notification Request message',
    7   : 'Notification Response message',
    # S121 (MME / HRPD Access Network), TS 29.276
    17  : 'RIM Information Transfer',
    # Sv (SRVCC mobility), # TS 29.280
    25  : 'SRVCC PS to CS Request',
    26  : 'SRVCC PS to CS Response',
    27  : 'SRVCC PS to CS Complete Notification',
    28  : 'SRVCC PS to CS Complete Acknowledge',
    29  : 'SRVCC PS to CS Cancel Notification',
    30  : 'SRVCC PS to CS Cancel Acknowledge',
    31  : 'SRVCC CS to PS Request',
    240 : 'SRVCC CS to PS Response',
    241 : 'SRVCC CS to PS Complete Notification',
    242 : 'SRVCC CS to PS Complete Acknowledge',
    243 : 'SRVCC CS to PS Cancel Notification',
    244 : 'SRVCC CS to PS Cancel Acknowledge',
    # S4/S11, S5/S8, S2a, S2b (SGSN/MME/TWAN/ePDG to PGW)
    32  : 'Create Session Request',
    33  : 'Create Session Response',
    36  : 'Delete Session Request',
    37  : 'Delete Session Response',
    # S4/S11, S5/S8, S2b (SGSN/MME/ePDG to PGW)
    34  : 'Modify Bearer Request',
    35  : 'Modify Bearer Response',
    # S11, S5/S8 (MME to PGW)
    40  : 'Remote UE Report Notification',
    41  : 'Remote UE Report Acknowledge',
    # S4/S11, S5/S8 (SGSN/MME to PGW)
    38  : 'Change Notification Request',
    39  : 'Change Notification Response',
    164 : 'Resume Notification',
    165 : 'Resume Acknowledge',
    # messages without explicit response
    64  : 'Modify Bearer Command', # (MME/SGSN/TWAN/ePDG to PGW – S4/S11, S5/S8, S2a, S2b)
    65  : 'Modify Bearer Failure Indication', # (PGW to MME/SGSN/TWAN/ePDG – S4/S11, S5/S8, S2a, S2b)
    66  : 'Delete Bearer Command', # (MME/SGSN to PGW – S4/S11, S5/S8)
    67  : 'Delete Bearer Failure Indication', # (PGW to MME/SGSN – S4/S11, S5/S8)
    68	: 'Bearer Resource Command', # (MME/SGSN/TWAN/ePDG to PGW – S4/S11, S5/S8, S2a, S2b)
    69  : 'Bearer Resource Failure Indication', # (PGW to MME/SGSN/TWAN/ePDG – S4/S11, S5/S8, S2a, S2b)
    70  : 'Downlink Data Notification Failure Indication', # (SGSN/MME to SGW – S4/S11)
    71  : 'Trace Session Activation', # (MME/SGSN/TWAN/ePDG to PGW – S4/S11, S5/S8, S2a, S2b)
    72  : 'Trace Session Deactivation', # (MME/SGSN/TWAN/ePDG to PGW – S4/S11, S5/S8, S2a, S2b)
    73  : 'Stop Paging Indication', # (SGW to MME/SGSN – S4/S11)
    # S4/S11, S5/S8, S2a, S2b (PGW to SGSN/MME/TWAN/ePDG)
    95  : 'Create Bearer Request',
    96  : 'Create Bearer Response',
    97  : 'Update Bearer Request',
    98  : 'Update Bearer Response',
    99  : 'Delete Bearer Request',
    100 : 'Delete Bearer Response',
    # S11, S5/S8, S2a, S2b (PGW to MME, MME to PGW, SGW to PGW, SGW to MME, PGW to TWAN/ePDG, TWAN/ePDG to PGW)
    101 : 'Delete PDN Connection Set Request',
    102 : 'Delete PDN Connection Set Response',
    # S4/S11, S5 (PGW to SGSN/MME)
    103 : 'PGW Downlink Triggering Notification',
    104 : 'PGW Downlink Triggering Acknowledge',
    # S3, S10, S16, N26 (MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN, MME to AMF, AMF to MME)
    128 : 'Identification Request',
    129 : 'Identification Response',
    130 : 'Context Request',
    131 : 'Context Response',
    132 : 'Context Acknowledge',
    133 : 'Forward Relocation Request',
    134 : 'Forward Relocation Response',
    135 : 'Forward Relocation Complete Notification',
    136 : 'Forward Relocation Complete Acknowledge',
    139 : 'Relocation Cancel Request',
    140 : 'Relocation Cancel Response',
    # S10, S16 (SGSN to MME, MME to SGSN, SGSN to SGSN)
    137 : 'Forward Access Context Notification',
    138 : 'Forward Access Context Acknowledge',
    # S10, N26 (SGSN to MME, MME to SGSN, MME to AMF, AMF to MME)
    141 : 'Configuration Transfer Tunnel',
    # S3, S16 (MME to MME, SGSN to SGSN)
    152 : 'RAN Information Relay',
    # S3 (SGSN to MME, MME to SGSN)
    149 : 'Detach Notification',
    150 : 'Detach Acknowledge',
    151 : 'CS Paging Indication',
    153 : 'Alert MME Notification',
    154 : 'Alert MME Acknowledge',
    155 : 'UE Activity Notification',
    156 : 'UE Activity Acknowledge',
    157 : 'ISR Status Indication',
    158 : 'UE Registration Query Request',
    159 : 'UE Registration Query Response',
    # S3, S4/S11, S5/S8, S16 (SGSN to MME, SGSN/MME to SGW, SGW to PGW, SGSN to SGSN)
    162 : 'Suspend Notification',
    163 : 'Suspend Acknowledge',
    # S4/S11 (SGSN/MME to SGW)
    160 : 'Create Forwarding Tunnel Request',
    161 : 'Create Forwarding Tunnel Response',
    166 : 'Create Indirect Data Forwarding Tunnel Request',
    167 : 'Create Indirect Data Forwarding Tunnel Response',
    168 : 'Delete Indirect Data Forwarding Tunnel Request',
    169 : 'Delete Indirect Data Forwarding Tunnel Response',
    170 : 'Release Access Bearers Request',
    171 : 'Release Access Bearers Response',
    # S4/S11 (SGW to SGSN/MME)
    176 : 'Downlink Data Notification',
    177 : 'Downlink Data Notification Acknowledge',
    179 : 'PGW Restart Notification',
    180 : 'PGW Restart Notification Acknowledge',
    # S4 (SGW to SGSN)
    178 : 'Reserved. Allocated in earlier version of the specification',
    # S5/S8 (SGW to PGW, PGW to SGW)
    200 : 'Update PDN Connection Set Request',
    201 : 'Update PDN Connection Set Response',
    # S11 (MME to SGW)
    211 : 'Modify Access Bearers Request',
    212 : 'Modify Access Bearers Response',
    # Sm/Sn (MBMS GW to MME/SGSN)
    231 : 'MBMS Session Start Request',
    232 : 'MBMS Session Start Response',
    233 : 'MBMS Session Update Request',
    234 : 'MBMS Session Update Response',
    235 : 'MBMS Session Stop Request',
    236 : 'MBMS Session Stop Response',
    }


# GTP-C v2 requests / responses (success, error)
GTPCReqResp = {
    1   : (2, 3),
    4   : (5, ),
    6   : (7, ),
    17  : (None, ),
    25  : (26, ),
    27  : (28, ),
    29  : (30, ),
    31  : (240, ),
    241 : (242, ),
    243 : (244, ),
    32  : (33, ),
    36  : (37, ),
    34  : (35, ),
    40  : (41, ),
    38  : (39, ),
    164 : (165, ),
    64  : (None, 65),
    66  : (None, 67),
    68  : (None, 69),
    70  : (None, ),
    71  : (None, ),
    72  : (None, ),
    73  : (None, ),
    95  : (96, ),
    97  : (98, ),
    99  : (100, ),
    101 : (102, ),
    103 : (104, ),
    128 : (129, ),
    130 : (131, 132),
    133 : (134, ),
    135 : (136, ),
    139 : (140, ),
    137 : (138, ),
    141 : (None, ),
    152 : (None, ),
    149 : (150, ),
    151 : (None, ),
    153 : (154, ),
    155 : (156, ),
    157 : (None, ),
    158 : (159, ),
    162 : (163, ),
    160 : (161, ),
    166 : (167, ),
    168 : (169, ),
    170 : (171, ),
    176 : (177, ),
    179 : (180, ),
    200 : (201, ),
    211 : (212, ),
    231 : (232, ),
    233 : (234, ),
    235 : (236, )
}


# GTP-C v2 interfaces and allowed message types
GTPC_IF_S101    = set((4, 5, 6, 7))
GTPC_IF_S121    = set((17, ))
GTPC_IF_Sv      = set((25, 26, 27, 28, 29, 30, 31, 240, 241, 242, 243, 244))
GTPC_IF_S4      = set((32, 33, 36, 37, 34, 35, 38, 39, 164, 165, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 
                       95, 96, 97, 98, 99, 100, 103, 104, 162, 163, 160, 161, 166, 167, 168, 169, 170, 171, 
                       176, 177, 179, 180))
GTPC_IF_S11     = set((32, 33, 36, 37, 34, 35, 40, 41, 38, 39, 164, 165, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 
                       95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 162, 163, 160, 161, 166, 167, 168, 169, 170, 171, 
                       176, 177, 179, 180, 211, 212))
GTPC_IF_S5      = set((32, 33, 36, 37, 34, 35, 40, 41, 38, 39, 164, 165, 64, 65, 66, 67, 68, 69, 71, 72, 
                       95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 162, 163, 200, 201))
GTPC_IF_S8      = set((32, 33, 36, 37, 34, 35, 40, 41, 38, 39, 164, 165, 64, 65, 66, 67, 68, 69, 71, 72, 
                       95, 96, 97, 98, 99, 100, 101, 102, 162, 163, 200, 201))
GTPC_IF_S2a     = set((32, 33, 36, 37, 64, 65, 68, 69, 71, 72, 95, 96, 97, 98, 99, 100, 101, 102))
GTPC_IF_S2b     = set((32, 33, 36, 37, 34, 35, 64, 65, 68, 69, 71, 72, 95, 96, 97, 98, 99, 100, 101, 102))
GTPC_IF_S3      = set((128, 129, 130, 131, 132, 133, 134, 135, 136, 139, 140, 152, 
                       149, 150, 151, 153, 154, 155, 156, 157, 158, 159, 162, 163))
GTPC_IF_S10     = set((128, 129, 130, 131, 132, 133, 134, 135, 136, 139, 140, 137, 138, 141))
GTPC_IF_S16     = set((128, 129, 130, 131, 132, 133, 134, 135, 136, 139, 140, 137, 138, 152, 162, 163))
GTPC_IF_N26     = set((128, 129, 130, 131, 132, 133, 134, 135, 136, 139, 140, 141))
GTPC_IF_Sm      = set((231, 232, 233, 234, 235, 236))


class GTPCHdr(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('Version', val=2, bl=3),
        Uint('P', bl=1),
        Uint('T', val=1, bl=1), # T=0 only for EchoRequest, EchoResponse and VersionNotSupported
        Uint('MP', bl=1),
        Uint('spare', bl=2),
        Uint8('Type', dic=GTPCType_dict),
        Uint16('Len'),
        # if T=1
        Uint32('TEID', rep=REPR_HEX),
        Uint24('SeqNum'),
        # if MP=0
        Uint8('spare'),
        # if MP=1
        Uint('MsgPrio', bl=4, dic={0:'highest', 0xf:'lowest'}),
        Uint('spare', bl=4)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[6].set_valauto(lambda: self._get_len())
        self[7].set_transauto(lambda: False if self[2]() else True)
        self[9].set_transauto(lambda: True if self[3]() else False)
        self[10].set_transauto(lambda: False if self[3]() else True)
        self[11].set_transauto(lambda: False if self[3]() else True)
    
    def _get_len(self):
        l = 4 # length of SeqNum and last byte
        # length of TEID
        if self[2]():
            l += 4
        # length of IEs
        env = self.get_env()
        if env:
            l += sum(map(lambda e: e.get_len(), env._content[1:]))
        return l


#------------------------------------------------------------------------------#
# GTP-C Information Elements
# TS 29.274, section 8
#------------------------------------------------------------------------------#

# We define everything as Buf(), then overwrite with proper IE
# When all IEs are defined, we can get rid of these default Buf definitions
class AMBR(Buf):
    pass


class APNAndRelativeCapacity(Buf):
    pass


class APNRateControlStatus(Buf):
    pass


class APNRestriction(Buf):
    pass


class ARP(Buf):
    pass


class AbsoluteTimeOfMBMSDataTransfer(Buf):
    pass


class ActionInd(Buf):
    pass


class AdditionalFlagsForSRVCC(Buf):
    pass


class AdditionalMMContextForSRVCC(Buf):
    pass


class AdditionalPCO(Buf):
    pass


class BearerContext(Buf):
    pass


class BearerFlags(Buf):
    pass


class BearerQoS(Buf):
    pass


class BearerTFT(Buf):
    pass


class CIoTOptimizationsSupportInd(Buf):
    pass


class CMI(Buf):
    pass


class CNOperatorSelectionEntity(Buf):
    pass


class CSGID(Buf):
    pass


class CSGInfoReportingAction(Buf):
    pass


class Cause(Buf):
    pass


class ChangeReportingAction(Buf):
    pass


class ChangeToReportFlags(Buf):
    pass


class ChannelNeeded(Buf):
    pass


class ChargingCharacteristics(Buf):
    pass


class ChargingID(Buf):
    pass


class CompleteRequestMessage(Buf):
    pass


class Counter(Buf):
    pass


class DelayValue(Buf):
    pass


class DetachType(Buf):
    pass


class EBI(Buf):
    pass


class ECGIList(Buf):
    pass


class EMLPPPriority(Buf):
    pass


class EPCO(Buf):
    pass


class EPCTimer(Buf):
    pass


class ExtendedTraceInfo(Buf):
    pass


class FCause(Buf):
    pass


class FContainer(Buf):
    pass


class FQDN(Buf):
    pass


class FTEID(Buf):
    pass


class FlowQoS(Buf):
    pass


class GUTI(Buf):
    pass


class GlobalCNId(Buf):
    pass


class HeNBInfoReporting(Buf):
    pass


class HeaderCompressionConfiguration(Buf):
    pass


class HopCounter(Buf):
    pass


class IMSI(Buf):
    pass


class IPAddress(Buf):
    pass


class IPv4ConfigurationParameters(Buf):
    pass


class Ind(Buf):
    pass


class IntegerNumber(Buf):
    pass


class LDN(Buf):
    pass


class LoadControlInfo(Buf):
    pass


class MBMSDistributionAcknowledge(Buf):
    pass


class MBMSFlags(Buf):
    pass


class MBMSFlowIdent(Buf):
    pass


class MBMSIPMulticastDistribution(Buf):
    pass


class MBMSServiceArea(Buf):
    pass


class MBMSSessionDuration(Buf):
    pass


class MBMSSessionIdent(Buf):
    pass


class MBMSTimeToDataTransfer(Buf):
    pass


class MDTConfiguration(Buf):
    pass


class MEI(Buf):
    pass


class MMContext(Buf):
    pass


class MSISDN(Buf):
    pass


class MappedUEUsageType(Buf):
    pass


class MaximumPacketLossRate(Buf):
    pass


class Metric(Buf):
    pass


class MillisecondTimeStamp(Buf):
    pass


class MonitoringEventExtInfo(Buf):
    pass


class MonitoringEventInfo(Buf):
    pass


class NodeFeat(Buf):
    pass


class NodeIdent(Buf):
    pass


class NodeNumber(Buf):
    pass


class NodeType(Buf):
    pass


class OverloadControlInfo(Buf):
    pass


class PAA(Buf):
    pass


class PCO(Buf):
    pass


class PDNConnection(Buf):
    pass


class PDNType(Buf):
    pass


class PDUNumbers(Buf):
    pass


class PLMNID(Buf):
    pass


class PTI(Buf):
    pass


class PTMSI(Buf):
    pass


class PTMSISignature(Buf):
    pass


class PacketFlowID(Buf):
    pass


class PagingAndServiceInfo(Buf):
    pass


class PortNumber(Buf):
    pass


class PresenceReportingAreaAction(Buf):
    pass


class PresenceReportingAreaInfo(Buf):
    pass


class PrivExt(Buf):
    pass


class RABContext(Buf):
    pass


class RANNASCause(Buf):
    pass


class RATType(Buf):
    pass


class RFSPIndex(Buf):
    pass


class Recovery(Buf):
    pass


class RemoteUEContext(Buf):
    pass


class RemoteUEIPInfo(Buf):
    pass


class RemoteUserID(Buf):
    pass


class S103PDF(Buf):
    pass


class S1UDF(Buf):
    pass


class SCEFPDNConnection(Buf):
    pass


class STNSR(Buf):
    pass


class SecondaryRATUsageDataReport(Buf):
    pass


class SelectionMode(Buf):
    pass


class SequenceNumber(Buf):
    pass


class ServiceIndicator(Buf):
    pass


class ServingNetwork(Buf):
    pass


class ServingPLMNRateControl(Buf):
    pass


class SignallingPriorityInd(Buf):
    pass


class SourceIdentification(Buf):
    pass


class SourceRNCPDCPContextInfo(Buf):
    pass


class SpecialIETypeForIETypeExt(Buf):
    pass


class TAD(Buf):
    pass


class TMGI(Buf):
    pass


class TMSI(Buf):
    pass


class TWANIdent(Buf):
    pass


class TWANIdentTimestamp(Buf):
    pass


class TWMI(Buf):
    pass


class TargetIdentification(Buf):
    pass


class Throttling(Buf):
    pass


class TraceInfo(Buf):
    pass


class TraceReference(Buf):
    pass


class UCI(Buf):
    pass


class UETimeZone(Buf):
    pass


class ULI(Buf):
    pass


class ULITimestamp(Buf):
    pass


class UPFunctionSelectionIndFlags(Buf):
    pass


class WLANOffloadabilityInd(Buf):
    pass


# Following are all proper IE definitions

#------------------------------------------------------------------------------#
# IMSI
# TS 29.274, 8.3
#------------------------------------------------------------------------------#

class IMSI(BufBCD):
    pass


#------------------------------------------------------------------------------#
# Cause
# TS 29.274, 8.4
#------------------------------------------------------------------------------#

Cause_dict = {
    1 : 'Reserved',
    2 : 'Local Detach',
    3 : 'Complete Detach',
    4 : 'RAT changed from 3GPP to Non-3GPP',
    5 : 'ISR deactivation',
    6 : 'Error Indication received from RNC/eNodeB/S4-SGSN/MME',
    7 : 'IMSI Detach Only',
    8 : 'Reactivation Requested',
    9 : 'PDN reconnection to this APN disallowed',
    10 : 'Access changed from Non-3GPP to 3GPP',
    11 : 'PDN connection inactivity timer expires',
    12 : 'PGW not responding',
    13 : 'Network Failure',
    14 : 'QoS parameter mismatch',
    15 : 'EPS to 5GS Mobility',
    16 : 'Request accepted',
    17 : 'Request accepted partially',
    18 : 'New PDN type due to network preference.',
    19 : 'New PDN type due to single address bearer only.',
    64 : 'Context Not Found',
    65 : 'Invalid Message Format',
    66 : 'Version not supported by next peer',
    67 : 'Invalid length',
    68 : 'Service not supported',
    69 : 'Mandatory IE incorrect',
    70 : 'Mandatory IE missing',
    71 : 'Shall not be used. See NOTE 2 and NOTE 3.',
    72 : 'System failure',
    73 : 'No resources available',
    74 : 'Semantic error in the TFT operation',
    75 : 'Syntactic error in the TFT operation',
    76 : 'Semantic errors in packet filter(s)',
    77 : 'Syntactic errors in packet filter(s)',
    78 : 'Missing or unknown APN',
    79 : 'Shall not be used. See NOTE 2 and NOTE 3.',
    80 : 'GRE key not found',
    81 : 'Relocation failure',
    82 : 'Denied in RAT',
    83 : 'Preferred PDN type not supported',
    84 : 'All dynamic addresses are occupied',
    85 : 'UE context without TFT already activated. See NOTE 6.',
    86 : 'Protocol type not supported',
    87 : 'UE not responding. See NOTE 7.',
    88 : 'UE refuses',
    89 : 'Service denied. See NOTE 7.',
    90 : 'Unable to page UE',
    91 : 'No memory available',
    92 : 'User authentication failed',
    93 : 'APN access denied – no subscription',
    94 : 'Request rejected (reason not specified)',
    95 : 'P-TMSI Signature mismatch',
    96 : 'IMSI/IMEI not known',
    97 : 'Semantic error in the TAD operation',
    98 : 'Syntactic error in the TAD operation',
    99 : 'Shall not be used. See NOTE 2 and NOTE 3.',
    100 : 'Remote peer not responding',
    101 : 'Collision with network initiated request',
    102 : 'Unable to page UE due to Suspension',
    103 : 'Conditional IE missing',
    104 : 'APN Restriction type Incompatible with currently active PDN connection',
    105 : 'Invalid overall length of the triggered response message and a piggybacked initial message',
    106 : 'Data forwarding not supported',
    107 : 'Invalid reply from remote peer',
    108 : 'Fallback to GTPv1',
    109 : 'Invalid peer',
    110 : 'Temporarily rejected due to handover/TAU/RAU procedure in progress',
    111 : 'Modifications not limited to S1-U bearers',
    112 : 'Request rejected for a PMIPv6 reason (see 3GPP TS 29.275).',
    113 : 'APN Congestion',
    114 : 'Bearer handling not supported',
    115 : 'UE already re-attached. See NOTE 7.',
    116 : 'Multiple PDN connections for a given APN not allowed',
    117 : 'Target access restricted for the subscriber',
    118 : 'Shall not be used. See NOTE 2 and NOTE 3.',
    119 : 'MME/SGSN refuses due to VPLMN Policy',
    120 : 'GTP-C Entity Congestion',
    121 : 'Late Overlapping Request ',
    122 : 'Timed out Request ',
    123 : 'UE is temporarily not reachable due to power saving',
    124 : 'Relocation failure due to NAS message redirection',
    125 : 'UE not authorised by OCS or external AAA Server',
    126 : 'Multiple accesses to a PDN connection not allowed',
    127 : 'Request rejected due to UE capability',
    128 : 'S1-U Path Failure. See NOTE 8.',
    129 : '5GC not allowed',
    130 : 'PGW mismatch with network slice subscribed by the UE',
    }


class Cause(Envelope):
    _GEN = (
        Uint8('Val', dic=Cause_dict),
        Uint('spare', bl=5),
        Uint('PCE', bl=1, dic={1: 'error in the PDN Connection IE'}),
        Uint('BCE', bl=1, dic={1: 'error in the Bearer Context IE'}),
        Uint('CS', bl=1, dic={1: 'error originated by the remote node'}),
        Envelope('OffendingIE', GEN=(
            Uint8('Type'),
            Uint16('Len'),
            Uint('spare', bl=4),
            Uint('Inst', bl=4)
            ))
        )
    
    def _from_char(self, char):
        ie = self.get_env()
        if ie is not None and ie[0][1].get_val() >= 6:
            # this is an arbitrary choice to expect the OffendingIE part if 
            # the IE length is long enough
            self[5].set_trans(False)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# Recovery
# TS 29.274, 8.5
#------------------------------------------------------------------------------#

class Recovery(Uint8):
    pass


#------------------------------------------------------------------------------#
# APN
# TS 29.274, 8.6
#------------------------------------------------------------------------------#

# imported from TS24008_IE
#class APN(APN):
#    pass


#------------------------------------------------------------------------------#
# AMBR
# TS 29.274, 8.7
#------------------------------------------------------------------------------#

class AMBR(Envelope):
    _GEN = (
        Uint32('APN-AMBR-UL'),
        Uint32('APN-AMBR-DL')
        )


#------------------------------------------------------------------------------#
# EBI
# TS 29.274, 8.8
#------------------------------------------------------------------------------#

class EBI(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Val', val=5, bl=4),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# IP Address
# TS 29.274, 8.9
#------------------------------------------------------------------------------#

class IPAddress(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# MEI
# TS 29.274, 8.10
#------------------------------------------------------------------------------#

class MEI(BufBCD):
    pass


#------------------------------------------------------------------------------#
# MSISDN
# TS 29.274, 8.11
#------------------------------------------------------------------------------#

class MSISDN(BufBCD):
    pass


#------------------------------------------------------------------------------#
# Indication
# TS 29.274, 8.12
#------------------------------------------------------------------------------#

class Ind(BitFlags):
    _GEN = (
        Envelope('Octet1', GEN=(
            Uint('DAF', bl=1),
            Uint('DTF', bl=1),
            Uint('HI', bl=1),
            Uint('DFI', bl=1),
            Uint('OI', bl=1),
            Uint('ISRSI', bl=1),
            Uint('ISRAI', bl=1),
            Uint('SGWCI', bl=1))),
        Envelope('Octet2', GEN=(
            Uint('SQCI', bl=1),
            Uint('UIMSI', bl=1),
            Uint('CFSI', bl=1),
            Uint('CRSI', bl=1),
            Uint('P', bl=1),
            Uint('PT', bl=1),
            Uint('SI', bl=1),
            Uint('MSV', bl=1))),
        Envelope('Octet3', GEN=(
            Uint('RetLoc', bl=1),
            Uint('PBIC', bl=1),
            Uint('SRNI', bl=1),
            Uint('S6AF', bl=1),
            Uint('S4AF', bl=1),
            Uint('MBMDT', bl=1),
            Uint('ISRAU', bl=1),
            Uint('CCRSI', bl=1))),
        Envelope('Octet4', GEN=(
            Uint('CPRAI', bl=1),
            Uint('ARRL', bl=1),
            Uint('PPOF', bl=1),
            Uint('PPON/PPEI', bl=1),
            Uint('PPSI', bl=1),
            Uint('CSFBI', bl=1),
            Uint('CLII', bl=1),
            Uint('CPSR', bl=1))),
        Envelope('Octet5', GEN=(
            Uint('NSI', bl=1),
            Uint('UASI', bl=1),
            Uint('DTCI', bl=1),
            Uint('BDWI', bl=1),
            Uint('PCSI', bl=1),
            Uint('PCRI', bl=1),
            Uint('AOSI', bl=1),
            Uint('AOPI', bl=1))),
        Envelope('Octet6', GEN=(
            Uint('ROAAI', bl=1),
            Uint('EPCOSI', bl=1),
            Uint('CPOPCI', bl=1),
            Uint('PMTSMI', bl=1),
            Uint('S11TF', bl=1),
            Uint('PNSI', bl=1),
            Uint('UNACCSI', bl=1),
            Uint('WPMSI', bl=1))),
        Envelope('Octet7', GEN=(
            Uint('5GSNN26', bl=1),
            Uint('REPREFI', bl=1),
            Uint('5GSIWK', bl=1),
            Uint('EEVRSI', bl=1),
            Uint('LTEMUI', bl=1),
            Uint('LTEMPI', bl=1),
            Uint('ENBCRSI', bl=1),
            Uint('TSPCMI', bl=1))),
        Envelope('Octet8', GEN=(
            Uint('CSRMFI', bl=1),
            Uint('MTEDTN', bl=1),
            Uint('MTEDTA', bl=1),
            Uint('N5GNMI', bl=1),
            Uint('5GCNRS', bl=1),
            Uint('5GCNRI', bl=1),
            Uint('5SRHOI', bl=1),
            Uint('ETHPDN', bl=1))),
        Envelope('Octet9', GEN=(
            Uint('spare', bl=1),
            Uint('PGWRNSI', bl=1),
            Uint('RPPCSI', bl=1),
            Uint('PGWCHI', bl=1),
            Uint('SISSME', bl=1),
            Uint('NSENBI', bl=1),
            Uint('IDFUPF', bl=1),
            Uint('EMCI', bl=1))),
        Buf('ext', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# PCO
# TS 29.274, 8.13
#------------------------------------------------------------------------------#

class PCO(ProtConfig):
    pass


#------------------------------------------------------------------------------#
# PAA
# TS 29.274, 8.14
#------------------------------------------------------------------------------#

PDNType_dict = {
    1 : 'IPv4',
    2 : 'IPv6',
    3 : 'IPv4v6',
    4 : 'Non-IP',
    5 : 'Ethernet'
    }

class PAA(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('PDNType', val=1, bl=3, dic=PDNType_dict),
        Buf('PDNAddress', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Bearer QoS
# TS 29.274, 8.15
#------------------------------------------------------------------------------#

class BearerQoS(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('PCI', bl=1),
        Uint('PL', bl=4),
        Uint('spare', bl=1),
        Uint('PVI', bl=1),
        Uint8('QCI', val=9),
        Uint('MaxBitRateUL', val=10000, bl=40),
        Uint('MaxBitRateDL', val=10000, bl=40),
        Uint('GuaranteedBitRateUL', bl=40),
        Uint('GuaranteedBitRateDL', bl=40),
        Buf('ext', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Flow QoS
# TS 29.274, 8.16
#------------------------------------------------------------------------------#

class FlowQoS(Envelope):
    _GEN = (
        Uint8('QCI', val=9),
        Uint('MaxBitRateUL', val=10000, bl=40),
        Uint('MaxBitRateDL', val=10000, bl=40),
        Uint('GuaranteedBitRateUL', bl=40),
        Uint('GuaranteedBitRateDL', bl=40),
        Buf('ext', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# RAT Type
# TS 29.274, 8.17
#------------------------------------------------------------------------------#

RATType_dict = {
    0 : 'reserved',
    1 : 'UTRAN',
    2 : 'GERAN',
    3 : 'WLAN',
    4 : 'GAN',
    5 : 'HSPA Evolution',
    6 : 'EUTRAN (WB-E-UTRAN)',
    7 : 'Virtual',
    8 : 'EUTRAN-NB-IoT',
    9 : 'LTE-M',
    10 : 'NR'
    }

class RATType(Envelope):
    _GEN = (
        Uint8('Val', val=6, dic=RATType_dict),
        Buf('ext', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Serving Network
# TS 29.274, 8.18
#------------------------------------------------------------------------------#

class ServingNetwork(Envelope):
    _GEN = (
        PLMN(),
        Buf('ext', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Bearer TFT
# TS 29.274, 8.19
#------------------------------------------------------------------------------#

class BearerTFT(TFT):
    pass


#------------------------------------------------------------------------------#
# Traffic Aggregate Description (TAD)
# TS 29.274, 8.20
#------------------------------------------------------------------------------#

class TAD(TFT):
    pass


#------------------------------------------------------------------------------#
# User Location Information (ULI)
# TS 29.274, 8.21
#------------------------------------------------------------------------------#
# Warning, within TS 29.274, the RAC is 2 bytes, with 2nd byte being 0xff
# this is different from other specification where the RAC is only 1 byte

# 8.21.1 CGI field
class CGI(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint16('CI', rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val(), self[2].get_val())


# 8.21.2 SAI field
class SAI(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint16('SAC', rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val(), self[2].get_val())


# 8.21.3 RAI field
class RAI(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint8('RAC', rep=REPR_HEX),
        Uint8('spare', val=0xff, rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val(), self[2].get_val())


# 8.21.4 TAI field, identical to TS 24.301

# 8.21.5 ECGI field
class ECGI(Envelope):
    _GEN = (
        PLMN(),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('ECI', bl=28, rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[2].get_val())


# 8.21.6 LAI field, identical to TS 24.008

# 8.21.7 Macro eNodeB ID field
class MacroENBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('MacroENBID', bl=20, rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[2].get_val())


# 8.21.8 Extended Macro eNodeB ID field
class ExtMacroENBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('SMeNB', bl=1, dic={0: 'long', 1: 'short'}),
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('ExtMacroENBID', bl=21, rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val(), self[3].get_val())


class ULI(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Envelope('Flags', GEN=(
            Uint('ExtMacroENBID', bl=1),
            Uint('MacroENBID', bl=1),
            Uint('LAI', bl=1),
            Uint('ECGI', bl=1),
            Uint('TAI', bl=1),
            Uint('RAI', bl=1),
            Uint('SAI', bl=1),
            Uint('CGI', bl=1)
            )),
        CGI(),
        SAI(),
        RAI(),
        TAI(),
        ECGI(),
        LAI(),
        MacroENBID(),
        ExtMacroENBID(),
        Buf('ext', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(lambda: self[0][7].get_val() == 0)
        self[2].set_transauto(lambda: self[0][6].get_val() == 0)
        self[3].set_transauto(lambda: self[0][5].get_val() == 0)
        self[4].set_transauto(lambda: self[0][4].get_val() == 0)
        self[5].set_transauto(lambda: self[0][3].get_val() == 0)
        self[6].set_transauto(lambda: self[0][2].get_val() == 0)
        self[7].set_transauto(lambda: self[0][1].get_val() == 0)
        self[8].set_transauto(lambda: self[0][0].get_val() == 0)


#------------------------------------------------------------------------------#
# Fully Qualified TEID (F-TEID)
# TS 29.274, 8.22
#------------------------------------------------------------------------------#

FTEIDIF_dict = {
    0: 'S1-U eNodeB GTP-U interface',
    1: 'S1-U SGW GTP-U interface',
    2: 'S12 RNC GTP-U interface',
    3: 'S12 SGW GTP-U interface',
    4: 'S5/S8 SGW GTP-U interface',
    5: 'S5/S8 PGW GTP-U interface',
    6: 'S5/S8 SGW GTP-C interface',
    7: 'S5/S8 PGW GTP-C interface',
    8: 'S5/S8 SGW PMIPv6 interface (the 32 bit GRE key is encoded in 32 bit TEID field)',
    9: 'S5/S8 PGW PMIPv6 interface (the 32 bit GRE key is encoded in the 32 bit TEID field, see clause 6.3 of 3GPP TS 29.275)',
    10: 'S11 MME GTP-C interface',
    11: 'S11/S4 SGW GTP-C interface',
    12: 'S10/N26 MME GTP-C interface',
    13: 'S3 MME GTP-C interface',
    14: 'S3 SGSN GTP-C interface',
    15: 'S4 SGSN GTP-U interface',
    16: 'S4 SGW GTP-U interface',
    17: 'S4 SGSN GTP-C interface',
    18: 'S16 SGSN GTP-C interface',
    19: 'eNodeB GTP-U interface for DL data forwarding',
    20: 'eNodeB GTP-U interface for UL data forwarding',
    21: 'RNC GTP-U interface for data forwarding',
    22: 'SGSN GTP-U interface for data forwarding',
    23: 'SGW/UPF GTP-U interface for DL data forwarding',
    24: 'Sm MBMS GW GTP-C interface',
    25: 'Sn MBMS GW GTP-C interface',
    26: 'Sm MME GTP-C interface',
    27: 'Sn SGSN GTP-C interface',
    28: 'SGW GTP-U interface for UL data forwarding',
    29: 'Sn SGSN GTP-U interface',
    30: 'S2b ePDG GTP-C interface',
    31: 'S2b-U ePDG GTP-U interface',
    32: 'S2b PGW GTP-C interface',
    33: 'S2b-U PGW GTP-U interface',
    34: 'S2a TWAN GTP-U interface',
    35: 'S2a TWAN GTP-C interface',
    36: 'S2a PGW GTP-C interface',
    37: 'S2a PGW GTP-U interface',
    38: 'S11 MME GTP-U interface',
    39: 'S11 SGW GTP-U interface',
    40: 'N26 AMF GTP-C interface',
    }

class FTEID(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('V4', val=1, bl=1),
        Uint('V6', bl=1),
        Uint('IF', bl=6, dic=FTEIDIF_dict),
        Uint32('TEID_GREKey', rep=REPR_HEX),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Buf('ext')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_transauto(lambda: self[0].get_val() == 0)
        self[5].set_transauto(lambda: self[1].get_val() == 0)


#------------------------------------------------------------------------------#
# TMSI
# TS 29.274, 8.23
#------------------------------------------------------------------------------#

class TMSI(Uint32):
    rep = REPR_HEX


#------------------------------------------------------------------------------#
# Global CN-Id
# TS 29.274, 8.24
#------------------------------------------------------------------------------#
# in RANAP, CN-ID is an INTEGER (0..4096)
# but TS 29.274 does not provide any boundary on the length

class GlobalCNId(Envelope):
    _GEN = (
        PLMN(),
        Buf('CNId', val=b'\0\0', rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val())


#------------------------------------------------------------------------------#
# S103 PDN Data Forwarding Info (S103PDF)
# TS 29.274, 8.25
#------------------------------------------------------------------------------#

class S103PDF(Envelope):
    _GEN = (
        Uint8('HSGWAddrLen'),
        Buf('HSGWAddr', val=4*b'\0', rep=REPR_HEX), # IPv4 or v6
        Uint32('GREKey', rep=REPR_HEX),
        Uint8('EBINum'),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('EBI', val=5, bl=4)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['HSGWAddrLen'].set_valauto(lambda: self['HSGWAddr'].get_len())
        self['HSGWAddr'].set_blauto(lambda: self['HSGWAddrLen'].get_val()<<3)


#------------------------------------------------------------------------------#
# S1-U Data Forwarding (S1UDF)
# TS 29.274, 8.26
#------------------------------------------------------------------------------#

class S1UDF(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('EBI', val=5, bl=4),
        Uint8('SGWAddrLen'),
        Buf('SGWAddr', val=4*b'\0', rep=REPR_HEX), # IPv4 or v6
        Uint32('TEID', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Delay Value
# TS 29.274, 8.27
#------------------------------------------------------------------------------#

class DelayValue(Envelope):
    _GEN = (
        Uint8('Val', desc='50 ms multiple'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Bearer Context
# TS 29.274, 8.28
#------------------------------------------------------------------------------#
# Bearer Context is a grouped IE that is always defined locally for each GTPCMsg

class BearerContext(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Charging ID
# TS 29.274, 8.29
#------------------------------------------------------------------------------#

class ChargingID(Envelope):
    _GEN = (
        Uint32('Val', rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Charging Characteristics
# TS 29.274, 8.30
#------------------------------------------------------------------------------#

class ChargingCharacteristics(Envelope):
    _GEN = (
        Uint16('Val', rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Trace Information
# TS 29.274, 8.31
#------------------------------------------------------------------------------#

class TraceInfo(Envelope):
    _GEN = (
        PLMN(),
        Uint24('TraceID', rep=REPR_HEX),
        Uint64('TriggeringEvents', rep=REPR_HEX),
        Uint16('ListOfNETypes', rep=REPR_HEX),
        Uint8('SessionTraceDepth'),
        Buf('ListOfInterfaces', bl=96, rep=REPR_HEX),
        Buf('IPAddrForCollection', val=4*b'\0', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Bearer Flags
# TS 29.274, 8.32
#------------------------------------------------------------------------------#

class BearerFlags(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('ASI', bl=1),
        Uint('Vind', bl=1),
        Uint('VB', bl=1),
        Uint('PPC', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# PDN Type
# TS 29.274, 8.34
#------------------------------------------------------------------------------#

class PDNType(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('Val', val=1, bl=3, dic=PDNType_dict)
        )


#------------------------------------------------------------------------------#
# Procedure Transaction ID (PTI) 
# TS 29.274, 8.35
#------------------------------------------------------------------------------#

class PTI(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# MM Context
# TS 29.274, 8.38
#------------------------------------------------------------------------------#

# 8.38-7
class MMContextTriplet(Envelope):
    _GEN = (
        Buf('RAND', bl=128, rep=REPR_HEX),
        Buf('SRES', bl=32, rep=REPR_HEX),
        Buf('Kc', bl=64, rep=REPR_HEX)
        )


# 8.38-8
class MMContextQuintuplet(Envelope):
    _GEN = (
        Buf('RAND', bl=128, rep=REPR_HEX),
        Uint8('XRESLen'),
        Buf('XRES', rep=REPR_HEX),
        Buf('CK', bl=128, rep=REPR_HEX),
        Buf('IK', bl=128, rep=REPR_HEX),
        Uint8('AUTNLen'),
        Buf('AUTN', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: 8*self[1].get_val())
        self[5].set_valauto(lambda: self[6].get_len())
        self[6].set_blauto(lambda: 8*self[5].get_val())


# 8.38-9
class MMContextQuadruplet(Envelope):
    _GEN = (
        Buf('RAND', bl=128, rep=REPR_HEX),
        Uint8('XRESLen'),
        Buf('XRES', rep=REPR_HEX),
        Uint8('AUTNLen'),
        Buf('AUTN', rep=REPR_HEX),
        Buf('KASME', bl=256, rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: 8*self[1].get_val())
        self[3].set_valauto(lambda: self[4].get_len())
        self[4].set_blauto(lambda: 8*self[3].get_val())


# 8.38-10
class MMContextAPNRateCtrlStat(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint16('APNLen'),
        Buf('APN'),
        Uint32('ULNumOfPktAllowed'),
        Uint32('NumAddExceptReports'),
        Uint32('DLNumOfPktAllowed'),
        Uint64('ValidityTime')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: 8*self[1].get_val())


MMContextSecurityType_dict = {
    0 : 'GSM Key and Triplets',
    1 : 'UMTS Key, Used Cipher and Quintuplets',
    2 : 'GSM Key, Used Cipher and Quintuplets',
    3 : 'UMTS Key and Quintuplets',
    4 : 'EPS Security Context and Quadruplets',
    5 : 'UMTS Key, Quadruplets and Quintuplets',
    }


# some automated basic structures
class MMContextUENetCap(Envelope):
    _GEN = (
        Uint8('Len'),
        UENetCap()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = min(char._cur + 8 * self[0].get_val(), char_lb)
        self[1]._from_char(char)
        char._len_bit = char_lb


class MMContextMSNetCap(Envelope):
    _GEN = (
        Uint8('Len'),
        ms_network_capability_value_part
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = min(char._cur + 8 * self[0].get_val(), char_lb)
        self[1]._from_char(char)
        char._len_bit = char_lb


class MMContextMEI(Envelope):
    _GEN = (
        Uint8('Len'),
        BufBCD('MEI')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())


class MMContextVoiceDomPref(Envelope):
    _GEN = (
        Uint8('Len'),
        VoiceDomPref()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = min(char._cur + 8 * self[0].get_val(), char_lb)
        self[1]._from_char(char)
        char._len_bit = char_lb
    

class MMContextHigherBitRate(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('HigherBitRate', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())


class MMContextExtAccessRestrictData(Envelope):
    _GEN = (
        Uint8('Len', val=1),
        Uint('spare', bl=6),
        Uint('USSRNA', bl=1),
        Uint('NRSRNA', bl=1)
        )


class MMContextUERadioCapForPaging(Envelope):
    _GEN = (
        Uint16('Len'),
        Buf('UERadioCapForPaging', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())


class MMContextUEAddSecCap(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('UEAddSecCap', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())


class MMContextUENRSecCap(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('UENRSecCap', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())


class MMContextAPNRateCtrlStats(Envelope):
    _GEN = (
        Uint16('Len'),
        Sequence('APNRateCtrlStats', GEN=MMContextAPNRateCtrlStat())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = min(char._cur + 8 * self[0].get_val(), char_lb)
        self[1]._from_char(char)
        char._len_bit = char_lb


# 8.38-1
# Type 103
class MMContext_GSMKeyTriplets(Envelope):
    _GEN = (
        Uint('SecurityMode', bl=3, dic=MMContextSecurityType_dict),
        Uint('spare', bl=1),
        Uint('DRXI', bl=1),
        Uint('CKSN', bl=3),
        Uint('NumOfTriplets', bl=3),
        Uint('spare', bl=3),
        Uint('UAMBRI', bl=1),
        Uint('SAMBRI', bl=1),
        Uint('spare', bl=5),
        Uint('UsedCipher', bl=3),
        Buf('Kc', bl=64, rep=REPR_HEX),
        Sequence('Triplets', GEN=MMContextTriplet()),
        DRXParam(),
        Uint32('ULSubscribedUEAMBR'),
        Uint32('DLSubscribedUEAMBR'),
        Uint32('ULUsedUEAMBR'),
        Uint32('DLUsedUEAMBR'),
        MMContextUENetCap(),
        MMContextMSNetCap(),
        MMContextMEI(),
        Uint('ECNA', bl=1),
        Uint('NBNA', bl=1),
        Uint('HNNA', bl=1),
        Uint('ENA', bl=1),
        Uint('INA', bl=1),
        Uint('GANA', bl=1),
        Uint('GENA', bl=1),
        Uint('UNA', bl=1),
        MMContextVoiceDomPref(),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumOfTriplets'].set_valauto(lambda: self['Triplets'].get_num())
        self['Triplets'].set_numauto(lambda: self['NumOfTriplets'].get_val())


# 8.38-2
# Type 104
class MMContext_UMTSKeyUsedCipherQuintuplets(Envelope):
    _GEN = (
        Uint('SecurityMode', bl=3, dic=MMContextSecurityType_dict),
        Uint('spare', bl=1),
        Uint('DRXI', bl=1),
        Uint('CKSN', bl=3),
        Uint('NumOfQuintuplets', bl=3),
        Uint('IOVI', bl=1),
        Uint('GUPII', bl=1),
        Uint('UGIPAI', bl=1),
        Uint('UAMBRI', bl=1),
        Uint('SAMBRI', bl=1),
        Uint('spare', bl=2),
        Uint('UsedGPRSIntegrityProtAlg', bl=3),
        Uint('UsedCipher', bl=3),
        Buf('CK', bl=128, rep=REPR_HEX),
        Buf('IK', bl=128, rep=REPR_HEX),
        Sequence('Quintuplets', GEN=MMContextQuintuplet()),
        DRXParam(),
        Uint32('ULSubscribedUEAMBR'),
        Uint32('DLSubscribedUEAMBR'),
        Uint32('ULUsedUEAMBR'),
        Uint32('DLUsedUEAMBR'),
        MMContextUENetCap(),
        MMContextMSNetCap(),
        MMContextMEI(),
        Uint('ECNA', bl=1),
        Uint('NBNA', bl=1),
        Uint('HNNA', bl=1),
        Uint('ENA', bl=1),
        Uint('INA', bl=1),
        Uint('GANA', bl=1),
        Uint('GENA', bl=1),
        Uint('UNA', bl=1),
        MMContextVoiceDomPref(),
        MMContextHigherBitRate(),
        Uint8('IOVUpdateCounter'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumOfQuintuplets'].set_valauto(lambda: self['Quintuplets'].get_num())
        self['Quintuplets'].set_numauto(lambda: self['NumOfQuintuplets'].get_val())


# 8.38-3
# Type 105
class MMContext_GSMKeyUsedCipherQuintuplets(Envelope):
    _GEN = (
        Uint('SecurityMode', bl=3, dic=MMContextSecurityType_dict),
        Uint('spare', bl=1),
        Uint('DRXI', bl=1),
        Uint('CKSN', bl=3),
        Uint('NumOfQuintuplets', bl=3),
        Uint('spare', bl=3),
        Uint('UAMBRI', bl=1),
        Uint('SAMBRI', bl=1),
        Uint('spare', bl=5),
        Uint('UsedCipher', bl=3),
        Buf('Kc', bl=64, rep=REPR_HEX),
        Sequence('Quintuplets', GEN=MMContextQuintuplet()),
        DRXParam(),
        Uint32('ULSubscribedUEAMBR'),
        Uint32('DLSubscribedUEAMBR'),
        Uint32('ULUsedUEAMBR'),
        Uint32('DLUsedUEAMBR'),
        MMContextUENetCap(),
        MMContextMSNetCap(),
        MMContextMEI(),
        Uint('ECNA', bl=1),
        Uint('NBNA', bl=1),
        Uint('HNNA', bl=1),
        Uint('ENA', bl=1),
        Uint('INA', bl=1),
        Uint('GANA', bl=1),
        Uint('GENA', bl=1),
        Uint('UNA', bl=1),
        MMContextVoiceDomPref(),
        MMContextHigherBitRate(),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumOfQuintuplets'].set_valauto(lambda: self['Quintuplets'].get_num())
        self['Quintuplets'].set_numauto(lambda: self['NumOfQuintuplets'].get_val())


# 8.38-4
# Type 106
class MMContext_UMTSKeyQuintuplets(Envelope):
    _GEN = (
        Uint('SecurityMode', bl=3, dic=MMContextSecurityType_dict),
        Uint('spare', bl=1),
        Uint('DRXI', bl=1),
        Uint('KSI', bl=3),
        Uint('NumOfQuintuplets', bl=3),
        Uint('IOVI', bl=1),
        Uint('GUPII', bl=1),
        Uint('UGIPAI', bl=1),
        Uint('UAMBRI', bl=1),
        Uint('SAMBRI', bl=1),
        Uint('spare', bl=5),
        Uint('UsedGPRSIntegrityProtAlg', bl=3),
        Buf('CK', bl=128, rep=REPR_HEX),
        Buf('IK', bl=128, rep=REPR_HEX),
        Sequence('Quintuplets', GEN=MMContextQuintuplet()),
        DRXParam(),
        Uint32('ULSubscribedUEAMBR'),
        Uint32('DLSubscribedUEAMBR'),
        Uint32('ULUsedUEAMBR'),
        Uint32('DLUsedUEAMBR'),
        MMContextUENetCap(),
        MMContextMSNetCap(),
        MMContextMEI(),
        Uint('ECNA', bl=1),
        Uint('NBNA', bl=1),
        Uint('HNNA', bl=1),
        Uint('ENA', bl=1),
        Uint('INA', bl=1),
        Uint('GANA', bl=1),
        Uint('GENA', bl=1),
        Uint('UNA', bl=1),
        MMContextVoiceDomPref(),
        MMContextHigherBitRate(),
        Uint8('IOVUpdatesCounter'),
        MMContextExtAccessRestrictData(),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumOfQuintuplets'].set_valauto(lambda: self['Quintuplets'].get_num())
        self['Quintuplets'].set_numauto(lambda: self['NumOfQuintuplets'].get_val())


# 8.38-5
# Type 107
class MMContext_EPSSecContextQuadruplets(Envelope):
    _GEN = (
        Uint('SecurityMode', bl=3, dic=MMContextSecurityType_dict),
        Uint('NHI', bl=1),
        Uint('DRXI', bl=1),
        Uint('KSI', bl=3),
        Uint('NumOfQuintuplets', bl=3),
        Uint('NumOfQuadruplets', bl=3),
        Uint('UAMBRI', bl=1),
        Uint('OSCI', bl=1),
        Uint('SAMBRI', bl=1),
        Uint('NASIntegrityProtAlg', bl=3),
        Uint('NASCipherAlg', bl=3),
        Uint16('NASDLCount'),
        Uint16('NASULCount'),
        Buf('KASME', bl=256, rep=REPR_HEX),
        Sequence('Quadruplets', GEN=MMContextQuadruplet()),
        Sequence('Quintuplets', GEN=MMContextQuintuplet()),
        DRXParam(),
        Buf('NH', bl=256, rep=REPR_HEX),
        Uint('spare', bl=5),
        Uint('NCC', bl=3),
        Uint32('ULSubscribedUEAMBR'),
        Uint32('DLSubscribedUEAMBR'),
        Uint32('ULUsedUEAMBR'),
        Uint32('DLUsedUEAMBR'),
        MMContextUENetCap(),
        MMContextMSNetCap(),
        MMContextMEI(),
        Uint('ECNA', bl=1),
        Uint('NBNA', bl=1),
        Uint('HNNA', bl=1),
        Uint('ENA', bl=1),
        Uint('INA', bl=1),
        Uint('GANA', bl=1),
        Uint('GENA', bl=1),
        Uint('UNA', bl=1),
        Uint('S', bl=1),
        Uint('NHIOld', bl=1),
        Uint('spare', bl=1),
        Uint('KSIOld', bl=3),
        Uint('NCCOld', bl=3),
        Buf('KASMEOld', bl=256, rep=REPR_HEX),
        Buf('NHOld', bl=256, rep=REPR_HEX),
        MMContextVoiceDomPref(),
        MMContextUERadioCapForPaging(),
        MMContextExtAccessRestrictData(),
        MMContextUEAddSecCap(),
        MMContextUENRSecCap(),
        MMContextAPNRateCtrlStats(),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumOfQuintuplets'].set_valauto(lambda: self['Quintuplets'].get_num())
        self['Quintuplets'].set_numauto(lambda: self['NumOfQuintuplets'].get_val())
        self['NumOfQuadruplets'].set_valauto(lambda: self['Quadruplets'].get_num())
        self['Quadruplets'].set_numauto(lambda: self['NumOfQuadruplets'].get_val())


# 8.38-6
# UMTS Key, Quadruplets and Quintuplets
class MMContext_UMTSKeyQuadrupletsQuintuplets(Envelope):
    _GEN = (
        Uint('SecurityMode', bl=3, dic=MMContextSecurityType_dict),
        Uint('spare', bl=1),
        Uint('DRXI', bl=1),
        Uint('KSI', bl=3),
        Uint('NumOfQuintuplets', bl=3),
        Uint('NumOfQuadruplets', bl=3),
        Uint('UAMBRI', bl=1),
        Uint('SAMBRI', bl=1),
        Uint8('spare', rep=REPR_HEX),
        Buf('CK', bl=128, rep=REPR_HEX),
        Buf('IK', bl=128, rep=REPR_HEX),
        Sequence('Quadruplets', GEN=MMContextQuadruplet()),
        Sequence('Quintuplets', GEN=MMContextQuintuplet()),
        DRXParam(),
        Uint32('ULSubscribedUEAMBR'),
        Uint32('DLSubscribedUEAMBR'),
        Uint32('ULUsedUEAMBR'),
        Uint32('DLUsedUEAMBR'),
        MMContextUENetCap(),
        MMContextMSNetCap(),
        MMContextMEI(),
        Uint('ECNA', bl=1),
        Uint('NBNA', bl=1),
        Uint('HNNA', bl=1),
        Uint('ENA', bl=1),
        Uint('INA', bl=1),
        Uint('GANA', bl=1),
        Uint('GENA', bl=1),
        Uint('UNA', bl=1),
        MMContextVoiceDomPref(),
        MMContextAPNRateCtrlStats(),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumOfQuintuplets'].set_valauto(lambda: self['Quintuplets'].get_num())
        self['Quintuplets'].set_numauto(lambda: self['NumOfQuintuplets'].get_val())
        self['NumOfQuadruplets'].set_valauto(lambda: self['Quadruplets'].get_num())
        self['Quadruplets'].set_numauto(lambda: self['NumOfQuadruplets'].get_val())


class MMContext(Alt):
    _GEN = {
        103: MMContext_GSMKeyTriplets(),
        104: MMContext_UMTSKeyUsedCipherQuintuplets(),
        105: MMContext_GSMKeyUsedCipherQuintuplets(),
        106: MMContext_UMTSKeyQuintuplets(),
        107: MMContext_EPSSecContextQuadruplets(),
        108: MMContext_UMTSKeyQuadrupletsQuintuplets()
        }
    DEFAULT = Buf('MMContext')
    _sel = lambda a, b: b.get_env()[0][0].get_val() # GTPCIEHdr['Type']


#------------------------------------------------------------------------------#
# PDN Connection
# TS 29.274, 8.39
#------------------------------------------------------------------------------#
# PDN Connection is a grouped IE that is always defined locally for each GTPCMsg

class PDNConnection(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# PDU Numbers
# TS 29.274, 8.40
#------------------------------------------------------------------------------#

class PDUNumbers(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NSAPI', bl=4),
        Uint16('DLGTPUSeqn'),
        Uint16('ULGTPUSeqn'),
        Uint16('SendNPDUNum'),
        Uint16('RecvNFPUNum'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Packet TMSI (P-TMSI)
# TS 29.274, 8.41
#------------------------------------------------------------------------------#

class PTMSI(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# P-TMSI Signature
# TS 29.274, 8.42
#------------------------------------------------------------------------------#

class PTMSISignature(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Hop Counter
# TS 29.274, 8.43
#------------------------------------------------------------------------------#

class HopCounter(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# UE Time Zone
# TS 29.274, 8.44
#------------------------------------------------------------------------------#

class UETimeZone(Envelope):
    _GEN = (
        TimeZone(),
        DLSavingTime(),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Trace Reference
# TS 29.274, 8.45
#------------------------------------------------------------------------------#

class TraceReference(Envelope):
    _GEN = (
        PLMN(),
        Uint24('TraceID', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Complete Request Message
# TS 29.274, 8.46
#------------------------------------------------------------------------------#

class CompleteRequestMessage(Envelope):
    _GEN = (
        Uint8('MsgType', dic={0: 'Attach Request', 1: 'TAU Request'}),
        Buf('Msg', rep=REPR_HEX)
        )
        

#------------------------------------------------------------------------------#
# GUTI
# TS 29.274, 8.47
#------------------------------------------------------------------------------#

class GUTI(Envelope):
    _GEN = (
        PLMN(),
        Uint16('MMEGroupID', rep=REPR_HEX),
        Uint8('MMECode', rep=REPR_HEX),
        Uint32('MTMSI', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Fully Qualified Container (F-Container)
# TS 29.274, 8.48
#------------------------------------------------------------------------------#

FContainerType_dict = {
    1 : 'UTRAN Transparent Container',
    2 : 'BSS Container',
    3 : 'E-UTRAN Transparent Container',
    4 : 'NBIFOM Container',
    5 : 'EN-DC Container',
    }

class FContainer(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Type', bl=4, dic=FContainerType_dict),
        Buf('Cont', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Fully Qualified Cause (F-Cause)
# TS 29.274, 8.49
#------------------------------------------------------------------------------#

FCauseType_dict = {
    0 : 'Radio Network Layer',
    1 : 'Transport Layer',
    2 : 'NAS',
    3 : 'Protocol',
    4 : 'Miscellaneous',
    }

class FCause(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Type', bl=4, dic=FCauseType_dict),
        Buf('Cause', val=b'\x6f', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# PLMN ID
# TS 29.274, 8.50
#------------------------------------------------------------------------------#

class PLMNID(PLMN):
    pass


#------------------------------------------------------------------------------#
# Target Identification
# TS 29.274, 8.51
#------------------------------------------------------------------------------#

TargetIdType_dict = {
    0 : 'RNC ID',
    1 : 'Macro eNodeB ID',
    2 : 'Cell Identifier',
    3 : 'Home eNodeB ID',
    4 : 'Extended Macro eNodeB ID',
    5 : 'gNodeB ID',
    6 : 'Macro ng-eNodeB ID',
    7 : 'Extended ng-eNodeB ID',
    8 : 'en-gNB ID',
    }


class RNCID(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint8('RAC', rep=REPR_HEX),
        Uint16('RNCID', rep=REPR_HEX),
        Buf('ExtRNCID', val=b'', rep=REPR_HEX)
        )


class MacroENBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('MacroENBID', bl=20, rep=REPR_HEX),
        Uint16('TAC', rep=REPR_HEX)
        )


class HENBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('HENBID', bl=28, rep=REPR_HEX),
        Uint16('TAC', rep=REPR_HEX)
        )


class ExtMacroENBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('SMeNB', bl=1),
        Alt('ENBID', GEN={
            0 : Envelope('Long', GEN=(
                Uint('spare', bl=2, rep=REPR_HEX),
                Uint('MacroENBID', bl=21, rep=REPR_HEX))),
            1 : Envelope('Short', GEN=(
                Uint('spare', bl=5, rep=REPR_HEX),
                Uint('MacroENBID', bl=18, rep=REPR_HEX)))},
            sel=lambda self: self.get_env()['SMeNB'].get_val()),
        Uint16('TAC', rep=REPR_HEX)
        )


class CellID(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint8('RAC', rep=REPR_HEX),
        Uint16('CellID', rep=REPR_HEX)
        )


class GNBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('GNBIDLen', val=32, bl=6), # 24 or 32, where MSB of GNBID are to be set to 0 if 24
        Uint32('GNBID', rep=REPR_HEX),
        Uint24('5GSTAC', rep=REPR_HEX)
        )


class MacroNGENBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('MacroENBID', bl=20, rep=REPR_HEX),
        Uint24('5GSTAC', rep=REPR_HEX)
        )


class ExtNGENBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('SMeNB', bl=1),
        Alt('ENBID', GEN={
            0 : Envelope('Long', GEN=(
                Uint('spare', bl=2, rep=REPR_HEX),
                Uint('MacroENBID', bl=21, rep=REPR_HEX))),
            1 : Envelope('Short', GEN=(
                Uint('spare', bl=5, rep=REPR_HEX),
                Uint('MacroENBID', bl=18, rep=REPR_HEX)))},
            sel=lambda self: self.get_env()['SMeNB'].get_val()),
        Uint24('5GSTAC', rep=REPR_HEX)
        )


class ENGNBID(Envelope):
    _GEN = (
        PLMN(),
        Uint('5TAC', val=1, bl=1),
        Uint('ETAC', bl=1),
        Uint('GNBIDLen', val=32, bl=6), # 24 or 32, where MSB of GNBID are to be set to 0 if 24
        Uint32('GNBID', rep=REPR_HEX),
        Uint16('TAC', rep=REPR_HEX),
        Uint24('5GSTAC', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['TAC'].set_transauto(lambda: self['ETAC'].get_val() == 0)
        self['5GSTAC'].set_transauto(lambda: self['5TAC'].get_val() == 0)


class TargetIdentification(Envelope):
    _GEN = (
        Uint8('Type', dic=TargetIdType_dict),
        Alt('Id', GEN={
            0 : RNCID(),
            1 : MacroENBID(),
            2 : CellID(),
            3 : HENBID(),
            4 : ExtMacroENBID(),
            5 : GNBID(),
            6 : MacroNGENBID(),
            7 : ExtNGENBID(),
            8 : ENGNBID()},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


#------------------------------------------------------------------------------#
# Packet Flow ID
# TS 29.274, 8.53
#------------------------------------------------------------------------------#

class PacketFlowID(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('EBI', val=5, bl=4),
        Buf('Val', val=b'\0\0\0\0', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# RAB Context
# TS 29.274, 8.54
#------------------------------------------------------------------------------#

class RABContext(Envelope):
    _GEN = (
        Uint('ULPSI', bl=1),
        Uint('DLPSI', bl=1),
        Uint('ULGSI', bl=1),
        Uint('DLGSI', bl=1),
        Uint('NSAPI', bl=4),
        Uint16('DLGTPUSeqn'),
        Uint16('ULGTPUSeqn'),
        Uint16('DLPDCPSeqn'),
        Uint16('ULPDCPSeqn'),
        )


#------------------------------------------------------------------------------#
# Source RNC PDCP context info
# TS 29.274, 8.55
#------------------------------------------------------------------------------#

class SourceRNCPDCPContextInfo(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Port Number
# TS 29.274, 8.56
#------------------------------------------------------------------------------#

class PortNumber(Envelope):
    _GEN = (
        Uint16('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# APN Restriction
# TS 29.274, 8.57
#------------------------------------------------------------------------------#

class APNRestriction(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Selection Mode
# TS 29.274, 8.58
#------------------------------------------------------------------------------#

SelectionMode_dict = {
    0 : 'MS or network provided APN, subscription verified',
    1 : 'MS provided APN, subscription not verified',
    2 : 'Network provided APN, subscription not verified',
    }

class SelectionMode(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('Val', bl=2, dic=SelectionMode_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Source Identification
# TS 29.274, 8.59
#------------------------------------------------------------------------------#

class SourceIdentification(Envelope):
    _GEN = (
        CellID('TargetCellID'),
        Uint8('SourceType', dic={0: 'CellID', 1: 'RNCID'}),
        Alt('SourceID', GEN={
            0 : CellID(),
            1 : Buf('RNCID', rep=REPR_HEX), # ASN.1 APER encoded RANAP IE 
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['SourceType'].get_val()
            )
        )


#------------------------------------------------------------------------------#
# Change Reporting Action
# TS 29.274, 8.61
#------------------------------------------------------------------------------#

class ChangeReportingAction(Uint8):
    _dic = {
        0 : 'Stop Reporting',
        1 : 'Start Reporting CGI/SAI',
        2 : 'Start Reporting RAI',
        3 : 'Start Reporting TAI',
        4 : 'Start Reporting ECGI',
        5 : 'Start Reporting CGI/SAI and RAI',
        6 : 'Start Reporting TAI and ECGI',
        7 : 'Start Reporting Macro eNodeB ID and Extended Macro eNodeB ID',
        8 : 'Start Reporting TAI, Macro eNodeB ID and Extended Macro eNodeB ID'
        }


#------------------------------------------------------------------------------#
# Fully qualified PDN Connection Set Identifier (FQ-CSID)
# TS 29.274, 8.62
#------------------------------------------------------------------------------#

# imported from TS29244_PFCP
#class FQCSID(FQCSID):
#    pass


#------------------------------------------------------------------------------#
# Channel Needed
# TS 29.274, 8.63
#------------------------------------------------------------------------------#

class ChannelNeeded(Envelope):
    _GEN = (
        Uint('IEI', val=0xe, rep=REPR_HEX),
        ) + tuple(ChanNeeded()._content)


#------------------------------------------------------------------------------#
# eMLPP Priority
# TS 29.274, 8.64
#------------------------------------------------------------------------------#
# TODO: eMLPP-Priority IE defined in 3GPP TS 48.008

class EMLPPPriority(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Node Type
# TS 29.274, 8.65
#------------------------------------------------------------------------------#

class NodeType(Envelope):
    _GEN = (
        Uint8('Val', dic={0: 'MME', 1: 'SGSN'}),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    

#------------------------------------------------------------------------------#
# Fully Qualified Domain Name (FQDN)
# TS 29.274, 8.66
#------------------------------------------------------------------------------#

class FQDN(_FQDN):
    pass


#------------------------------------------------------------------------------#
# Private Extension
# TS 29.274, 8.67
#------------------------------------------------------------------------------#

class PrivExt(Envelope):
    _GEN = (
        Uint16('EnterpriseID'),
        Buf('Val', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Transaction Identifier
# TS 29.274, 8.68
#------------------------------------------------------------------------------#

# imported from TS24007
#class TI(TI):
#    pass


#------------------------------------------------------------------------------#
# MBMS Session Duration
# TS 29.274, 8.69
#------------------------------------------------------------------------------#

class MBMSSessionDuration(Envelope):
    _GEN = (
        Uint24('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# MBMS Service Area
# TS 29.274, 8.70
#------------------------------------------------------------------------------#

class MBMSServiceArea(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('MBMSServiceAreaCodes', GEN=Uint16('Code'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Num'].set_valauto(lambda: self['MBMSServiceAreaCodes'].get_num())
        self['MBMSServiceAreaCodes'].set_numauto(lambda: self['Num'].get_val())


#------------------------------------------------------------------------------#
# MBMS Session Identifier
# TS 29.274, 8.71
#------------------------------------------------------------------------------#

class MBMSSessionIdent(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# MBMS Flow Identifier
# TS 29.274, 8.72
#------------------------------------------------------------------------------#

class MBMSFlowIdent(Envelope):
    _GEN = (
        Uint16('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# MBMS IP Multicast Distribution
# TS 29.274, 8.73
#------------------------------------------------------------------------------#

class MulticastAddr(Envelope):
    _GEN = (
        Uint('Type', val=0, bl=2, dic={0: 'V4', 1: 'V6'}),
        Uint('Len', bl=6),
        Alt('Addr', GEN={
            0: Buf('IPv4Addr', bl=32, rep=REPR_HEX),
            1: Buf('IPv6Addr', bl=128, rep=REPR_HEX)},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Addr'].get_len())
        self['Addr'].set_blauto(lambda: self['Len'].get_val()<<3)


class MBMSIPMulticastDistribution(Envelope):
    _GEN = (
        Uint32('CommonTEID', rep=REPR_HEX),
        MulticastAddr('DistribAddr'),
        MulticastAddr('SourceAddr'),
        Uint8('MBMSHCInd'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )   


#------------------------------------------------------------------------------#
# MBMS Distribution Acknowledge
# TS 29.274, 8.74
#------------------------------------------------------------------------------#

MBMSDistribInd_dict = {
    0 : 'No RNCs have accepted IP multicast distribution',
    1 : 'All RNCs have accepted IP multicast distribution',
    2 : 'Some RNCs have accepted IP multicast distribution',
    }

class MBMSDistributionAcknowledge(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('Ind', bl=2, dic=MBMSDistribInd_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# User CSG Information
# TS 29.274, 8.75
#------------------------------------------------------------------------------#

class UCI(Envelope):
    _GEN = (
        PLMN(),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('CSGID', bl=27, rep=REPR_HEX),
        Uint('AccessMode', bl=2, dic={0: 'Closed mode', 1: 'Hybrid mode'}),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('LCSG', bl=1),
        Uint('CMI', bl=1, dic={0: 'Non-CSG membership', 1: 'CSG membership'}),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# CSG Information Reporting Action
# TS 29.274, 8.76
#------------------------------------------------------------------------------#

class CSGInfoReportingAction(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('UCIUHC', bl=1),
        Uint('UCISHC', bl=1),
        Uint('UCICSG', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# RFSP Index
# TS 29.274, 8.77
#------------------------------------------------------------------------------#

class RFSPIndex(Uint16):
    pass


#------------------------------------------------------------------------------#
# CSG ID
# TS 29.274, 8.78
#------------------------------------------------------------------------------#

class CSGID(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Val', bl=27, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# CSG Membership Indication (CMI)
# TS 29.274, 8.79
#------------------------------------------------------------------------------#

class CMI(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('CMI', bl=1, dic={0: 'Non-CSG membership', 1: 'CSG membership'}),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Service indicator
# TS 29.274, 8.80
#------------------------------------------------------------------------------#

class ServiceIndicator(Uint8):
    _dic = {
        1 : 'CS call indicator',
        2 : 'SMS indicator'
        }


#------------------------------------------------------------------------------#
# Detach Type
# TS 29.274, 8.81
#------------------------------------------------------------------------------#

class DetachType(Uint8):
    _dic = {
        1 : 'PS Detach',
        2 : 'Combined PS/CS Detach'
        }


#------------------------------------------------------------------------------#
# Local Distinguished Name (LDN)
# TS 29.274, 8.82
#------------------------------------------------------------------------------#

class LDN(Buf):
    pass


#------------------------------------------------------------------------------#
# Node Features
# TS 29.274, 8.83
#------------------------------------------------------------------------------#

class NodeFeat(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('MTEDT', bl=1),
        Uint('ETH', bl=1),
        Uint('S1UN', bl=1),
        Uint('CIOT', bl=1),
        Uint('NTSR', bl=1),
        Uint('MABR', bl=1),
        Uint('PRN', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# MBMS Time to Data Transfer
# TS 29.274, 8.84
#------------------------------------------------------------------------------#

class MBMSTimeToDataTransfer(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Throttling
# TS 29.274, 8.85
#------------------------------------------------------------------------------#

class Throttling(Envelope):
    _GEN = (
        Uint('DelayUnit', bl=3, dic=TimerUnit_dict),
        Uint('DelayVal', bl=5),
        Uint8('Factor'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
        

#------------------------------------------------------------------------------#
# Allocation/Retention Priority (ARP)
# TS 29.274, 8.86
#------------------------------------------------------------------------------#

class ARP(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('PCI', bl=1),
        Uint('PL', bl=4),
        Uint('spare', bl=1),
        Uint('PVI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# EPC Timer
# TS 29.274, 8.87
#------------------------------------------------------------------------------#

class EPCTimer(_Timer):
    pass


#------------------------------------------------------------------------------#
# Signalling Priority Indication
# TS 29.274, 8.88
#------------------------------------------------------------------------------#

class SignallingPriorityInd(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('LAPI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Temporary Mobile Group Identity
# TS 29.274, 8.89
#------------------------------------------------------------------------------#

# _TMGI imported from TS24008_IE
class TMGI(Envelope):
    _GEN = tuple(_TMGI()._content) + (
        Buf('ext', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# Additional MM context for SRVCC
# TS 29.274, 8.90
#------------------------------------------------------------------------------#

class AdditionalMMContextForSRVCC(Envelope):
    _GEN = (
        Type4LV('MSCm2', val={'V':b'@\0\0'}, IE=MSCm2()),
        Type4LV('MSCm3', val={'V': b''}, IE=classmark_3_value_part),
        Type4LV('SuppCodecs', val={'V': b'\0\x01\0'}, IE=SuppCodecList()),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Additional flags for SRVCC
# TS 29.274, 8.91
#------------------------------------------------------------------------------#

class AdditionalFlagsForSRVCC(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('VF', bl=1),
        Uint('ICS', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# MDT Configuration
# TS 29.274, 8.93
#------------------------------------------------------------------------------#

class MDTConfiguration(Envelope):
    _GEN = (
        Uint8('JobType'),
        Uint32('ListOfMeasurements'),
        Uint8('ReportingTrigger'),
        Uint8('ReportInterval'),
        Uint8('ReportAmount'),
        Uint8('EventThresholdRSRP'),
        Uint8('EventThresholdRSRQ'),
        Uint8('LenAreaScope'),
        Buf('AreaScope', rep=REPR_HEX),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('PLI', bl=1),
        Uint('PMI', bl=1),
        Uint('MPI', bl=1),
        Uint('CRRMI', bl=1),
        Uint8('CollectionPeriod'),
        Uint8('MeasurementPeriod'),
        Uint8('PositioningMethod'),
        Uint8('MDTPLMNsNum'),
        Sequence('MDTPLMNs', GEN=PLMN()),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['LenAreaScope'].set_valauto(lambda: self['AreaScope'].get_len())
        self['AreaScope'].set_blauto(lambda: self['LenAreaScope'].get_val()<<3)
        self['MDTPLMNsNum'].set_valauto(lambda: self['MDTPLMNs'].get_num())
        self['MDTPLMNs'].set_numauto(lambda: self['MDTPLMNsNum'].get_val())


#------------------------------------------------------------------------------#
# Additional Protocol Configuration Options (APCO)
# TS 29.274, 8.94
#------------------------------------------------------------------------------#

class AdditionalPCO(ProtConfig):
    pass


#------------------------------------------------------------------------------#
# Absolute Time of MBMS Data Transfer
# TS 29.274, 8.95
#------------------------------------------------------------------------------#

class AbsoluteTimeOfMBMSDataTransfer(Envelope):
    _GEN = (
        Uint64('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# H(e)NB Information Reporting
# TS 29.274, 8.96
#------------------------------------------------------------------------------#

class HeNBInfoReporting(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('FTI', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# IPv4 Configuration Parameters (IP4CP)
# TS 29.274, 8.97
#------------------------------------------------------------------------------#

class IPv4ConfigurationParameters(Envelope):
    _GEN = (
        Uint8('SubnetPrefLen'),
        Buf('IPv4DefaultRouterAddr', bl=32, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Change to Report Flags
# TS 29.274, 8.98
#------------------------------------------------------------------------------#

class ChangeToReportFlags(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('TZCR', bl=1),
        Uint('SNCR', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Action Indication
# TS 29.274, 8.99
#------------------------------------------------------------------------------#

ActionInd_dict = {
    0 : 'No Action',
    1 : 'Deactivation Indication',
    2 : 'Paging Indication',
    3 : 'Paging Stop Indication'
    }

class ActionInd(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Val', bl=3, dic=ActionInd_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


# TODO: to be continued...
#------------------------------------------------------------------------------#
# 
# TS 29.274, 8.
#------------------------------------------------------------------------------#


#------------------------------------------------------------------------------#
# 
# TS 29.274, 8.
#------------------------------------------------------------------------------#



# extracted from Table 8.1-1: Information Element types for GTPv2
# tag: (class, length, description)
# length: -1 is undefined or extensive, >= 0 is fixed length
GTPCIETags_dict = {
    1  : (IMSI, -1, 'International Mobile Subscriber Identity (IMSI)'),
    2  : (Cause, -1, 'Cause'),
    3  : (Recovery, -1, 'Recovery (Restart Counter)'),
    51 : (STNSR, -1, 'STN-SR'),
    71 : (APN, -1, 'Access Point Name (APN)'),
    72 : (AMBR, 8, 'Aggregate Maximum Bit Rate (AMBR)'),
    73 : (EBI, 1, 'EPS Bearer ID (EBI)'),
    74 : (IPAddress, -1, 'IP Address'),
    75 : (MEI, -1, 'Mobile Equipment Identity (MEI)'),
    76 : (MSISDN, -1, 'MSISDN'),
    77 : (Ind, 2, 'Indication'),
    78 : (PCO, -1, 'Protocol Configuration Options (PCO)'),
    79 : (PAA, -1, 'PDN Address Allocation (PAA)'),
    80 : (BearerQoS, 22, 'Bearer Level Quality of Service (Bearer QoS)'),
    81 : (FlowQoS, 21, 'Flow Quality of Service (Flow QoS)'),
    82 : (RATType, 1, 'RAT Type'),
    83 : (ServingNetwork, 3, 'Serving Network'),
    84 : (BearerTFT, -1, 'EPS Bearer Level Traffic Flow Template (Bearer TFT)'),
    85 : (TAD, -1, 'Traffic Aggregation Description (TAD)'),
    86 : (ULI, -1, 'User Location Information (ULI)'),
    87 : (FTEID, -1, 'Fully Qualified Tunnel Endpoint Identifier (F-TEID)'),
    88 : (TMSI, -1, 'TMSI'),
    89 : (GlobalCNId, -1, 'Global CN-Id'),
    90 : (S103PDF, -1, 'S103 PDN Data Forwarding Info (S103PDF)'),
    91 : (S1UDF, -1, 'S1-U Data Forwarding Info (S1UDF)'),
    92 : (DelayValue, 1, 'Delay Value'),
    93 : (BearerContext, -1, 'Bearer Context'),
    94 : (ChargingID, 4, 'Charging ID'),
    95 : (ChargingCharacteristics, 2, 'Charging Characteristics'),
    96 : (TraceInfo, -1, 'Trace Information'),
    97 : (BearerFlags, 1, 'Bearer Flags'),
    99 : (PDNType, 1, 'PDN Type'),
    100: (PTI, 1, 'Procedure Transaction ID'),
    103: (MMContext, -1, 'MM Context (GSM Key and Triplets)'),
    104: (MMContext, -1, 'MM Context (UMTS Key, Used Cipher and Quintuplets)'),
    105: (MMContext, -1, 'MM Context (GSM Key, Used Cipher and Quintuplets)'),
    106: (MMContext, -1, 'MM Context (UMTS Key and Quintuplets)'),
    107: (MMContext, -1, 'MM Context (EPS Security Context, Quadruplets and Quintuplets)'),
    108: (MMContext, -1, 'MM Context (UMTS Key, Quadruplets and Quintuplets)'),
    109: (PDNConnection, -1, 'PDN Connection'),
    110: (PDUNumbers, 9, 'PDU Numbers'),
    111: (PTMSI, -1, 'P-TMSI'),
    112: (PTMSISignature, -1, 'P-TMSI Signature'),
    113: (HopCounter, 1, 'Hop Counter'),
    114: (UETimeZone, 2, 'UE Time Zone'),
    115: (TraceReference, 6, 'Trace Reference'),
    116: (CompleteRequestMessage, -1, 'Complete Request Message'),
    117: (GUTI, -1, 'GUTI'),
    118: (FContainer, -1, 'F-Container'),
    119: (FCause, -1, 'F-Cause'),
    120: (PLMNID, -1, 'PLMN ID'),
    121: (TargetIdentification, -1, 'Target Identification'),
    123: (PacketFlowID, -1, 'Packet Flow ID'),
    124: (RABContext, 9, 'RAB Context'),
    125: (SourceRNCPDCPContextInfo, -1, 'Source RNC PDCP Context Info'),
    126: (PortNumber, 2, 'Port Number'),
    127: (APNRestriction, 1, 'APN Restriction'),
    128: (SelectionMode, 1, 'Selection Mode'),
    129: (SourceIdentification, -1, 'Source Identification'),
    131: (ChangeReportingAction, -1, 'Change Reporting Action'),
    132: (FQCSID, -1, 'Fully Qualified PDN Connection Set Identifier (FQ-CSID)'),
    133: (ChannelNeeded, -1, 'Channel needed'),
    134: (EMLPPPriority, -1, 'eMLPP Priority'),
    135: (NodeType, 1, 'Node Type'),
    136: (FQDN, -1, 'Fully Qualified Domain Name (FQDN)'),
    137: (TI, -1, 'Transaction Identifier (TI)'),
    138: (MBMSSessionDuration, 3, 'MBMS Session Duration'),
    139: (MBMSServiceArea, -1, 'MBMS Service Area'),
    140: (MBMSSessionIdent, 1, 'MBMS Session Identifier'),
    141: (MBMSFlowIdent, 2, 'MBMS Flow Identifier'),
    142: (MBMSIPMulticastDistribution, -1, 'MBMS IP Multicast Distribution'),
    143: (MBMSDistributionAcknowledge, 1, 'MBMS Distribution Acknowledge'),
    144: (RFSPIndex, 2, 'RFSP Index'),
    145: (UCI, 8, 'User CSG Information (UCI)'),
    146: (CSGInfoReportingAction, 1, 'CSG Information Reporting Action'),
    147: (CSGID, 4, 'CSG ID'),
    148: (CMI, 1, 'CSG Membership Indication (CMI)'),
    149: (ServiceIndicator, 1, 'Service indicator'),
    150: (DetachType, 1, 'Detach Type'),
    151: (LDN, -1, 'Local Distinguished Name (LDN)'),
    152: (NodeFeat, 1, 'Node Features'),
    153: (MBMSTimeToDataTransfer, 1, 'MBMS Time to Data Transfer'),
    154: (Throttling, 2, 'Throttling'),
    155: (ARP, 1, 'Allocation/Retention Priority (ARP)'),
    156: (EPCTimer, 1, 'EPC Timer'),
    157: (SignallingPriorityInd, 1, 'Signalling Priority Indication'),
    158: (TMGI, 6, 'Temporary Mobile Group Identity (TMGI)'),
    159: (AdditionalMMContextForSRVCC, -1, 'Additional MM context for SRVCC'),
    160: (AdditionalFlagsForSRVCC, 1, 'Additional flags for SRVCC'),
    162: (MDTConfiguration, -1, 'MDT Configuration'),
    163: (AdditionalPCO, -1, 'Additional Protocol Configuration Options (APCO)'),
    164: (AbsoluteTimeOfMBMSDataTransfer, 8, 'Absolute Time of MBMS Data Transfer'),
    165: (HeNBInfoReporting, 1, 'H(e)NB Information Reporting'),
    166: (IPv4ConfigurationParameters, 5, 'IPv4 Configuration Parameters (IP4CP)'),
    167: (ChangeToReportFlags, 1, 'Change to Report Flags'),
    168: (ActionInd, 1, 'Action Indication'),
    169: (TWANIdent, -1, 'TWAN Identifier'),
    170: (ULITimestamp, 4, 'ULI Timestamp'),
    171: (MBMSFlags, 1, 'MBMS Flags'),
    172: (RANNASCause, -1, 'RAN/NAS Cause'),
    173: (CNOperatorSelectionEntity, 1, 'CN Operator Selection Entity'),
    174: (TWMI, 1, 'Trusted WLAN Mode Indication'),
    175: (NodeNumber, -1, 'Node Number'),
    176: (NodeIdent, -1, 'Node Identifier'),
    177: (PresenceReportingAreaAction, -1, 'Presence Reporting Area Action'),
    178: (PresenceReportingAreaInfo, 4, 'Presence Reporting Area Information'),
    179: (TWANIdentTimestamp, 4, 'TWAN Identifier Timestamp'),
    180: (OverloadControlInfo, -1, 'Overload Control Information'),
    181: (LoadControlInfo, -1, 'Load Control Information'),
    182: (Metric, 1, 'Metric'),
    183: (SequenceNumber, 4, 'Sequence Number'),
    184: (APNAndRelativeCapacity, -1, 'APN and Relative Capacity'),
    185: (WLANOffloadabilityInd, 1, 'WLAN Offloadability Indication'),
    186: (PagingAndServiceInfo, -1, 'Paging and Service Information'),
    187: (IntegerNumber, -1, 'Integer Number'),
    188: (MillisecondTimeStamp, 6, 'Millisecond Time Stamp'),
    189: (MonitoringEventInfo, -1, 'Monitoring Event Information'),
    190: (ECGIList, -1, 'ECGI List'),
    191: (RemoteUEContext, -1, 'Remote UE Context'),
    192: (RemoteUserID, -1, 'Remote User ID'),
    193: (RemoteUEIPInfo, -1, 'Remote UE IP information'),
    194: (CIoTOptimizationsSupportInd, 1, 'CIoT Optimizations Support Indication'),
    195: (SCEFPDNConnection, -1, 'SCEF PDN Connection'),
    196: (HeaderCompressionConfiguration, 4, 'Header Compression Configuration'),
    197: (EPCO, -1, 'Extended Protocol Configuration Options (ePCO)'),
    198: (ServingPLMNRateControl, 4, 'Serving PLMN Rate Control'),
    199: (Counter, 5, 'Counter'),
    200: (MappedUEUsageType, 2, 'Mapped UE Usage Type'),
    201: (SecondaryRATUsageDataReport, 27, 'Secondary RAT Usage Data Report'),
    202: (UPFunctionSelectionIndFlags, 1, 'UP Function Selection Indication Flags'),
    203: (MaximumPacketLossRate, 1, 'Maximum Packet Loss Rate'),
    204: (APNRateControlStatus, 20, 'APN Rate Control Status'),
    205: (ExtendedTraceInfo, -1, 'Extended Trace Information'),
    206: (MonitoringEventExtInfo, -1, 'Monitoring Event Extension Information'),
    254: (SpecialIETypeForIETypeExt, -1, 'Special IE type for IE Type Extension'),
    255: (PrivExt, -1, 'Private Extension'),
    }


GTPCIETagDesc_dict = {k: v[2] for k, v in GTPCIETags_dict.items()}


class GTPCIEHdr(Envelope):
    """GTPv2-C Information Element's header
    """
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint8('Type', dic=GTPCIETagDesc_dict),
        Uint16('Len'),
        Uint('spare', bl=4),
        Uint('Inst', bl=4),
        Uint16('TypeExt', dic=GTPCIETags_dict),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_transauto(lambda: self[0].get_val() != 254)


class GTPCIE(Envelope):
    """GTPv2-C Information Element
    """
    
    _GEN = (
        GTPCIEHdr(),
        Buf('GTPCIEData', rep=REPR_HEX, hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][1].set_valauto(lambda: self._get_len())
        
    def _get_len(self):
        l = 0
        if len(self._content) > 1:
            # IE data
            l += self._content[1].get_len()
        if self[0][0].get_val() == 254:
            # extended type
            l += 2
        return l
    
    def set_val(self, val):
        if isinstance(val, (tuple, list)) and val:
            self[0].set_val(val[0])
            self.set_ie_class()
            if len(val) > 1:
                self[1].set_val(val[1])
        else:
            if isinstance(val, dict) and 'GTPCIEHdr' in val:
                self[0].set_val(val['GTPCIEHdr'])
                del val['GTPCIEHdr']
                self.set_ie_class()
            Envelope.set_val(self, val)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self.set_ie_class()
        # truncate char according to Len and decode IE data
        ie_len = self[0][1].get_val()
        if self[0][0].get_val() == 254:
            ie_len -= 2
        char_lb = char._len_bit
        char._len_bit = min(char._cur + 8 * ie_len, char_lb)
        self[1]._from_char(char)
        char._len_bit = char_lb
    
    #--------------------------------------------------------------------------#
    # specific methods to deal with MAND / OPT dict at decoding and encoding
    #--------------------------------------------------------------------------#
    
    def set_ie_class(self):
        # this is were the potential replacement of the generic GTPCIEData happens,
        # according to the GTPCIEHdr value
        ie_type = self[0][0].get_val()
        if ie_type == 254:
            ie_type = self[0][4].get_val()
        ie_inst = self[0][3].get_val()
        ie_data, ie_desc = self._select_ie(ie_type, ie_inst)
        if ie_data is not None:
            self.replace(self[1], ie_data)
        if ie_desc is not None:
            self._name = ie_desc
    
    def _select_ie(self, ie_type, ie_inst=0):
        # get the envelope of the IE (GTPCMsg or GTPCIEGrouped) to check 
        # msg-specific (locally defined) MAND / OPT IEs
        ie_class, ie_desc = None, None
        env = self.get_env()
        if env is not None and hasattr(env, 'MAND') and hasattr(env, 'OPT'):
            if ie_type in env.MAND:
                ie_class, ie_desc = env.MAND[ie_type]
            elif (ie_type, ie_inst) in env.MAND:
                ie_class, ie_desc = env.MAND[(ie_type, ie_inst)]
            elif ie_type in env.OPT:
                ie_class, ie_desc = env.OPT[ie_type]
            elif (ie_type, ie_inst) in env.OPT:
                ie_class, ie_desc = env.OPT[(ie_type, ie_inst)]
        if ie_class is None and ie_type in GTPCIETags_dict:
            # IE type / instance not defined for this specific msg
            ie_class = GTPCIETags_dict[ie_type][0]
        if ie_class is None:
            return None, ie_desc
        else:
            return ie_class(hier=1), ie_desc
    
    def init_mand(self):
        """initialize all IEs that are mandatory
        """
        # TODO
        pass
    
    def init_opt(self):
        """initialize all IEs that are optional
        """
        # TODO
        pass
    

class GTPCIEs(Sequence):
    """GTPv2-C Grouped Information Element
    """
    
    _GEN = GTPCIE()
    
    # this is to raise in case not all mandatory IEs are set in the grouped IE
    VERIF_MAND = True
    
    # Each IE is identified by its Tag + Instance identifiers
    # Each mandatory IE must be included at least 1 time in the msg
    # Each C, CO or Optional IE can be included 1 time or more in the msg
    # When linking IE, locally defined (grouped) IE have precedence over 
    # globally defined IE (defined in GTPCIETags_dict)
    
    # Hence a GTPCIEGrouped have 2 dicts:
    # MAND: (Tag, Inst) -> locally or globally defined IE class
    # OPT : (Tag, Inst) -> locally or globally defined IE class
    MAND = {}
    OPT  = {}
    
    # Warning: a single IE can be identified by several Tags, corresponding to different
    # formatting (e.g. MMContext with tags 103 to 108)
    # Also a single tag can lead to different IE formatting, depending of the grouped IE
    # this is due to locally defined grouped IE for certain message types
    
    def __init__(self, *args, **kwargs):
        Sequence.__init__(self, *args, **kwargs)
        self._ie_mand = set()
        for _, ie_name in self.MAND.values():
            self._ie_mand.add(ie_name)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        #
        self.__init__()
        Sequence._from_char(self, char)
        #
        # eventually verify mandatory IE
        if self.VERIF_MAND:
            for ie in self:
                if ie._name in self._ie_mand:
                    self._ie_mand.remove(ie._name)
            if self._ie_mand:
                raise(PycrateErr('{0}: missing mandatory IE(s), {1}'\
                      .format(self._name, ', '.join(sorted(self._ie_mand)))))
    
    def add_ie(self, ie_type, ie_inst=0, val=None):
        self.set_val({self.get_num(): {'GTPCIEHdr': {'Type': ie_type, 'Inst': ie_inst}}})
        if val is not None:
            self[-1][1].set_val(val)
    
    def rem_ie(self, ie_type, ie_inst=0):
        for ie in self._content[::-1]:
            if (ie[0]['Type'].get_val(), ie[0]['Inst'].get_val()) == (ie_type, ie_inst):
                self._content.remove(ie)
                break


#------------------------------------------------------------------------------#
# GTP-C messages
# TS 29.274, section 7
#------------------------------------------------------------------------------#

class GTPCMsg(Envelope):
    """parent class for all GTPv2-C messages
    """
    
    _GEN = (
        GTPCHdr(),
        GTPCIEs(hier=1),
        )
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # decode msg header
        self[0]._from_char(char)
        # truncate char according to Len
        len_ies = self[0][6].get_val() - 4
        if self[0][2].get_val():
            len_ies -= 4
        char_lb = char._len_bit
        char._lb = char._cur + 8 * len_ies
        # decode all IEs
        self[1]._from_char(char)
        # restore original char length
        char._len_bit = char_lb


# extracted from Table 7.1.1-1: Information Elements in Echo Request
class EchoRequestIEs(GTPCIEs):
    MAND = {
        (3, 0)   : (Recovery, 'Recovery'),
        }
    OPT  = {
        (152, 0) : (NodeFeat, 'SendingNodeFeat'),
        255      : (PrivExt, 'PrivExt'),
        }


class EchoRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 1, 'T': 0}),
        EchoRequestIEs(hier=1)
        )


# extracted from Table 7.1.2-1: Information Elements in Echo Response
class EchoResponseIEs(GTPCIEs):
    MAND = {
        (3, 0)   : (Recovery, 'Recovery'),
        }
    OPT  = {
        (152, 0) : (NodeFeat, 'SendingNodeFeat'),
        255      : (PrivExt, 'PrivExt'),
        }


class EchoResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 2, 'T': 0}),
        EchoResponseIEs(hier=1)
        )


# extracted from Table 7.2.1-5: Remote UE Context Connected within Create Session Request
class CreateSessionRequest_RemoteUEContextConnected(GTPCIEs):
    MAND = {
        (192, 0) : (RemoteUserID, 'RemoteUserID'),
        (193, 0) : (RemoteUEIPInfo, 'RemoteUEIPInfo'),
        }
    OPT  = {
        }


# extracted from Table 7.2.1-4: Overload Control Information within Create Session Request
class CreateSessionRequest_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.1-3: Bearer Context to be removed within Create Session Request
class CreateSessionRequest_BearerContextToBeRemoved(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (87, 0)  : (FTEID, 'S4USGSNFTEID'),
        }


# extracted from Table 7.2.1-2: Bearer Context to be created within Create Session Request
class CreateSessionRequest_BearerContextToBeCreated(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        (80, 0)  : (BearerQoS, 'BearerLevelQoS'),
        }
    OPT  = {
        (84, 0)  : (BearerTFT, 'TFT'),
        (87, 4)  : (FTEID, 'S12RNCFTEID'),
        (87, 3)  : (FTEID, 'S5S8UPGWFTEID'),
        (87, 5)  : (FTEID, 'S2bUEPDGFTEID'),
        (87, 0)  : (FTEID, 'S1UENodeBFTEID'),
        (87, 1)  : (FTEID, 'S4USGSNFTEID'),
        (87, 6)  : (FTEID, 'S2aUTWANFTEID'),
        (87, 7)  : (FTEID, 'S11UMMEFTEID'),
        (87, 2)  : (FTEID, 'S5S8USGWFTEID'),
        }


# extracted from Table 7.2.1-1: Information Elements in a Create Session Request
class CreateSessionRequestIEs(GTPCIEs):
    MAND = {
        (71, 0)  : (APN, 'AccessPointName'),
        (82, 0)  : (RATType, 'RATType'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (93, 0)  : (CreateSessionRequest_BearerContextToBeCreated, 'BearerContextsToBeCreated'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (3, 0)   : (Recovery, 'Recovery'),
        (72, 0)  : (AMBR, 'AggregateMaximumBitRate'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (74, 1)  : (IPAddress, 'HeNBLocalIPAddress'),
        (74, 2)  : (IPAddress, 'MMES4SGSNIdent'),
        (74, 3)  : (IPAddress, 'EPDGIPAddress'),
        (74, 0)  : (IPAddress, 'UELocalIPAddress'),
        (75, 0)  : (MEI, 'MEIdentity'),
        (76, 0)  : (MSISDN, 'MSISDN'),
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (79, 0)  : (PAA, 'PDNAddressAllocation'),
        (83, 0)  : (ServingNetwork, 'ServingNetwork'),
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (86, 1)  : (ULI, 'UserLocationInfoForSGW'),
        (87, 1)  : (FTEID, 'PGWS5S8AddressForControlPlaneOrPMIP'),
        (93, 1)  : (CreateSessionRequest_BearerContextToBeRemoved, 'BearerContextsToBeRemoved'),
        (95, 0)  : (ChargingCharacteristics, 'ChargingCharacteristics'),
        (96, 0)  : (TraceInfo, 'TraceInfo'),
        (99, 0)  : (PDNType, 'PDNType'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (126, 0) : (PortNumber, 'UEUDPPort'),
        (126, 2) : (PortNumber, 'UETCPPort'),
        (126, 1) : (PortNumber, 'HeNBUDPPort'),
        (127, 0) : (APNRestriction, 'MaximumAPNRestriction'),
        (128, 0) : (SelectionMode, 'SelectionMode'),
        (132, 0) : (FQCSID, 'MMEFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (132, 2) : (FQCSID, 'EPDGFQCSID'),
        (132, 3) : (FQCSID, 'TWANFQCSID'),
        (136, 0) : (FQDN, 'SGWUNodeName'),
        (145, 0) : (UCI, 'UserCSGInfo'),
        (151, 3) : (LDN, 'TWANLDN'),
        (151, 2) : (LDN, 'EPDGLDN'),
        (151, 1) : (LDN, 'SGWLDN'),
        (151, 0) : (LDN, 'MMES4SGSNLDN'),
        (157, 0) : (SignallingPriorityInd, 'SignallingPriorityInd'),
        (163, 0) : (AdditionalPCO, 'AdditionalPCO'),
        (169, 1) : (TWANIdent, 'WLANLocationInfo'),
        (169, 0) : (TWANIdent, 'TWANIdent'),
        (173, 0) : (CNOperatorSelectionEntity, 'CNOperatorSelectionEntity'),
        (174, 0) : (TWMI, 'TWMI'),
        (176, 0) : (NodeIdent, '3GPPAAAServerIdent'),
        (178, 0) : (PresenceReportingAreaInfo, 'PresenceReportingAreaInfo'),
        (179, 0) : (TWANIdentTimestamp, 'WLANLocationTimestamp'),
        (180, 2) : (CreateSessionRequest_OverloadControlInfo, 'TWANePDGsOverloadControlInfo'),
        (180, 0) : (CreateSessionRequest_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        (180, 1) : (CreateSessionRequest_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (187, 0) : (IntegerNumber, 'MaximumWaitTime'),
        (188, 0) : (MillisecondTimeStamp, 'OriginationTimeStamp'),
        (191, 0) : (CreateSessionRequest_RemoteUEContextConnected, 'RemoteUEContextConnected'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        (198, 0) : (ServingPLMNRateControl, 'ServingPLMNRateControl'),
        (199, 0) : (Counter, 'MOExceptionDataCounter'),
        (200, 0) : (MappedUEUsageType, 'MappedUEUsageType'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        (202, 0) : (UPFunctionSelectionIndFlags, 'UPFunctionSelectionIndFlags'),
        (204, 0) : (APNRateControlStatus, 'APNRateControlStatus'),
        255      : (PrivExt, 'PrivExt'),
        }


class CreateSessionRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 32}),
        CreateSessionRequestIEs(hier=1)
        )


# extracted from Table 7.2.2-5: Overload Control Information within Create Session Response
class CreateSessionResponse_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.2-4: Load Control Information within Create Session Response
class CreateSessionResponse_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        (184, 0) : (APNAndRelativeCapacity, 'ListOfAPNAndRelativeCapacity'),
        }


# extracted from Table 7.2.2-3: Bearer Context marked for removal within a Create Session Response
class CreateSessionResponse_BearerContextMarkedForRemoval(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        }


# extracted from Table 7.2.2-2: Bearer Context Created within Create Session Response
class CreateSessionResponse_BearerContextCreated(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (80, 0)  : (BearerQoS, 'BearerLevelQoS'),
        (87, 4)  : (FTEID, 'S2bUPGWFTEID'),
        (87, 3)  : (FTEID, 'S12SGWFTEID'),
        (87, 5)  : (FTEID, 'S2aUPGWFTEID'),
        (87, 0)  : (FTEID, 'S1USGWFTEID'),
        (87, 1)  : (FTEID, 'S4USGWFTEID'),
        (87, 6)  : (FTEID, 'S11USGWFTEID'),
        (87, 2)  : (FTEID, 'S5S8UPGWFTEID'),
        (94, 0)  : (ChargingID, 'ChargingID'),
        (97, 0)  : (BearerFlags, 'BearerFlags'),
        }


# extracted from Table 7.2.2-1: Information Elements in a Create Session Response
class CreateSessionResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (93, 0)  : (CreateSessionResponse_BearerContextCreated, 'BearerContextsCreated'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (72, 0)  : (AMBR, 'AggregateMaximumBitRate'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (74, 0)  : (IPAddress, 'ChargingGatewayAddress'),
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (79, 0)  : (PAA, 'PDNAddressAllocation'),
        (87, 1)  : (FTEID, 'PGWS5S8S2aS2bFTEIDForPMIPBasedInterfaceOrForGTPBasedControlPlaneInterface'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (93, 1)  : (CreateSessionResponse_BearerContextMarkedForRemoval, 'BearerContextsMarkedForRemoval'),
        (94, 0)  : (ChargingID, 'PDNConnectionChargingID'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (127, 0) : (APNRestriction, 'APNRestriction'),
        (131, 0) : (ChangeReportingAction, 'ChangeReportingAction'),
        (132, 0) : (FQCSID, 'PGWFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (136, 0) : (FQDN, 'ChargingGatewayName'),
        (146, 0) : (CSGInfoReportingAction, 'CSGInfoReportingAction'),
        (151, 0) : (LDN, 'SGWLDN'),
        (151, 1) : (LDN, 'PGWLDN'),
        (156, 0) : (EPCTimer, 'PGWBackOffTime'),
        (163, 0) : (AdditionalPCO, 'AdditionalPCO'),
        (165, 0) : (HeNBInfoReporting, 'HeNBInfoReporting'),
        (166, 0) : (IPv4ConfigurationParameters, 'TrustedWLANIPv4Parameters'),
        (177, 0) : (PresenceReportingAreaAction, 'PresenceReportingAreaAction'),
        (180, 0) : (CreateSessionResponse_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        (180, 1) : (CreateSessionResponse_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (181, 2) : (CreateSessionResponse_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        (181, 1) : (CreateSessionResponse_LoadControlInfo, 'PGWsAPNLevelLoadControlInfo'),
        (181, 0) : (CreateSessionResponse_LoadControlInfo, 'PGWsNodeLevelLoadControlInfo'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        255      : (PrivExt, 'PrivExt'),
        }


class CreateSessionResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 33}),
        CreateSessionResponseIEs(hier=1)
        )


# extracted from Table 7.2.3-4: Overload Control Information within Create Bearer Request
class CreateBearerRequest_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.3-3: Load Control Information within Create Bearer Request
class CreateBearerRequest_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        (184, 0) : (APNAndRelativeCapacity, 'ListOfAPNAndRelativeCapacity'),
        }


# extracted from Table 7.2.3-2: Bearer Context within Create Bearer Request
class CreateBearerRequest_BearerContext(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        (80, 0)  : (BearerQoS, 'BearerLevelQoS'),
        (84, 0)  : (BearerTFT, 'TFT'),
        }
    OPT  = {
        (78, 0)  : (PCO, 'PCO'),
        (87, 4)  : (FTEID, 'S2bUPGWFTEID'),
        (87, 3)  : (FTEID, 'S4USGWFTEID'),
        (87, 5)  : (FTEID, 'S2aUPGWFTEID'),
        (87, 0)  : (FTEID, 'S1USGWFTEID'),
        (87, 1)  : (FTEID, 'S58UPGWFTEID'),
        (87, 2)  : (FTEID, 'S12SGWFTEID'),
        (94, 0)  : (ChargingID, 'ChargingID'),
        (97, 0)  : (BearerFlags, 'BearerFlags'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        (203, 0) : (MaximumPacketLossRate, 'MaximumPacketLossRate'),
        }


# extracted from Table 7.2.3-1: Information Elements in a Create Bearer Request
class CreateBearerRequestIEs(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (93, 0)  : (CreateBearerRequest_BearerContext, 'BearerContexts'),
        }
    OPT  = {
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (100, 0) : (PTI, 'PTI'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (131, 0) : (ChangeReportingAction, 'ChangeReportingAction'),
        (132, 0) : (FQCSID, 'PGWFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (146, 0) : (CSGInfoReportingAction, 'CSGInfoReportingAction'),
        (165, 0) : (HeNBInfoReporting, 'HeNBInfoReporting'),
        (177, 0) : (PresenceReportingAreaAction, 'PresenceReportingAreaAction'),
        (180, 0) : (CreateBearerRequest_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        (180, 1) : (CreateBearerRequest_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (181, 0) : (CreateBearerRequest_LoadControlInfo, 'PGWsNodeLevelLoadControlInfo'),
        (181, 1) : (CreateBearerRequest_LoadControlInfo, 'PGWsAPNLevelLoadControlInfo'),
        (181, 2) : (CreateBearerRequest_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class CreateBearerRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 95}),
        CreateBearerRequestIEs(hier=1)
        )


# extracted from Table 7.2.4-3: Overload Control Information within Create Bearer Response
class CreateBearerResponse_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.4-2: Bearer Context within Create Bearer Response
class CreateBearerResponse_BearerContext(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (78, 0)  : (PCO, 'PCO'),
        (87, 4)  : (FTEID, 'S12RNCFTEID'),
        (87, 5)  : (FTEID, 'S12SGWFTEID'),
        (87, 10) : (FTEID, 'S2aUTWANFTEID'),
        (87, 11) : (FTEID, 'S2aUPGWFTEID'),
        (87, 8)  : (FTEID, 'S2bUEPDGFTEID'),
        (87, 2)  : (FTEID, 'S58USGWFTEID'),
        (87, 9)  : (FTEID, 'S2bUPGWFTEID'),
        (87, 3)  : (FTEID, 'S58UPGWFTEID'),
        (87, 0)  : (FTEID, 'S1UENodeBFTEID'),
        (87, 1)  : (FTEID, 'S1USGWFTEID'),
        (87, 6)  : (FTEID, 'S4USGSNFTEID'),
        (87, 7)  : (FTEID, 'S4USGWFTEID'),
        (172, 0) : (RANNASCause, 'RANNASCause'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        }


# extracted from Table 7.2.4-1: Information Elements in a Create Bearer Response
class CreateBearerResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (93, 0)  : (CreateBearerResponse_BearerContext, 'BearerContexts'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (74, 0)  : (IPAddress, 'UELocalIPAddress'),
        (78, 0)  : (PCO, 'PCO'),
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (126, 1) : (PortNumber, 'UETCPPort'),
        (126, 0) : (PortNumber, 'UEUDPPort'),
        (132, 3) : (FQCSID, 'TWANFQCSID'),
        (132, 2) : (FQCSID, 'EPDGFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (132, 0) : (FQCSID, 'MMEFQCSID'),
        (169, 0) : (TWANIdent, 'TWANIdent'),
        (169, 1) : (TWANIdent, 'WLANLocationInfo'),
        (178, 0) : (PresenceReportingAreaInfo, 'PresenceReportingAreaInfo'),
        (179, 1) : (TWANIdentTimestamp, 'WLANLocationTimestamp'),
        (180, 2) : (CreateBearerResponse_OverloadControlInfo, 'TWANePDGsOverloadControlInfo'),
        (180, 1) : (CreateBearerResponse_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (CreateBearerResponse_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class CreateBearerResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 96}),
        CreateBearerResponseIEs(hier=1)
        )


# extracted from Table 7.2.5-2: Overload Control Information within Bearer Resource Command
class BearerResourceCommand_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.5-1: Information Elements in a Bearer Resource Command
class BearerResourceCommandIEs(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (85, 0)  : (TAD, 'TrafficAggregateDescription'),
        (100, 0) : (PTI, 'PTI'),
        }
    OPT  = {
        (73, 1)  : (EBI, 'EPSBearerID'),
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (81, 0)  : (FlowQoS, 'FlowQualityOfService'),
        (82, 0)  : (RATType, 'RATType'),
        (83, 0)  : (ServingNetwork, 'ServingNetwork'),
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (87, 2)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (87, 0)  : (FTEID, 'S4USGSNFTEID'),
        (87, 1)  : (FTEID, 'S12RNCFTEID'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (157, 0) : (SignallingPriorityInd, 'SignallingPriorityInd'),
        (180, 1) : (BearerResourceCommand_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (BearerResourceCommand_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        255      : (PrivExt, 'PrivExt'),
        }


class BearerResourceCommand(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 68}),
        BearerResourceCommandIEs(hier=1)
        )


# extracted from Table 7.2.6-2: Overload Control Information within Bearer Resource Failure Indication
class BearerResourceFailureIndication_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.6-1: Information Elements in a Bearer Resource Failure Indication
class BearerResourceFailureIndicationIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (100, 0) : (PTI, 'PTI'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (77, 0)  : (Ind, 'IndFlags'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (180, 1) : (BearerResourceFailureIndication_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (BearerResourceFailureIndication_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class BearerResourceFailureIndication(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 69}),
        BearerResourceFailureIndicationIEs(hier=1)
        )


# extracted from Table 7.2.7-4: Overload Control Information within Modify Bearer Request
class ModifyBearerRequest_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.7-3: Bearer Context to be removed within Modify Bearer Request
class ModifyBearerRequest_BearerContextToBeRemoved(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        }


# extracted from Table 7.2.7-2: Bearer Context to be modified within Modify Bearer Request
class ModifyBearerRequest_BearerContextToBeModified(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (87, 4)  : (FTEID, 'S11UMMEFTEID'),
        (87, 3)  : (FTEID, 'S4USGSNFTEID'),
        (87, 0)  : (FTEID, 'S1ENodeBFTEID'),
        (87, 2)  : (FTEID, 'S12RNCFTEID'),
        (87, 1)  : (FTEID, 'S58USGWFTEID'),
        }


# extracted from Table 7.2.7-1 : Information Elements in a Modify Bearer Request
class ModifyBearerRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (3, 0)   : (Recovery, 'Recovery'),
        (72, 0)  : (AMBR, 'AggregateMaximumBitRate'),
        (74, 1)  : (IPAddress, 'UELocalIPAddress'),
        (74, 0)  : (IPAddress, 'HeNBLocalIPAddress'),
        (74, 2)  : (IPAddress, 'MMES4SGSNIdent'),
        (75, 0)  : (MEI, 'MEIdentity'),
        (77, 0)  : (Ind, 'IndFlags'),
        (82, 0)  : (RATType, 'RATType'),
        (83, 0)  : (ServingNetwork, 'ServingNetwork'),
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (86, 1)  : (ULI, 'UserLocationInfoForSGW'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (92, 0)  : (DelayValue, 'DelayDownlinkPacketNotificationRequest'),
        (93, 0)  : (ModifyBearerRequest_BearerContextToBeModified, 'BearerContextsToBeModified'),
        (93, 1)  : (ModifyBearerRequest_BearerContextToBeRemoved, 'BearerContextsToBeRemoved'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (126, 0) : (PortNumber, 'HeNBUDPPort'),
        (126, 1) : (PortNumber, 'UEUDPPort'),
        (132, 0) : (FQCSID, 'MMEFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (145, 0) : (UCI, 'UserCSGInfo'),
        (151, 0) : (LDN, 'MMES4SGSNLDN'),
        (151, 1) : (LDN, 'SGWLDN'),
        (169, 0) : (TWANIdent, 'WLANLocationInfo'),
        (173, 0) : (CNOperatorSelectionEntity, 'CNOperatorSelectionEntity'),
        (178, 0) : (PresenceReportingAreaInfo, 'PresenceReportingAreaInfo'),
        (179, 0) : (TWANIdentTimestamp, 'WLANLocationTimestamp'),
        (180, 0) : (ModifyBearerRequest_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        (180, 2) : (ModifyBearerRequest_OverloadControlInfo, 'EPDGsOverloadControlInfo'),
        (180, 1) : (ModifyBearerRequest_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (198, 0) : (ServingPLMNRateControl, 'ServingPLMNRateControl'),
        (199, 0) : (Counter, 'MOExceptionDataCounter'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        255      : (PrivExt, 'PrivExt'),
        }


class ModifyBearerRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 34}),
        ModifyBearerRequestIEs(hier=1)
        )


# extracted from Table 7.2.8-5: Overload Control Information within Modify Bearer Response
class ModifyBearerResponse_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.8-4: Load Control Information within Modify Bearer Response
class ModifyBearerResponse_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        (184, 0) : (APNAndRelativeCapacity, 'ListOfAPNAndRelativeCapacity'),
        }


# extracted from Table 7.2.8-3: Bearer Context marked for removal within Modify Bearer Response
class ModifyBearerResponse_BearerContextMarkedForRemoval(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        }


# extracted from Table 7.2.8-2: Bearer Context modified within Modify Bearer Response
class ModifyBearerResponse_BearerContextModified(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (87, 3)  : (FTEID, 'S11USGWFTEID'),
        (87, 0)  : (FTEID, 'S1USGWFTEID'),
        (87, 1)  : (FTEID, 'S12SGWFTEID'),
        (87, 2)  : (FTEID, 'S4USGWFTEID'),
        (94, 0)  : (ChargingID, 'ChargingID'),
        (97, 0)  : (BearerFlags, 'BearerFlags'),
        }


# extracted from Table 7.2.8-1: Information Elements in a Modify Bearer Response
class ModifyBearerResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (74, 0)  : (IPAddress, 'ChargingGatewayAddress'),
        (76, 0)  : (MSISDN, 'MSISDN'),
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (93, 0)  : (ModifyBearerResponse_BearerContextModified, 'BearerContextsModified'),
        (93, 1)  : (ModifyBearerResponse_BearerContextMarkedForRemoval, 'BearerContextsMarkedForRemoval'),
        (94, 0)  : (ChargingID, 'PDNConnectionChargingID'),
        (127, 0) : (APNRestriction, 'APNRestriction'),
        (131, 0) : (ChangeReportingAction, 'ChangeReportingAction'),
        (132, 0) : (FQCSID, 'PGWFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (136, 0) : (FQDN, 'ChargingGatewayName'),
        (146, 0) : (CSGInfoReportingAction, 'CSGInfoReportingAction'),
        (151, 1) : (LDN, 'PGWLDN'),
        (151, 0) : (LDN, 'SGWLDN'),
        (165, 0) : (HeNBInfoReporting, 'HeNBInfoReporting'),
        (177, 0) : (PresenceReportingAreaAction, 'PresenceReportingAreaAction'),
        (180, 0) : (ModifyBearerResponse_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        (180, 1) : (ModifyBearerResponse_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (181, 1) : (ModifyBearerResponse_LoadControlInfo, 'PGWsAPNLevelLoadControlInfo'),
        (181, 0) : (ModifyBearerResponse_LoadControlInfo, 'PGWsNodeLevelLoadControlInfo'),
        (181, 2) : (ModifyBearerResponse_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class ModifyBearerResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 35}),
        ModifyBearerResponseIEs(hier=1)
        )


# extracted from Table 7.2.9.1-2: Overload Control Information within Delete Session Request
class DeleteSessionRequest_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.9.1-1: Information Elements in a Delete Session Request
class DeleteSessionRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (74, 0)  : (IPAddress, 'UELocalIPAddress'),
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (126, 0) : (PortNumber, 'UEUDPPort'),
        (126, 1) : (PortNumber, 'UETCPPort'),
        (135, 0) : (NodeType, 'OriginatingNode'),
        (169, 0) : (TWANIdent, 'TWANIdent'),
        (169, 1) : (TWANIdent, 'WLANLocationInfo'),
        (170, 0) : (ULITimestamp, 'ULITimestamp'),
        (172, 0) : (RANNASCause, 'RANNASReleaseCause'),
        (179, 1) : (TWANIdentTimestamp, 'WLANLocationTimestamp'),
        (179, 0) : (TWANIdentTimestamp, 'TWANIdentTimestamp'),
        (180, 2) : (DeleteSessionRequest_OverloadControlInfo, 'TWANePDGsOverloadControlInfo'),
        (180, 0) : (DeleteSessionRequest_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        (180, 1) : (DeleteSessionRequest_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeleteSessionRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 36}),
        DeleteSessionRequestIEs(hier=1)
        )


# extracted from Table 7.2.9-4: Overload Control Information within Delete Bearer Request
class DeleteBearerRequest_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.9-3: Load Control Information within Delete Bearer Request
class DeleteBearerRequest_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        (184, 0) : (APNAndRelativeCapacity, 'ListOfAPNAndRelativeCapacity'),
        }


# extracted from Table 7.2.9.2-2: Bearer Context within Delete Bearer Request
class DeleteBearerRequest_BearerContext(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        }


# extracted from Table 7.2.9.2-1: Information Elements in a Delete Bearer Request
class DeleteBearerRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (73, 1)  : (EBI, 'EPSBearerIDs'),
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (93, 0)  : (DeleteBearerRequest_BearerContext, 'FailedBearerContexts'),
        (100, 0) : (PTI, 'PTI'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (132, 0) : (FQCSID, 'PGWFQCSID'),
        (180, 0) : (DeleteBearerRequest_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        (180, 1) : (DeleteBearerRequest_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (181, 0) : (DeleteBearerRequest_LoadControlInfo, 'PGWsNodeLevelLoadControlInfo'),
        (181, 1) : (DeleteBearerRequest_LoadControlInfo, 'PGWsAPNLevelLoadControlInfo'),
        (181, 2) : (DeleteBearerRequest_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        (204, 0) : (APNRateControlStatus, 'APNRateControlStatus'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeleteBearerRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 99}),
        DeleteBearerRequestIEs(hier=1)
        )


# extracted from Table 7.2.10.1-3: Overload Control Information within Delete Session Response
class DeleteSessionResponse_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.10.1-2: Load Control Information within Delete Session Response
class DeleteSessionResponse_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        (184, 0) : (APNAndRelativeCapacity, 'ListOfAPNAndRelativeCapacity'),
        }


# extracted from Table 7.2.10.1-1: Information Elements in a Delete Session Response
class DeleteSessionResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (180, 1) : (DeleteSessionResponse_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (DeleteSessionResponse_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        (181, 0) : (DeleteSessionResponse_LoadControlInfo, 'PGWsNodeLevelLoadControlInfo'),
        (181, 1) : (DeleteSessionResponse_LoadControlInfo, 'PGWsAPNLevelLoadControlInfo'),
        (181, 2) : (DeleteSessionResponse_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        (204, 0) : (APNRateControlStatus, 'APNRateControlStatus'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeleteSessionResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 37}),
        DeleteSessionResponseIEs(hier=1)
        )


# extracted from Table 7.2.10.2-3: Overload Control Information within Delete Bearer Response
class DeleteBearerResponse_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.10.2-2: Bearer Context within Delete Bearer Response
class DeleteBearerResponse_BearerContext(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (78, 0)  : (PCO, 'PCO'),
        (172, 0) : (RANNASCause, 'RANNASCause'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        }


# extracted from Table 7.2.10.2-1: Information Elements in Delete Bearer Response
class DeleteBearerResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (74, 0)  : (IPAddress, 'UELocalIPAddress'),
        (78, 0)  : (PCO, 'PCO'),
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (93, 0)  : (DeleteBearerResponse_BearerContext, 'BearerContexts'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (126, 0) : (PortNumber, 'UEUDPPort'),
        (126, 1) : (PortNumber, 'UETCPPort'),
        (132, 2) : (FQCSID, 'EPDGFQCSID'),
        (132, 0) : (FQCSID, 'MMEFQCSID'),
        (132, 3) : (FQCSID, 'TWANFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (169, 0) : (TWANIdent, 'TWANIdent'),
        (169, 1) : (TWANIdent, 'WLANLocationInfo'),
        (170, 0) : (ULITimestamp, 'ULITimestamp'),
        (179, 1) : (TWANIdentTimestamp, 'WLANLocationTimestamp'),
        (179, 0) : (TWANIdentTimestamp, 'TWANIdentTimestamp'),
        (180, 2) : (DeleteBearerResponse_OverloadControlInfo, 'TWANePDGsOverloadControlInfo'),
        (180, 0) : (DeleteBearerResponse_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        (180, 1) : (DeleteBearerResponse_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeleteBearerResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 100}),
        DeleteBearerResponseIEs(hier=1)
        )


# extracted from Table 7.2.11.1-3: Overload Control Information within Downlink Data Notification
class DownlinkDataNotification_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.11.1-2: Load Control Information within Downlink Data Notification
class DownlinkDataNotification_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.11.1-1: Information Elements in a Downlink Data Notification
class DownlinkDataNotificationIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        (77, 0)  : (Ind, 'IndFlags'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (155, 0) : (ARP, 'AllocationRetentionPriority'),
        (180, 0) : (DownlinkDataNotification_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (181, 0) : (DownlinkDataNotification_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        (186, 0) : (PagingAndServiceInfo, 'PagingAndServiceInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class DownlinkDataNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 176}),
        DownlinkDataNotificationIEs(hier=1)
        )


# extracted from Table 7.2.11.2-1: Information Elements in a Downlink Data Notification Acknowledge
class DownlinkDataNotificationAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (3, 0)   : (Recovery, 'Recovery'),
        (92, 0)  : (DelayValue, 'DataNotificationDelay'),
        (154, 0) : (Throttling, 'DLLowPriorityTrafficThrottling'),
        (156, 0) : (EPCTimer, 'DLBufferingDuration'),
        (187, 0) : (IntegerNumber, 'DLBufferingSuggestedPacketCount'),
        255      : (PrivExt, 'PrivExt'),
        }


class DownlinkDataNotificationAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 177}),
        DownlinkDataNotificationAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.2.11.3-1: Information Elements in a Downlink Data Notification Failure Indication
class DownlinkDataNotificationFailureIndicationIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (135, 0) : (NodeType, 'OriginatingNode'),
        255      : (PrivExt, 'PrivExt'),
        }


class DownlinkDataNotificationFailureIndication(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 70}),
        DownlinkDataNotificationFailureIndicationIEs(hier=1)
        )


# extracted from Table 7.2.12-1: Information Element in Delete Indirect Data Forwarding Tunnel Request
class DeleteIndirectDataForwardingTunnelRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class DeleteIndirectDataForwardingTunnelRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 168}),
        DeleteIndirectDataForwardingTunnelRequestIEs(hier=1)
        )


# extracted from Table 7.2.13-1: Information Element in Delete Indirect Data Forwarding Tunnel Response
class DeleteIndirectDataForwardingTunnelResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeleteIndirectDataForwardingTunnelResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 169}),
        DeleteIndirectDataForwardingTunnelResponseIEs(hier=1)
        )


# extracted from Table 7.2.14-3: Overload Control Information within Modify Bearer Command
class ModifyBearerCommand_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.14.1-2: Bearer Context within Modify Bearer Command
class ModifyBearerCommand_BearerContext(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (80, 0)  : (BearerQoS, 'BearerLevelQoS'),
        }


# extracted from Table 7.2.14.1-1: Information Elements in a Modify Bearer Command
class ModifyBearerCommandIEs(GTPCIEs):
    MAND = {
        (72, 0)  : (AMBR, 'APNAggregateMaximumBitRate'),
        (93, 0)  : (ModifyBearerCommand_BearerContext, 'BearerContext'),
        }
    OPT  = {
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (180, 2) : (ModifyBearerCommand_OverloadControlInfo, 'TWANePDGsOverloadControlInfo'),
        (180, 1) : (ModifyBearerCommand_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (ModifyBearerCommand_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class ModifyBearerCommand(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 64}),
        ModifyBearerCommandIEs(hier=1)
        )


# extracted from Table 7.2.14-2: Overload Control Information within Modify Bearer Failure Indication
class ModifyBearerFailureIndication_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.14.2-1: Information Elements in a Modify Bearer Failure Indication
class ModifyBearerFailureIndicationIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (77, 0)  : (Ind, 'IndFlags'),
        (180, 1) : (ModifyBearerFailureIndication_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (ModifyBearerFailureIndication_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class ModifyBearerFailureIndication(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 65}),
        ModifyBearerFailureIndicationIEs(hier=1)
        )


# extracted from Table 7.2.15-4: Overload Control Information within Update Bearer Request
class UpdateBearerRequest_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.15-3: Load Control Information within Update Bearer Request
class UpdateBearerRequest_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        (184, 0) : (APNAndRelativeCapacity, 'ListOfAPNAndRelativeCapacity'),
        }


# extracted from Table 7.2.15-2: Bearer Context within Update Bearer Request
class UpdateBearerRequest_BearerContext(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (78, 0)  : (PCO, 'PCO'),
        (80, 0)  : (BearerQoS, 'BearerLevelQoS'),
        (84, 0)  : (BearerTFT, 'TFT'),
        (97, 0)  : (BearerFlags, 'BearerFlags'),
        (163, 0) : (AdditionalPCO, 'AdditionalPCO'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        (203, 0) : (MaximumPacketLossRate, 'MaximumPacketLossRate'),
        }


# extracted from Table 7.2.15-1: Information Elements in an Update Bearer Request
class UpdateBearerRequestIEs(GTPCIEs):
    MAND = {
        (72, 0)  : (AMBR, 'AggregateMaximumBitRate'),
        (93, 0)  : (UpdateBearerRequest_BearerContext, 'BearerContexts'),
        }
    OPT  = {
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (100, 0) : (PTI, 'PTI'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (131, 0) : (ChangeReportingAction, 'ChangeReportingAction'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (132, 0) : (FQCSID, 'PGWFQCSID'),
        (146, 0) : (CSGInfoReportingAction, 'CSGInfoReportingAction'),
        (165, 0) : (HeNBInfoReporting, 'HeNBInfoReporting'),
        (177, 0) : (PresenceReportingAreaAction, 'PresenceReportingAreaAction'),
        (180, 0) : (UpdateBearerRequest_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        (180, 1) : (UpdateBearerRequest_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (181, 0) : (UpdateBearerRequest_LoadControlInfo, 'PGWsNodeLevelLoadControlInfo'),
        (181, 1) : (UpdateBearerRequest_LoadControlInfo, 'PGWsAPNLevelLoadControlInfo'),
        (181, 2) : (UpdateBearerRequest_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class UpdateBearerRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 97}),
        UpdateBearerRequestIEs(hier=1)
        )


# extracted from Table 7.2.16-3: Overload Control Information within Update Bearer Response
class UpdateBearerResponse_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.16-2: Bearer Context within Update Bearer Response
class UpdateBearerResponse_BearerContext(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (78, 0)  : (PCO, 'PCO'),
        (87, 0)  : (FTEID, 'S4USGSNFTEID'),
        (87, 1)  : (FTEID, 'S12RNCFTEID'),
        (172, 0) : (RANNASCause, 'RANNASCause'),
        (197, 0) : (EPCO, 'ExtendedPCO'),
        }


# extracted from Table 7.2.16-1: Information Elements in an Update Bearer Response
class UpdateBearerResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (93, 0)  : (UpdateBearerResponse_BearerContext, 'BearerContexts'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (74, 0)  : (IPAddress, 'UELocalIPAddress'),
        (77, 0)  : (Ind, 'IndFlags'),
        (78, 0)  : (PCO, 'PCO'),
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (118, 0) : (FContainer, 'NBIFOMContainer'),
        (126, 1) : (PortNumber, 'UETCPPort'),
        (126, 0) : (PortNumber, 'UEUDPPort'),
        (132, 3) : (FQCSID, 'TWANFQCSID'),
        (132, 2) : (FQCSID, 'EPDGFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (132, 0) : (FQCSID, 'MMEFQCSID'),
        (169, 0) : (TWANIdent, 'TWANIdent'),
        (169, 1) : (TWANIdent, 'WLANLocationInfo'),
        (178, 0) : (PresenceReportingAreaInfo, 'PresenceReportingAreaInfo'),
        (179, 1) : (TWANIdentTimestamp, 'WLANLocationTimestamp'),
        (180, 2) : (UpdateBearerResponse_OverloadControlInfo, 'TWANePDGsOverloadControlInfo'),
        (180, 1) : (UpdateBearerResponse_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (UpdateBearerResponse_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class UpdateBearerResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 98}),
        UpdateBearerResponseIEs(hier=1)
        )


# extracted from Table 7.2.17.1-3: Overload Control Information within Delete Bearer Command
class DeleteBearerCommand_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.17.1-2: Bearer Context within Delete Bearer Command
class DeleteBearerCommand_BearerContext(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (97, 0)  : (BearerFlags, 'BearerFlags'),
        (172, 0) : (RANNASCause, 'RANNASReleaseCause'),
        }


# extracted from Table 7.2.17.1-1: Information Elements in Delete Bearer Command
class DeleteBearerCommandIEs(GTPCIEs):
    MAND = {
        (93, 0)  : (DeleteBearerCommand_BearerContext, 'BearerContexts'),
        }
    OPT  = {
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (170, 0) : (ULITimestamp, 'ULITimestamp'),
        (180, 1) : (DeleteBearerCommand_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (DeleteBearerCommand_OverloadControlInfo, 'MMES4SGSNsOverloadControlInfo'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeleteBearerCommand(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 66}),
        DeleteBearerCommandIEs(hier=1)
        )


# extracted from Table 7.2.17-3: Overload Control Information within Delete Bearer Failure Indication
class DeleteBearerFailureIndication_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        (71, 0)  : (APN, 'ListOfAccessPointName'),
        }


# extracted from Table 7.2.17.2-2: Bearer Context within Delete Bearer Failure Indication
class DeleteBearerFailureIndication_BearerContext(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        }


# extracted from Table 7.2.17.2-1: Information Elements in a Delete Bearer Failure Indication
class DeleteBearerFailureIndicationIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (93, 0)  : (DeleteBearerFailureIndication_BearerContext, 'BearerContext'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (77, 0)  : (Ind, 'IndFlags'),
        (180, 1) : (DeleteBearerFailureIndication_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (180, 0) : (DeleteBearerFailureIndication_OverloadControlInfo, 'PGWsOverloadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeleteBearerFailureIndication(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 67}),
        DeleteBearerFailureIndicationIEs(hier=1)
        )


# extracted from Table 7.2.18-2: Bearer Context within Create Indirect Data Forwarding Tunnel Request
class CreateIndirectDataForwardingTunnelRequest_BearerContext(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (87, 4)  : (FTEID, 'ENodeBFTEIDForULDataForwarding'),
        (87, 3)  : (FTEID, 'RNCFTEIDForDLDataForwarding'),
        (87, 5)  : (FTEID, 'SGWFTEIDForULDataForwarding'),
        (87, 0)  : (FTEID, 'ENodeBFTEIDForDLDataForwarding'),
        (87, 1)  : (FTEID, 'SGWUPFFTEIDForDLDataForwarding'),
        (87, 6)  : (FTEID, 'MMEFTEIDForDLDataForwarding'),
        (87, 2)  : (FTEID, 'SGSNFTEIDForDLDataForwarding'),
        }


# extracted from Table 7.2.18-1: Information Elements in a Create Indirect Data Forwarding Tunnel Request
class CreateIndirectDataForwardingTunnelRequestIEs(GTPCIEs):
    MAND = {
        (93, 0)  : (CreateIndirectDataForwardingTunnelRequest_BearerContext, 'BearerContexts'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (3, 0)   : (Recovery, 'Recovery'),
        (75, 0)  : (MEI, 'MEIdentity'),
        (77, 0)  : (Ind, 'IndFlags'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        255      : (PrivExt, 'PrivExt'),
        }


class CreateIndirectDataForwardingTunnelRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 166}),
        CreateIndirectDataForwardingTunnelRequestIEs(hier=1)
        )


# extracted from Table 7.2.19-2: Bearer Context within Create Indirect Data Forwarding Tunnel Response
class CreateIndirectDataForwardingTunnelResponse_BearerContext(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (87, 4)  : (FTEID, 'S1USGWFTEIDForULDataForwarding'),
        (87, 3)  : (FTEID, 'SGWFTEIDForDLDataForwarding'),
        (87, 5)  : (FTEID, 'SGWFTEIDForULDataForwarding'),
        (87, 0)  : (FTEID, 'S1USGWFTEIDForDLDataForwarding'),
        (87, 1)  : (FTEID, 'S12SGWFTEIDForDLDataForwarding'),
        (87, 2)  : (FTEID, 'S4USGWFTEIDForDLDataForwarding'),
        }


# extracted from Table 7.2.19-1: Information Elements in a Create Indirect Data Forwarding Tunnel Response
class CreateIndirectDataForwardingTunnelResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (93, 0)  : (CreateIndirectDataForwardingTunnelResponse_BearerContext, 'BearerContexts'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        255      : (PrivExt, 'PrivExt'),
        }


class CreateIndirectDataForwardingTunnelResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 167}),
        CreateIndirectDataForwardingTunnelResponseIEs(hier=1)
        )


# extracted from Table 7.2.21-1: Information Element in Release Access Bearers Request
class ReleaseAccessBearersRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (73, 0)  : (EBI, 'ListOfRABs'),
        (77, 0)  : (Ind, 'IndFlags'),
        (135, 0) : (NodeType, 'OriginatingNode'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        255      : (PrivExt, 'PrivExt'),
        }


class ReleaseAccessBearersRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 170}),
        ReleaseAccessBearersRequestIEs(hier=1)
        )


# extracted from Table 7.2.22-3: Overload Control Information within Release Access Bearers Response
class ReleaseAccessBearersResponse_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.22-2: Load Control Information within Release Access Bearers Response
class ReleaseAccessBearersResponse_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.22-1: Information Element in Release Access Bearers Response
class ReleaseAccessBearersResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (77, 0)  : (Ind, 'IndFlags'),
        (180, 0) : (ReleaseAccessBearersResponse_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (181, 0) : (ReleaseAccessBearersResponse_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class ReleaseAccessBearersResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 171}),
        ReleaseAccessBearersResponseIEs(hier=1)
        )


# extracted from Table 7.2.23-1: Information Elements in a Stop Paging Indication
class StopPagingIndicationIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        255      : (PrivExt, 'PrivExt'),
        }


class StopPagingIndication(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 73}),
        StopPagingIndicationIEs(hier=1)
        )


# extracted from Table 7.2.24-3: Bearer Context to be removed within Modify Access Bearers Request
class ModifyAccessBearersRequest_BearerContextToBeRemoved(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        }


# extracted from Table 7.2.24-2: Bearer Context to be modified within Modify Access Bearers Request
class ModifyAccessBearersRequest_BearerContextToBeModified(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (87, 0)  : (FTEID, 'S1UENodeBFTEID'),
        (87, 1)  : (FTEID, 'S11UMMEFTEID'),
        }


# extracted from Table 7.2.24-1 : Information Elements in a Modify Access Bearers Request
class ModifyAccessBearersRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (77, 0)  : (Ind, 'IndFlags'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (92, 0)  : (DelayValue, 'DelayDownlinkPacketNotificationRequest'),
        (93, 1)  : (ModifyAccessBearersRequest_BearerContextToBeRemoved, 'BearerContextsToBeRemoved'),
        (93, 0)  : (ModifyAccessBearersRequest_BearerContextToBeModified, 'BearerContextsToBeModified'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        255      : (PrivExt, 'PrivExt'),
        }


class ModifyAccessBearersRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 211}),
        ModifyAccessBearersRequestIEs(hier=1)
        )


# extracted from Table 7.2.25-5: Overload Control Information within Modify Access Bearers Response
class ModifyAccessBearersResponse_OverloadControlInfo(GTPCIEs):
    MAND = {
        (156, 0) : (EPCTimer, 'PeriodOfValidity'),
        (182, 0) : (Metric, 'OverloadReductionMetric'),
        (183, 0) : (SequenceNumber, 'OverloadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.25-4: Load Control Information within Modify Access Bearers Response
class ModifyAccessBearersResponse_LoadControlInfo(GTPCIEs):
    MAND = {
        (182, 0) : (Metric, 'LoadMetric'),
        (183, 0) : (SequenceNumber, 'LoadControlSequenceNumber'),
        }
    OPT  = {
        }


# extracted from Table 7.2.25-3: Bearer Context marked for removal within Modify Access Bearers Response
class ModifyAccessBearersResponse_BearerContextMarkedForRemoval(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        }


# extracted from Table 7.2.25-2: Bearer Context modified within Modify Access Bearers Response
class ModifyAccessBearersResponse_BearerContextModified(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (73, 0)  : (EBI, 'EPSBearerID'),
        }
    OPT  = {
        (87, 0)  : (FTEID, 'S1USGWFTEID'),
        (87, 1)  : (FTEID, 'S11USGWFTEID'),
        }


# extracted from Table 7.2.25-1: Information Elements in a Modify Access Bearers Response
class ModifyAccessBearersResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (77, 0)  : (Ind, 'IndFlags'),
        (93, 1)  : (ModifyAccessBearersResponse_BearerContextMarkedForRemoval, 'BearerContextsMarkedForRemoval'),
        (93, 0)  : (ModifyAccessBearersResponse_BearerContextModified, 'BearerContextsModified'),
        (180, 0) : (ModifyAccessBearersResponse_OverloadControlInfo, 'SGWsOverloadControlInfo'),
        (181, 0) : (ModifyAccessBearersResponse_LoadControlInfo, 'SGWsNodeLevelLoadControlInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class ModifyAccessBearersResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 212}),
        ModifyAccessBearersResponseIEs(hier=1)
        )


# extracted from Table 7.2.26-2: Remote UE Context Connected within Remote UE Report Notification
class RemoteUEReportNotification_RemoteUEContextConnected(GTPCIEs):
    MAND = {
        (192, 0) : (RemoteUserID, 'RemoteUserID'),
        (193, 0) : (RemoteUEIPInfo, 'RemoteUEIPInfo'),
        }
    OPT  = {
        }


# extracted from Table 7.2.26-1: Information Elements in Remote UE Report Notification
class RemoteUEReportNotificationIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (191, 0) : (RemoteUEReportNotification_RemoteUEContextConnected, 'RemoteUEContextConnected'),
        (191, 1) : (RemoteUEContext, 'RemoteUEContextDisconnected'),
        255      : (PrivExt, 'PrivExt'),
        }


class RemoteUEReportNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 40}),
        RemoteUEReportNotificationIEs(hier=1)
        )


# extracted from Table 7.2.27-1: Information Elements in Remote UE Report Acknowledge
class RemoteUEReportAcknowledgeIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class RemoteUEReportAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 41}),
        RemoteUEReportAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.3.1-5: MME UE SCEF PDN Connections within Forward Relocation Request
class ForwardRelocationRequest_MMEUESCEFPDNConnections(GTPCIEs):
    MAND = {
        (71, 0)  : (APN, 'APN'),
        (73, 0)  : (EBI, 'DefaultEPSBearerID'),
        (176, 0) : (NodeIdent, 'SCEFID'),
        }
    OPT  = {
        }


# extracted from Table 7.3.1-4: Remote UE Context Connected within MME/SGSN UE EPS PDN Connections within Forward Relocation Request
class ForwardRelocationRequest_MMESGSNUEEPSPDNConnections_RemoteUEContextConnected(GTPCIEs):
    MAND = {
        (192, 0) : (RemoteUserID, 'RemoteUserID'),
        (193, 0) : (RemoteUEIPInfo, 'RemoteUEIPInfo'),
        }
    OPT  = {
        }


# extracted from Table 7.3.1-3: Bearer Context within MME/SGSN/AMF UE EPS PDN Connections within Forward Relocation Request
class ForwardRelocationRequest_MMESGSNAMFUEEPSPDNConnections_BearerContext(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        (80, 0)  : (BearerQoS, 'BearerLevelQoS'),
        (87, 0)  : (FTEID, 'SGWS1S4S12IPAddressAndTEIDForUserPlane'),
        }
    OPT  = {
        (84, 0)  : (BearerTFT, 'TFT'),
        (87, 1)  : (FTEID, 'PGWS5S8IPAddressAndTEIDForUserPlane'),
        (87, 2)  : (FTEID, 'SGWS11IPAddressAndTEIDForUserPlane'),
        (97, 0)  : (BearerFlags, 'BearerFlags'),
        (118, 0) : (FContainer, 'BSSContainer'),
        (137, 0) : (TI, 'TransactionIdent'),
        }


# extracted from Table 7.3.1-2: MME/SGSN/AMF UE EPS PDN Connections within Forward Relocation Request
class ForwardRelocationRequest_MMESGSNAMFUEEPSPDNConnections(GTPCIEs):
    MAND = {
        (71, 0)  : (APN, 'APN'),
        (72, 0)  : (AMBR, 'AggregateMaximumBitRate'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (87, 0)  : (FTEID, 'PGWS5S8IPAddressForControlPlaneOrPMIP'),
        }
    OPT  = {
        (74, 1)  : (IPAddress, 'IPv6Address'),
        (74, 0)  : (IPAddress, 'IPv4Address'),
        (77, 0)  : (Ind, 'IndFlags'),
        (93, 0)  : (ForwardRelocationRequest_MMESGSNAMFUEEPSPDNConnections_BearerContext, 'BearerContexts'),
        (95, 0)  : (ChargingCharacteristics, 'ChargingCharacteristics'),
        (99, 0)  : (PDNType, 'PDNType'),
        (127, 0) : (APNRestriction, 'APNRestriction'),
        (128, 0) : (SelectionMode, 'SelectionMode'),
        (131, 0) : (ChangeReportingAction, 'ChangeReportingAction'),
        (136, 0) : (FQDN, 'PGWNodeName'),
        (136, 1) : (FQDN, 'LocalHomeNetworkID'),
        (146, 0) : (CSGInfoReportingAction, 'CSGInfoReportingAction'),
        (157, 0) : (SignallingPriorityInd, 'SignallingPriorityInd'),
        (165, 0) : (HeNBInfoReporting, 'HeNBInfoReporting'),
        (167, 0) : (ChangeToReportFlags, 'ChangeToReportFlags'),
        (177, 0) : (PresenceReportingAreaAction, 'PresenceReportingAreaAction'),
        (185, 0) : (WLANOffloadabilityInd, 'WLANOffloadabilityInd'),
        (191, 0) : (ForwardRelocationRequest_MMESGSNUEEPSPDNConnections_RemoteUEContextConnected, 'RemoteUEContextConnected'),
        (196, 0) : (HeaderCompressionConfiguration, 'HeaderCompressionConfiguration'),
        }


# extracted from Table 7.3.1-1: Information Elements in a Forward Relocation Request
class ForwardRelocationRequestIEs(GTPCIEs):
    MAND = {
        (87, 0)  : (FTEID, 'SendersFTEIDForControlPlane'),
        (103, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (104, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (105, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (106, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (107, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (108, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (3, 0)   : (Recovery, 'Recovery'),
        (51, 0)  : (STNSR, 'STNSR'),
        (74, 1)  : (IPAddress, '1xIWSS102IPAddress'),
        (74, 0)  : (IPAddress, 'HRPDAccessNodeS101IPAddress'),
        (76, 1)  : (MSISDN, 'MSISDN'),
        (76, 0)  : (MSISDN, 'CMSISDN'),
        (77, 0)  : (Ind, 'IndFlags'),
        (83, 0)  : (ServingNetwork, 'ServingNetwork'),
        (87, 1)  : (FTEID, 'SGWS11S4IPAddressAndTEIDForControlPlane'),
        (96, 0)  : (TraceInfo, 'TraceInfo'),
        (109, 0) : (ForwardRelocationRequest_MMESGSNAMFUEEPSPDNConnections, 'MMESGSNAMFUEEPSPDNConnections'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (118, 2) : (FContainer, 'BSSContainer'),
        (118, 1) : (FContainer, 'UTRANTransparentContainer'),
        (118, 0) : (FContainer, 'EUTRANTransparentContainer'),
        (119, 2) : (FCause, 'BSSGPCause'),
        (119, 0) : (FCause, 'S1APCause'),
        (119, 1) : (FCause, 'RANAPCause'),
        (120, 0) : (PLMNID, 'SelectedPLMNID'),
        (121, 0) : (TargetIdentification, 'TargetIdentification'),
        (126, 0) : (PortNumber, 'SourceUDPPortNumber'),
        (129, 0) : (SourceIdentification, 'SourceIdentification'),
        (136, 2) : (FQDN, 'MMENodeName'),
        (136, 0) : (FQDN, 'SGWNodeName'),
        (136, 1) : (FQDN, 'SGSNNodeName'),
        (144, 0) : (RFSPIndex, 'SubscribedRFSPIndex'),
        (144, 1) : (RFSPIndex, 'RFSPIndexInUse'),
        (145, 0) : (UCI, 'UserCSGInfo'),
        (147, 0) : (CSGID, 'CSGID'),
        (148, 0) : (CMI, 'CSGMembershipInd'),
        (151, 0) : (LDN, 'MMES4SGSNLDN'),
        (159, 0) : (AdditionalMMContextForSRVCC, 'AdditionalMMContextForSRVCC'),
        (160, 0) : (AdditionalFlagsForSRVCC, 'AdditionalFlagsForSRVCC'),
        (162, 0) : (MDTConfiguration, 'MDTConfiguration'),
        (187, 0) : (IntegerNumber, 'UEUsageType'),
        (189, 0) : (MonitoringEventInfo, 'MonitoringEventInfo'),
        (195, 0) : (ForwardRelocationRequest_MMEUESCEFPDNConnections, 'MMESGSNUESCEFPDNConnections'),
        (198, 0) : (ServingPLMNRateControl, 'ServingPLMNRateControl'),
        (205, 0) : (ExtendedTraceInfo, 'ExtendedTraceInfo'),
        (206, 0) : (MonitoringEventExtInfo, 'MonitoringEventExtInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class ForwardRelocationRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 133}),
        ForwardRelocationRequestIEs(hier=1)
        )


# extracted from Table 7.3.2-1: Information Elements in a Forward Relocation Response
class ForwardRelocationResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (77, 0)  : (Ind, 'IndFlags'),
        (87, 0)  : (FTEID, 'SendersFTEIDForControlPlane'),
        (93, 2)  : (BearerContext, 'ListOfSetupPFCs'),
        (93, 0)  : (BearerContext, 'ListOfSetupBearers'),
        (93, 1)  : (BearerContext, 'ListOfSetupRABs'),
        (93, 3)  : (BearerContext, 'ListOfSetupBearersForSCEFPDNConnections'),
        (118, 2) : (FContainer, 'BSSContainer'),
        (118, 1) : (FContainer, 'UTRANTransparentContainer'),
        (118, 0) : (FContainer, 'EUTRANTransparentContainer'),
        (119, 2) : (FCause, 'BSSGPCause'),
        (119, 1) : (FCause, 'RANAPCause'),
        (119, 0) : (FCause, 'S1APCause'),
        (136, 0) : (FQDN, 'SGSNNodeName'),
        (136, 1) : (FQDN, 'MMENodeName'),
        (151, 0) : (LDN, 'MMES4SGSNLDN'),
        (175, 0) : (NodeNumber, 'SGSNNumber'),
        (175, 1) : (NodeNumber, 'MMENumberForMTSMS'),
        (176, 3) : (NodeIdent, 'MMEIdentForMTSMS'),
        (176, 1) : (NodeIdent, 'MMEIdent'),
        (176, 2) : (NodeIdent, 'SGSNIdentForMTSMS'),
        (176, 0) : (NodeIdent, 'SGSNIdent'),
        255      : (PrivExt, 'PrivExt'),
        }


class ForwardRelocationResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 134}),
        ForwardRelocationResponseIEs(hier=1)
        )


# extracted from Table 7.3.3-1: Information Elements in a Forward Relocation Complete Notification
class ForwardRelocationCompleteNotificationIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (77, 0)  : (Ind, 'IndFlags'),
        255      : (PrivExt, 'PrivExt'),
        }


class ForwardRelocationCompleteNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 135}),
        ForwardRelocationCompleteNotificationIEs(hier=1)
        )


# extracted from Table 7.3.4-1: Information Elements in a Forward Relocation Complete Acknowledge
class ForwardRelocationCompleteAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        255      : (PrivExt, 'PrivExt'),
        }


class ForwardRelocationCompleteAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 136}),
        ForwardRelocationCompleteAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.3.5-1: Information Elements in a Context Request
class ContextRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (77, 0)  : (Ind, 'Ind'),
        (82, 0)  : (RATType, 'RATType'),
        (83, 0)  : (ServingNetwork, 'TargetPLMNID'),
        (86, 0)  : (ULI, 'RouteingAreaIdentity'),
        (87, 0)  : (FTEID, 'S3S16S10N26AddressAndTEIDForControlPlane'),
        (111, 0) : (PTMSI, 'PacketTMSI'),
        (112, 0) : (PTMSISignature, 'PTMSISignature'),
        (113, 0) : (HopCounter, 'HopCounter'),
        (116, 0) : (CompleteRequestMessage, 'CompleteTAURequestMessage'),
        (117, 0) : (GUTI, 'GUTI'),
        (126, 0) : (PortNumber, 'UDPSourcePortNumber'),
        (136, 1) : (FQDN, 'MMENodeName'),
        (136, 0) : (FQDN, 'SGSNNodeName'),
        (151, 0) : (LDN, 'MMES4SGSNLDN'),
        (175, 0) : (NodeNumber, 'SGSNNumber'),
        (176, 0) : (NodeIdent, 'SGSNIdent'),
        (176, 1) : (NodeIdent, 'MMEIdent'),
        (194, 0) : (CIoTOptimizationsSupportInd, 'CIoTOptimizationsSupportInd'),
        255      : (PrivExt, 'PrivExt'),
        }


class ContextRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 130}),
        ContextRequestIEs(hier=1)
        )


# extracted from Table 7.3.6-5: MME/SGSN UE SCEF PDN Connections within Context Response
class ContextResponse_MMESGSNUESCEFPDNConnections(GTPCIEs):
    MAND = {
        (71, 0)  : (APN, 'APN'),
        (73, 0)  : (EBI, 'DefaultEPSBearerID'),
        (176, 0) : (NodeIdent, 'SCEFID'),
        }
    OPT  = {
        }


# extracted from Table 7.3.6-4: Remote UE Context Connected within MME/SGSN UE EPS PDN Connections within Context Response
class ContextResponse_MMESGSNUEEPSPDNConnections_RemoteUEContextConnected(GTPCIEs):
    MAND = {
        (192, 0) : (RemoteUserID, 'RemoteUserID'),
        (193, 0) : (RemoteUEIPInfo, 'RemoteUEIPInfo'),
        }
    OPT  = {
        }


# extracted from Table 7.3.6-3: Bearer Context within MME/SGSN/AMF UE EPS PDN Connections within Context Response
class ContextResponse_MMESGSNAMFUEEPSPDNConnections_BearerContext(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        (80, 0)  : (BearerQoS, 'BearerLevelQoS'),
        }
    OPT  = {
        (84, 0)  : (BearerTFT, 'TFT'),
        (87, 0)  : (FTEID, 'SGWS1S4S12S11IPAddressAndTEIDForUserPlane'),
        (87, 1)  : (FTEID, 'PGWS5S8IPAddressAndTEIDForUserPlane'),
        (87, 2)  : (FTEID, 'SGWS11IPAddressAndTEIDForUserPlane'),
        (118, 0) : (FContainer, 'BSSContainer'),
        (137, 0) : (TI, 'TransactionIdent'),
        }


# extracted from Table 7.3.6-2: MME/SGSN/AMF UE EPS PDN Connections within Context Response
class ContextResponse_MMESGSNAMFUEEPSPDNConnections(GTPCIEs):
    MAND = {
        (71, 0)  : (APN, 'APN'),
        (72, 0)  : (AMBR, 'AggregateMaximumBitRate'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (87, 0)  : (FTEID, 'PGWS5S8IPAddressForControlPlaneOrPMIP'),
        (93, 0)  : (ContextResponse_MMESGSNAMFUEEPSPDNConnections_BearerContext, 'BearerContexts'),
        }
    OPT  = {
        (74, 1)  : (IPAddress, 'IPv6Address'),
        (74, 0)  : (IPAddress, 'IPv4Address'),
        (77, 0)  : (Ind, 'IndFlags'),
        (95, 0)  : (ChargingCharacteristics, 'ChargingCharacteristics'),
        (99, 0)  : (PDNType, 'PDNType'),
        (127, 0) : (APNRestriction, 'APNRestriction'),
        (128, 0) : (SelectionMode, 'SelectionMode'),
        (131, 0) : (ChangeReportingAction, 'ChangeReportingAction'),
        (136, 0) : (FQDN, 'PGWNodeName'),
        (136, 1) : (FQDN, 'LocalHomeNetworkID'),
        (146, 0) : (CSGInfoReportingAction, 'CSGInfoReportingAction'),
        (157, 0) : (SignallingPriorityInd, 'SignallingPriorityInd'),
        (165, 0) : (HeNBInfoReporting, 'HeNBInfoReporting'),
        (167, 0) : (ChangeToReportFlags, 'ChangeToReportFlags'),
        (177, 0) : (PresenceReportingAreaAction, 'PresenceReportingAreaAction'),
        (185, 0) : (WLANOffloadabilityInd, 'WLANOffloadabilityInd'),
        (191, 0) : (ContextResponse_MMESGSNUEEPSPDNConnections_RemoteUEContextConnected, 'RemoteUEContextConnected'),
        (196, 0) : (HeaderCompressionConfiguration, 'HeaderCompressionConfiguration'),
        }


# extracted from Table 7.3.6-1: Information Elements in a Context Response
class ContextResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (74, 1)  : (IPAddress, '1xIWSS102IPAddress'),
        (74, 0)  : (IPAddress, 'HRPDAccessNodeS101IPAddress'),
        (77, 0)  : (Ind, 'IndFlags'),
        (82, 0)  : (RATType, 'RATType'),
        (87, 1)  : (FTEID, 'SGWS11S4IPAddressAndTEIDForControlPlane'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (96, 0)  : (TraceInfo, 'TraceInfo'),
        (103, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (104, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (105, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (106, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (107, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (108, 0) : (MMContext, 'MMESGSNAMFUEMMContext'),
        (109, 0) : (ContextResponse_MMESGSNAMFUEEPSPDNConnections, 'MMESGSNAMFUEEPSPDNConnections'),
        (114, 0) : (UETimeZone, 'UETimeZone'),
        (136, 2) : (FQDN, 'MMENodeName'),
        (136, 0) : (FQDN, 'SGWNodeName'),
        (136, 1) : (FQDN, 'SGSNNodeName'),
        (144, 0) : (RFSPIndex, 'SubscribedRFSPIndex'),
        (144, 1) : (RFSPIndex, 'RFSPIndexInUse'),
        (145, 0) : (UCI, 'UserCSGInfo'),
        (151, 0) : (LDN, 'MMES4SGSNLDN'),
        (162, 0) : (MDTConfiguration, 'MDTConfiguration'),
        (187, 0) : (IntegerNumber, 'UEUsageType'),
        (187, 1) : (IntegerNumber, 'RemainingRunningServiceGapTimer'),
        (189, 0) : (MonitoringEventInfo, 'MonitoringEventInfo'),
        (195, 0) : (ContextResponse_MMESGSNUESCEFPDNConnections, 'MMESGSNUESCEFPDNConnections'),
        (198, 0) : (ServingPLMNRateControl, 'ServingPLMNRateControl'),
        (199, 0) : (Counter, 'MOExceptionDataCounter'),
        (205, 0) : (ExtendedTraceInfo, 'ExtendedTraceInfo'),
        (206, 0) : (MonitoringEventExtInfo, 'MonitoringEventExtInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class ContextResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 131}),
        ContextResponseIEs(hier=1)
        )


# extracted from Table 7.3.7-2: Bearer Context within Context Acknowledge
class ContextAcknowledge_BearerContext(GTPCIEs):
    MAND = {
        (73, 0)  : (EBI, 'EPSBearerID'),
        (87, 0)  : (FTEID, 'ForwardingFTEID'),
        }
    OPT  = {
        }


# extracted from Table 7.3.7-1: Information Elements in a Context Acknowledge
class ContextAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (77, 0)  : (Ind, 'IndFlags'),
        (87, 0)  : (FTEID, 'ForwardingFTEID'),
        (93, 0)  : (ContextAcknowledge_BearerContext, 'BearerContexts'),
        (175, 0) : (NodeNumber, 'SGSNNumber'),
        (175, 1) : (NodeNumber, 'MMENumberForMTSMS'),
        (176, 1) : (NodeIdent, 'MMEIdentForMTSMS'),
        (176, 0) : (NodeIdent, 'SGSNIdentForMTSMS'),
        255      : (PrivExt, 'PrivExt'),
        }


class ContextAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 132}),
        ContextAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.3.8-1: Information Elements in an Identification Request
class IdentificationRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (74, 0)  : (IPAddress, 'AddressForControlPlane'),
        (83, 0)  : (ServingNetwork, 'TargetPLMNID'),
        (86, 0)  : (ULI, 'RouteingAreaIdentity'),
        (111, 0) : (PTMSI, 'PacketTMSI'),
        (112, 0) : (PTMSISignature, 'PTMSISignature'),
        (113, 0) : (HopCounter, 'HopCounter'),
        (116, 0) : (CompleteRequestMessage, 'CompleteAttachRequestMessage'),
        (117, 0) : (GUTI, 'GUTI'),
        (126, 0) : (PortNumber, 'UDPSourcePortNumber'),
        255      : (PrivExt, 'PrivExt'),
        }


class IdentificationRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 128}),
        IdentificationRequestIEs(hier=1)
        )


# extracted from Table 7.3.9-1: Information Elements in an Identification Response
class IdentificationResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (96, 0)  : (TraceInfo, 'TraceInfo'),
        (103, 0) : (MMContext, 'MMESGSNUEMMContext'),
        (104, 0) : (MMContext, 'MMESGSNUEMMContext'),
        (105, 0) : (MMContext, 'MMESGSNUEMMContext'),
        (106, 0) : (MMContext, 'MMESGSNUEMMContext'),
        (107, 0) : (MMContext, 'MMESGSNUEMMContext'),
        (108, 0) : (MMContext, 'MMESGSNUEMMContext'),
        (187, 0) : (IntegerNumber, 'UEUsageType'),
        (189, 0) : (MonitoringEventInfo, 'MonitoringEventInfo'),
        (205, 0) : (ExtendedTraceInfo, 'ExtendedTraceInfo'),
        (206, 0) : (MonitoringEventExtInfo, 'MonitoringEventExtInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class IdentificationResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 129}),
        IdentificationResponseIEs(hier=1)
        )


# extracted from Table 7.3.10-1: Information Elements in a Forward Access Context Notification
class ForwardAccessContextNotificationIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (110, 0) : (PDUNumbers, 'PDUNumbers'),
        (118, 0) : (FContainer, 'EUTRANTransparentContainer'),
        (124, 0) : (RABContext, 'RABContexts'),
        (125, 0) : (SourceRNCPDCPContextInfo, 'SourceRNCPDCPContextInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class ForwardAccessContextNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 137}),
        ForwardAccessContextNotificationIEs(hier=1)
        )


# extracted from Table 7.3.11-1: Information Elements in a Forward Access Context Acknowledge
class ForwardAccessContextAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class ForwardAccessContextAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 138}),
        ForwardAccessContextAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.3.12-1: Information Elements in a Detach Notification
class DetachNotificationIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (150, 0) : (DetachType, 'DetachType'),
        255      : (PrivExt, 'PrivExt'),
        }


class DetachNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 149}),
        DetachNotificationIEs(hier=1)
        )


# extracted from Table 7.3.13-1: Information Elements in a Detach Acknowledge
class DetachAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        255      : (PrivExt, 'PrivExt'),
        }


class DetachAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 150}),
        DetachAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.3.14-1: Information Element in Change Notification Request
class ChangeNotificationRequestIEs(GTPCIEs):
    MAND = {
        (82, 0)  : (RATType, 'RATType'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (73, 0)  : (EBI, 'LBI'),
        (74, 0)  : (IPAddress, 'PGWS5S8GTPCIPAddress'),
        (75, 0)  : (MEI, 'MEIdentity'),
        (77, 0)  : (Ind, 'IndFlags'),
        (86, 0)  : (ULI, 'UserLocationInfo'),
        (145, 0) : (UCI, 'UserCSGInfo'),
        (178, 0) : (PresenceReportingAreaInfo, 'PresenceReportingAreaInfo'),
        (199, 0) : (Counter, 'MOExceptionDataCounter'),
        (201, 0) : (SecondaryRATUsageDataReport, 'SecondaryRATUsageDataReport'),
        255      : (PrivExt, 'PrivExt'),
        }


class ChangeNotificationRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 38}),
        ChangeNotificationRequestIEs(hier=1)
        )


# extracted from Table 7.3.15-1: Information Element in Change Notification Response
class ChangeNotificationResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (75, 0)  : (MEI, 'MEIdentity'),
        (131, 0) : (ChangeReportingAction, 'ChangeReportingAction'),
        (146, 0) : (CSGInfoReportingAction, 'CSGInfoReportingAction'),
        (177, 0) : (PresenceReportingAreaAction, 'PresenceReportingAreaAction'),
        255      : (PrivExt, 'PrivExt'),
        }


class ChangeNotificationResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 39}),
        ChangeNotificationResponseIEs(hier=1)
        )


# extracted from Table 7.3.16-1: Information Elements in Relocation Cancel Request
class RelocationCancelRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (75, 0)  : (MEI, 'MEIdentity'),
        (77, 0)  : (Ind, 'IndFlags'),
        (119, 0) : (FCause, 'RANAPCause'),
        255      : (PrivExt, 'PrivExt'),
        }


class RelocationCancelRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 139}),
        RelocationCancelRequestIEs(hier=1)
        )


# extracted from Table 7.3.17-1: Information Elements in Relocation Cancel Response
class RelocationCancelResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class RelocationCancelResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 140}),
        RelocationCancelResponseIEs(hier=1)
        )


# extracted from Table 7.3.18-1: Information Elements in a Configuration Transfer Tunnel Message
class ConfigurationTransferTunnelMessageIEs(GTPCIEs):
    MAND = {
        (118, 0) : (FContainer, 'EUTRANTransparentContainerENDCContainer'),
        (121, 0) : (TargetIdentification, 'TargetENodeBIDEngNBID'),
        }
    OPT  = {
        (121, 1) : (TargetIdentification, 'ConnectedTargetENodeBID'),
        }


class ConfigurationTransferTunnelMessage(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 141}),
        ConfigurationTransferTunnelMessageIEs(hier=1)
        )


# extracted from Table 7.3.19-1: Information Elements in a RAN Information Relay
class RANInformationRelayIEs(GTPCIEs):
    MAND = {
        (118, 0) : (FContainer, 'BSSContainer'),
        }
    OPT  = {
        (121, 0) : (TargetIdentification, 'RIMRoutingAddress'),
        255      : (PrivExt, 'PrivExt'),
        }


class RANInformationRelay(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 152}),
        RANInformationRelayIEs(hier=1)
        )


# extracted from Table 7.3.20-1: Information Elements in an ISR Status Indication
class ISRStatusIndicationIEs(GTPCIEs):
    MAND = {
        (168, 0) : (ActionInd, 'ActionInd'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class ISRStatusIndication(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 157}),
        ISRStatusIndicationIEs(hier=1)
        )


# extracted from Table 7.3.21-1: Information Elements in UE Registration Query Request
class UERegistrationQueryRequestIEs(GTPCIEs):
    MAND = {
        (1, 0)   : (IMSI, 'IMSI'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class UERegistrationQueryRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 158}),
        UERegistrationQueryRequestIEs(hier=1)
        )


# extracted from Table 7.3.22-1: Information Elements in UE Registration Query Response
class UERegistrationQueryResponseIEs(GTPCIEs):
    MAND = {
        (1, 0)   : (IMSI, 'IMSI'),
        (120, 0) : (PLMNID, 'SelectedCoreNetworkOperatorIdent'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class UERegistrationQueryResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 159}),
        UERegistrationQueryResponseIEs(hier=1)
        )


# extracted from Table 7.4.1-1: Information Element in Suspend Notification
class SuspendNotificationIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (74, 0)  : (IPAddress, 'AddressForControlPlane'),
        (86, 0)  : (ULI, 'RouteingAreaIdentity'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (111, 0) : (PTMSI, 'PacketTMSI'),
        (113, 0) : (HopCounter, 'HopCounter'),
        (126, 0) : (PortNumber, 'UDPSourcePortNumber'),
        (135, 0) : (NodeType, 'OriginatingNode'),
        255      : (PrivExt, 'PrivExt'),
        }


class SuspendNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 162}),
        SuspendNotificationIEs(hier=1)
        )


# extracted from Table 7.4.2-1: Information Element in Suspend Acknowledge
class SuspendAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class SuspendAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 163}),
        SuspendAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.4.3-1: Information Element in Resume Notification
class ResumeNotificationIEs(GTPCIEs):
    MAND = {
        (1, 0)   : (IMSI, 'IMSI'),
        }
    OPT  = {
        (73, 0)  : (EBI, 'LinkedEPSBearerID'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (135, 0) : (NodeType, 'OriginatingNode'),
        255      : (PrivExt, 'PrivExt'),
        }


class ResumeNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 164}),
        ResumeNotificationIEs(hier=1)
        )


# extracted from Table 7.4.4-1: Information Element in Resume Acknowledge
class ResumeAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class ResumeAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 165}),
        ResumeAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.4.5-1: Information Element in CS Paging Indication
class CSPagingIndicationIEs(GTPCIEs):
    MAND = {
        (1, 0)   : (IMSI, 'IMSI'),
        (136, 0) : (FQDN, 'VLRName'),
        }
    OPT  = {
        (86, 0)  : (ULI, 'LocationAreaIdent'),
        (88, 0)  : (TMSI, 'TMSI'),
        (89, 0)  : (GlobalCNId, 'GlobalCNId'),
        (133, 0) : (ChannelNeeded, 'ChannelNeeded'),
        (134, 0) : (EMLPPPriority, 'EMLPPPriority'),
        (149, 0) : (ServiceIndicator, 'ServiceIndicator'),
        255      : (PrivExt, 'PrivExt'),
        }


class CSPagingIndication(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 151}),
        CSPagingIndicationIEs(hier=1)
        )


# extracted from Table 7.4.6-1: Information Element in Alert MME Notification
class AlertMMENotificationIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class AlertMMENotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 153}),
        AlertMMENotificationIEs(hier=1)
        )


# extracted from Table 7.4.7-1: Information Elements in Alert MME Acknowledge
class AlertMMEAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class AlertMMEAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 154}),
        AlertMMEAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.4.8-1: Information Element in UE Activity Notification
class UEActivityNotificationIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class UEActivityNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 155}),
        UEActivityNotificationIEs(hier=1)
        )


# extracted from Table 7.4.z-1: Information Elements in UE Activity Acknowledge
class UEActivityAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class UEActivityAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 156}),
        UEActivityAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.5.1-1: Information Elements in a Create Forwarding Tunnel Request
class CreateForwardingTunnelRequestIEs(GTPCIEs):
    MAND = {
        (90, 0)  : (S103PDF, 'S103PDNDataForwardingInfo'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class CreateForwardingTunnelRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 160}),
        CreateForwardingTunnelRequestIEs(hier=1)
        )


# extracted from Table 7.5.2-1: Information Elements in a Create Forwarding Tunnel Response
class CreateForwardingTunnelResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (91, 0)  : (S1UDF, 'S1UDataForwardingInfo'),
        255      : (PrivExt, 'PrivExt'),
        }


class CreateForwardingTunnelResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 161}),
        CreateForwardingTunnelResponseIEs(hier=1)
        )


# extracted from Table 7.9.1-1: Information Elements in a Delete PDN Connection Set Request
class DeletePDNConnectionSetRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (132, 3) : (FQCSID, 'EPDGFQCSID'),
        (132, 2) : (FQCSID, 'PGWFQCSID'),
        (132, 4) : (FQCSID, 'TWANFQCSID'),
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (132, 0) : (FQCSID, 'MMEFQCSID'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeletePDNConnectionSetRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 101}),
        DeletePDNConnectionSetRequestIEs(hier=1)
        )


# extracted from Table 7.9.2: Information Elements in a Delete PDN Connection Set Response
class DeletePDNConnectionSetResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        255      : (PrivExt, 'PrivExt'),
        }


class DeletePDNConnectionSetResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 102}),
        DeletePDNConnectionSetResponseIEs(hier=1)
        )


# extracted from Table 7.9.3-1: Information Elements in a Update PDN Connection Set Request
class UpdatePDNConnectionSetRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (132, 1) : (FQCSID, 'SGWFQCSID'),
        (132, 0) : (FQCSID, 'MMEFQCSID'),
        255      : (PrivExt, 'PrivExt'),
        }


class UpdatePDNConnectionSetRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 200}),
        UpdatePDNConnectionSetRequestIEs(hier=1)
        )


# extracted from Table 7.9.4-1: Information Elements in a Update PDN Connection Set Response
class UpdatePDNConnectionSetResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (132, 0) : (FQCSID, 'PGWFQCSID'),
        255      : (PrivExt, 'PrivExt'),
        }


class UpdatePDNConnectionSetResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 201}),
        UpdatePDNConnectionSetResponseIEs(hier=1)
        )


# extracted from Table 7.9.5-1: Information Elements in PGW Restart Notification
class PGWRestartNotificationIEs(GTPCIEs):
    MAND = {
        (74, 0)  : (IPAddress, 'PGWS5S8IPAddressForControlPlaneOrPMIP'),
        (74, 1)  : (IPAddress, 'SGWS11S4IPAddressForControlPlane'),
        }
    OPT  = {
        (2, 0)   : (Cause, 'Cause'),
        255      : (PrivExt, 'PrivExt'),
        }


class PGWRestartNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 179}),
        PGWRestartNotificationIEs(hier=1)
        )


# extracted from Table 7.9.6-1: Information Elements in PGW Restart Notification Acknowledge
class PGWRestartNotificationAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        255      : (PrivExt, 'PrivExt'),
        }


class PGWRestartNotificationAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 180}),
        PGWRestartNotificationAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.9.7-1: Information Elements in PGW Downlink Triggering Notification
class PGWDownlinkTriggeringNotificationIEs(GTPCIEs):
    MAND = {
        (1, 0)   : (IMSI, 'IMSI'),
        }
    OPT  = {
        (74, 0)  : (IPAddress, 'MMES4SGSNIdent'),
        (87, 0)  : (FTEID, 'PGWS5FTEIDForGTPOrPMIPControlPlane'),
        255      : (PrivExt, 'PrivExt'),
        }


class PGWDownlinkTriggeringNotification(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 103}),
        PGWDownlinkTriggeringNotificationIEs(hier=1)
        )


# extracted from Table 7.9.8-1: Information Elements in PGW Downlink Triggering Acknowledge
class PGWDownlinkTriggeringAcknowledgeIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (74, 0)  : (IPAddress, 'MMES4SGSNIdent'),
        255      : (PrivExt, 'PrivExt'),
        }


class PGWDownlinkTriggeringAcknowledge(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 104}),
        PGWDownlinkTriggeringAcknowledgeIEs(hier=1)
        )


# extracted from Table 7.12.1-1: Information Elements in a Trace Session Activation
class TraceSessionActivationIEs(GTPCIEs):
    MAND = {
        (96, 0)  : (TraceInfo, 'TraceInfo'),
        }
    OPT  = {
        (1, 0)   : (IMSI, 'IMSI'),
        (75, 0)  : (MEI, 'MEIdentity'),
        }


class TraceSessionActivation(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 71}),
        TraceSessionActivationIEs(hier=1)
        )


# extracted from Table 7.12.2-1: Information Elements in a Trace Session Deactivation
class TraceSessionDeactivationIEs(GTPCIEs):
    MAND = {
        (115, 0) : (TraceReference, 'TraceReference'),
        }
    OPT  = {
        }


class TraceSessionDeactivation(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 72}),
        TraceSessionDeactivationIEs(hier=1)
        )


# extracted from Table 7.13.1-1: Information Elements in a MBMS Session Start Request
class MBMSSessionStartRequestIEs(GTPCIEs):
    MAND = {
        (80, 0)  : (BearerQoS, 'QoSProfile'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (138, 0) : (MBMSSessionDuration, 'MBMSSessionDuration'),
        (139, 0) : (MBMSServiceArea, 'MBMSServiceArea'),
        (142, 0) : (MBMSIPMulticastDistribution, 'MBMSIPMulticastDistribution'),
        (158, 0) : (TMGI, 'TemporaryMobileGroupIdentity'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (140, 0) : (MBMSSessionIdent, 'MBMSSessionIdent'),
        (141, 0) : (MBMSFlowIdent, 'MBMSFlowIdent'),
        (142, 1) : (MBMSIPMulticastDistribution, 'MBMSAlternativeIPMulticastDistribution'),
        (153, 0) : (MBMSTimeToDataTransfer, 'MBMSTimeToDataTransfer'),
        (164, 0) : (AbsoluteTimeOfMBMSDataTransfer, 'MBMSDataTransferStart'),
        (171, 0) : (MBMSFlags, 'MBMSFlags'),
        (190, 0) : (ECGIList, 'MBMSCellList'),
        255      : (PrivExt, 'PrivExt'),
        }


class MBMSSessionStartRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 231}),
        MBMSSessionStartRequestIEs(hier=1)
        )


# extracted from Table 7.13.2-1: Information Elements in a MBMS Session Start Response
class MBMSSessionStartResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (87, 1)  : (FTEID, 'SnUSGSNFTEID'),
        (143, 0) : (MBMSDistributionAcknowledge, 'MBMSDistributionAcknowledge'),
        255      : (PrivExt, 'PrivExt'),
        }


class MBMSSessionStartResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 232}),
        MBMSSessionStartResponseIEs(hier=1)
        )


# extracted from Table 7.13.3-1: Information Elements in a MBMS Session Update Request
class MBMSSessionUpdateRequestIEs(GTPCIEs):
    MAND = {
        (80, 0)  : (BearerQoS, 'QoSProfile'),
        (138, 0) : (MBMSSessionDuration, 'MBMSSessionDuration'),
        (158, 0) : (TMGI, 'TemporaryMobileGroupIdentity'),
        }
    OPT  = {
        (87, 0)  : (FTEID, 'SenderFTEIDForControlPlane'),
        (139, 0) : (MBMSServiceArea, 'MBMSServiceArea'),
        (140, 0) : (MBMSSessionIdent, 'MBMSSessionIdent'),
        (141, 0) : (MBMSFlowIdent, 'MBMSFlowIdent'),
        (153, 0) : (MBMSTimeToDataTransfer, 'MBMSTimeToDataTransfer'),
        (164, 0) : (AbsoluteTimeOfMBMSDataTransfer, 'MBMSDataTransferStartUpdateStop'),
        (190, 0) : (ECGIList, 'MBMSCellList'),
        255      : (PrivExt, 'PrivExt'),
        }


class MBMSSessionUpdateRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 233}),
        MBMSSessionUpdateRequestIEs(hier=1)
        )


# extracted from Table 7.13.4-1: Information Elements in a MBMS Session Update Response
class MBMSSessionUpdateResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        (87, 0)  : (FTEID, 'SnUSGSNFTEID'),
        (143, 0) : (MBMSDistributionAcknowledge, 'MBMSDistributionAcknowledge'),
        255      : (PrivExt, 'PrivExt'),
        }


class MBMSSessionUpdateResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 234}),
        MBMSSessionUpdateResponseIEs(hier=1)
        )


# extracted from Table 7.13.5-1: Information Elements in a MBMS Session Stop Request
class MBMSSessionStopRequestIEs(GTPCIEs):
    MAND = {
        }
    OPT  = {
        (141, 0) : (MBMSFlowIdent, 'MBMSFlowIdent'),
        (164, 0) : (AbsoluteTimeOfMBMSDataTransfer, 'MBMSDataTransferStop'),
        (171, 0) : (MBMSFlags, 'MBMSFlags'),
        255      : (PrivExt, 'PrivExt'),
        }


class MBMSSessionStopRequest(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 235}),
        MBMSSessionStopRequestIEs(hier=1)
        )


# extracted from Table 7.13.6-1: Information Elements in a MBMS Session Stop Response
class MBMSSessionStopResponseIEs(GTPCIEs):
    MAND = {
        (2, 0)   : (Cause, 'Cause'),
        }
    OPT  = {
        (3, 0)   : (Recovery, 'Recovery'),
        255      : (PrivExt, 'PrivExt'),
        }


class MBMSSessionStopResponse(GTPCMsg):
    _GEN = (
        GTPCHdr(val={'Type': 236}),
        MBMSSessionStopResponseIEs(hier=1)
        )


#------------------------------------------------------------------------------#
# General parser    
# TS 29.274, section 6
#------------------------------------------------------------------------------#

GTPCDispatcher = {
    1  : EchoRequest,
    2  : EchoResponse,
    32 : CreateSessionRequest,
    33 : CreateSessionResponse,
    34 : ModifyBearerRequest,
    35 : ModifyBearerResponse,
    36 : DeleteSessionRequest,
    37 : DeleteSessionResponse,
    38 : ChangeNotificationRequest,
    39 : ChangeNotificationResponse,
    40 : RemoteUEReportNotification,
    41 : RemoteUEReportAcknowledge,
    64 : ModifyBearerCommand,
    65 : ModifyBearerFailureIndication,
    66 : DeleteBearerCommand,
    67 : DeleteBearerFailureIndication,
    68 : BearerResourceCommand,
    69 : BearerResourceFailureIndication,
    70 : DownlinkDataNotificationFailureIndication,
    71 : TraceSessionActivation,
    72 : TraceSessionDeactivation,
    73 : StopPagingIndication,
    95 : CreateBearerRequest,
    96 : CreateBearerResponse,
    97 : UpdateBearerRequest,
    98 : UpdateBearerResponse,
    99 : DeleteBearerRequest,
    100: DeleteBearerResponse,
    101: DeletePDNConnectionSetRequest,
    102: DeletePDNConnectionSetResponse,
    103: PGWDownlinkTriggeringNotification,
    104: PGWDownlinkTriggeringAcknowledge,
    128: IdentificationRequest,
    129: IdentificationResponse,
    130: ContextRequest,
    131: ContextResponse,
    132: ContextAcknowledge,
    133: ForwardRelocationRequest,
    134: ForwardRelocationResponse,
    135: ForwardRelocationCompleteNotification,
    136: ForwardRelocationCompleteAcknowledge,
    137: ForwardAccessContextNotification,
    138: ForwardAccessContextAcknowledge,
    139: RelocationCancelRequest,
    140: RelocationCancelResponse,
    141: ConfigurationTransferTunnelMessage,
    149: DetachNotification,
    150: DetachAcknowledge,
    151: CSPagingIndication,
    152: RANInformationRelay,
    153: AlertMMENotification,
    154: AlertMMEAcknowledge,
    155: UEActivityNotification,
    156: UEActivityAcknowledge,
    157: ISRStatusIndication,
    158: UERegistrationQueryRequest,
    159: UERegistrationQueryResponse,
    160: CreateForwardingTunnelRequest,
    161: CreateForwardingTunnelResponse,
    162: SuspendNotification,
    163: SuspendAcknowledge,
    164: ResumeNotification,
    165: ResumeAcknowledge,
    166: CreateIndirectDataForwardingTunnelRequest,
    167: CreateIndirectDataForwardingTunnelResponse,
    168: DeleteIndirectDataForwardingTunnelRequest,
    169: DeleteIndirectDataForwardingTunnelResponse,
    170: ReleaseAccessBearersRequest,
    171: ReleaseAccessBearersResponse,
    176: DownlinkDataNotification,
    177: DownlinkDataNotificationAcknowledge,
    179: PGWRestartNotification,
    180: PGWRestartNotificationAcknowledge,
    200: UpdatePDNConnectionSetRequest,
    201: UpdatePDNConnectionSetResponse,
    211: ModifyAccessBearersRequest,
    212: ModifyAccessBearersResponse,
    231: MBMSSessionStartRequest,
    232: MBMSSessionStartResponse,
    233: MBMSSessionUpdateRequest,
    234: MBMSSessionUpdateResponse,
    235: MBMSSessionStopRequest,
    236: MBMSSessionStopResponse,
    }


ERR_GTPC_BUF_TOO_SHORT = 1
ERR_GTPC_BUF_INVALID   = 2
ERR_GTPC_TYPE_NONEXIST = 3


def parse_GTPC(buf):
    """parses the buffer `buf' for GTP-C message and returns a 2-tuple:
    - GTP-C message structure, or None if parsing failed
    - parsing error code, 0 if parsing succeeded, > 0 otherwise
    """
    if len(buf) < 8:
        return None, ERR_GTPC_BUF_TOO_SHORT
    if python_version < 3:
        type = ord(buf[1])
    else:
        type = buf[1]
    try:
        Msg = GTPCDispatcher[type]()
    except KeyError:
        return None, ERR_GTPC_TYPE_NONEXIST
    try:
        Msg.from_bytes(buf)
    except Exception:
        return None, ERR_GTPC_BUF_INVALID
    else:
        # TODO: support piggy-backed GTP-C message (see 5.5.1 and P flag)
        return Msg, 0

