# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
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
# * File Name : pycrate_mobile/TS29244_PFCP.py
# * Created : 2021-04-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/


#__all__ = [
#    ]


#------------------------------------------------------------------------------#
# 3GPP TS 29.244: Interface between the Control Plane and the User Plane nodes
# release 17 (h00)
#------------------------------------------------------------------------------#
# Packet Forwarding Control Protocol
# listening on UDP 8805

import re
from enum   import IntEnum


from pycrate_core.utils     import *
from pycrate_core.elt       import *
from pycrate_core.base      import *
from pycrate_core.charpy    import *

'''some L3 IE may be required
from pycrate_mobile.TS24501_IE  import 
from pycrate_mobile.TS24301_IE  import 
from pycrate_mobile.TS24008_IE  import 
'''


def strip_name(s):
    # change 3GPP starting str with TGPP
    s = re.sub('^3G', 'TG', s)
    # remove unneeded chars
    s = re.sub('[\s\(\)\'-/]', '', s).strip()
    return s


#------------------------------------------------------------------------------#
# TS 29.244, section 8.1: Information Elements Format
#------------------------------------------------------------------------------#

PFCPIEType_dict = {
    0 : 'Reserved',
    1 : 'Create PDR',
    2 : 'PDI',
    3 : 'Create FAR',
    4 : 'Forwarding Parameters',
    5 : 'Duplicating Parameters',
    6 : 'Create URR',
    7 : 'Create QER',
    8 : 'Created PDR',
    9 : 'Update PDR',
    10 : 'Update FAR',
    11 : 'Update Forwarding Parameters',
    12 : 'Update BAR (Session Report Response)',
    13 : 'Update URR',
    14 : 'Update QER',
    15 : 'Remove PDR',
    16 : 'Remove FAR',
    17 : 'Remove URR',
    18 : 'Remove QER',
    19 : 'Cause',
    20 : 'Source Interface',
    21 : 'F-TEID',
    22 : 'Network Instance',
    23 : 'SDF Filter',
    24 : 'Application ID',
    25 : 'Gate Status',
    26 : 'MBR',
    27 : 'GBR',
    28 : 'QER Correlation ID',
    29 : 'Precedence',
    30 : 'Transport Level Marking',
    31 : 'Volume Threshold',
    32 : 'Time Threshold',
    33 : 'Monitoring Time',
    34 : 'Subsequent Volume Threshold',
    35 : 'Subsequent Time Threshold',
    36 : 'Inactivity Detection Time',
    37 : 'Reporting Triggers',
    38 : 'Redirect Information',
    39 : 'Report Type',
    40 : 'Offending IE',
    41 : 'Forwarding Policy',
    42 : 'Destination Interface',
    43 : 'UP Function Features',
    44 : 'Apply Action',
    45 : 'Downlink Data Service Information',
    46 : 'Downlink Data Notification Delay',
    47 : 'DL Buffering Duration',
    48 : 'DL Buffering Suggested Packet Count',
    49 : 'PFCPSMReq-Flags',
    50 : 'PFCPSRRsp-Flags',
    51 : 'Load Control Information',
    52 : 'Sequence Number',
    53 : 'Metric',
    54 : 'Overload Control Information',
    55 : 'Timer',
    56 : 'PDR ID',
    57 : 'F-SEID',
    58 : 'Application ID\'s PFDs',
    59 : 'PFD Context',
    60 : 'Node ID',
    61 : 'PFD Contents',
    62 : 'Measurement Method',
    63 : 'Usage Report Trigger',
    64 : 'Measurement Period',
    65 : 'FQ-CSID',
    66 : 'Volume Measurement',
    67 : 'Duration Measurement',
    68 : 'Application Detection Information',
    69 : 'Time of First Packet',
    70 : 'Time of Last Packet',
    71 : 'Quota Holding Time',
    72 : 'Dropped DL Traffic Threshold',
    73 : 'Volume Quota',
    74 : 'Time Quota',
    75 : 'Start Time',
    76 : 'End Time',
    77 : 'Query URR',
    78 : 'Usage Report (Session Modification Response)',
    79 : 'Usage Report (Session Deletion Response)',
    80 : 'Usage Report (Session Report Request)',
    81 : 'URR ID',
    82 : 'Linked URR ID',
    83 : 'Downlink Data Report',
    84 : 'Outer Header Creation',
    85 : 'Create BAR',
    86 : 'Update BAR (Session Modification Request)',
    87 : 'Remove BAR',
    88 : 'BAR ID',
    89 : 'CP Function Features',
    90 : 'Usage Information',
    91 : 'Application Instance ID',
    92 : 'Flow Information',
    93 : 'UE IP address',
    94 : 'Packet Rate',
    95 : 'Outer Header Removal',
    96 : 'Recovery Time Stamp',
    97 : 'DL Flow Level Marking',
    98 : 'Header Enrichment',
    99 : 'Error Indication Report',
    100 : 'Measurement Information',
    101 : 'Node Report Type',
    102 : 'User Plane Path Failure Report',
    103 : 'Remote GTP-U Peer',
    104 : 'UR-SEQN',
    105 : 'Update Duplicating Parameters',
    106 : 'Activate Predefined Rules ',
    107 : 'Deactivate Predefined Rules ',
    108 : 'FAR ID',
    109 : 'QER ID',
    110 : 'OCI Flags',
    111 : 'PFCP Association Release Request',
    112 : 'Graceful Release Period',
    113 : 'PDN Type',
    114 : 'Failed Rule ID',
    115 : 'Time Quota Mechanism',
    116 : 'Reserved',
    117 : 'User Plane Inactivity Timer',
    118 : 'Aggregated URRs',
    119 : 'Multiplier',
    120 : 'Aggregated URR ID',
    121 : 'Subsequent Volume Quota',
    122 : 'Subsequent Time Quota',
    123 : 'RQI',
    124 : 'QFI',
    125 : 'Query URR Reference',
    126 : 'Additional Usage Reports Information',
    127 : 'Create Traffic Endpoint',
    128 : 'Created Traffic Endpoint',
    129 : 'Update Traffic Endpoint',
    130 : 'Remove Traffic Endpoint',
    131 : 'Traffic Endpoint ID',
    132 : 'Ethernet Packet Filter',
    133 : 'MAC address',
    134 : 'C-TAG',
    135 : 'S-TAG',
    136 : 'Ethertype',
    137 : 'Proxying',
    138 : 'Ethernet Filter ID',
    139 : 'Ethernet Filter Properties',
    140 : 'Suggested Buffering Packets Count',
    141 : 'User ID',
    142 : 'Ethernet PDU Session Information',
    143 : 'Ethernet Traffic Information',
    144 : 'MAC Addresses Detected',
    145 : 'MAC Addresses Removed',
    146 : 'Ethernet Inactivity Timer',
    147 : 'Additional Monitoring Time',
    148 : 'Event Quota',
    149 : 'Event Threshold',
    150 : 'Subsequent Event Quota',
    151 : 'Subsequent Event Threshold',
    152 : 'Trace Information',
    153 : 'Framed-Route',
    154 : 'Framed-Routing',
    155 : 'Framed-IPv6-Route',
    156 : 'Time Stamp ',
    157 : 'Averaging Window',
    158 : 'Paging Policy Indicator',
    159 : 'APN/DNN',
    160 : '3GPP Interface Type',
    161 : 'PFCPSRReq-Flags',
    162 : 'PFCPAUReq-Flags',
    163 : 'Activation Time',
    164 : 'Deactivation Time',
    165 : 'Create MAR',
    166 : '3GPP Access Forwarding Action Information',
    167 : 'Non-3GPP Access Forwarding Action Information',
    168 : 'Remove MAR',
    169 : 'Update MAR',
    170 : 'MAR ID',
    171 : 'Steering Functionality',
    172 : 'Steering Mode',
    173 : 'Weight',
    174 : 'Priority',
    175 : 'Update 3GPP Access Forwarding Action Information',
    176 : 'Update Non 3GPP Access Forwarding Action Information',
    177 : 'UE IP address Pool Identity',
    178 : 'Alternative SMF IP Address',
    179 : 'Packet Replication and Detection Carry-On Information',
    180 : 'SMF Set ID',
    181 : 'Quota Validity Time',
    182 : 'Number of Reports',
    183 : 'Session Retention Information',
    184 : 'PFCPASRsp-Flags',
    185 : 'CP PFCP Entity IP Address',
    186 : 'PFCPSEReq-Flags',
    187 : 'User Plane Path Recovery Report',
    188 : 'IP Multicast Addressing Info',
    189 : 'Join IP Multicast Information',
    190 : 'Leave IP Multicast Information',
    191 : 'IP Multicast Address',
    192 : 'Source IP Address',
    193 : 'Packet Rate Status',
    194 : 'Create Bridge Info for TSC',
    195 : 'Created Bridge Info for TSC',
    196 : 'DS-TT Port Number',
    197 : 'NW-TT Port Number',
    198 : 'TSN Bridge ID',
    199 : 'TSC Management Information (Session Modification Request)',
    200 : 'TSC Management Information (Session Modification Response)',
    201 : 'TSC Management Information (Session Report Request)',
    202 : 'Port Management Information Container',
    203 : 'Clock Drift Control Information',
    204 : 'Requested Clock Drift Information',
    205 : 'Clock Drift Report',
    206 : 'TSN Time Domain Number',
    207 : 'Time Offset Threshold',
    208 : 'Cumulative rateRatio Threshold',
    209 : 'Time Offset Measurement',
    210 : 'Cumulative rateRatio Measurement',
    211 : 'Remove SRR ',
    212 : 'Create SRR ',
    213 : 'Update SRR',
    214 : 'Session Report',
    215 : 'SRR ID',
    216 : 'Access Availability Control Information',
    217 : 'Requested Access Availability Information',
    218 : 'Access Availability Report',
    219 : 'Access Availability Information',
    220 : 'Provide ATSSS Control Information',
    221 : 'ATSSS Control Parameters',
    222 : 'MPTCP Control Information',
    223 : 'ATSSS-LL Control Information',
    224 : 'PMF Control Information',
    225 : 'MPTCP Parameters',
    226 : 'ATSSS-LL Parameters',
    227 : 'PMF Parameters',
    228 : 'MPTCP Address Information',
    229 : 'UE Link-Specific IP Address',
    230 : 'PMF Address Information',
    231 : 'ATSSS-LL Information',
    232 : 'Data Network Access Identifier',
    233 : 'UE IP address Pool Information',
    234 : 'Average Packet Delay',
    235 : 'Minimum Packet Delay',
    236 : 'Maximum Packet Delay',
    237 : 'QoS Report Trigger',
    238 : 'GTP-U Path QoS Control Information',
    239 : 'GTP-U Path QoS Report',
    240 : 'QoS Information',
    241 : 'GTP-U Path Interface Type',
    242 : 'QoS Monitoring per QoS flow Control Information',
    243 : 'Requested QoS Monitoring',
    244 : 'Reporting Frequency',
    245 : 'Packet Delay Thresholds',
    246 : 'Minimum Wait Time',
    247 : 'QoS Monitoring Report',
    248 : 'QoS Monitoring Measurement',
    249 : 'MT-EDT Control Information',
    250 : 'DL Data Packets Size',
    251 : 'QER Control Indications',
    252 : 'Packet Rate Status Report',
    253 : 'NF Instance ID',
    254 : 'Ethernet Context Information',
    255 : 'Redundant Transmission Detection Parameters',
    256 : 'Updated PDR',
    257 : 'S-NSSAI',
    258 : 'IP version',
    259 : 'PFCPASReq-Flags',
    260 : 'Data Status',
    261 : 'Provide RDS Configuration Information',
    262 : 'RDS Configuration Information',
    263 : 'Query Packet Rate Status',
    264 : 'Packet Rate Status Report (Session Modification Response)',
    265 : 'MPTCP Applicable Indication',
    266 : 'Bridge Management Information Container',
    267 : 'UE IP Address Usage Information',
    268 : 'Number of UE IP Addresses',
    269 : 'Validity Timer',
    270 : 'Redundant Transmission Forwarding Parameters',
    271 : 'Transport Delay Reporting',
    272 : 'Partial Failure Information (Session Establishment Response) ',
    273 : 'Partial Failure Information (Session Modification Response) ',
    274 : 'Offending IE Information',
    275 : 'RAT Type',
    }

PFCPIEType = IntEnum('PFCPIEType', {strip_name(v): k for k, v in PFCPIEType_dict.items()})


class PFCPIE(Envelope):
    _GEN = (
        Uint16('Type', dic=PFCPIEType_dict),
        Uint16('Len'),
        Uint16('EID', rep=REPR_HEX),
        Buf('Data', hier=1, rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Data'].get_len() + (2 if self['Type'].get_val() & 0x8000 else 0))
        self['EID'].set_transauto(lambda: False if self['Type'].get_val() & 0x8000 else True)
        self['Data'].set_blauto(lambda: (self['Len'].get_val() - (2 if self['Type'].get_val() & 0x8000 else 0)) << 3)
    
    def set_val(self, val):
        if isinstance(val, (tuple, list)) and len(val) == 4:
            t, d = val[0], val[3]
        elif isinstance(val, dict) and 'Type' in val and 'Data' in val:
            t, d = val['Type'], val['Data']
        if t in PFCPIELUT and not isinstance(d, bytes_types):
            self.set_ie_class(t)
        Envelope.set_val(self, val)
    
    def _from_char(self, char):
        t = char.to_uint(16)
        if t in PFCPIELUT:
            self.set_ie_class(t)
        Envelope._from_char(self, char)
    
    def set_ie_class(self, t):
        """replace the default Data buffer with a specifically defined class structure
        according to the IE Type value `t'
        """
        IE = PFCPIELUT[t]('Data', hier=1)
        self.replace(self[3], IE)
        IE.set_blauto(lambda: (self['Len'].get_val() - (2 if self['Type'].get_val() & 0x8000 else 0)) << 3)


class PFCPIEs(Sequence):
    # for mandatory / optional IE types
    MAND = ()
    OPT  = ()
    #
    _GEN = PFCPIE()
    
    def __init__(self, *args, **kwargs):
        Sequence.__init__(self, *args, **kwargs)
        if 'mand' in kwargs:
            ids = kwargs['mand']
            assert( isinstance(ids, (tuple, list)) and all([isinstance(i, integer_types) for i in ids]) )
            self.MAND = tuple(ids)
        if 'opt' in kwargs:
            ids = kwargs['opt']
            assert( isinstance(ids, (tuple, list)) and all([isinstance(i, integer_types) for i in ids]) )
            self.OPT = tuple(ids)
    
    def chk_comp(self):
        """check the compliance of the sequence of IEs against the list of mandatory
        IEs and the potential presence of unexpected IEs
        
        return 2 lists
            1st contains the list of missing mandatory IE types
            2nd contains the list of unexpected IE types
        """
        # check the sequence of PFCP IEs for errors against the list of mandatory 
        # and optional IEs
        mand = list(self.MAND)
        opt  = list(self.OPT)
        unex = []
        if ie in self:
            ie_type = ie['Type'].get_val()
            if ie_type in mand:
                mand.remove(ie_type)
            elif ie_type in opt:
                opt.remove(ie_type)
            else:
                unex.append(ie_type)
        return mand, unex


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.3.1: PFCP PFD Management Request
#------------------------------------------------------------------------------#

# IE Type: 58
class ApplicationIDsPFDs(PFCPIEs):
    MAND = (
        PFCPIEType.ApplicationID.value,
        )
    OPT  = (
        PFCPIEType.PFDContext.value,
        )


# IE Type: 59
class PFDContext(PFCPIEs):
    MAND = (
        PFCPIEType.PFDContents.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.4.1: PFCP Association Setup Request
#------------------------------------------------------------------------------#

# IE Type: 183
class SessionRetentionInformation(PFCPIEs):
    OPT  = (
        PFCPIEType.CPPFCPEntityIPAddress.value,
        )


# IE Type: 233
class UEIPaddressPoolInformation(PFCPIEs):
    MAND = (
        PFCPIEType.UEIPaddressPoolIdentity.value,
        )
    OPT  = (
        PFCPIEType.NetworkInstance.value,
        PFCPIEType.SNSSAI.value,
        PFCPIEType.IPversion.value
        )


# IE Type: 203
class ClockDriftControlInformation(PFCPIEs):
    MAND = (
        PFCPIEType.RequestedClockDriftInformation.value,
        )
    OPT  = (
        PFCPIEType.TSNTimeDomainNumber.value,
        PFCPIEType.TimeOffsetThreshold.value,
        PFCPIEType.CumulativerateRatioThreshold.value
        )


# IE Type: 238
class GTPUPathQoSControlInformation(PFCPIEs):
    MAND = (
        PFCPIEType.QoSReportTrigger.value,
        )
    OPT  = (
        PFCPIEType.RemoteGTPUPeer.value,
        PFCPIEType.GTPUPathInterfaceType.value,
        PFCPIEType.TransportLevelMarking.value,
        PFCPIEType.MeasurementPeriod.value,
        PFCPIEType.AveragePacketDelay.value,
        PFCPIEType.MinimumPacketDelay.value,
        PFCPIEType.MaximumPacketDelay.value,
        PFCPIEType.Timer.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.4.3.1: UE IP Address Usage Information IE within PFCP Association Update Request
#------------------------------------------------------------------------------#

# IE Type: 267
class UEIPAddressUsageInformation(PFCPIEs):
    MAND = (
        PFCPIEType.SequenceNumber.value,
        PFCPIEType.Metric.value,
        PFCPIEType.ValidityTimer.value,
        PFCPIEType.NumberofUEIPAddresses.value,
        PFCPIEType.NetworkInstance.value
        )
    OPT  = (
        PFCPIEType.UEIPaddressPoolIdentity.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.5.1.2: User Plane Path Failure Report IE within PFCP Node Report Request
#------------------------------------------------------------------------------#

# IE Type: 102
class UserPlanePathFailureReport(PFCPIEs):
    MAND = (
        PFCPIEType.RemoteGTPUPeer.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.5.1.3: User Plane Path Recovery Report IE within PFCP Node Report Request
#------------------------------------------------------------------------------#

# IE Type: 187
class UserPlanePathRecoveryReport(PFCPIEs):
    MAND = (
        PFCPIEType.RemoteGTPUPeer.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.5.1.4: Clock Drift Report IE within PFCP Node Report Request
#------------------------------------------------------------------------------#

# IE Type: 205
class ClockDriftReport(PFCPIEs):
    MAND = (
        PFCPIEType.TSNTimeDomainNumber.value,
        )
    OPT  = (
        PFCPIEType.TimeOffsetMeasurement.value,
        PFCPIEType.CumulativerateRatioMeasurement.value,
        PFCPIEType.TimeStamp.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.5.1.5: GTP-U Path QoS Report IE within PFCP Node Report Request
#------------------------------------------------------------------------------#

# IE Type: 239
class GTPUPathQoSReport(PFCPIEs):
    MAND = (
        PFCPIEType.RemoteGTPUPeer.value,
        PFCPIEType.QoSReportTrigger.value,
        PFCPIEType.TimeStamp.value,
        PFCPIEType.QoSInformation.value
        )
    OPT  = (
        PFCPIEType.GTPUPathInterfaceType.value,
        PFCPIEType.StartTime.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.5.1.6: QoS Information in GTP-U Path QoS Report IE
#------------------------------------------------------------------------------#

# IE Type: 240
class QoSInformation(PFCPIEs):
    MAND = (
        PFCPIEType.AveragePacketDelay.value,
        )
    OPT  = (
        PFCPIEType.MinimumPacketDelay.value,
        PFCPIEType.MaximumPacketDelay.value,
        PFCPIEType.TransportLevelMarking.value
        )

        
#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.2: Create PDR IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 1
class CreatePDR(PFCPIEs):
    MAND = (
        PFCPIEType.PDRID.value,
        PFCPIEType.Precedence.value,
        PFCPIEType.PDI.value
        )
    OPT  = (
        PFCPIEType.OuterHeaderRemoval.value,
        PFCPIEType.FARID.value,
        PFCPIEType.URRID.value,
        PFCPIEType.QERID.value,
        PFCPIEType.ActivatePredefinedRules.value,
        PFCPIEType.ActivationTime.value,
        PFCPIEType.DeactivationTime.value,
        PFCPIEType.MARID.value,
        PFCPIEType.PacketReplicationandDetectionCarryOnInformation.value,
        PFCPIEType.IPMulticastAddressingInfo.value,
        PFCPIEType.UEIPaddressPoolIdentity.value,
        PFCPIEType.MPTCPApplicableIndication.value,
        PFCPIEType.TransportDelayReporting.value
        )


# IE Type: 2
class PDI(PFCPIEs):
    MAND = (
        PFCPIEType.SourceInterface.value,
        )
    OPT  = (
        PFCPIEType.FTEID.value,
        PFCPIEType.NetworkInstance.value,
        PFCPIEType.RedundantTransmissionDetectionParameters.value,
        PFCPIEType.UEIPaddress.value,
        PFCPIEType.TrafficEndpointID.value,
        PFCPIEType.SDFFilter.value,
        PFCPIEType.ApplicationID.value,
        PFCPIEType.EthernetPDUSessionInformation.value,
        PFCPIEType.EthernetPacketFilter.value,
        PFCPIEType.QFI.value,
        PFCPIEType.FramedRoute.value,
        PFCPIEType.FramedRouting.value,
        PFCPIEType.FramedIPv6Route.value,
        PFCPIEType.TGPPInterfaceType.value,
        PFCPIEType.IPMulticastAddressingInfo.value
        )


# IE Type: 132
class EthernetPacketFilter(PFCPIEs):
    OPT  = (
        PFCPIEType.EthernetFilterID.value,
        PFCPIEType.EthernetFilterProperties.value,
        PFCPIEType.MACaddress.value,
        PFCPIEType.Ethertype.value,
        PFCPIEType.CTAG.value,
        PFCPIEType.STAG.value,
        PFCPIEType.SDFFilter.value,
        )


# IE Type: 188
class IPMulticastAddressingInfo(PFCPIEs):
    MAND = (
        PFCPIEType.IPMulticastAddress.value,
        )
    OPT  = (
        PFCPIEType.SourceIPAddress.value,
        )


# IE Type: 255
class RedundantTransmissionDetectionParameters(PFCPIEs):
    MAND = (
        PFCPIEType.FTEID.value,
        )
    OPT  = (
        PFCPIEType.NetworkInstance.value,
        )


# IE Type: 271
class TransportDelayReporting(PFCPIEs):
    MAND = (
        PFCPIEType.RemoteGTPUPeer.value,
        )
    OPT  = (
        PFCPIEType.TransportLevelMarking.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.3: Create FAR IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 3
class CreateFAR(PFCPIEs):
    MAND = (
        PFCPIEType.FARID.value,
        PFCPIEType.ApplyAction.value,
        )
    OPT  = (
        PFCPIEType.ForwardingParameters.value,
        PFCPIEType.DuplicatingParameters.value,
        PFCPIEType.BARID.value,
        PFCPIEType.RedundantTransmissionForwardingParameters.value
        )


# IE Type: 4
class ForwardingParameters(PFCPIEs):
    MAND = (
        PFCPIEType.DestinationInterface.value,
        )
    OPT  = (
        PFCPIEType.NetworkInstance.value,
        PFCPIEType.RedirectInformation.value,
        PFCPIEType.OuterHeaderCreation.value,
        PFCPIEType.TransportLevelMarking.value,
        PFCPIEType.ForwardingPolicy.value,
        PFCPIEType.HeaderEnrichment.value,
        PFCPIEType.TrafficEndpointID.value,
        PFCPIEType.Proxying.value,
        PFCPIEType.TGPPInterfaceType.value,
        PFCPIEType.DataNetworkAccessIdentifier.value
        )


# IE Type: 5
class DuplicatingParameters(PFCPIEs):
    MAND = (
        PFCPIEType.DestinationInterface.value,
        )
    OPT  = (
        PFCPIEType.OuterHeaderCreation.value,
        PFCPIEType.TransportLevelMarking.value,
        PFCPIEType.ForwardingPolicy.value
        )


# IE Type: 270
class RedundantTransmissionForwardingParameters(PFCPIEs):
    MAND = (
        PFCPIEType.OuterHeaderCreation.value,
        )
    OPT  = (
        PFCPIEType.NetworkInstance.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.4: Create URR IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 6
class CreateURR(PFCPIEs):
    MAND = (
        PFCPIEType.URRID.value,
        PFCPIEType.MeasurementMethod.value,
        PFCPIEType.ReportingTriggers.value
        )
    OPT  = (
        PFCPIEType.MeasurementPeriod.value,
        PFCPIEType.VolumeThreshold.value,
        PFCPIEType.VolumeQuota.value,
        PFCPIEType.EventThreshold.value,
        PFCPIEType.EventQuota.value,
        PFCPIEType.TimeThreshold.value,
        PFCPIEType.TimeQuota.value,
        PFCPIEType.QuotaHoldingTime.value,
        PFCPIEType.DroppedDLTrafficThreshold.value,
        PFCPIEType.QuotaValidityTime.value,
        PFCPIEType.MonitoringTime.value,
        PFCPIEType.SubsequentVolumeThreshold.value,
        PFCPIEType.SubsequentTimeThreshold.value,
        PFCPIEType.SubsequentVolumeQuota.value,
        PFCPIEType.SubsequentTimeQuota.value,
        PFCPIEType.SubsequentEventThreshold.value,
        PFCPIEType.SubsequentEventQuota.value,
        PFCPIEType.InactivityDetectionTime.value,
        PFCPIEType.LinkedURRID.value,
        PFCPIEType.MeasurementInformation.value,
        PFCPIEType.TimeQuotaMechanism.value,
        PFCPIEType.AggregatedURRs.value,
        PFCPIEType.FARID.value,
        PFCPIEType.EthernetInactivityTimer.value,
        PFCPIEType.AdditionalMonitoringTime.value,
        PFCPIEType.NumberofReports.value,
        PFCPIEType.ApplicationID.value,
        PFCPIEType.SDFFilter.value
        )


# IE Type: 118
class AggregatedURRs(PFCPIEs):
    MAND = (
        PFCPIEType.AggregatedURRID.value,
        PFCPIEType.Multiplier.value
        )


# IE Type: 147
class AdditionalMonitoringTime(PFCPIEs):
    MAND = (
        PFCPIEType.MonitoringTime.value,
        )
    OPT  = (
        PFCPIEType.SubsequentVolumeThreshold.value,
        PFCPIEType.SubsequentTimeThreshold.value,
        PFCPIEType.SubsequentVolumeQuota.value,
        PFCPIEType.SubsequentTimeQuota.value,
        PFCPIEType.EventThreshold.value,
        PFCPIEType.EventQuota.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.5: Create QER IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 7
class CreateQER(PFCPIEs):
    MAND = (
        PFCPIEType.QERID.value,
        PFCPIEType.GateStatus.value
        )
    OPT  = (
        PFCPIEType.QERCorrelationID.value,
        PFCPIEType.MBR.value,
        PFCPIEType.GBR.value,
        PFCPIEType.PacketRate.value,
        PFCPIEType.PacketRateStatus.value,
        PFCPIEType.DLFlowLevelMarking.value,
        PFCPIEType.QFI.value,
        PFCPIEType.RQI.value,
        PFCPIEType.PagingPolicyIndicator.value,
        PFCPIEType.AveragingWindow.value,
        PFCPIEType.QERControlIndications.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.6: Create BAR IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 85
class CreateBAR(PFCPIEs):
    MAND = (
        PFCPIEType.BARID.value,
        )
    OPT  = (
        PFCPIEType.DownlinkDataNotificationDelay.value,
        PFCPIEType.SuggestedBufferingPacketsCount.value,
        PFCPIEType.MTEDTControlInformation.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.7: Create Traffic Endpoint IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type:
class CreateTrafficEndpoint(PFCPIEs):
    MAND = (
        PFCPIEType.TrafficEndpointID.value,
        )
    OPT  = (
        PFCPIEType.FTEID.value,
        PFCPIEType.NetworkInstance.value,
        PFCPIEType.RedundantTransmissionDetectionParameters.value,
        PFCPIEType.UEIPaddress.value,
        PFCPIEType.EthernetPDUSessionInformation.value,
        PFCPIEType.FramedRoute.value,
        PFCPIEType.FramedRouting.value,
        PFCPIEType.FramedIPv6Route.value,
        PFCPIEType.QFI.value,
        PFCPIEType.TGPPInterfaceType.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.8: Create MAR IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 165
class CreateMAR(PFCPIEs):
    MAND = (
        PFCPIEType.MARID.value,
        PFCPIEType.SteeringFunctionality.value,
        PFCPIEType.SteeringMode.value
        )
    OPT  = (
        PFCPIEType.TGPPAccessForwardingActionInformation.value,
        PFCPIEType.Non3GPPAccessForwardingActionInformation.value
        )


# IE Type: 166
class TGPPAccessForwardingActionInformation(PFCPIEs):
    MAND = (
        PFCPIEType.FARID.value,
        )
    OPT  = (
        PFCPIEType.Weight.value,
        PFCPIEType.Priority.value,
        PFCPIEType.URRID.value
        )


# IE Type: 167
class Non3GPPAccessForwardingActionInformation(PFCPIEs):
    MAND = (
        PFCPIEType.FARID.value,
        )
    OPT  = (
        PFCPIEType.Weight.value,
        PFCPIEType.Priority.value,
        PFCPIEType.URRID.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.9: Create SRR IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 212
class CreateSRR(PFCPIEs):
    MAND = (
        PFCPIEType.SRRID.value,
        )
    OPT  = (
        PFCPIEType.AccessAvailabilityControlInformation.value,
        PFCPIEType.QoSMonitoringperQoSflowControlInformation.value
        )


# IE Type: 216
class AccessAvailabilityControlInformation(PFCPIEs):
    MAND = (
        PFCPIEType.RequestedAccessAvailabilityInformation.value,
        )


# IE Type: 242
class QoSMonitoringperQoSflowControlInformation(PFCPIEs):
    MAND = (
        PFCPIEType.QFI.value,
        PFCPIEType.RequestedQoSMonitoring.value,
        PFCPIEType.ReportingFrequency.value
        )
    OPT  = (
        PFCPIEType.PacketDelayThresholds.value,
        PFCPIEType.MinimumWaitTime.value,
        PFCPIEType.MeasurementPeriod.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.10: Provide ATSSS Control Information IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 220
class ProvideATSSSControlInformation(PFCPIEs):
    OPT  = (
        PFCPIEType.MPTCPControlInformation.value,
        PFCPIEType.ATSSSLLControlInformation.value,
        PFCPIEType.PMFControlInformation.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2.11: Provide RDS Configuration Information IE within PFCP Session Establishment Request
#------------------------------------------------------------------------------#

# IE Type: 261
class ProvideRDSConfigurationInformation(PFCPIEs):
    OPT  = (
        PFCPIEType.RDSConfigurationInformation.value,
        )



#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.3: PFCP Session Establishment Response
#------------------------------------------------------------------------------#

# IE Type: 272
class PartialFailureInformationSessionEstablishmentResponse(PFCPIEs):
    MAND = (
        PFCPIEType.FailedRuleID.value,
        PFCPIEType.Cause.value,
        PFCPIEType.OffendingIEInformation.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.3.2: Created PDR IE within PFCP Session Establishment Response
#------------------------------------------------------------------------------#

# IE Type: 8
class CreatedPDR(PFCPIEs):
    MAND = (
        PFCPIEType.PDRID.value,
        )
    OPT  = (
        PFCPIEType.FTEID.value,
        PFCPIEType.FTEID.value,
        PFCPIEType.UEIPaddress.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.3.3: Load Control Information IE within PFCP Session Establishment Response
#------------------------------------------------------------------------------#

# IE Type: 51
class LoadControlInformation(PFCPIEs):
    MAND = (
        PFCPIEType.SequenceNumber.value,
        PFCPIEType.Metric.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.3.4: Overload Control Information IE within PFCP Session Establishment Response
#------------------------------------------------------------------------------#

# IE Type: 54
class OverloadControlInformation(PFCPIEs):
    MAND = (
        PFCPIEType.SequenceNumber.value,
        PFCPIEType.Metric.value,
        PFCPIEType.Timer.value
        )
    OPT  = (
        PFCPIEType.OCIFlags.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.3.5: Created Traffic Endpoint IE within PFCP Session Establishment Response
#------------------------------------------------------------------------------#

# IE Type: 128
class CreatedTrafficEndpoint(PFCPIEs):
    MAND = (
        PFCPIEType.TrafficEndpointID.value,
        )
    OPT  = (
        PFCPIEType.FTEID.value,
        PFCPIEType.FTEID.value,
        PFCPIEType.UEIPaddress.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.3.6: Created Bridge Info for TSC IE within PFCP Session Establishment Response
#------------------------------------------------------------------------------#

# IE Type: 195
class CreatedBridgeInfoforTSC(PFCPIEs):
    OPT  = (
        PFCPIEType.DSTTPortNumber.value,
        PFCPIEType.TSNBridgeID.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.3.7: ATSSS Control Parameters IE within PFCP Session Establishment Response
#------------------------------------------------------------------------------#

# IE Type: 221
class ATSSSControlParameters(PFCPIEs):
    OPT  = (
        PFCPIEType.MPTCPParameters.value,
        PFCPIEType.ATSSSLLParameters.value,
        PFCPIEType.PMFParameters.value
        )


# IE Type: 225
class MPTCPParameters(PFCPIEs):
    MAND = (
        PFCPIEType.MPTCPAddressInformation.value,
        PFCPIEType.UELinkSpecificIPAddress.value
        )


# IE Type: 226
class ATSSSLLParameters(PFCPIEs):
    MAND = (
        PFCPIEType.ATSSSLLInformation.value,
        )


# IE Type: 227
class PMFParameters(PFCPIEs):
    MAND = (
        PFCPIEType.PMFAddressInformation.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.2: Update PDR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 9
class UpdatePDR(PFCPIEs):
    MAND = (
        PFCPIEType.PDRID.value,
        )
    OPT  = (
        PFCPIEType.OuterHeaderRemoval.value,
        PFCPIEType.Precedence.value,
        PFCPIEType.PDI.value,
        PFCPIEType.FARID.value,
        PFCPIEType.URRID.value,
        PFCPIEType.QERID.value,
        PFCPIEType.ActivatePredefinedRules.value,
        PFCPIEType.DeactivatePredefinedRules.value,
        PFCPIEType.ActivationTime.value,
        PFCPIEType.DeactivationTime.value,
        PFCPIEType.IPMulticastAddressingInfo.value,
        PFCPIEType.TransportDelayReporting.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.3: Update FAR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 10
class UpdateFAR(PFCPIEs):
    MAND = (
        PFCPIEType.FARID.value,
        )
    OPT  = (
        PFCPIEType.ApplyAction.value,
        PFCPIEType.UpdateForwardingParameters.value,
        PFCPIEType.UpdateDuplicatingParameters.value,
        PFCPIEType.RedundantTransmissionForwardingParameters.value,
        PFCPIEType.BARID.value
        )


# IE Type: 11
class UpdateForwardingParameters(PFCPIEs):
    OPT  = (
        PFCPIEType.DestinationInterface.value,
        PFCPIEType.NetworkInstance.value,
        PFCPIEType.RedirectInformation.value,
        PFCPIEType.OuterHeaderCreation.value,
        PFCPIEType.TransportLevelMarking.value,
        PFCPIEType.ForwardingPolicy.value,
        PFCPIEType.HeaderEnrichment.value,
        PFCPIEType.PFCPSMReqFlags.value,
        PFCPIEType.TrafficEndpointID.value,
        PFCPIEType.TGPPInterfaceType.value,
        PFCPIEType.DataNetworkAccessIdentifier.value
        )


# IE Type: 105
class UpdateDuplicatingParameters(PFCPIEs):
    OPT  = (
        PFCPIEType.DestinationInterface.value,
        PFCPIEType.OuterHeaderCreation.value,
        PFCPIEType.TransportLevelMarking.value,
        PFCPIEType.ForwardingPolicy.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.4: Update URR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 13
class UpdateURR(PFCPIEs):
    MAND = (
        PFCPIEType.URRID.value,
        )
    OPT  = (
        PFCPIEType.MeasurementMethod.value,
        PFCPIEType.ReportingTriggers.value,
        PFCPIEType.MeasurementPeriod.value,
        PFCPIEType.VolumeThreshold.value,
        PFCPIEType.VolumeQuota.value,
        PFCPIEType.TimeThreshold.value,
        PFCPIEType.TimeQuota.value,
        PFCPIEType.EventThreshold.value,
        PFCPIEType.EventQuota.value,
        PFCPIEType.QuotaHoldingTime.value,
        PFCPIEType.DroppedDLTrafficThreshold.value,
        PFCPIEType.QuotaValidityTime.value,
        PFCPIEType.MonitoringTime.value,
        PFCPIEType.SubsequentVolumeThreshold.value,
        PFCPIEType.SubsequentTimeThreshold.value,
        PFCPIEType.SubsequentVolumeQuota.value,
        PFCPIEType.SubsequentTimeQuota.value,
        PFCPIEType.SubsequentEventThreshold.value,
        PFCPIEType.SubsequentEventQuota.value,
        PFCPIEType.InactivityDetectionTime.value,
        PFCPIEType.LinkedURRID.value,
        PFCPIEType.MeasurementInformation.value,
        PFCPIEType.TimeQuotaMechanism.value,
        PFCPIEType.AggregatedURRs.value,
        PFCPIEType.FARID.value,
        PFCPIEType.EthernetInactivityTimer.value,
        PFCPIEType.AdditionalMonitoringTime.value,
        PFCPIEType.NumberofReports.value,
        PFCPIEType.ApplicationID.value,
        PFCPIEType.SDFFilter.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.5: Update QER IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 14
class UpdateQER(PFCPIEs):
    MAND = (
        PFCPIEType.QERID.value,
        )
    OPT  = (
        PFCPIEType.QERCorrelationID.value,
        PFCPIEType.GateStatus.value,
        PFCPIEType.MBR.value,
        PFCPIEType.GBR.value,
        PFCPIEType.PacketRate.value,
        PFCPIEType.DLFlowLevelMarking.value,
        PFCPIEType.QFI.value,
        PFCPIEType.RQI.value,
        PFCPIEType.PagingPolicyIndicator.value,
        PFCPIEType.AveragingWindow.value,
        PFCPIEType.QERControlIndications.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.6: Remove PDR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 15
class RemovePDR(PFCPIEs):
    MAND = (
        PFCPIEType.PDRID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.7: Remove FAR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 16
class RemoveFAR(PFCPIEs):
    MAND = (
        PFCPIEType.FARID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.8: Remove URR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 17
class RemoveURR(PFCPIEs):
    MAND = (
        PFCPIEType.URRID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.9: Remove QER IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 18
class RemoveQER(PFCPIEs):
    MAND = (
        PFCPIEType.QERID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.10: Query URR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 77
class QueryURR(PFCPIEs):
    MAND = (
        PFCPIEType.URRID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.11: Update BAR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 86
class UpdateBARSessionModificationRequest(PFCPIEs):
    MAND = (
        PFCPIEType.BARID.value,
        )
    OPT  = (
        PFCPIEType.DownlinkDataNotificationDelay.value,
        PFCPIEType.SuggestedBufferingPacketsCount.value,
        PFCPIEType.MTEDTControlInformation.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.12: Remove BAR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 87
class RemoveBAR(PFCPIEs):
    MAND = (
        PFCPIEType.BARID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.13: Update Traffic Endpoint IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 129
class UpdateTrafficEndpoint(PFCPIEs):
    MAND = (
        PFCPIEType.TrafficEndpointID.value,
        )
    OPT  = (
        PFCPIEType.FTEID.value,
        PFCPIEType.NetworkInstance.value,
        PFCPIEType.RedundantTransmissionDetectionParameters.value,
        PFCPIEType.UEIPaddress.value,
        PFCPIEType.FramedRoute.value,
        PFCPIEType.FramedRouting.value,
        PFCPIEType.FramedIPv6Route.value,
        PFCPIEType.QFI.value,
        PFCPIEType.TGPPInterfaceType.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.14: Remove Traffic Endpoint IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 130
class RemoveTrafficEndpoint(PFCPIEs):
    MAND = (
        PFCPIEType.TrafficEndpointID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.15: Remove MAR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 168
class RemoveMAR(PFCPIEs):
    MAND = (
        PFCPIEType.MARID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.16: Update MAR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 169
class UpdateMAR(PFCPIEs):
    MAND = (
        PFCPIEType.MARID.value,
        )
    OPT  = (
        PFCPIEType.SteeringFunctionality.value,
        PFCPIEType.SteeringMode.value,
        PFCPIEType.Update3GPPAccessForwardingActionInformation.value,
        PFCPIEType.UpdateNon3GPPAccessForwardingActionInformation.value,
        PFCPIEType.TGPPAccessForwardingActionInformation.value,
        PFCPIEType.Non3GPPAccessForwardingActionInformation.value
        )


# IE Type: 175
class Update3GPPAccessForwardingActionInformation(PFCPIEs):
    OPT  = (
        PFCPIEType.FARID.value,
        PFCPIEType.Weight.value,
        PFCPIEType.Priority.value,
        PFCPIEType.URRID.value
        )


# IE Type: 176
class UpdateNon3GPPAccessForwardingActionInformation(PFCPIEs):
    OPT  = (
        PFCPIEType.FARID.value,
        PFCPIEType.Weight.value,
        PFCPIEType.Priority.value,
        PFCPIEType.URRID.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.18: TSC Management Information IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 199
class TSCManagementInformationSessionModificationRequest(PFCPIEs):
    OPT  = (
        PFCPIEType.PortManagementInformationContainer.value,
        PFCPIEType.BridgeManagementInformationContainer.value,
        PFCPIEType.NWTTPortNumber.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.19: Remove SRR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 211
class RemoveSRR(PFCPIEs):
    MAND = (
        PFCPIEType.SRRID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.20: Update SRR IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 213
class UpdateSRR(PFCPIEs):
    MAND = (
        PFCPIEType.SRRID.value,
        )
    OPT  = (
        PFCPIEType.AccessAvailabilityControlInformation.value,
        PFCPIEType.QoSMonitoringperQoSflowControlInformation.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.21: Ethernet Context Information within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 254
class EthernetContextInformation(PFCPIEs):
    MAND = (
        PFCPIEType.MACAddressesDetected.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4.22: Query Packet Rate Status IE within PFCP Session Modification Request
#------------------------------------------------------------------------------#

# IE Type: 263
class QueryPacketRateStatus(PFCPIEs):
    MAND = (
        PFCPIEType.QERID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.5: PFCP Session Modification Response
#------------------------------------------------------------------------------#

# IE Type: 273
class PartialFailureInformationSessionModificationResponse(PFCPIEs):
    MAND = (
        PFCPIEType.FailedRuleID.value,
        PFCPIEType.Cause.value,
        PFCPIEType.OffendingIEInformation.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.5.2: Usage Report IE within PFCP Session Modification Response
#------------------------------------------------------------------------------#

# IE Type: 78
class UsageReportSessionModificationResponse(PFCPIEs):
    MAND = (
        PFCPIEType.URRID.value,
        PFCPIEType.URSEQN.value,
        PFCPIEType.UsageReportTrigger.value
        )
    OPT  = (
        PFCPIEType.StartTime.value,
        PFCPIEType.EndTime.value,
        PFCPIEType.VolumeMeasurement.value,
        PFCPIEType.DurationMeasurement.value,
        PFCPIEType.TimeofFirstPacket.value,
        PFCPIEType.TimeofLastPacket.value,
        PFCPIEType.UsageInformation.value,
        PFCPIEType.QueryURRReference.value,
        PFCPIEType.EthernetTrafficInformation.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.5.3: TSC Management Information IE within PFCP Session Modification Response
#------------------------------------------------------------------------------#

# IE Type: 200
class TSCManagementInformationSessionModificationResponse(PFCPIEs):
    OPT  = (
        PFCPIEType.PortManagementInformationContainer.value,
        PFCPIEType.BridgeManagementInformationContainer.value,
        PFCPIEType.NWTTPortNumber.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.5.4: Packet Rate Status Report IE within PFCP Session Modification Response
#------------------------------------------------------------------------------#

# IE Type: 264
class PacketRateStatusReportSessionModificationResponse(PFCPIEs):
    MAND = (
        PFCPIEType.QERID.value,
        PFCPIEType.PacketRateStatus.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.5.5: Updated PDR IE within PFCP Session Modification Response
#------------------------------------------------------------------------------#

# IE Type: 256
class UpdatedPDR(PFCPIEs):
    MAND = (
        PFCPIEType.PDRID.value,
        )
    OPT  = (
        PFCPIEType.FTEID.value,
        PFCPIEType.FTEID.value,
        PFCPIEType.UEIPaddress.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.7: PFCP Session Deletion Response
#------------------------------------------------------------------------------#

# IE Type: 252
class PacketRateStatusReport(PFCPIEs):
    MAND = (
        PFCPIEType.QERID.value,
        PFCPIEType.PacketRateStatus.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.7.2: Usage Report IE within PFCP Session Deletion Response
#------------------------------------------------------------------------------#

# IE Type: 79
class UsageReportSessionDeletionResponse(PFCPIEs):
    MAND = (
        PFCPIEType.URRID.value,
        PFCPIEType.URSEQN.value,
        PFCPIEType.UsageReportTrigger.value
        )
    OPT  = (
        PFCPIEType.StartTime.value,
        PFCPIEType.EndTime.value,
        PFCPIEType.VolumeMeasurement.value,
        PFCPIEType.DurationMeasurement.value,
        PFCPIEType.TimeofFirstPacket.value,
        PFCPIEType.TimeofLastPacket.value,
        PFCPIEType.UsageInformation.value,
        PFCPIEType.EthernetTrafficInformation.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.8.2: Downlink Data Report IE within PFCP Session Report Request
#------------------------------------------------------------------------------#

# IE Type: 83
class DownlinkDataReport(PFCPIEs):
    MAND = (
        PFCPIEType.PDRID.value,
        )
    OPT  = (
        PFCPIEType.DownlinkDataServiceInformation.value,
        PFCPIEType.DLDataPacketsSize.value,
        PFCPIEType.DataStatus.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.8.3: Usage Report IE within PFCP Session Report Request
#------------------------------------------------------------------------------#

# IE Type: 80
class UsageReportSessionReportRequest(PFCPIEs):
    MAND = (
        PFCPIEType.DownlinkDataServiceInformation.value,
        PFCPIEType.DLDataPacketsSize.value,
        PFCPIEType.DataStatus.value
        )
    OPT  = (
        PFCPIEType.StartTime.value,
        PFCPIEType.EndTime.value,
        PFCPIEType.VolumeMeasurement.value,
        PFCPIEType.DurationMeasurement.value,
        PFCPIEType.ApplicationDetectionInformation.value,
        PFCPIEType.UEIPaddress.value,
        PFCPIEType.NetworkInstance.value,
        PFCPIEType.TimeofFirstPacket.value,
        PFCPIEType.TimeofLastPacket.value,
        PFCPIEType.UsageInformation.value,
        PFCPIEType.QueryURRReference.value,
        PFCPIEType.TimeStamp.value,
        PFCPIEType.EthernetTrafficInformation.value,
        PFCPIEType.JoinIPMulticastInformation.value,
        PFCPIEType.LeaveIPMulticastInformation.value
        )


# IE Type: 68
class ApplicationDetectionInformation(PFCPIEs):
    MAND = (
        PFCPIEType.ApplicationID.value,
        )
    OPT  = (
        PFCPIEType.ApplicationInstanceID.value,
        PFCPIEType.FlowInformation.value,
        PFCPIEType.PDRID.value
        )


# IE Type: 143
class EthernetTrafficInformation(PFCPIEs):
    OPT  = (
        PFCPIEType.MACAddressesDetected.value,
        PFCPIEType.MACAddressesRemoved.value
        )


# IE Type: 189
class JoinIPMulticastInformation(PFCPIEs):
    MAND = (
        PFCPIEType.IPMulticastAddress.value,
        )
    OPT  = (
        PFCPIEType.SourceIPAddress.value,
        )


# IE Type: 190
class LeaveIPMulticastInformation(PFCPIEs):
    MAND = (
        PFCPIEType.IPMulticastAddress.value,
        )
    OPT  = (
        PFCPIEType.SourceIPAddress.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.8.4: Error Indication Report IE within PFCP Session Report Reques
#------------------------------------------------------------------------------#

# IE Type: 99
class ErrorIndicationReport(PFCPIEs):
    MAND = (
        PFCPIEType.FTEID.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.8.5 TSC: Management Information IE within PFCP Session Report Request
#------------------------------------------------------------------------------#

# IE Type: 201
class TSCManagementInformationSessionReportRequest(PFCPIEs):
    OPT  = (
        PFCPIEType.PortManagementInformationContainer.value,
        PFCPIEType.BridgeManagementInformationContainer.value,
        PFCPIEType.NWTTPortNumber.value
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.8.6: Session Report IE within PFCP Session Report Request
#------------------------------------------------------------------------------#

# IE Type: 218
class SessionReport(PFCPIEs):
    MAND = (
        PFCPIEType.SRRID.value,
        )
    OPT  = (
        PFCPIEType.AccessAvailabilityReport.value,
        PFCPIEType.QoSMonitoringReport.value,
        )


# IE Type: 247
class QoSMonitoringReport(PFCPIEs):
    MAND = (
        PFCPIEType.QFI.value,
        PFCPIEType.QoSMonitoringMeasurement.value,
        PFCPIEType.TimeStamp.value
        )
    OPT  = (
        PFCPIEType.StartTime.value,
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.9.2: Update BAR IE within PFCP Session Report Response
#------------------------------------------------------------------------------#

# IE Type: 12
class UpdateBARSessionReportResponse(PFCPIEs):
    MAND = (
        PFCPIEType.BARID.value,
        )
    OPT  = (
        PFCPIEType.DownlinkDataNotificationDelay.value,
        PFCPIEType.DLBufferingDuration.value,
        PFCPIEType.DLBufferingSuggestedPacketCount.value,
        PFCPIEType.SuggestedBufferingPacketsCount.value
        )



'''
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,
        PFCPIEType..value,

class PFCPIEGrouped(Envelope):
    _GEN = (
        Uint16('Type', dic=PFCPIEType_dict),
        Uint16('Len'),
        Uint16('EID', rep=REPR_HEX),
        PFCPIEs('IEs')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['IEs'].get_len() + 2 if self['Type'].get_val() & 0x8000 else 0)
        self['EID'].set_transauto(lambda: False if self['Type'].get_val() & 0x8000 else True)
        self['IEs'].set_blauto(lambda: (self['Len'].get_val() - 2 if self['Type'].get_val() & 0x8000 else 0) << 3)

class PFCP(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType..value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                ],
            opt=[
                ])
        )

'''



PFCPIELUT = {
    1 : CreatePDR,
    2 : PDI,
    3 : CreateFAR,
    4 : ForwardingParameters,
    5 : DuplicatingParameters,
    6 : CreateURR,
    7 : CreateQER,
    8 : CreatedPDR,
    9 : UpdatePDR,
    10 : UpdateFAR,
    11 : UpdateForwardingParameters,
    12 : UpdateBARSessionReportResponse,
    13 : UpdateURR,
    14 : UpdateQER,
    15 : RemovePDR,
    16 : RemoveFAR,
    17 : RemoveURR,
    18 : RemoveQER,
    51 : LoadControlInformation,
    54 : OverloadControlInformation,
    58 : ApplicationIDsPFDs,
    59 : PFDContext,
    68 : ApplicationDetectionInformation,
    77 : QueryURR,
    78 : UsageReportSessionModificationResponse,
    79 : UsageReportSessionDeletionResponse,
    80 : UsageReportSessionReportRequest,
    83 : DownlinkDataReport,
    85 : CreateBAR,
    86 : UpdateBARSessionModificationRequest,
    87 : RemoveBAR,
    99 : ErrorIndicationReport,
    102 : UserPlanePathFailureReport,
    105 : UpdateDuplicatingParameters,
    118 : AggregatedURRs,
    127 : CreateTrafficEndpoint,
    128 : CreatedTrafficEndpoint,
    129 : UpdateTrafficEndpoint,
    130 : RemoveTrafficEndpoint,
    132 : EthernetPacketFilter,
    143 : EthernetTrafficInformation,
    147 : AdditionalMonitoringTime,
    165 : CreateMAR,
    166 : TGPPAccessForwardingActionInformation,
    167 : Non3GPPAccessForwardingActionInformation,
    168 : RemoveMAR,
    169 : UpdateMAR,
    175 : Update3GPPAccessForwardingActionInformation,
    176 : UpdateNon3GPPAccessForwardingActionInformation,
    183 : SessionRetentionInformation,
    187 : UserPlanePathRecoveryReport,
    188 : IPMulticastAddressingInfo,
    189 : JoinIPMulticastInformation,
    190 : LeaveIPMulticastInformation,
    195 : CreatedBridgeInfoforTSC,
    199 : TSCManagementInformationSessionModificationRequest,
    200 : TSCManagementInformationSessionModificationResponse,
    201 : TSCManagementInformationSessionReportRequest,
    203 : ClockDriftControlInformation,
    205 : ClockDriftReport,
    211 : RemoveSRR,
    212 : CreateSRR,
    213 : UpdateSRR,
    214 : SessionReport,
    216 : AccessAvailabilityControlInformation,
    220 : ProvideATSSSControlInformation,
    221 : ATSSSControlParameters,
    225 : MPTCPParameters,
    226 : ATSSSLLParameters,
    227 : PMFParameters,
    233 : UEIPaddressPoolInformation,
    238 : GTPUPathQoSControlInformation,
    239 : GTPUPathQoSReport,
    240 : QoSInformation,
    242 : QoSMonitoringperQoSflowControlInformation,
    247 : QoSMonitoringReport,
    252 : PacketRateStatusReport,
    254 : EthernetContextInformation,
    255 : RedundantTransmissionDetectionParameters,
    256 : UpdatedPDR,
    261 : ProvideRDSConfigurationInformation,
    263 : QueryPacketRateStatus,
    264 : PacketRateStatusReportSessionModificationResponse,
    267 : UEIPAddressUsageInformation,
    270 : RedundantTransmissionForwardingParameters,
    271 : TransportDelayReporting,
    272 : PartialFailureInformationSessionEstablishmentResponse,
    273 : PartialFailureInformationSessionModificationResponse
    }


#------------------------------------------------------------------------------#
# TS 29.244, section 7.3: Message Types
#------------------------------------------------------------------------------#

PFCPMsgType_dict = {
    0 : 'Reserved',
    # PFCP Node related messages
    1 : 'PFCP Heartbeat Request',
    2 : 'PFCP Heartbeat Response',
    3 : 'PFCP PFD Management Request',
    4 : 'PFCP PFD Management Response',
    5 : 'PFCP Association Setup Request',
    6 : 'PFCP Association Setup Response',
    7 : 'PFCP Association Update Request',
    8 : 'PFCP Association Update Response',
    9 : 'PFCP Association Release Request',
    10 : 'PFCP Association Release Response',
    11 : 'PFCP Version Not Supported Response',
    12 : 'PFCP Node Report Request',
    13 : 'PFCP Node Report Response',
    14 : 'PFCP Session Set Deletion Request',
    15 : 'PFCP Session Set Deletion Response',
    # PFCP Session related messages
    50 : 'PFCP Session Establishment Request',
    51 : 'PFCP Session Establishment Response',
    52 : 'PFCP Session Modification Request',
    53 : 'PFCP Session Modification Response',
    54 : 'PFCP Session Deletion Request',
    55 : 'PFCP Session Deletion Response',
    56 : 'PFCP Session Report Request',
    57 : 'PFCP Session Report Response',
    }

PFCPMsgType = IntEnum('PFCPMsgType', {strip_name(v) : k for k, v in PFCPMsgType_dict.items()})


#------------------------------------------------------------------------------#
# TS 29.244, section 7.2: Message Format
#------------------------------------------------------------------------------#

class PFCPHdr(Envelope):
    _GEN = (
        Uint('Vers', val=1, bl=3),
        Uint('spare', bl=2),
        Uint('FO', bl=1, dic={0: 'no Follow-On message', 1: 'Follow-On message'}),
        Uint('MP', bl=1),
        Uint('S', bl=1, dic={0: 'SEID not present', 1: 'SEID present'}),
        Uint8('Type', dic=PFCPMsgType_dict),
        Uint16('Len'),
        Uint64('SEID', rep=REPR_HEX),
        Uint24('Seqn'),
        Alt('MPSel', GEN={
            0 : Uint8('spare'),
            1 : Envelope('MP', GEN=(
                    Uint('MsgPriority', bl=4, dic={0:'lowest priority', 15:'highest priority'}),
                    Uint('spare', bl=4)
                    ))},
            sel=lambda self: self.get_env()['MP'].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['FO'].set_valauto(lambda: 1 if self.get_next() is not None else 0)
        self['Len'].set_valauto(lambda: self.get_payload().get_len() + (12 if self['S'].get_val() else 4))
        self['SEID'].set_transauto(lambda: self['S'].get_val() == 0)


# PFCP Node Related Msg: S = 0
# PFCP Session Related Msg: S = 1


class PFCPMsg(Envelope):
    _GEN = (
        PFCPHdr('Hdr'),
        PFCPIEs('IEs', hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IEs'].set_blauto(lambda: (self['Hdr']['Len'].get_val() - (12 if self['Hdr']['S'].get_val() else 4)) << 3)


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.2: Heartbeat Messages
#------------------------------------------------------------------------------#

class PFCPHeartbeatRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPHeartbeatRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.RecoveryTimeStamp.value
                ],
            opt=[
                PFCPIEType.SourceIPAddress.value
                ])
        )


class PFCPHeartbeatResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPHeartbeatResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.RecoveryTimeStamp.value
                ],
            opt=[])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.3: PFCP PFD Management
#------------------------------------------------------------------------------#

class PFCPPFDManagementRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPPFDManagementRequest.value}),
        PFCPIEs('IEs', hier=1,
            opt=[
                PFCPIEType.ApplicationIDsPFDs.value,
                PFCPIEType.NodeID.value
                ])
        )


class PFCPPFDManagementResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPPFDManagementResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.Cause.value
                ],
            opt=[
                PFCPIEType.OffendingIE.value,
                PFCPIEType.NodeID.value
                ])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.4: PFCP Association messages
#------------------------------------------------------------------------------#

class PFCPAssociationSetupRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPAssociationSetupRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.RecoveryTimeStamp.value
                ],
            opt=[
                PFCPIEType.UPFunctionFeatures.value,
                PFCPIEType.CPFunctionFeatures.value,
                PFCPIEType.AlternativeSMFIPAddress.value,
                PFCPIEType.SMFSetID.value,
                PFCPIEType.SessionRetentionInformation.value,
                PFCPIEType.UEIPaddressPoolInformation.value,
                PFCPIEType.GTPUPathQoSControlInformation.value,
                PFCPIEType.ClockDriftControlInformation.value,
                PFCPIEType.NFInstanceID.value,
                PFCPIEType.PFCPASReqFlags.value
                ])
        )


class PFCPAssociationSetupResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPAssociationSetupResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.Cause.value,
                PFCPIEType.RecoveryTimeStamp.value
                ],
            opt=[
                PFCPIEType.UPFunctionFeatures.value,
                PFCPIEType.CPFunctionFeatures.value,
                PFCPIEType.AlternativeSMFIPAddress.value,
                PFCPIEType.SMFSetID.value,
                PFCPIEType.PFCPASRspFlags.value,
                PFCPIEType.ClockDriftControlInformation.value,
                PFCPIEType.UEIPaddressPoolInformation.value,
                PFCPIEType.GTPUPathQoSControlInformation.value,
                PFCPIEType.NFInstanceID.value
                ])
        )


class PFCPAssociationUpdateRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPAssociationUpdateRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                ],
            opt=[
                PFCPIEType.UPFunctionFeatures.value,
                PFCPIEType.CPFunctionFeatures.value,
                PFCPIEType.PFCPAssociationReleaseRequest.value,
                PFCPIEType.GracefulReleasePeriod.value,
                PFCPIEType.PFCPAUReqFlags.value,
                PFCPIEType.AlternativeSMFIPAddress.value,
                PFCPIEType.SMFSetID.value,
                PFCPIEType.ClockDriftControlInformation.value,
                PFCPIEType.UEIPaddressPoolInformation.value,
                PFCPIEType.GTPUPathQoSControlInformation.value,
                PFCPIEType.UEIPAddressUsageInformation.value
                ])
        )


class PFCPAssociationUpdateResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPAssociationUpdateResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.Cause.value
                ],
            opt=[
                PFCPIEType.UPFunctionFeatures.value,
                PFCPIEType.CPFunctionFeatures.value,
                PFCPIEType.UEIPAddressUsageInformation.value
                ])
        )


class PFCPAssociationReleaseRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPAssociationReleaseRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                ])
        )


class PFCPAssociationReleaseResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPAssociationReleaseResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.Cause.value
                ])
        )


class PFCPVersionNotSupportedResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPVersionNotSupportedResponse.value}),
        PFCPIEs('IEs', hier=1)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.5: PFCP Node Report Procedure
#------------------------------------------------------------------------------#

class PFCPNodeReportRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPNodeReportRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.NodeReportType.value
                ],
            opt=[
                PFCPIEType.UserPlanePathFailureReport.value,
                PFCPIEType.UserPlanePathRecoveryReport.value,
                PFCPIEType.ClockDriftReport.value,
                PFCPIEType.GTPUPathQoSReport.value
                ])
        )


class PFCPNodeReportResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPNodeReportResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.Cause.value
                ],
            opt=[
                PFCPIEType.OffendingIE.value
                ])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.4.6: PFCP Session Set Deletion
#------------------------------------------------------------------------------#

class PFCPSessionSetDeletionRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPSessionSetDeletionRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value
                ],
            opt=[
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                ])
        )


class PFCPSessionSetDeletionResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 0, 'Type': PFCPMsgType.PFCPSessionSetDeletionResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.Cause.value
                ],
            opt=[
                PFCPIEType.OffendingIE.value
                ])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.2: PFCP Session Establishment Request
#------------------------------------------------------------------------------#

class PFCPSessionEstablishmentRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType.PFCPSessionEstablishmentRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.FSEID.value,
                PFCPIEType.CreatePDR.value,
                PFCPIEType.CreateFAR.value
                ],
            opt=[
                PFCPIEType.CreateURR.value,
                PFCPIEType.CreateQER.value,
                PFCPIEType.CreateBAR.value,
                PFCPIEType.CreateTrafficEndpoint.value,
                PFCPIEType.PDNType.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.UserPlaneInactivityTimer.value,
                PFCPIEType.UserID.value,
                PFCPIEType.TraceInformation.value,
                PFCPIEType.APNDNN.value,
                PFCPIEType.CreateMAR.value,
                PFCPIEType.PFCPSEReqFlags.value,
                PFCPIEType.CreateBridgeInfoforTSC.value,
                PFCPIEType.CreateSRR.value,
                PFCPIEType.ProvideATSSSControlInformation.value,
                PFCPIEType.RecoveryTimeStamp.value,
                PFCPIEType.SNSSAI.value,
                PFCPIEType.ProvideRDSConfigurationInformation.value,
                PFCPIEType.RATType.value,
                ])
        )


class PFCPSessionEstablishmentResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType.PFCPSessionEstablishmentResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.NodeID.value,
                PFCPIEType.Cause.value
                ],
            opt=[
                PFCPIEType.OffendingIE.value,
                PFCPIEType.FSEID.value,
                PFCPIEType.CreatePDR.value,
                PFCPIEType.LoadControlInformation.value,
                PFCPIEType.OverloadControlInformation.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FailedRuleID.value,
                PFCPIEType.CreatedTrafficEndpoint.value,
                PFCPIEType.CreatedBridgeInfoforTSC.value,
                PFCPIEType.ATSSSControlParameters.value,
                PFCPIEType.RDSConfigurationInformation.value,
                PFCPIEType.PartialFailureInformationSessionEstablishmentResponse.value
                ])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.4: PFCP Session Modification Request
#------------------------------------------------------------------------------#

class PFCPSessionModificationRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType.PFCPSessionModificationRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                ],
            opt=[
                PFCPIEType.FSEID.value,
                PFCPIEType.RemovePDR.value,
                PFCPIEType.RemoveFAR.value,
                PFCPIEType.RemoveURR.value,
                PFCPIEType.RemoveQER.value,
                PFCPIEType.RemoveBAR.value,
                PFCPIEType.RemoveTrafficEndpoint.value,
                PFCPIEType.CreatePDR.value,
                PFCPIEType.CreateFAR.value,
                PFCPIEType.CreateURR.value,
                PFCPIEType.CreateQER.value,
                PFCPIEType.CreateBAR.value,
                PFCPIEType.CreateTrafficEndpoint.value,
                PFCPIEType.UpdatePDR.value,
                PFCPIEType.UpdateFAR.value,
                PFCPIEType.UpdateURR.value,
                PFCPIEType.UpdateQER.value,
                PFCPIEType.UpdateBARSessionModificationRequest.value,
                PFCPIEType.UpdateTrafficEndpoint.value,
                PFCPIEType.PFCPSMReqFlags.value,
                PFCPIEType.QueryURR.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.FQCSID.value,
                PFCPIEType.UserPlaneInactivityTimer.value,
                PFCPIEType.QueryURRReference.value,
                PFCPIEType.TraceInformation.value,
                PFCPIEType.RemoveMAR.value,
                PFCPIEType.UpdateMAR.value,
                PFCPIEType.CreateMAR.value,
                PFCPIEType.NodeID.value,
                PFCPIEType.TSCManagementInformationSessionModificationRequest.value,
                PFCPIEType.RemoveSRR.value,
                PFCPIEType.CreateSRR.value,
                PFCPIEType.UpdateSRR.value,
                PFCPIEType.ProvideATSSSControlInformation.value,
                PFCPIEType.EthernetContextInformation.value,
                PFCPIEType.AccessAvailabilityInformation.value,
                PFCPIEType.QueryPacketRateStatus.value,
                PFCPIEType.SNSSAI.value,
                PFCPIEType.RATType.value,
                ])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.5: PFCP Session Modification Response
#------------------------------------------------------------------------------#

class PFCPSessionModificationResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType.PFCPSessionModificationResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.Cause.value
                ],
            opt=[
                PFCPIEType.OffendingIE.value,
                PFCPIEType.CreatedPDR.value,
                PFCPIEType.LoadControlInformation.value,
                PFCPIEType.OverloadControlInformation.value,
                PFCPIEType.UsageReportSessionModificationResponse.value,
                PFCPIEType.FailedRuleID.value,
                PFCPIEType.AdditionalUsageReportsInformation.value,
                PFCPIEType.CreatedTrafficEndpoint.value,
                PFCPIEType.TSCManagementInformationSessionModificationResponse.value,
                PFCPIEType.ATSSSControlParameters.value,
                PFCPIEType.UpdatedPDR.value,
                PFCPIEType.PacketRateStatusReport.value,
                PFCPIEType.PartialFailureInformationSessionModificationResponse.value
                ])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.6: PFCP Session Deletion Request
#------------------------------------------------------------------------------#

class PFCPSessionDeletionRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType.PFCPSessionDeletionRequest.value}),
        PFCPIEs('IEs', hier=1)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.7: PFCP Session Deletion Response
#------------------------------------------------------------------------------#

class PFCPSessionDeletionResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType.PFCPSessionDeletionResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.Cause.value
                ],
            opt=[
                PFCPIEType.OffendingIE.value,
                PFCPIEType.LoadControlInformation.value,
                PFCPIEType.OverloadControlInformation.value,
                PFCPIEType.UsageReportSessionDeletionResponse.value,
                PFCPIEType.AdditionalUsageReportsInformation.value,
                PFCPIEType.PacketRateStatusReport.value,
                PFCPIEType.SessionReport.value
                ])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.8: PFCP Session Report Request
#------------------------------------------------------------------------------#

class PFCPSessionReportRequest(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType.PFCPSessionReportRequest.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.ReportType.value
                ],
            opt=[
                PFCPIEType.DownlinkDataReport.value,
                PFCPIEType.UsageReportSessionReportRequest.value,
                PFCPIEType.ErrorIndicationReport.value,
                PFCPIEType.LoadControlInformation.value,
                PFCPIEType.OverloadControlInformation.value,
                PFCPIEType.AdditionalUsageReportsInformation.value,
                PFCPIEType.PFCPSRReqFlags.value,
                PFCPIEType.FSEID.value,
                PFCPIEType.PacketRateStatusReport.value,
                PFCPIEType.TSCManagementInformationSessionReportRequest.value,
                PFCPIEType.SessionReport.value
                ])
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 7.5.9: PFCP Session Report Response
#------------------------------------------------------------------------------#

class PFCPSessionReportResponse(PFCPMsg):
    _GEN = (
        PFCPHdr('Hdr', val={'S': 1, 'Type': PFCPMsgType.PFCPSessionReportResponse.value}),
        PFCPIEs('IEs', hier=1,
            mand=[
                PFCPIEType.Cause.value
                ],
            opt=[
                PFCPIEType.OffendingIE.value,
                PFCPIEType.UpdateBARSessionReportResponse.value,
                PFCPIEType.PFCPSRRspFlags.value,
                PFCPIEType.FSEID.value,
                PFCPIEType.FTEID.value,
                PFCPIEType.AlternativeSMFIPAddress.value
                ])
        )


#------------------------------------------------------------------------------#
# General parser
#------------------------------------------------------------------------------#

PFCPDispatcher = {
    1 : PFCPHeartbeatRequest,
    2 : PFCPHeartbeatResponse,
    3 : PFCPPFDManagementRequest,
    4 : PFCPPFDManagementResponse,
    5 : PFCPAssociationSetupRequest,
    6 : PFCPAssociationSetupResponse,
    7 : PFCPAssociationUpdateRequest,
    8 : PFCPAssociationUpdateResponse,
    9 : PFCPAssociationReleaseRequest,
    10 : PFCPAssociationReleaseResponse,
    11 : PFCPVersionNotSupportedResponse,
    12 : PFCPNodeReportRequest,
    13 : PFCPNodeReportResponse,
    14 : PFCPSessionSetDeletionRequest,
    15 : PFCPSessionSetDeletionResponse,
    50 : PFCPSessionEstablishmentRequest,
    51 : PFCPSessionEstablishmentResponse,
    52 : PFCPSessionModificationRequest,
    53 : PFCPSessionModificationResponse,
    54 : PFCPSessionDeletionRequest,
    55 : PFCPSessionDeletionResponse,
    56 : PFCPSessionReportRequest,
    57 : PFCPSessionReportResponse
    }


ERR_PFCP_BUF_TOO_SHORT = 1
ERR_PFCP_BUF_INVALID   = 2
ERR_PFCP_TYPE_NONEXIST = 3


def parse_PFCP(buf):
    """parses the buffer `buf' for PFCP message and returns a 2-tuple:
    - PFCP message structure, or None if parsing failed
    - parsing error code, 0 if parsing succeeded, > 0 otherwise
    """
    if len(buf) < 8:
        return None, ERR_PFCP_BUF_TOO_SHORT
    if python_version < 3:
        type = ord(buf[1])
    else:
        type = buf[1]
    try:
        Msg = PFCPDispatcher[type]()
    except KeyError:
        return None, ERR_PFCP_TYPE_NONEXIST
    try:
        Msg.from_bytes(buf)
    except Exception:
        return None, ERR_PFCP_BUF_INVALID
    else:
        # TODO: support piggy-backed PFCP message (FO flag)
        return Msg, 0

# test buffers
# 2001000c0000bd0000600004e42eaecf
# 2002000c00007c0000600004e42eaecf
# 2005001a00000100003c000500c0a8386900600004e4296d960059000100
# 2006009b00000100003c00050203757067001300010100600004e4296caa002b00060001000000000074000f2900ac10000108696e7465726e65748002006048f9767070207632312e30312e302d31337e67656565386361393037206275696c742062792074726176656c70696e67206f6e2074726176656c70696e672d5669727475616c426f7820617420323032312d30342d31335431393a30393a3337
# 2005001b00000300003c000500c0a814fa00600004e367dc2d002b00021001
# 2006001a00000300003c000500c0a81403001300010100600004e367dc46
# 2132006d000000000000000000000100003c000500c0a814030039000d020000000000002710c0a8140300010029003800020001001d0004000003e80002000a00140001030015000105005f000100006c00040000000100030016006c000400000001002c00010200040005002a000100
# 213300110000000000000000000001000013000141
