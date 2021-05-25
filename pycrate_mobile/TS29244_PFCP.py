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

from pycrate_ether.Ethernet     import EtherType_dict
from pycrate_mobile.TS24008_IE  import PLMN


#------------------------------------------------------------------------------#
# some utilities and generic structures
#------------------------------------------------------------------------------#

def strip_name(s):
    # change 3GPP starting str with TGPP
    s = re.sub('^3G', 'TG', s)
    # remove unneeded chars
    s = re.sub('[\s\(\)\'-/]', '', s).strip()
    return s


class BitFlags(Envelope):
    """Envelope containing a list of 1-byte structures
    
    Those structures eventually get set to transparent when decoding a shorter buffer
    and encoding a shorter list of values 
    """
    
    ENV_SEL_TRANS = False
    
    def set_val(self, vals):
        vals_inner = None
        if isinstance(vals, (list, tuple)):
            l = len(vals)
            if l < len(self._content)-1:
                # set last Octets as transparent
                [o.set_trans(True) for o in self._content[l:]]
        elif isinstance(vals, dict):
            # when a key is not identifying a direct OctetX sub-structure
            # we take it appart for setting it afterwards
            vals_inner = {}
            for k, v in vals.items():
                if k not in self._by_name:
                    vals_inner[k] = v
                    del vals[k]
        Envelope.set_val(self, vals)
        if vals_inner:
            # iterate over each OctetX and check if a bit flag is to be set
            for i, o in enumerate(self._content):
                for k, v in vals_inner.items():
                    if hasattr(o, '_by_name') and k in o._by_name:
                        o[k].set_val(v)
                        del vals_inner[k]
                if not vals_inner:
                    break
            for o in self._content[:1+i]:
                    o.set_trans(False)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # check if some 1-byte structures need to be set transparent
        if self._blauto is not None:
            l = self._blauto() >> 3
        else:
            l = char.len_byte()
        if l < len(self._content)-1:
            [o.set_trans(True) for o in self._content[l:]]
        Envelope._from_char(self, char)


class _IEExtUint32(Envelope):
    _GEN = (
        Uint32('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


class _LU8V(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('Val', val=b'')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)
        if 'rep' in kwargs:
            self['Val']._rep = kwargs['rep']


class _LU16V(Envelope):
    _GEN = (
        Uint16('Len'),
        Buf('Val', val=b'')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)
        if 'rep' in kwargs:
            self['Val']._rep = kwargs['rep']


class _LU16LU16V(Envelope):
    _GEN = (
        Uint16('Len'),
        Sequence('Vals', GEN=_LU16V())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Vals'].get_len())
        self['Vals'].set_blauto(lambda: self['Len'].get_val()<<3)
        self['Vals']._tmpl._name = self._name
        if 'rep' in kwargs:
            self['Vals']._tmpl['Val']._rep = kwargs['rep']


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
    93 : 'UE IP Address',
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
    111 : 'Association Release Request',
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
    133 : 'MAC Address',
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
    177 : 'UE IP Address Pool Identity',
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
    208 : 'Cumulative RateRatio Threshold',
    209 : 'Time Offset Measurement',
    210 : 'Cumulative RateRatio Measurement',
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
    233 : 'UE IP Address Pool Information',
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
    """PFCP Information Element
    """
    
    # this is to decode the content of the Data into each specific IE structure
    DECODE_IE_DATA = True
    
    _GEN = (
        Uint16('Type', dic=PFCPIEType_dict),
        Uint16('Len'),
        Uint16('EID', rep=REPR_HEX),
        Buf('Data', rep=REPR_HEX)
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
        if self.DECODE_IE_DATA:
            t = char.to_uint(16)
            if t in PFCPIELUT:
                self.set_ie_class(t)
        Envelope._from_char(self, char)
    
    def set_ie_class(self, t):
        """replace the default Data buffer with a specifically defined class structure
        according to the IE Type value `t'
        """
        IE = PFCPIELUT[t]('Data')
        self.replace(self[3], IE)
        if not hasattr(IE, '_bl') or IE._bl is None:
            IE.set_blauto(lambda: (self['Len'].get_val() - (2 if self['Type'].get_val() & 0x8000 else 0)) << 3)


class PFCPIEs(Sequence):
    """PFCP Grouped Information Element
    """
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
class UEIPAddressPoolInformation(PFCPIEs):
    MAND = (
        PFCPIEType.UEIPAddressPoolIdentity.value,
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
        PFCPIEType.CumulativeRateRatioThreshold.value
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
        PFCPIEType.UEIPAddressPoolIdentity.value,
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
        PFCPIEType.CumulativeRateRatioMeasurement.value,
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
        PFCPIEType.UEIPAddressPoolIdentity.value,
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
        PFCPIEType.UEIPAddress.value,
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
        PFCPIEType.MACAddress.value,
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
        PFCPIEType.UEIPAddress.value,
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
        PFCPIEType.UEIPAddress.value
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
        PFCPIEType.UEIPAddress.value
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
        PFCPIEType.UEIPAddress.value,
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
        PFCPIEType.UEIPAddress.value
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
        PFCPIEType.UEIPAddress.value,
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

# IE Type: 214
class SessionReport(PFCPIEs):
    MAND = (
        PFCPIEType.SRRID.value,
        )
    OPT  = (
        PFCPIEType.AccessAvailabilityReport.value,
        PFCPIEType.QoSMonitoringReport.value,
        )
    

# IE Type: 218
class AccessAvailabilityReport(PFCPIEs):
    MAND = (
        PFCPIEType.AccessAvailabilityInformation
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


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.1: Cause
#------------------------------------------------------------------------------#

Cause_dict = {
    1  : 'Request accepted',
    2  : 'More Usage Report to send',
    3  : 'Request partially accepted',
    64 : 'Request rejected (reason not specified)',
    65 : 'Session context not found',
    66 : 'Mandatory IE missing',
    67 : 'Conditional IE missing',
    68 : 'Invalid length',
    69 : 'Mandatory IE incorrect',
    70 : 'Invalid Forwarding Policy',
    71 : 'Invalid F-TEID allocation option',
    72 : 'No established PFCP Association ',
    73 : 'Rule creation/modification Failure ',
    74 : 'PFCP entity in congestion',
    75 : 'No resources available',
    76 : 'Service not supported',
    77 : 'System failure',
    78 : 'Redirection Requested',
    79 : 'All dynamic addresses are occupied',
    80 : 'Unknown Pre-defined Rule',
    81 : 'Unknown Application ID',
    }


# IE Type: 19
class Cause(Uint8):
    _dic = Cause_dict


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.2: Source Interface
#------------------------------------------------------------------------------#

SourceInterface_dict = {
    0 : 'Access',
    1 : 'Core',
    2 : 'SGi-LAN/N6-LAN',
    3 : 'CP-function',
    4 : '5G VN Internal'
    }


# IE Type: 20
class SourceInterface(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('If', bl=4, dic=SourceInterface_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.3: F-TEID
#------------------------------------------------------------------------------#

# IE Type: 21
class FTEID(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('CHID', bl=1),
        Uint('CH', bl=1),
        Uint('V6', bl=1),
        Uint('V4', bl=1),
        Uint32('TEID'),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Uint8('CHOOSE_ID'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['TEID'].set_transauto(lambda: True if self['CH'].get_val() else False)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() and not self['CH'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() and not self['CH'].get_val() else True)
        self['CHOOSE_ID'].set_transauto(lambda: False if self['CHID'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.4: Network Instance
#------------------------------------------------------------------------------#

# IE Type: 22
class NetworkInstance(Buf):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.5: SDF Filter
#------------------------------------------------------------------------------#

# IE Type: 23
class SDFFilter(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('spare', bl=3, rep=REPR_HEX),
        Uint('BID', bl=1),
        Uint('FL', bl=1),
        Uint('SPI', bl=1),
        Uint('TTC', bl=1),
        Uint('FD', bl=1),
        Uint8('spare', rep=REPR_HEX),
        _LU16V('FlowDesc', rep=REPR_HEX),
        Buf('ToSTrafficClass', val=b'\0\0', bl=16, rep=REPR_HEX),
        Buf('SecurityParameterIndex', val=b'\0\0\0\0', bl=32, rep=REPR_HEX),
        Buf('FlowLabel', bal=b'\0\0\0', bl=24, rep=REPR_HEX),
        Uint32('SDFFilterID'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['FlowDesc'].set_transauto(lambda: False if self['FD'].get_val() else True)
        self['ToSTrafficClass'].set_transauto(lambda: False if self['TTC'].get_val() else True)
        self['SecurityParameterIndex'].set_transauto(lambda: False if self['SPI'].get_val() else True)
        self['FlowLabel'].set_transauto(lambda: False if self['FL'].get_val() else True)
        self['SDFFilterID'].set_transauto(lambda: False if self['BID'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.6: Application ID
#------------------------------------------------------------------------------#

# IE Type: 24
class ApplicationID(Buf):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.7: Gate Status
#------------------------------------------------------------------------------#

# IE Type: 25
class GateStatus(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('ULGate', bl=2, dic={0: 'Open', 1: 'Close'}),
        Uint('DLGate', bl=2, dic={0: 'Open', 1: 'Close'}),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.8: MBR
#------------------------------------------------------------------------------#

class _ULDLBR(Envelope):
    _GEN = (
        Uint('UL', bl=40), # in kbps
        Uint('DL', bl=40), # in kbps
        Buf('ext', val=b'', rep=REPR_HEX)
        )


# IE Type: 26
class MBR(_ULDLBR):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.9: GBR
#------------------------------------------------------------------------------#

# IE Type: 27
class GBR(_ULDLBR):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.10: QER Correlation ID
#------------------------------------------------------------------------------#

# IE Type: 28
class QERCorrelationID(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.11: Precedence
#------------------------------------------------------------------------------#

# IE Type: 29
class Precedence(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.12: Transport Level Marking
#------------------------------------------------------------------------------#

# IE Type: 30
class TransportLevelMarking(Envelope):
    _GEN = (
        Buf('ToSTrafficClass', val=b'\0\0', bl=16, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.13: Volume Threshold
#------------------------------------------------------------------------------#

class _Volume(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('DLVOL', bl=1),
        Uint('ULVOL', bl=1),
        Uint('TOVOL', bl=1),
        Uint64('Total'),
        Uint64('Uplink'),
        Uint64('Downlink'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Total'].set_transauto(lambda: False if self['TOVOL'].get_val() else True)
        self['Uplink'].set_transauto(lambda: False if self['ULVOL'].get_val() else True)
        self['Downlink'].set_transauto(lambda: False if self['DLVOL'].get_val() else True)


# IE Type: 31
class VolumeThreshold(_Volume):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.14: Time Threshold
#------------------------------------------------------------------------------#

# IE Type: 32
class TimeThreshold(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.15: Monitoring Time
#------------------------------------------------------------------------------#

# IE Type: 33
class MonitoringTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.16: Subsequent Volume Threshold
#------------------------------------------------------------------------------#

# IE Type: 34
class SubsequentVolumeThreshold(VolumeThreshold):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.17: Subsequent Time Threshold
#------------------------------------------------------------------------------#

# IE Type: 35
class SubsequentTimeThreshold(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.18: Inactivity Detection Time
#------------------------------------------------------------------------------#

# IE Type: 36
class InactivityDetectionTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.19: Reporting Triggers
#------------------------------------------------------------------------------#

# IE Type: 37
class ReportingTriggers(BitFlags):
    _GEN = (
        Envelope('Octet1', GEN=(
            Uint('LIUSA', bl=1),
            Uint('DROTH', bl=1),
            Uint('STOPT', bl=1),
            Uint('START', bl=1),
            Uint('QUHTI', bl=1),
            Uint('TIMTH', bl=1),
            Uint('VOLTH', bl=1),
            Uint('PERIO', bl=1))),
        Envelope('Octet2', GEN=(
            Uint('QUVTI', bl=1),
            Uint('IPMJL', bl=1),
            Uint('EVEQU', bl=1),
            Uint('EVETH', bl=1),
            Uint('MACAR', bl=1),
            Uint('ENVCL', bl=1),
            Uint('TIMQU', bl=1),
            Uint('VOLQU', bl=1))),
        Envelope('Octet3', GEN=( 
            Uint('spare', bl=7, rep=REPR_HEX),
            Uint('REEMR', bl=1))),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.20: Redirect Information
#------------------------------------------------------------------------------#

RedirectAccessType_dict = {
    0 : 'IPv4 address',
    1 : 'IPv6 address',
    2 : 'URL',
    3 : 'SIP URI',
    4 : 'IPv4 and IPv6 addresses',
    }


class _RedirectServerAddr(Envelope):
    _GEN = (
        Uint16('Len'),
        UTF8String('Val')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)


# IE Type: 38
class RedirectInformation(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('RedirectAccessType', bl=4, dic=RedirectAccessType_dict),
        _RedirectServerAddr('RedirectServerAddr'),
        _RedirectServerAddr('OtherRedirectServerAddr'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['OtherRedirectServerAddr'].set_transauto(lambda: False if self['RedirectAccessType'].get_val() == 4 else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.21: Report Type
#------------------------------------------------------------------------------#

# IE Type: 39
class ReportType(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('UISR', bl=1),
        Uint('SESR', bl=1),
        Uint('TMIR', bl=1),
        Uint('UPIR', bl=1),
        Uint('ERIR', bl=1),
        Uint('USAR', bl=1),
        Uint('DLDR', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.22: Offending IE
#------------------------------------------------------------------------------#

# IE Type: 40
class OffendingIE(Uint16):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.23: Forwarding Policy
#------------------------------------------------------------------------------#

# IE Type: 41
class ForwardingPolicy(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('ID', val=b'', rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['ID'].get_len())
        self['ID'].set_blauto(lambda: self['Len'].get_val()<<3)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.24: Destination Interface
#------------------------------------------------------------------------------#

DestinationInterface_dict = {
    0 : 'Access',
    1 : 'Core',
    2 : 'SGi-LAN/N6-LAN',
    3 : 'CP- Function',
    4 : 'LI Function',
    5 : '5G VN Internal'
    }

# IE Type: 42
class DestinationInterface(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Val', bl=4, dic=DestinationInterface_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.25: UP Function Features
#------------------------------------------------------------------------------#

# IE Type: 43
class UPFunctionFeatures(BitFlags):
    _GEN = (
        Envelope('Octet1', GEN=(
            Uint('TREU', bl=1),
            Uint('HEEU', bl=1),
            Uint('PFDM', bl=1),
            Uint('FTUP', bl=1),
            Uint('TRST', bl=1),
            Uint('DLBD', bl=1),
            Uint('DDND', bl=1),
            Uint('BUCP', bl=1))
            ),
        Envelope('Octet2', GEN=(
            Uint('EPFAR', bl=1),
            Uint('PFDE', bl=1),
            Uint('FRRT', bl=1),
            Uint('TRACE', bl=1),
            Uint('QUOAC', bl=1),
            Uint('UDBC', bl=1),
            Uint('PDIU', bl=1),
            Uint('EMPU', bl=1))
            ),
        Envelope('Octet3', GEN=(
            Uint('GCOM', bl=1),
            Uint('BUNDL', bl=1),
            Uint('MTE', bl=1),
            Uint('MNOP', bl=1),
            Uint('SSET', bl=1),
            Uint('UEIP', bl=1),
            Uint('ADPDP', bl=1),
            Uint('DPDRA', bl=1))
            ),
        Envelope('Octet4', GEN=(
            Uint('MPTCP', bl=1),
            Uint('TSCU', bl=1),
            Uint('IP6PL', bl=1),
            Uint('IPTV', bl=1),
            Uint('NORP', bl=1),
            Uint('VTIME', bl=1),
            Uint('RTTL', bl=1),
            Uint('MPAS', bl=1))
            ),
        Envelope('Octet5', GEN=(
            Uint('RDS', bl=1),
            Uint('DDDS', bl=1),
            Uint('ETHAR', bl=1),
            Uint('CIOT', bl=1),
            Uint('MT-EDT', bl=1),
            Uint('GPQM', bl=1),
            Uint('QFQM', bl=1),
            Uint('ATSSS-LL', bl=1))
            ),
        Envelope('Octet6', GEN=(
            Uint('spare', bl=5, rep=REPR_HEX),
            Uint('NSPOC', bl=1),
            Uint('QUASF', bl=1),
            Uint('RTTWP', bl=1))
            ),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.26: Apply Action
#------------------------------------------------------------------------------#

# IE Type: 44
class ApplyAction(BitFlags):
    _GEN = (
        Envelope('Octet1', GEN=(
            Uint('DFRT', bl=1),
            Uint('IPMD', bl=1),
            Uint('IPMA', bl=1),
            Uint('DUPL', bl=1),
            Uint('NOCP', bl=1),
            Uint('BUFF', bl=1),
            Uint('FORW', bl=1),
            Uint('DROP', bl=1))),
        Envelope('Octet2', GEN=(
            Uint('spare', bl=5, rep=REPR_HEX),
            Uint('DDPN', bl=1),
            Uint('BDPN', bl=1),
            Uint('EDRT', bl=1))),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.27: Downlink Data Service Information
#------------------------------------------------------------------------------#

class _IEUint6(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('Val', bl=6)
        )


# IE Type: 45
class DownlinkDataServiceInformation(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('QFII', bl=1),
        Uint('PPI', bl=1),
        _IEUint6('PagingPolicyInd'),
        _IEUint6('QFI'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['PagingPolicyInd'].set_transauto(lambda: False if self['PPI'].get_val() else True)
        self['QFI'].set_transauto(lambda: False if self['QFII'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.28: Downlink Data Notification Delay
#------------------------------------------------------------------------------#

# IE Type: 46
class DownlinkDataNotificationDelay(Envelope):
    _GEN = (
        Uint8('Val', desc='multiple of 50ms'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.29: DL Buffering Duration
#------------------------------------------------------------------------------#

TimerUnit_dict = {
    0 : '2 sec',
    1 : '1 min',
    2 : '10 min',
    3 : '1 hr',
    4 : '10 hr',
    7 : 'infinite'
    }

class _Timer(Envelope):
    _GEN = (
        Uint('TimerUnit', bl=3, dic=TimerUnit_dict),
        Uint('TimerVal', bl=5),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


# IE Type: 47
class DLBufferingDuration(_Timer):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.30: DL Buffering Suggested Packet Count
#------------------------------------------------------------------------------#

# IE Type: 48
# this is an Uint, of the length indicated in the length prefix... life is such dangerous !
class DLBufferingSuggestedPacketCount(Uint):
    
    # to get it properly working with pycrate_core, we need to set the bit length
    # when a value is set
    def set_val(self, val):
        self._bl = val.bit_length()
        if self._bl % 8:
            # need to increase the bl to the next multiple of 8 bits
            self._bl += 8 - (self._bl % 8)
        Uint.set_val(self, val)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.31: PFCPSMReq-Flags
#------------------------------------------------------------------------------#

# IE Type: 49
class PFCPSMReqFlags(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('QAURR', bl=1),
        Uint('SNDEM', bl=1),
        Uint('DROBU', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.32: PFCPSRRsp-Flags
#------------------------------------------------------------------------------#

# IE Type: 50
class PFCPSRRspFlags(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('DROBU', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.33: Sequence Number
#------------------------------------------------------------------------------#

# IE Type: 52
class SequenceNumber(Uint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.34: Metric
#------------------------------------------------------------------------------#

# IE Type: 53
class Metric(Uint8):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.35: Timer
#------------------------------------------------------------------------------#

# IE Type: 55
class Timer(_Timer):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.36: Packet Detection Rule ID (PDR ID)
#------------------------------------------------------------------------------#

# IE Type: 56
class PDRID(Envelope):
    _GEN = (
        Uint16('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.37: F-SEID
#------------------------------------------------------------------------------#

# IE Type: 57
class FSEID(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('V4', bl=1),
        Uint('V6', bl=1),
        Uint64('SEID'),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.38: Node ID
#------------------------------------------------------------------------------#

NodeIDType_dict = {
    0 : 'IPv4 address',
    1 : 'IPv6 address',
    2 : 'FQDN'
    }


class _FQDN(Sequence):
    _GEN = _LU8V('Label')


# IE Type: 60
class NodeID(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Type', bl=4, dic=NodeIDType_dict),
        Alt('Val', GEN={
            0 : Buf('IPv4Addr', bl=32, rep=REPR_HEX),
            1 : Buf('IPv6Addr', bl=128, rep=REPR_HEX),
            2 : _FQDN('FQDN')},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val()
            ),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.39: PFD Contents
#------------------------------------------------------------------------------#

# IE Type: 61
class PFDContents(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('ADNP', bl=1),
        Uint('AU', bl=1),
        Uint('AFD', bl=1),
        Uint('DNP', bl=1),
        Uint('CP', bl=1),
        Uint('DN', bl=1),
        Uint('U', bl=1),
        Uint('FD', bl=1),
        Uint8('spare', rep=REPR_HEX),
        _LU16V('FlowDesc', rep=REPR_HEX),
        _LU16V('URL'),
        _LU16V('DomainName'),
        _LU16V('CustomPFDContent', rep=REPR_HEX),
        _LU16V('DomainNameProtocol'),
        _LU16LU16V('AdditionalFlowDesc'),
        _LU16LU16V('AdditionalURL'),
        _LU16LU16V('AdditionalDomainNameAndProtocol'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['FlowDesc'].set_transauto(lambda: False if self['FD'].get_val() else True)
        self['URL'].set_transauto(lambda: False if self['U'].get_val() else True)
        self['DomainName'].set_transauto(lambda: False if self['DN'].get_val() else True)
        self['CustomPFDContent'].set_transauto(lambda: False if self['CP'].get_val() else True)
        self['DomainNameProtocol'].set_transauto(lambda: False if self['DNP'].get_val() else True)
        self['AdditionalFlowDesc'].set_transauto(lambda: False if self['AFD'].get_val() else True)
        self['AdditionalURL'].set_transauto(lambda: False if self['AU'].get_val() else True)
        self['AdditionalDomainNameAndProtocol'].set_transauto(lambda: False if self['ADNP'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.40: Measurement Method
#------------------------------------------------------------------------------#

# IE Type: 62
class MeasurementMethod(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('EVENT', bl=1),
        Uint('VOLUM', bl=1),
        Uint('DURAT', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.41: Usage Report Trigger
#------------------------------------------------------------------------------#

# IE Type: 63
class UsageReportTrigger(BitFlags):
    _GEN = (
        Envelope('Octet1', GEN=(
            Uint('IMMER', bl=1),
            Uint('DROTH', bl=1),
            Uint('STOPT', bl=1),
            Uint('START', bl=1),
            Uint('QUHTI', bl=1),
            Uint('TIMTH', bl=1),
            Uint('VOLTH', bl=1),
            Uint('PERIO', bl=1))),
        Envelope('Octet2', GEN=(
            Uint('EVETH', bl=1),
            Uint('MACAR', bl=1),
            Uint('ENVCL', bl=1),
            Uint('MONIT', bl=1),
            Uint('TERMR', bl=1),
            Uint('LIUSA', bl=1),
            Uint('TIMQU', bl=1),
            Uint('VOLQU', bl=1))),
        Envelope('Octet3', GEN=(
            Uint('spare', bl=3, rep=REPR_HEX),
            Uint('EMRRE', bl=1),
            Uint('QUVTI', bl=1),
            Uint('IPMJL', bl=1),
            Uint('TEBUR', bl=1),
            Uint('EVEQU', bl=1))),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.42: Measurement Period
#------------------------------------------------------------------------------#

# IE Type: 64
class MeasurementPeriod(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.43: Fully qualified PDN Connection Set Identifier (FQ-CSID)
#------------------------------------------------------------------------------#

NodeType_dict = {
    0 : 'MME',
    1 : 'SGW-C',
    2 : 'PGW-C',
    3 : 'ePDG',
    4 : 'TWAN',
    5 : 'PGW-U/SGW-U'
    }


# IE Type: 65
class FQCSID(Envelope):
    _GEN = (
        Uint('NodeIDType', bl=4, dic={0: 'IPv4', 1: 'IPv6', 2:'MCCMNC-based'}),
        Uint('NumCSIDs', bl=4),
        Alt('NodeAddr', GEN={
            0 : Buf('IPv4Addr', bl=32, rep=REPR_HEX),
            1 : Buf('IPv6Addr', bl=128, rep=REPR_HEX),
            2 : Buf('MCCMNCAddr', bl=32, rep=REPR_HEX)},
            DEFAULT=Buf('none', bl=0),
            sel=lambda self: self.get_env()['NodeIDType'].get_val()),
        Sequence('CSIDs', GEN=Uint16('CSID')),
        Uint('spare', bl=4),
        Uint('NodeType', bl=4, dic=NodeType_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumCSIDs'].set_valauto(lambda: self['CSIDs'].get_num())
        self['CSIDs'].set_numauto(lambda: self['NumCSIDs'].get_val())


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.44: Volume Measurement
#------------------------------------------------------------------------------#

# IE Type: 66
class VolumeMeasurement(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('DLNOP', bl=1),
        Uint('ULNOP', bl=1),
        Uint('TONOP', bl=1),
        Uint('DLVOL', bl=1),
        Uint('ULVOL', bl=1),
        Uint('TOVOL', bl=1),
        Uint64('TotalVolume'),
        Uint64('UplinkVolume'),
        Uint64('DownlinkVolume'),
        Uint64('TotalNumPackets'),
        Uint64('UplinkNumPackets'),
        Uint64('DownlinkNumPackets'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['TotalVolume'].set_transauto(lambda: False if self['TOVOL'].get_val() else True)
        self['UplinkVolume'].set_transauto(lambda: False if self['ULVOL'].get_val() else True)
        self['DownlinkVolume'].set_transauto(lambda: False if self['DLVOL'].get_val() else True)
        self['TotalNumPackets'].set_transauto(lambda: False if self['TONOP'].get_val() else True)
        self['UplinkNumPackets'].set_transauto(lambda: False if self['ULNOP'].get_val() else True)
        self['DownlinkNumPackets'].set_transauto(lambda: False if self['DLNOP'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.45: Duration Measurement
#------------------------------------------------------------------------------#

# IE Type: 67
class DurationMeasurement(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.46: Time of First Packet
#------------------------------------------------------------------------------#

# IE Type: 69
class TimeofFirstPacket(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.47: Time of Last Packet
#------------------------------------------------------------------------------#

# IE Type: 70
class TimeofLastPacket(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.48: Quota Holding Time
#------------------------------------------------------------------------------#

# IE Type: 71
class QuotaHoldingTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.49: Dropped DL Traffic Threshold
#------------------------------------------------------------------------------#

# IE Type: 72
class DroppedDLTrafficThreshold(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('DLBY', bl=1),
        Uint('DLPA', bl=1),
        Uint64('DLPackets'),
        Uint64('NumBytesDLData'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.50: Volume Quota
#------------------------------------------------------------------------------#

# IE Type: 73
class VolumeQuota(_Volume):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.51: Time Quota
#------------------------------------------------------------------------------#

# IE Type: 74
class TimeQuota(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.52: Start Time
#------------------------------------------------------------------------------#

# IE Type: 75
class StartTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.53: End Time
#------------------------------------------------------------------------------#

# IE Type: 76
class EndTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.54: URR ID
#------------------------------------------------------------------------------#

# IE Type: 81
class URRID(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.55: Linked URR ID
#------------------------------------------------------------------------------#

# IE Type: 82
class LinkedURRID(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.56: Outer Header Creation
#------------------------------------------------------------------------------#

# IE Type: 84
class OuterHeaderCreation(Envelope):
    _GEN = (
        Uint('STAG', bl=1),
        Uint('CTAG', bl=1),
        Uint('IPv6', bl=1),
        Uint('IPv4', bl=1),
        Uint('UDP_IPv6', bl=1),
        Uint('UDP_IPv4', bl=1),
        Uint('GTPU_UDP_IPv6', bl=1),
        Uint('GTPU_UDP_IPv4', bl=1),
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('N6', bl=1),
        Uint('N19', bl=1),
        Uint32('TEID'),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Uint16('Port'),
        Buf('VLAN_CTAG', bl=24, rep=REPR_HEX),
        Buf('VLAN_STAG', bl=24, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['TEID'].set_transauto(lambda: False if (
            self['GTPU_UDP_IPv6'].get_val() or self['GTPU_UDP_IPv4'].get_val()) else True)
        self['IPv4Addr'].set_transauto(lambda: False if (
            self['IPv4'].get_val() or self['UDP_IPv4'].get_val() or self['GTPU_UDP_IPv4'].get_val()) else True)
        self['IPv6Addr'].set_transauto(lambda: False if (
            self['IPv6'].get_val() or self['UDP_IPv6'].get_val() or self['GTPU_UDP_IPv6'].get_val()) else True)
        self['Port'].set_transauto(lambda: False if (
            self['UDP_IPv6'].get_val() or self['UDP_IPv4'].get_val() or self['GTPU_UDP_IPv6'].get_val() or self['GTPU_UDP_IPv4'].get_val()) else True)
        self['VLAN_CTAG'].set_transauto(lambda: False if (
            self['CTAG'].get_val()) else True)
        self['VLAN_STAG'].set_transauto(lambda: False if (
            self['STAG'].get_val()) else True)
        

#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.57: BAR ID
#------------------------------------------------------------------------------#

# IE Type: 88
class BARID(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.58: CP Function Features
#------------------------------------------------------------------------------#

# IE Type: 89
class CPFunctionFeatures(BitFlags):
    _GEN = (
        Envelope('Octet1', GEN=(
            Uint('UIAUR', bl=1),
            Uint('ARDR', bl=1),
            Uint('MPAS', bl=1),
            Uint('BUNDL', bl=1),
            Uint('SSET', bl=1),
            Uint('EPFAR', bl=1),
            Uint('OVRL', bl=1),
            Uint('LOAD', bl=1))),
        Envelope('Octet2', GEN=(
            Uint('spare', bl=7, rep=REPR_HEX),
            Uint('PSUCC', bl=1))),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.59: Usage Information
#------------------------------------------------------------------------------#

# IE Type: 90
class UsageInformation(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('UBE', bl=1),
        Uint('UAE', bl=1),
        Uint('AFT', bl=1),
        Uint('BEF', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.60: Application Instance ID
#------------------------------------------------------------------------------#

# IE Type: 91
class ApplicationInstanceID(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.61: Flow Information
#------------------------------------------------------------------------------#

FlowDirection_dict = {
    0 : 'Unspecified',
    1 : 'Downlink',
    2 : 'Uplink',
    3 : 'Bidirectional'
    }


# IE Type: 92
class FlowInformation(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('FlowDir', bl=3, dic=FlowDirection_dict),
        Uint16('Len'),
        Buf('FlowDesc', rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['FlowDesc'].get_len())
        self['FlowDesc'].set_blauto(lambda: self['Len'].get_val()<<3)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.62: UE IP Address
#------------------------------------------------------------------------------#

# IE Type: 93
class UEIPAddress(Envelope):
    _GEN = (
        Uint('spare', bl=1, rep=REPR_HEX),
        Uint('IP6PL', bl=1),
        Uint('CHV6', bl=1),
        Uint('CHV4', bl=1),
        Uint('IPv6D', bl=1),
        Uint('SD', bl=1),
        Uint('V4', bl=1),
        Uint('V6', bl=1),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
	    Uint8('IPv6PrefDeleg'),
        Uint8('IPv6PrefLen'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)
        self['IPv6PrefDeleg'].set_transauto(lambda: False if self['IPv6D'].get_val() else True)
        self['IPv6PrefLen'].set_transauto(lambda: False if self['IP6PL'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.63: Packet Rate
#------------------------------------------------------------------------------#

TimeUnit_dict = {
    0 : 'min',
    1 : '6 min',
    2 : 'hr',
    3 : 'day',
    4 : 'week'
    }

# IE Type: 94
class PacketRate(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('APRC', bl=1),
        Uint('DLPR', bl=1),
        Uint('ULPR', bl=1),
        Envelope('Uplink', GEN=(
            Uint('spare', bl=5, rep=REPR_HEX),
            Uint('TimeUnit', bl=3, dic=TimeUnit_dict),
            Uint16('PacketRate'))
            ),
        Envelope('Downlink', GEN=( 
            Uint('spare', bl=5, rep=REPR_HEX),
            Uint('TimeUnit', bl=3, dic=TimeUnit_dict),
            Uint16('PacketRate'))
            ),
        Envelope('AddUplink', GEN=(
            Uint('spare', bl=5, rep=REPR_HEX),
            Uint('TimeUnit', bl=3, dic=TimeUnit_dict),
            Uint16('PacketRate'))
            ),
        Envelope('AddDownlink', GEN=(
            Uint('spare', bl=5, rep=REPR_HEX),
            Uint('TimeUnit', bl=3, dic=TimeUnit_dict),
            Uint16('PacketRate'))
            ),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Uplink'].set_transauto(lambda: False if self['ULPR'].get_val() else True)
        self['Downlink'].set_transauto(lambda: False if self['DLPR'].get_val() else True)
        self['AddUplink'].set_transauto(lambda: False if (self['ULPR'].get_val() and self['APRC'].get_val()) else True)
        self['AddDownlink'].set_transauto(lambda: False if (self['DLPR'].get_val() and self['APRC'].get_val()) else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.64: Outer Header Removal
#------------------------------------------------------------------------------#

OuterHeaderRemovalDesc_dict = {
    0 : 'GTP-U/UDP/IPv4',
    1 : 'GTP-U/UDP/IPv6',
    2 : 'UDP/IPv4',
    3 : 'UDP/IPv6',
    4 : 'IPv4',
    5 : 'IPv6',
    6 : 'GTP-U/UDP/IP',
    7 : 'VLAN S-TAG',
    8 : 'S-TAG and C-TAG'
    }


class _GTPUExtHdrDel(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('PDUSessionContainer', bl=1)
        )


# IE Type: 95
class OuterHeaderRemoval(Envelope):
    _GEN = (
        Uint8('Desc', dic=OuterHeaderRemovalDesc_dict),
        _GTPUExtHdrDel('GTPUExtHdrDel'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        # Warning: spec is really unclear about to have GTPUExtHdrDel or not
        self['GTPUExtHdrDel'].set_transauto(lambda: False if self['Desc'].get_val() == 6 else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.65: Recovery Time Stamp
#------------------------------------------------------------------------------#

# IE Type: 96
class RecoveryTimeStamp(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.66: DL Flow Level Marking
#------------------------------------------------------------------------------#

# IE Type: 97
class DLFlowLevelMarking(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('SCI', bl=1),
        Uint('TTC', bl=1),
        Buf('ToSTrafficClass', val=b'\0\0', bl=16, rep=REPR_HEX),
        Buf('ServiceClassInd', val=b'\0\0', bl=16, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['ToSTrafficClass'].set_transauto(lambda: False if self['TTC'].get_val() else True)
        self['ServiceClassInd'].set_transauto(lambda: False if self['SCI'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.67: Header Enrichment
#------------------------------------------------------------------------------#

# IE Type: 98
class HeaderEnrichment(Envelope):
    _GEN = (
        Uint('spare', bl=3, rep=REPR_HEX),
        Uint('Type', bl=5, dic={0: 'HTTP'}),
        _LU8V('HeaderFieldName'),
        _LU16V('HeaderFieldValue'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.68: Measurement Information
#------------------------------------------------------------------------------#

# IE Type: 100
class MeasurementInformation(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('ASPOC', bl=1),
        Uint('SSPOC', bl=1),
        Uint('MNOP', bl=1),
        Uint('ISTM', bl=1),
        Uint('RADI', bl=1),
        Uint('INAM', bl=1),
        Uint('MBQE', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.69: Node Report Type
#------------------------------------------------------------------------------#

# IE Type: 101
class NodeReportType(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('GPQR', bl=1),
        Uint('CKDR', bl=1),
        Uint('UPRR', bl=1),
        Uint('UPFR', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.70:  Remote GTP-U Peer
#------------------------------------------------------------------------------#

# IE Type: 103
class RemoteGTPUPeer(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('NI', bl=1),
        Uint('DI', bl=1),
        Uint('V4', bl=1),
        Uint('V6', bl=1),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        _LU16V('DestinationInterface'),
        _LU16V('NetworkInstance'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)
        self['DestinationInterface'].set_transauto(lambda: False if self['DI'].get_val() else True)
        self['NetworkInstance'].set_transauto(lambda: False if self['NI'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.71: UR-SEQN
#------------------------------------------------------------------------------#

# IE Type: 104
class URSEQN(Uint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.72: Activate Predefined Rules
#------------------------------------------------------------------------------#

# IE Type: 106
class ActivatePredefinedRules(Buf):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.73: Deactivate Predefined Rules
#------------------------------------------------------------------------------#

# IE Type: 107
class DeactivatePredefinedRules(Buf):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.74: FAR ID
#------------------------------------------------------------------------------#

# IE Type: 108
class FARID(Envelope):
    _GEN = (
        Uint32('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.75: QER ID
#------------------------------------------------------------------------------#

# IE Type: 109
class QERID(Envelope):
    _GEN = (
        Uint32('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.76: OCI Flags
#------------------------------------------------------------------------------#

# IE Type: 110
class OCIFlags(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('AOCI', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.77: PFCP Association Release Request
#------------------------------------------------------------------------------#

# IE Type: 111
class AssociationReleaseRequest(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('URSS', bl=1),
        Uint('SARR', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.78: Graceful Release Period
#------------------------------------------------------------------------------#

# IE Type: 112
class GracefulReleasePeriod(_Timer):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.79: PDN Type
#------------------------------------------------------------------------------#

PDNType_dict = {
    1 : 'IPv4',
    2 : 'IPv6',
    3 : 'IPv4v6',
    4 : 'Non-IP',
    5 : 'Ethernet'
    }

# IE Type: 113
class PDNType(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Val', bl=3, dic=PDNType_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.80: Failed Rule ID
#------------------------------------------------------------------------------#

RuleIDType_dict = {
    0 : 'PDR',
    1 : 'FAR',
    2 : 'QER',
    3 : 'URR',
    4 : 'BAR',
    5 : 'MAR',
    6 : 'SRR',
    }

# IE Type: 114
class FailedRuleID(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('RuleIDType', bl=4, dic=RuleIDType_dict),
        Alt('RuleIDVal', GEN={
            0 : Uint16('PDRID'),
            1 : Uint32('FARID'),
            2 : Uint32('QERID'),
            3 : Uint32('URRID'),
            4 : Uint8('BARID'),
            5 : Uint16('MARID'),
            6 : Uint8('SRRID')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['RuleIDType'].get_val()
            ),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.81: Time Quota Mechanism
#------------------------------------------------------------------------------#

# IE Type: 115
class TimeQuotaMechanism(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('BTIT', bl=2, dic={0: 'CTP', 1: 'DTP'}),
        Uint32('BaseTimeInterval'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.83: User Plane Inactivity Timer
#------------------------------------------------------------------------------#

# IE Type: 117
class UserPlaneInactivityTimer(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.84: Multiplier
#------------------------------------------------------------------------------#

# IE Type: 119
class Multiplier(Envelope):
    _GEN = (
        Int64('ValueDigits'),
        Int32('Exponent')
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.85: Aggregated URR ID IE
#------------------------------------------------------------------------------#

# IE Type: 120
class AggregatedURRID(Uint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.86: Subsequent Volume Quota
#------------------------------------------------------------------------------#

# IE Type: 121
class SubsequentVolumeQuota(_Volume):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.87: Subsequent Time Quota
#------------------------------------------------------------------------------#

# IE Type: 122
class SubsequentTimeQuota(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.88: RQI
#------------------------------------------------------------------------------#

# IE Type: 123
class RQI(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('RQI', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.89: QFI
#------------------------------------------------------------------------------#

# IE Type: 124
class QFI(Envelope):
    _GEN = (
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('QFI', val=1, bl=6),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.90: Query URR Reference
#------------------------------------------------------------------------------#

# IE Type: 125
class QueryURRReference(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.91: Additional Usage Reports Information
#------------------------------------------------------------------------------#

# IE Type: 126
class AdditionalUsageReportsInformation(Envelope):
    _GEN = (
        Uint('AURI', bl=1),
        Uint('Num', bl=15),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.92: Traffic Endpoint ID
#------------------------------------------------------------------------------#

# IE Type: 131
class TrafficEndpointID(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.93: MAC address
#------------------------------------------------------------------------------#

# IE Type: 133
class MACAddress(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('UDES', bl=1),
        Uint('USOU', bl=1),
        Uint('DEST', bl=1),
        Uint('SOUR', bl=1),
        Buf('SrcMACAddr', bl=48, rep=REPR_HEX),
        Buf('DstMACAddr', bl=48, rep=REPR_HEX),
        Buf('UpperSrcMACAddr', bl=48, rep=REPR_HEX),
        Buf('UpperDstMACAddr', bl=48, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['SrcMACAddr'].set_transauto(lambda: False if self['SOUR'].get_val() else True)
        self['DstMACAddr'].set_transauto(lambda: False if self['DEST'].get_val() else True)
        self['UpperSrcMACAddr'].set_transauto(lambda: False if self['USOU'].get_val() else True)
        self['UpperDstMACAddr'].set_transauto(lambda: False if self['UDES'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.94: C-TAG (Customer-VLAN tag)
#------------------------------------------------------------------------------#

class _VLANTAG(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('VID', bl=1),
        Uint('DEI', bl=1),
        Uint('PCP', bl=1),
        Uint('CVID_MSB', bl=4),
        Uint('DEIFlag', bl=1),
        Uint('PCPValue', bl=1),
        Uint8('CVID_LSB'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


# IE Type: 134
class CTAG(_VLANTAG):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.95: S-TAG (Service-VLAN tag)
#------------------------------------------------------------------------------#

# IE Type: 135
class STAG(_VLANTAG):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.96: Ethertype
#------------------------------------------------------------------------------#

# IE Type: 136
class Ethertype(Envelope):
    _GEN = (
        Uint16('Val', rep=REPR_HEX, dic=EtherType_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.97: Proxying
#------------------------------------------------------------------------------#

# IE Type: 137
class Proxying(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('INS', bl=1),
        Uint('ARP', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.98: Ethernet Filter ID
#------------------------------------------------------------------------------#

# IE Type: 138
class EthernetFilterID(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.99: Ethernet Filter Properties
#------------------------------------------------------------------------------#

# IE Type: 139
class EthernetFilterProperties(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('BIDE', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.100: Suggested Buffering Packets Count
#------------------------------------------------------------------------------#

# IE Type: 140
class SuggestedBufferingPacketsCount(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.101: User ID
#------------------------------------------------------------------------------#

# IE Type: 141
class UserID(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NAIF', bl=1),
        Uint('MSISDNF', bl=1),
        Uint('IMEIF', bl=1),
        Uint('IMSIF', bl=1),
        _LU8V('IMSI'),
        _LU8V('IMEI'),
        _LU8V('MSISDN'),
        _LU8V('NAI'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IMSI'].set_transauto(lambda: False if self['IMSIF'].get_val() else True)
        self['IMEI'].set_transauto(lambda: False if self['IMEIF'].get_val() else True)
        self['MSISDN'].set_transauto(lambda: False if self['MSISDNF'].get_val() else True)
        self['NAI'].set_transauto(lambda: False if self['NAIF'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.102: Ethernet PDU Session Information
#------------------------------------------------------------------------------#

# IE Type: 142
class EthernetPDUSessionInformation(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('ETHI', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    

#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.103: MAC Addresses Detected
#------------------------------------------------------------------------------#

class _MACAddresses(Envelope):
    _GEN = (
        Uint8('NumAddrs'),
        Sequence('Addrs', GEN=Buf('MACAddr', bl=48, rep=REPR_HEX)),
        _LU8V('CTAG', rep=REPR_HEX),
        _LU8V('STAG', rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumAddrs'].set_valauto(lambda: self['Addrs'].get_num())
        self['Addrs'].set_numauto(lambda: self['NumAddrs'].get_val())


# IE Type: 144
class MACAddressesDetected(_MACAddresses):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.104: MAC Addresses Removed
#------------------------------------------------------------------------------#

# IE Type: 145
class MACAddressesRemoved(_MACAddresses):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.105: Ethernet Inactivity Timer
#------------------------------------------------------------------------------#

# IE Type: 146
class EthernetInactivityTimer(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.106: Subsequent Event Quota
#------------------------------------------------------------------------------#

# IE Type: 150
class SubsequentEventQuota(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.107: Subsequent Event Threshold
#------------------------------------------------------------------------------#

# IE Type: 151
class SubsequentEventThreshold(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.108: Trace Information
#------------------------------------------------------------------------------#

# IE Type: 152
class TraceInformation(Envelope):
    _GEN = (
        PLMN(),
        Uint24('TraceID'),
        _LU8V('TriggeringEvents', rep=REPR_HEX),
        Uint8('SessionTraceDepth'),
        _LU8V('ListOfInterfaces', rep=REPR_HEX),
        _LU8V('IPAdressOfTraceCollectionEntity', rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.109: Framed-Route
#------------------------------------------------------------------------------#

# IE Type: 153
class FramedRoute(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.110: Framed-Routing
#------------------------------------------------------------------------------#

# IE Type: 154
class FramedRouting(Uint32):
    _dic = {
        0 : 'None',
        1 : 'Send routing packets',
        2 : 'Listen for routing packets',
        3 : 'Send and Listen'
        }


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.111: Framed-IPv6-Route
#------------------------------------------------------------------------------#

# IE Type: 155
class FramedIPv6Route(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.112: Event Quota
#------------------------------------------------------------------------------#

# IE Type: 148
class EventQuota(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.113: Event Threshold
#------------------------------------------------------------------------------#

# IE Type: 149
class EventThreshold(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.114: Time Stamp
#------------------------------------------------------------------------------#

# IE Type: 156
class TimeStamp(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.115: Averaging Window
#------------------------------------------------------------------------------#

# IE Type: 157
class AveragingWindow(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.116: Paging Policy Indicator (PPI)
#------------------------------------------------------------------------------#

# IE Type: 158
class PagingPolicyIndicator(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('PPI', bl=3),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.117: APN/DNN
#------------------------------------------------------------------------------#

# IE Type: 159
class APNDNN(_FQDN):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.118: 3GPP Interface Type
#------------------------------------------------------------------------------#

TGPPInterfaceType_dict = {
    0 : 'S1-U',
    1 : 'S5 /S8-U',
    2 : 'S4-U',
    3 : 'S11-U',
    4 : 'S12',
    5 : 'Gn/Gp-U',
    6 : 'S2a-U',
    7 : 'S2b-U',
    8 : 'eNodeB GTP-U interface for DL data forwarding',
    9 : 'eNodeB GTP-U interface for UL data forwarding',
    10 : 'SGW/UPF GTP-U interface for DL data forwarding',
    11 : 'N3 3GPP Access',
    12 : 'N3 Trusted Non-3GPP Access',
    13 : 'N3 Untrusted Non-3GPP Access',
    14 : 'N3 for data forwarding',
    15 : 'N9',
    16 : 'SGi',
    17 : 'N6',
    18 : 'N19',
    19 : 'S8-U',
    20 : 'Gp-U',
    21 : 'N9 for roaming',
    22 : 'Iu-U',
    23 : 'N9 for data forwarding',
    24 : 'Sxa-U',
    25 : 'Sxb-U',
    26 : 'Sxc-U',
    27 : 'N4-U',
    28 : 'SGW/UPF GTP-U interface for UL data forwarding',
    }


# IE Type: 160
class TGPPInterfaceType(Envelope):
    _GEN = (
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('Val', bl=6, dic=TGPPInterfaceType_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.119: PFCPSRReq-Flags
#------------------------------------------------------------------------------#

# IE Type: 161
class PFCPSRReqFlags(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('PSDBU', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.120: PFCPAUReq-Flags
#------------------------------------------------------------------------------#

# IE Type: 162
class PFCPAUReqFlags(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('PARPS', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.121: Activation Time
#------------------------------------------------------------------------------#

# IE Type: 163
class ActivationTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.122: Deactivation Time
#------------------------------------------------------------------------------#

# IE Type: 164
class DeactivationTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.123: MAR ID
#------------------------------------------------------------------------------#

# IE Type: 170
class MARID(Envelope):
    _GEN = (
        Uint16('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.124: Steering Functionality
#------------------------------------------------------------------------------#

# IE Type: 171
class SteeringFunctionality(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Val', bl=4, dic={0: 'ATSSS-LL', 1: 'MPTCP'}),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.125: Steering Mode
#------------------------------------------------------------------------------#

SteeringMode_dict = {
    0 : 'Active-Standby',
    1 : 'Smallest Delay',
    2 : 'Load Balancing',
    3 : 'Priority-based'
    }


# IE Type: 172
class SteeringMode(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Val', bl=4, dic=SteeringMode_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.126: Weight
#------------------------------------------------------------------------------#

# IE Type: 173
class Weight(Uint8):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.127: Priority
#------------------------------------------------------------------------------#

Priority_dict = {
    0 : 'Active',
    1 : 'Standby',
    2 : 'No Standby',
    3 : 'High',
    4 : 'Low',
    }


# IE Type: 174
class Priority(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Val', bl=4, dic=Priority_dict),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.128: UE IP address Pool Identity
#------------------------------------------------------------------------------#

# IE Type: 177
class UEIPAddressPoolIdentity(Envelope):
    _GEN = (
        Uint16('Len'),
        Buf('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.129: Alternative SMF IP Address
#------------------------------------------------------------------------------#

# IE Type: 178
class AlternativeSMFIPAddress(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('V4', bl=1),
        Uint('V6', bl=1),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.130: Packet Replication and Detection Carry-On Information
#------------------------------------------------------------------------------#

# IE Type: 179
class PacketReplicationandDetectionCarryOnInformation(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('DCARONI', bl=1),
        Uint('PRIN6I', bl=1),
        Uint('PRIN19I', bl=1),
        Uint('PRIUEAI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.131: SMF Set ID
#------------------------------------------------------------------------------#

# IE Type: 180
class SMFSetID(Envelope):
    _GEN = (
        Uint8('spare'),
        _FQDN('FQDN'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.132: Quota Validity Time
#------------------------------------------------------------------------------#

# IE Type: 181
class QuotaValidityTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.133: Number of Reports
#------------------------------------------------------------------------------#

# IE Type: 182
class NumberofReports(Uint16):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.134: PFCPASRsp-Flags
#------------------------------------------------------------------------------#

# IE Type: 184
class PFCPASRspFlags(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('UUPSI', bl=1),
        Uint('PSREI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.135: CP PFCP Entity IP Address
#------------------------------------------------------------------------------#

# IE Type: 185
class CPPFCPEntityIPAddress(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('V4', bl=1),
        Uint('V6', bl=1),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.136: PFCPSEReq-Flags
#------------------------------------------------------------------------------#

# IE Type: 186
class PFCPSEReqFlags(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('RESTI', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.137: IP Multicast Address
#------------------------------------------------------------------------------#

# IE Type: 191
class IPMulticastAddress(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('A', bl=1),
        Uint('R', bl=1),
        Uint('V4', bl=1),
        Uint('V6', bl=1),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Buf('IPv4AddrEnd', bl=32, rep=REPR_HEX),
        Buf('IPv6AddrEnd', bl=128, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda:
            False if not self['A'].get_val() and self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda:
            False if not self['A'].get_val() and self['V6'].get_val() else True)
        self['IPv4AddrEnd'].set_transauto(lambda:
            False if not self['A'].get_val() and self['R'].get_val() and self['V4'].get_val() else True)
        self['IPv6AddrEnd'].set_transauto(lambda:
            False if not self['A'].get_val() and self['R'].get_val() and self['V6'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.138: Source IP Address
#------------------------------------------------------------------------------#

# IE Type: 192
class SourceIPAddress(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('MPL', bl=1),
        Uint('V4', bl=1),
        Uint('V6', bl=1),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Uint8('MaskPrefLen'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.139: Packet Rate Status
#------------------------------------------------------------------------------#

# IE Type: 193
class PacketRateStatus(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('APR', bl=1),
        Uint('DL', bl=1),
        Uint('UL', bl=1),
        Uint16('NumRemainUplinkPacketsAllowed'),
        Uint16('NumRemainAddUplinkPacketsAllowed'),
        Uint16('NumRemainDownlinkPacketsAllowed'),
        Uint16('NumRemainAddDownlinkPacketsAllowed'),
        Uint64('RateCtrlStatusValidityTime'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumRemainUplinkPacketsAllowed'].set_transauto(lambda:
            False if self['UL'].get_val() else True)
        self['NumRemainAddUplinkPacketsAllowed'].set_transauto(lambda:
            False if self['UL'].get_val() and self['APR'].get_val() else True)
        self['NumRemainDownlinkPacketsAllowed'].set_transauto(lambda:
            False if self['DL'].get_val() else True)
        self['NumRemainAddDownlinkPacketsAllowed'].set_transauto(lambda:
            False if self['DL'].get_val() and self['APR'].get_val() else True)
        self['RateCtrlStatusValidityTime'].set_transauto(lambda:
            False if self['UL'].get_val() or self['DL'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.140: Create Bridge Info for TSC IE
#------------------------------------------------------------------------------#

# IE Type: 194
class CreateBridgeInfoforTSC(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('BII', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.141: DS-TT Port Number
#------------------------------------------------------------------------------#

# IE Type: 196
class DSTTPortNumber(Uint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.142: NW-TT Port Number
#------------------------------------------------------------------------------#

# IE Type: 197
class NWTTPortNumber(Uint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.143: TSN Bridge ID
#------------------------------------------------------------------------------#

# IE Type: 198
class TSNBridgeID(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('BID', val=1, bl=1),
        Uint64('BridgeID'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['BridgeID'].set_transauto(lambda: False if self['BID'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.144: Port Management Information Container
#------------------------------------------------------------------------------#

# IE Type: 202
class PortManagementInformationContainer(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.145: Requested Clock Drift Information
#------------------------------------------------------------------------------#

# IE Type: 204
class RequestedClockDriftInformation(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('RRCR', bl=1),
        Uint('RRTO', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.146: TSN Time Domain Number
#------------------------------------------------------------------------------#

# IE Type: 206
class TSNTimeDomainNumber(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.147: Time Offset Threshold
#------------------------------------------------------------------------------#

# IE Type: 207
class TimeOffsetThreshold(Envelope):
    _GEN = (
        Int64('Val', desc='nanoseconds'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.148: Cumulative rateRatio Threshold
#------------------------------------------------------------------------------#

# IE Type: 208
class  CumulativeRateRatioThreshold(Envelope):
    _GEN = (
        Int32('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.149: Time Offset Measurement
#------------------------------------------------------------------------------#

# IE Type: 209
class TimeOffsetMeasurement(Envelope):
    _GEN = (
        Int64('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.150: Cumulative rateRatio Measurement
#------------------------------------------------------------------------------#

# IE Type: 210
class CumulativeRateRatioMeasurement(Envelope):
    _GEN = (
        Int32('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.151: SRR ID
#------------------------------------------------------------------------------#

# IE Type: 215
class SRRID(Envelope):
    _GEN = (
        Uint8('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.152: Requested Access Availability Information
#------------------------------------------------------------------------------#

# IE Type: 217
class RequestedAccessAvailabilityInformation(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('RRCA', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.153: Access Availability Information
#------------------------------------------------------------------------------#

# IE Type: 219
class AccessAvailabilityInformation(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('AvailabilityStatus', bl=2, dic={0: 'Access unavailable', 1: 'Access available'}),
        Uint('AccessType', bl=2, dic={0: '3GPP access type', 1: 'Non-3GPP access type'}),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.154: MPTCP Control Information
#------------------------------------------------------------------------------#

# IE Type: 222
class MPTCPControlInformation(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('TCI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.155: ATSSS-LL Control Information
#------------------------------------------------------------------------------#

# IE Type: 223
class ATSSSLLControlInformation(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('LLI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.156: PMF Control Information
#------------------------------------------------------------------------------#

# IE Type: 224
class PMFControlInformation(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('DRTTI', bl=1),
        Uint('PMFI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.157: MPTCP Address Information
#------------------------------------------------------------------------------#

# IE Type: 228
class MPTCPAddressInformation(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('V4', bl=1),
        Uint('V6', bl=1),
        Uint8('ProxyType'),
        Uint16('ProxyPort'),
        Buf('ProxyIPv4Addr', bl=32, rep=REPR_HEX),
        Buf('ProxyIPv6Addr', bl=128, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['ProxyIPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['ProxyIPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.158: UE Link-Specific IP Address
#------------------------------------------------------------------------------#

# IE Type: 229
class UELinkSpecificIPAddress(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NV6', bl=1),
        Uint('NV4', bl=1),
        Uint('V6', bl=1),
        Uint('V4', bl=1),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Buf('IPv4AddrNon3GPP', bl=32, rep=REPR_HEX),
        Buf('IPv6AddrNon3GPP', bl=128, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)
        self['IPv4AddrNon3GPP'].set_transauto(lambda: False if self['NV4'].get_val() else True)
        self['IPv6AddrNon3GPP'].set_transauto(lambda: False if self['NV6'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.159: PMF Address Information
#------------------------------------------------------------------------------#

# IE Type: 230
class PMFAddressInformation(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('MAC', bl=1),
        Uint('V6', bl=1),
        Uint('V4', bl=1),
        Buf('IPv4Addr', bl=32, rep=REPR_HEX),
        Buf('IPv6Addr', bl=128, rep=REPR_HEX),
        Uint16('Port3GPP'),
        Uint16('PortNon3GPP'),
        Buf('MAC3GPP', bl=48, rep=REPR_HEX),
        Buf('MACNon3GPP', bl=48, rep=REPR_HEX),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4Addr'].set_transauto(lambda: False if self['V4'].get_val() else True)
        self['IPv6Addr'].set_transauto(lambda: False if self['V6'].get_val() else True)
        self['Port3GPP'].set_transauto(lambda: False if (self['V4'].get_val() or self['V6'].get_val()) else True)
        self['PortNon3GPP'].set_transauto(lambda: False if (self['V4'].get_val() or self['V6'].get_val()) else True)
        self['MAC3GPP'].set_transauto(lambda: False if self['MAC'].get_val() else True)
        self['MACNon3GPP'].set_transauto(lambda: False if self['MAC'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.160: ATSSS-LL Information
#------------------------------------------------------------------------------#

# IE Type: 231
class ATSSSLLInformation(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('LLI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.161: Data Network Access Identifier
#------------------------------------------------------------------------------#

# IE Type: 232
class DataNetworkAccessIdentifier(Buf):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.162: Average Packet Delay
#------------------------------------------------------------------------------#

# IE Type: 234
class AveragePacketDelay(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.163: Minimum Packet Delay
#------------------------------------------------------------------------------#

# IE Type: 235
class MinimumPacketDelay(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.164: Maximum Packet Delay
#------------------------------------------------------------------------------#

# IE Type: 236
class MaximumPacketDelay(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.165: QoS Report Trigger
#------------------------------------------------------------------------------#

# IE Type: 237
class QoSReportTrigger(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('IRE', bl=1),
        Uint('THR', bl=1),
        Uint('PER', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.166: GTP-U Path Interface Type
#------------------------------------------------------------------------------#

# IE Type: 241
class GTPUPathInterfaceType(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('N3', bl=1),
        Uint('N9', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.167: Requested Qos Monitoring
#------------------------------------------------------------------------------#

# IE Type: 243
class RequestedQoSMonitoring(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('GTPUPM', bl=1),
        Uint('RP', bl=1),
        Uint('UL', bl=1),
        Uint('DL', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.168: Reporting Frequency
#------------------------------------------------------------------------------#

# IE Type: 244
class ReportingFrequency(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('SESRL', bl=1),
        Uint('PERIO', bl=1),
        Uint('EVETT', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.169: Packet Delay Thresholds
#------------------------------------------------------------------------------#

# IE Type: 245
class PacketDelayThresholds(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('RP', bl=1),
        Uint('UL', bl=1),
        Uint('DL', bl=1),
        Uint32('DownlinkPacketDelayThreshold'),
        Uint32('UplinkPacketDelayThreshold'),
        Uint32('RoundTripPacketDelayThreshold'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['DownlinkPacketDelayThreshold'].set_transauto(lambda: False if self['DL'].get_val() else True)
        self['UplinkPacketDelayThreshold'].set_transauto(lambda: False if self['UL'].get_val() else True)
        self['RoundTripPacketDelayThreshold'].set_transauto(lambda: False if self['RP'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.170: Minimum Wait Time
#------------------------------------------------------------------------------#

# IE Type: 246
class MinimumWaitTime(_IEExtUint32):
    pass


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.171: QoS Monitoring Measurement
#------------------------------------------------------------------------------#

# IE Type: 248
class QoSMonitoringMeasurement(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('PLMF', bl=1),
        Uint('RP', bl=1),
        Uint('UL', bl=1),
        Uint('DL', bl=1),
        Uint32('DownlinkPacketDelay'),
        Uint32('UplinkPacketDelay'),
        Uint32('RoundTripPacketDelay'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['DownlinkPacketDelay'].set_transauto(lambda: False if self['DL'].get_val() else True)
        self['UplinkPacketDelay'].set_transauto(lambda: False if self['UL'].get_val() else True)
        self['RoundTripPacketDelay'].set_transauto(lambda: False if self['RP'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.172: MT-EDT Control Information
#------------------------------------------------------------------------------#

# IE Type: 249
class MTEDTControlInformation(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('RDSI', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.173: DL Data Packets Size
#------------------------------------------------------------------------------#

# IE Type: 250
class DLDataPacketsSize(Envelope):
    _GEN = (
        Uint16('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.174: QER Control Indications
#------------------------------------------------------------------------------#

# IE Type: 251
class QERControlIndications(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('RCSR', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.175: NF Instance ID
#------------------------------------------------------------------------------#

# IE Type: 253
class NFInstanceID(Buf):
    _bl = 128


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.176: S-NSSAI
#------------------------------------------------------------------------------#

# IE Type: 257
class SNSSAI(Envelope):
    _GEN = (
        Uint8('SST'),
        Uint24('SD')
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.177: IP version
#------------------------------------------------------------------------------#

# IE Type: 258
class IPversion(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('V6', bl=1),
        Uint('V4', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.178: PFCPASReq-Flags
#------------------------------------------------------------------------------#

# IE Type: 259
class PFCPASReqFlags(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('UUPSI', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
        

#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.179: Data Status
#------------------------------------------------------------------------------#

# IE Type: 260
class DataStatus(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('BUFF', bl=1),
        Uint('DROP', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.180: RDS Configuration Information
#------------------------------------------------------------------------------#

# IE Type: 262
class RDSConfigurationInformation(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('RDS', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.181: MPTCP Applicable Indication
#------------------------------------------------------------------------------#

# IE Type: 265
class MPTCPApplicableIndication(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('MAI', val=1, bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.182: Bridge Management Information Container
#------------------------------------------------------------------------------#

# IE Type: 266
class BridgeManagementInformationContainer(Buf):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.183: Number of UE IP Addresses
#------------------------------------------------------------------------------#

# IE Type: 268
class NumberofUEIPAddresses(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('IPv6', bl=1),
        Uint('IPv4', bl=1),
        Uint32('NumOfUEIPv4Addrs'),
        Uint32('NumOfUEIPv6Addrs'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumOfUEIPv4Addrs'].set_transauto(lambda: False if self['IPv4'].get_val() else True)
        self['NumOfUEIPv6Addrs'].set_transauto(lambda: False if self['IPv6'].get_val() else True)


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.184: Validity Timer
#------------------------------------------------------------------------------#

# IE Type: 269
class ValidityTimer(Envelope):
    _GEN = (
        Uint16('Val'),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.185: Offending IE Information
#------------------------------------------------------------------------------#

# IE Type: 274
class OffendingIEInformation(Envelope):
    _GEN = (
        Uint16('Type'),
        Buf('Val', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# TS 29.244, section 8.2.186: RAT Type
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
    10 : 'NR',
    }

# IE Type: 275
class RATType(Envelope):
    _GEN = (
        Uint8('Val', dic=RATType_dict),
        Buf('Val', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# The Grand PFCP IE Lookup Table
#------------------------------------------------------------------------------#

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
    19 : Cause,
    20 : SourceInterface,
    21 : FTEID,
    22 : NetworkInstance,
    23 : SDFFilter,
    24 : ApplicationID,
    25 : GateStatus,
    26 : MBR,
    27 : GBR,
    28 : QERCorrelationID,
    29 : Precedence,
    30 : TransportLevelMarking,
    31 : VolumeThreshold,
    32 : TimeThreshold,
    33 : MonitoringTime,
    34 : SubsequentVolumeThreshold,
    35 : SubsequentTimeThreshold,
    36 : InactivityDetectionTime,
    37 : ReportingTriggers,
    38 : RedirectInformation,
    39 : ReportType,
    40 : OffendingIE,
    41 : ForwardingPolicy,
    42 : DestinationInterface,
    43 : UPFunctionFeatures,
    44 : ApplyAction,
    45 : DownlinkDataServiceInformation,
    46 : DownlinkDataNotificationDelay,
    47 : DLBufferingDuration,
    48 : DLBufferingSuggestedPacketCount,
    49 : PFCPSMReqFlags,
    50 : PFCPSRRspFlags,
    51 : LoadControlInformation,
    52 : SequenceNumber,
    53 : Metric,
    54 : OverloadControlInformation,
    55 : Timer,
    56 : PDRID,
    57 : FSEID,
    58 : ApplicationIDsPFDs,
    59 : PFDContext,
    60 : NodeID,
    61 : PFDContents,
    62 : MeasurementMethod,
    63 : UsageReportTrigger,
    64 : MeasurementPeriod,
    65 : FQCSID,
    66 : VolumeMeasurement,
    67 : DurationMeasurement,
    68 : ApplicationDetectionInformation,
    69 : TimeofFirstPacket,
    70 : TimeofLastPacket,
    71 : QuotaHoldingTime,
    72 : DroppedDLTrafficThreshold,
    73 : VolumeQuota,
    74 : TimeQuota,
    75 : StartTime,
    76 : EndTime,
    77 : QueryURR,
    78 : UsageReportSessionModificationResponse,
    79 : UsageReportSessionDeletionResponse,
    80 : UsageReportSessionReportRequest,
    81 : URRID,
    82 : LinkedURRID,
    83 : DownlinkDataReport,
    84 : OuterHeaderCreation,
    85 : CreateBAR,
    86 : UpdateBARSessionModificationRequest,
    87 : RemoveBAR,
    88 : BARID,
    89 : CPFunctionFeatures,
    90 : UsageInformation,
    91 : ApplicationInstanceID,
    92 : FlowInformation,
    93 : UEIPAddress,
    94 : PacketRate,
    95 : OuterHeaderRemoval,
    96 : RecoveryTimeStamp,
    97 : DLFlowLevelMarking,
    98 : HeaderEnrichment,
    99 : ErrorIndicationReport,
    100 : MeasurementInformation,
    101 : NodeReportType,
    102 : UserPlanePathFailureReport,
    103 : RemoteGTPUPeer,
    104 : URSEQN,
    105 : UpdateDuplicatingParameters,
    106 : ActivatePredefinedRules,
    107 : DeactivatePredefinedRules,
    108 : FARID,
    109 : QERID,
    110 : OCIFlags,
    111 : AssociationReleaseRequest,
    112 : GracefulReleasePeriod,
    113 : PDNType,
    114 : FailedRuleID,
    115 : TimeQuotaMechanism,
    117 : UserPlaneInactivityTimer,
    118 : AggregatedURRs,
    119 : Multiplier,
    120 : AggregatedURRID,
    121 : SubsequentVolumeQuota,
    122 : SubsequentTimeQuota,
    123 : RQI,
    124 : QFI,
    125 : QueryURRReference,
    126 : AdditionalUsageReportsInformation,
    127 : CreateTrafficEndpoint,
    128 : CreatedTrafficEndpoint,
    129 : UpdateTrafficEndpoint,
    130 : RemoveTrafficEndpoint,
    131 : TrafficEndpointID,
    132 : EthernetPacketFilter,
    133 : MACAddress,
    134 : CTAG,
    135 : STAG,
    136 : Ethertype,
    137 : Proxying,
    138 : EthernetFilterID,
    139 : EthernetFilterProperties,
    140 : SuggestedBufferingPacketsCount,
    141 : UserID,
    142 : EthernetPDUSessionInformation,
    143 : EthernetTrafficInformation,
    144 : MACAddressesDetected,
    145 : MACAddressesRemoved,
    146 : EthernetInactivityTimer,
    147 : AdditionalMonitoringTime,
    148 : EventQuota,
    149 : EventThreshold,
    150 : SubsequentEventQuota,
    151 : SubsequentEventThreshold,
    152 : TraceInformation,
    153 : FramedRoute,
    154 : FramedRouting,
    155 : FramedIPv6Route,
    156 : TimeStamp,
    157 : AveragingWindow,
    158 : PagingPolicyIndicator,
    159 : APNDNN,
    160 : TGPPInterfaceType,
    161 : PFCPSRReqFlags,
    162 : PFCPAUReqFlags,
    163 : ActivationTime,
    164 : DeactivationTime,
    165 : CreateMAR,
    166 : TGPPAccessForwardingActionInformation,
    167 : Non3GPPAccessForwardingActionInformation,
    168 : RemoveMAR,
    169 : UpdateMAR,
    170 : MARID,
    171 : SteeringFunctionality,
    172 : SteeringMode,
    173 : Weight,
    174 : Priority,
    175 : Update3GPPAccessForwardingActionInformation,
    176 : UpdateNon3GPPAccessForwardingActionInformation,
    177 : UEIPAddressPoolIdentity,
    178 : AlternativeSMFIPAddress,
    179 : PacketReplicationandDetectionCarryOnInformation,
    180 : SMFSetID,
    181 : QuotaValidityTime,
    182 : NumberofReports,
    183 : SessionRetentionInformation,
    184 : PFCPASRspFlags,
    185 : CPPFCPEntityIPAddress,
    186 : PFCPSEReqFlags,
    187 : UserPlanePathRecoveryReport,
    188 : IPMulticastAddressingInfo,
    189 : JoinIPMulticastInformation,
    190 : LeaveIPMulticastInformation,
    191 : IPMulticastAddress,
    192 : SourceIPAddress,
    193 : PacketRateStatus,
    194 : CreateBridgeInfoforTSC,
    195 : CreatedBridgeInfoforTSC,
    196 : DSTTPortNumber,
    197 : NWTTPortNumber,
    198 : TSNBridgeID,
    199 : TSCManagementInformationSessionModificationRequest,
    200 : TSCManagementInformationSessionModificationResponse,
    201 : TSCManagementInformationSessionReportRequest,
    202 : PortManagementInformationContainer,
    203 : ClockDriftControlInformation,
    204 : RequestedClockDriftInformation,
    205 : ClockDriftReport,
    206 : TSNTimeDomainNumber,
    207 : TimeOffsetThreshold,
    208 : CumulativeRateRatioThreshold,
    209 : TimeOffsetMeasurement,
    210 : CumulativeRateRatioMeasurement,
    211 : RemoveSRR,
    212 : CreateSRR,
    213 : UpdateSRR,
    214 : SessionReport,
    215 : SRRID,
    216 : AccessAvailabilityControlInformation,
    217 : RequestedAccessAvailabilityInformation,
    218 : AccessAvailabilityReport,
    219 : AccessAvailabilityInformation,
    220 : ProvideATSSSControlInformation,
    221 : ATSSSControlParameters,
    222 : MPTCPControlInformation,
    223 : ATSSSLLControlInformation,
    224 : PMFControlInformation,
    225 : MPTCPParameters,
    226 : ATSSSLLParameters,
    227 : PMFParameters,
    228 : MPTCPAddressInformation,
    229 : UELinkSpecificIPAddress,
    230 : PMFAddressInformation,
    231 : ATSSSLLInformation,
    232 : DataNetworkAccessIdentifier,
    233 : UEIPAddressPoolInformation,
    234 : AveragePacketDelay,
    235 : MinimumPacketDelay,
    236 : MaximumPacketDelay,
    237 : QoSReportTrigger,
    238 : GTPUPathQoSControlInformation,
    239 : GTPUPathQoSReport,
    240 : QoSInformation,
    241 : GTPUPathInterfaceType,
    242 : QoSMonitoringperQoSflowControlInformation,
    243 : RequestedQoSMonitoring,
    244 : ReportingFrequency,
    245 : PacketDelayThresholds,
    246 : MinimumWaitTime,
    247 : QoSMonitoringReport,
    248 : QoSMonitoringMeasurement,
    249 : MTEDTControlInformation,
    250 : DLDataPacketsSize,
    251 : QERControlIndications,
    252 : PacketRateStatusReport,
    253 : NFInstanceID,
    254 : EthernetContextInformation,
    255 : RedundantTransmissionDetectionParameters,
    256 : UpdatedPDR,
    257 : SNSSAI,
    258 : IPversion,
    259 : PFCPASReqFlags,
    260 : DataStatus,
    261 : ProvideRDSConfigurationInformation,
    262 : RDSConfigurationInformation,
    263 : QueryPacketRateStatus,
    264 : PacketRateStatusReportSessionModificationResponse,
    265 : MPTCPApplicableIndication,
    266 : BridgeManagementInformationContainer,
    267 : UEIPAddressUsageInformation,
    268 : NumberofUEIPAddresses,
    269 : ValidityTimer,
    270 : RedundantTransmissionForwardingParameters,
    271 : TransportDelayReporting,
    272 : PartialFailureInformationSessionEstablishmentResponse,
    273 : PartialFailureInformationSessionModificationResponse,
    274 : OffendingIEInformation,
    275 : RATType
    }


def _chk_ies():
    for ie in PFCPIEType: 
        if ie.value not in PFCPIELUT: 
            print('missing IE in LUT: %s %i' % (ie.name, ie.value)) 
        else:
            if PFCPIELUT[ie.value].__name__ != ie.name: 
                print('mismatching IE name: %i, %s - %s' % (ie.value, ie.name, PFCPIELUT[ie.value].__name__)) 


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

# PFCP Request / Response (success, error)
PFCPReqResp = {
    1 : (2, ),
    3 : (4, ),
    5 : (6, 11),
    7 : (8, ),
    9 : (10, ),
    12 : (13, ),
    14 : (15, ),
    50 : (51, ),
    52 : (53, ),
    54 : (55, ),
    56 : (57, ),
    }


#------------------------------------------------------------------------------#
# TS 29.244, section 7.2: Message Format
#------------------------------------------------------------------------------#

class PFCPHdr(Envelope):
    """PFCP Header
    """
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
        self['Len'].set_valauto(lambda: self.get_payload().get_len() + (12 if self['S'].get_val() else 4))
        self['SEID'].set_transauto(lambda: self['S'].get_val() == 0)


# PFCP Node Related Msg: S = 0
# PFCP Session Related Msg: S = 1


class PFCPMsg(Envelope):
    """PFCP Message
    """
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
                PFCPIEType.UEIPAddressPoolInformation.value,
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
                PFCPIEType.UEIPAddressPoolInformation.value,
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
                PFCPIEType.AssociationReleaseRequest.value,
                PFCPIEType.GracefulReleasePeriod.value,
                PFCPIEType.PFCPAUReqFlags.value,
                PFCPIEType.AlternativeSMFIPAddress.value,
                PFCPIEType.SMFSetID.value,
                PFCPIEType.ClockDriftControlInformation.value,
                PFCPIEType.UEIPAddressPoolInformation.value,
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

