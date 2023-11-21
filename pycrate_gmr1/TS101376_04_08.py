# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2018-2023. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS101376_04_08.py
# * Created : 2018-12-26
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# ETSI TS 101 376 04-08 GMR-1 NAS protocol
# release V3.4.1
#------------------------------------------------------------------------------#

from pycrate_core.utils         import *
from pycrate_core.elt           import *
from pycrate_core.base          import *
from pycrate_mobile.TS24007     import *
from pycrate_mobile.TS44018_RR  import (
    RRAssignmentComplete,
    RRAssignmentFailure,
    RRChannelModeModify,
    RRChannelModeModifyAck
    )

from .TS101376_04_08_IE         import *

#------------------------------------------------------------------------------#
# TS 101 376 04-08 Message specified with CSN.1
#------------------------------------------------------------------------------#

from pycrate_gmr1_csn1.channel_request_type_3_message_content import channel_request_type_3_message_content
from pycrate_gmr1_csn1.system_information_type_1 import system_information_type_1
from pycrate_gmr1_csn1.system_information_type_2 import system_information_type_2
from pycrate_gmr1_csn1.gbch_information import gbch_information_message
from pycrate_gmr1_csn1.gbch3_ecef_information_message import gbch3_ecef_information_message
from pycrate_gmr1_csn1.gbch3_kc_information_message import gbch3_kc_information_message


#------------------------------------------------------------------------------#
# GMR-1 RR header
# TS 101 376 04-08, section 11.4
#------------------------------------------------------------------------------#

GMR1Type_dict = {
    #
    1  : 'POWER CONTROL PARAMETERS UPDATE',
    2  : 'GUARD TIME VIOLATION',
    4  : 'EXTENDED CHANNEL REQUEST',
    # Channel release messages
    13 : 'CHANNEL RELEASE',
    14 : 'TtT SIGNALLING LINK FAILURE',
    # Miscellaneous messages
    16 : 'CHANNEL MODE MODIFY',
    17 : 'LINK CORRECTION MESSAGE',
    18 : 'RR STATUS',
    19 : 'CLASSMARK ENQUIRY',
    20 : 'POSITION UPDATE REQUEST',
    21 : 'POSITION UPDATE ACCEPT',
    22 : 'CLASSMARK CHANGE',
    23 : 'CHANNEL MODE MODIFY ACKNOWLEDGE',
    # DTRS messages
    25 : 'DTMF TONE GENERATE REQUEST',
    26 : 'DTMF TONE GENERATE ACKNOWLEDGE',
    # Paging messages
    33 : 'PAGING REQUEST TYPE 1',
    34 : 'PAGING REQUEST TYPE 2',
    36 : 'PAGING REQUEST TYPE 3',
    39 : 'PAGING RESPONSE',
    # Channel assignment/handover messages
    41 : 'ASSIGNMENT COMPLETE',
    42 : 'ASSIGNMENT COMMAND 2',
    43 : 'HANDOVER COMMAND',
    44 : 'HANDOVER COMPLETE',
    46 : 'ASSIGNMENT COMMAND 1',
    47 : 'ASSIGNMENT FAILURE',
    # Ciphering messages
    50 : 'CIPHERING MODE COMPLETE',
    53 : 'CIPHERING MODE COMMAND',
    # Channel establishment messages
    57 : 'POSITION VERIFICATION NOTIFY',
    58 : 'IMMEDIATE ASSIGNMENT REJECT TYPE 1',
    59 : 'IMMEDIATE ASSIGNMENT REJECT TYPE 2',
    #59 : 'EXTENDED IMMEDIATE ASSIGNMENT REJECT',
    62 : 'EXTENDED IMMEDIATE ASSIGNMENT',
    63 : 'IMMEDIATE ASSIGNMENT',
    # Status and Diagnostic Messages
    64 : 'INFORMATION REQUEST',
    65 : 'INFORMATION RESPONSE POSITION',
    66 : 'INFORMATION RESPONSE VERSION',
    67 : 'INFORMATION RESPONSE SPOT BEAM SELECTION',
    68 : 'INFORMATION RESPONSE POWER CONTROL',
    69 : 'INFORMATION RESPONSE VENDOR SPECIFIC',
    70 : 'INFORMATION RESPONSE CURRENT BEAM',
    79 : 'INFORMATION RESPONSE ERROR'
    }


class GMR1Header(Envelope):
    _GEN = (
        Uint('SkipInd', bl=4),
        Uint('ProtDisc', val=6, bl=4, dic=ProtDisc_dict),
        Uint('Type', bl=8, dic=GMR1Type_dict),
        )


# masquerage GSM RestOctets
# In GMR-1, default payload bit length is 1 byte more (23 without L2 pseudo length)
class RestOctets(RestOctets):
    _PBL = 184


#------------------------------------------------------------------------------#
# Assignment command 1 (A/Gb mode only)
# TS 101 376 04-08, section 10.1.2.1
#------------------------------------------------------------------------------#

class GMR1AssignmentCmd1(Layer3):
    _GEN = (
        GMR1Header(val={'Type': 46}),
        Type3V('ChannelDesc', val={'V': b'\0\0\0\0'}, bl={'V': 32}),
        Type3TV('TimingOffset', val={'T': 0x7D, 'V': b'\0\0'}, bl={'V': 16}, IE=TimingOffset()),
        Type3TV('FrequencyOffset', val={'T': 0x7F, 'V': b'\0\0'}, bl={'V': 16}, IE=FrequencyOffset()),
        Type3TV('ChannelMode', val={'T': 0x63, 'V': b'\0'}, bl={'V': 8}),
        Type3TV('PowerCtrlParams', val={'T': 0x71, 'V': 5*b'\0'}, bl={'V': 40}),
        Type1TV('CipherModeSetting', val={'T': 0x9, 'V':0}, IE=CipherModeSetting()),
        )


#------------------------------------------------------------------------------#
# Assignment command 2 (A/Gb mode only)
# TS 101 376 04-08, section 10.1.2.2
#------------------------------------------------------------------------------#

class GMR1AssignmentCmd2(Layer3):
    _GEN = (
        GMR1Header(val={'Type': 42}),
        Type3V('ChannelDesc', val={'V': b'\0\0\0\0'}, bl={'V': 32}),
        Type3V('TTCHChannelDesc', val={'V': b'\0\0\0'}, bl={'V': 24}),
        Type3V('MECConfig', val={'V': b'\0'}, bl={'V': 8}),
        Type3V('TtTCommonCipherKey', val={'V': 8*b'\0'}, bl={'V': 64}),
        Type3TV('PowerCtrlParams', val={'T': 0x71, 'V': 5*b'\0'}, bl={'V': 40}),
        Type3TV('TimingOffset', val={'T': 0x7D, 'V': b'\0\0'}, bl={'V': 16}, IE=TimingOffset()),
        Type3TV('FrequencyOffset', val={'T': 0x7F, 'V': b'\0\0'}, bl={'V': 16}, IE=FrequencyOffset()),
        Type3TV('ChannelMode', val={'T': 0x63, 'V': b'\0'}, bl={'V': 8}),
        Type1TV('CipherModeSetting', val={'T': 0x9, 'V':0}, IE=CipherModeSetting()),
        )

#------------------------------------------------------------------------------#
# Assignment complete (A/Gb mode only)
# TS 101 376 04-08, section 10.1.3
#------------------------------------------------------------------------------#

class GMR1AssignmentComplete(RRAssignmentComplete):
    pass


#------------------------------------------------------------------------------#
# Assignment failure (A/Gb mode only)
# TS 101 376 04-08, section 10.1.4
#------------------------------------------------------------------------------#

class GMR1AssignmentFailure(RRAssignmentFailure):
    pass


#------------------------------------------------------------------------------#
# Channel mode modify (A/Gb mode only)
# TS 101 376 04-08, section 10.1.5
#------------------------------------------------------------------------------#

class GMR1ChannelModeModify(RRChannelModeModify):
    pass


#------------------------------------------------------------------------------#
# Channel mode modify acknowledge (A/Gb mode only)
# TS 101 376 04-08, section 10.1.6
#------------------------------------------------------------------------------#

class GMR1ChannelModeModifyAck(RRChannelModeModifyAck):
    pass


#------------------------------------------------------------------------------#
# Channel release (A/Gb mode only)
# TS 101 376 04-08, section 10.1.7
#------------------------------------------------------------------------------#

class GMR1ChannelRelease(Layer3):
    _GEN = (
        GMR1Header(val={'Type': 13}),
        Type3V('RRCause', val={'V': b'\0'}, bl={'V': 8}, IE=RRCause())
        )


#------------------------------------------------------------------------------#
# Channel request
# TS 101 376 04-08 Rel.1, section 10.1.8
#------------------------------------------------------------------------------#

_EstCauseNumPlan_dict = {
    0  : 'Response to Paging - any channel needed',
    1  : 'Response to Paging - SDCCH needed',
    2  : 'Response to Paging - TCH3 needed',
    3  : 'Response to Paging - spare',
    4  : 'Response to Alerting',
    8  : 'Location Update',
    9  : 'IMSI Detach',
    10 : 'Supplementary Services',
    11 : 'Short Message Services',
    12 : 'Position Verification',
    15 : 'Emergency Call',
    16 : 'MO Call - numbering plan unknown',
    17 : 'MO Call - ISDN E.164/E.163',
    18 : 'MO Call - numbering plan not used',
    19 : 'MO Call - X.121',
    20 : 'MO Call - Telex F.69',
    24 : 'MO Call - national numbering plan',
    25 : 'MO Call - private numbering plan',
    31 : 'MO Call - reserved',
    }

_PrecorrInd_dict = {
    0 : 'Reserved',
    1 : '-47 symbols correction',
    2 : '-94 symbols correction',
    3 : '-141 symbols correction',
    4 : '+141 symbols correction',
    5 : '+94 symbols correction',
    6 : '+47 symbols correction',
    7 : 'No precorrection'
    }

_TypeOfNum_dict = {
    0 : 'Unknown',
    1 : 'International number',
    2 : 'National number',
    3 : 'Network-specific number',
    4 : 'Dedicated access short code'
    }    

class GMR1ChannelReq(Envelope):
    _GEN = (
        Uint('RetryCounter', bl=2),
        Uint('EstCauseNumPlan', bl=5, dic=_EstCauseNumPlan_dict),
        Uint('P', bl=1, dic={0:'Normal Call', 1:'Priority Call'}),
        Uint('PrecorrectionInd', bl=3, dic=_PrecorrInd_dict),
        Uint('RandRef', bl=5),
        Uint('MESPowerClass', bl=4),
        Uint('SP-HPLMN-Id', bl=20),
        Uint('PD', bl=2),
        Alt(GEN={
            1 : Buf('CalledPartyNum', bl=51, rep=REPR_HEX),
            0 : Envelope(GEN=(
                Uint('MSCID', bl=6),
                GPSTimestamp(),
                Uint('SVNum', bl=7),
                Uint('spare', bl=22, rep=REPR_HEX)))},
            sel=lambda self: self.get_env()[1].get_val() & 0x10),
        Uint('O', bl=1),
        Uint('R', bl=1),
        Uint('GPSCapInd', bl=1),
        GPSPosition(),
        Uint('TypeOfNum', bl=3, dic=_TypeOfNum_dict)
        )


#------------------------------------------------------------------------------#
# Extended channel request (A/Gb mode only)
# TS 101 376 04-08 Rel.3, section 10.1.8.1
#------------------------------------------------------------------------------#

class GMR1ExtChannelReq(Layer3):
    _GEN = (
        GMR1Header(val={'Type': 4}),
        Type3V('AccessInfo', val={'V': 5*b'\0'}, bl={'V': 40}),
        Type3V('GPSPosition', val={'V': 5*b'\0'}, bl={'V': 40}, IE=GPSPosition()),
        Type3V('Timestamp', val={'V': b'\0\0'}, bl={'V': 16}, IE=GPSTimestamp()),
        Type4TLV('CalledPartyNumber', val={'T': 0x5E, 'V': b'\x91\x88\x88'}, IE=CalledPartyBCDNumber()),
        Type3TV('SWVersionNumber', val={'T': 0x6D, 'V': b'\0'}, bl={'V': 8})
        )


#------------------------------------------------------------------------------#
# Channel request Type 1 (A/Gb mode only)
# TS 101 376 04-08 Rel.3, section 10.1.8.2
#------------------------------------------------------------------------------#

_EstCause_dict = {
    0  : 'Response to Paging - any channel needed',
    1  : 'Response to Paging - SDCCH needed',
    2  : 'Response to Paging - TCH3 needed',
    3  : 'Response to Paging - spare',
    7  : 'Channel Request Type 2',
    12 : 'Position Verification',
    13 : 'Attach / Routing Area Update',
    14 : 'Packet Data Transfer'
    }

class GMR1ChannelReqType1AC(Envelope):
    _GEN = (
        Uint('RetryCounter', bl=2),
        Uint('EstCause', bl=5, dic=_EstCause_dict),
        Uint('P', bl=1, dic={0:'Normal Call', 1:'Priority Call'}),
        Uint('PrecorrectionInd', bl=3, dic=_PrecorrInd_dict),
        Uint('RandRef', bl=5),
        Uint('GMPRSTermTypeIdMSB', bl=4),
        Uint('SP-HPLMN-Id', bl=20),
        Uint('PD', bl=2),
        Uint('spare', bl=1),
        Uint('RadioPriority', bl=2),
        Uint('GMPRSTermTypeIdLSB', bl=3),
        Uint32('TLLI'),
        Alt(GEN={
            14 : Envelope(GEN=(
                Uint8('NumOfRLCBlocksMSB'),
                Uint('spare', bl=2),
                Uint('PeakThroughput', bl=4),
                Uint('NumOfRLCBlocksLSB', bl=2)
                ))}, # Packet Data Transfer
            DEFAULT=GPSTimestamp(),
            sel=lambda self: self.get_env()[1].get_val()),
        GPSPosition(),
        Uint('spare', bl=1),
        Uint('LLCMode', bl=1),
        Uint('RLCMode', bl=1)
        )


class GMR1ChannelReqType1D(Envelope):
    _GEN = (
        Uint('RetryCounter', bl=2),
        Uint('EstCause', bl=5, dic=_EstCause_dict),
        Uint('P', bl=1, dic={0:'Normal Call', 1:'Priority Call'}),
        Uint('PrecorrectionInd', bl=3, dic=_PrecorrInd_dict),
        Uint('RandRef', bl=5),
        Uint('GMPRSTermTypeIdMSB', bl=4),
        Uint('DLPeakThroughput', bl=4),
        Uint16('reserved', rep=REPR_HEX),
        Uint('PD', bl=2),
        Uint('spare', bl=1),
        Uint('RadioPriority', bl=2),
        Uint('GMPRSTermTypeIdLSB', bl=3),
        Uint32('TLLI'),
        Alt(GEN={
            14 : Envelope(GEN=(
                Uint8('NumOfRLCBlocksMSB'),
                Uint('spare', bl=2),
                Uint('ULPeakThroughput', bl=4),
                Uint('NumOfRLCBlocksLSB', bl=2)
                ))}, # Packet Data Transfer
            DEFAULT=GPSTimestamp(),
            sel=lambda self: self.get_env()[1].get_val()),
        GPSPosition(),
        Uint('spare', bl=6),
        Uint('LLCMode', bl=1),
        Uint('RLCMode', bl=1)
        )


#------------------------------------------------------------------------------#
# Channel request Type 2 (A/Gb mode only)
# TS 101 376 04-08 Rel.3, section 10.1.8.3
#------------------------------------------------------------------------------#

_RequestType_dict = {
    0  : 'Suspend - Answer to Paging - any channel needed',
    1  : 'Suspend - Answer to Paging - SDCCH needed',
    2  : 'Suspend - Answer to Paging - TCH3 needed',
    3  : 'Suspend - Answer to Paging - spare',
    4  : 'Suspend - In Response to Alerting for circuit switched services',
    6  : 'Suspend - MO Call',
    7  : 'Resume',
    8  : 'Suspend - Location Update',
    9  : 'Suspend - IMSI Detach',
    10 : 'Suspend - Supplementary Services',
    11 : 'Suspend - Short Message Services',
    15 : 'Suspend - Emergency Call'
    }

class GMR1ChannelReqType2(Envelope):
    _GEN = (
        Uint('RetryCounter', bl=2),
        Uint('EstCause', val=7, bl=5, dic=_EstCause_dict),
        Uint('P', bl=1, dic={0:'Normal Call', 1:'Priority Call'}),
        Uint('PrecorrectionInd', bl=3, dic=_PrecorrInd_dict),
        Uint('RandRef', bl=5),
        Uint('GMPRSTermTypeIdMSB', bl=4),
        Uint('SP-HPLMN-Id', bl=20),
        Uint('PD', bl=2),
        Uint('MSCID', bl=6),
        Uint32('TLLI'),
        Uint('GMPRSTermTypeIdLSB', bl=3),
        Uint('RequestType', bl=5, dic=_RequestType_dict),
        Uint('SVNum', bl=7),
        Uint('spare', bl=1),
        GPSPosition(),
        Uint('O', bl=1),
        Uint('R', bl=1),
        Uint('GPSCapInd', bl=1),
        )


#------------------------------------------------------------------------------#
# Channel Request Type 3 (Iu mode only)
# TS 101 376 04-08, section 10.1.8.4
#------------------------------------------------------------------------------#

#class GMR1ChannelReqType3(channel_request_type_3_message_content):
#    pass


#------------------------------------------------------------------------------#
# Ciphering mode command (A/Gb mode only)
# TS 101 376 04-08, section 10.1.9
#------------------------------------------------------------------------------#

class GMR1CipherModeCmd(Layer3):
    _GEN = (
        GMR1Header(val={'Type':53}),
        Type1V('CipherResp', val={'V': 0}, IE=CipherResp()),
        Type1V('CipherModeSetting', val={'V': 0}, IE=CipherModeSetting()),
        Type3TV('PositionDisplay', val={'T': 0x75, 'V': 11*b'\0'}, bl={'V': 88}, IE=PositionDisplay())
        )


#------------------------------------------------------------------------------#
# Ciphering mode complete (A/Gb mode only)
# TS 101 376 04-08, section 10.1.10
#------------------------------------------------------------------------------#

class GMR1CipherModeComplete(Layer3):
    _GEN = (
        GMR1Header(val={'Type': 50}),
        Type4TLV('MEId', val={'T': 0x17, 'V': b'\0'}, IE=ID()),
        Type3TV('Timestamp', val={'T': 0x76, 'V': b'\0\0'}, bl={'V': 16}, IE=GPSTimestamp())
        )


#------------------------------------------------------------------------------#
# TODO:
# 10.1.11 Classmark change (A/Gb mode only)
# 10.1.12 Classmark enquiry (A/Gb mode only)
# 10.1.13 Frequency redefinition (A/Gb mode only)
# 10.1.14 Handover access (A/Gb mode only)
# 10.1.15 Handover command (A/Gb mode only)
# 10.1.16 Handover complete (A/Gb mode only)
# 10.1.17 Handover failure (A/Gb mode only)
#------------------------------------------------------------------------------#


#------------------------------------------------------------------------------#
# Immediate assignment (A/Gb mode only)
# TS 101 376 04-08, section 10.1.18.1
#------------------------------------------------------------------------------#

class GMR1ImmediateAssignment(Layer3):
    _GEN = (
        L2PseudoLength(),
        GMR1Header(val={'Type': 63}),
        Type3V('MESInfoFlag', val={'V': b'\0'}, bl={'V': 8}, IE=MESInfoFlag()),
        Type3V('RequestRef1', val={'V': b'\0\0'}, bl={'V': 16}, IE=RequestRef()),
        Type3V('GPSDiscriminator', val={'V': b'\0\0'}, bl={'V': 16}), # IE=prefixed_gps_position_ie),
        Type3V('ChanDesc', val={'V': b'\0\0\0\0'}, bl={'V': 32}, IE=ChanDesc()),
        Type3V('TimingOffset', val={'V': b'\0\0'}, bl={'V': 16}, IE=TimingOffset()),
        Type3V('FrequencyOffset', val={'V': b'\0\0'}, bl={'V': 16}, IE=FrequencyOffset()),
        Type3V('IDLEModePosUpdInfo', val={'V': b'\0\0'}, bl={'V': 16}, IE=PosUpdInfo()),
        Type3V('DediModePosUpdInfo', val={'V': b'\0\0'}, bl={'V': 16}, IE=PosUpdInfo()),
        Type3V('RequestRef2', val={'V': b'\0\0'}, bl={'V': 16}, IE=RequestRef()),
        Type3V('RequestRef3', val={'V': b'\0\0'}, bl={'V': 16}, IE=RequestRef()),
        Type3V('RequestRef4', val={'V': b'\0\0'}, bl={'V': 16}, IE=RequestRef()),
        RestOctets('IARestOctets')
        )
    
    def __init__(self, *args, **kwargs):
        Layer3.__init__(self, *args, **kwargs)
        self[4].set_transauto(lambda: False if self[2][0][6].get_val() != 2 else True)
        self[5].set_transauto(lambda: False if self[2][0][6].get_val() != 3 else True)
        self[6].set_transauto(lambda: False if self[2][0][6].get_val() != 3 else True)
        self[7].set_transauto(lambda: False if self[2][0][6].get_val() != 3 else True)
        self[8].set_transauto(lambda: False if self[2][0][5].get_val() else True)
        self[9].set_transauto(lambda: False if self[2][0][4].get_val() else True)
        self[10].set_transauto(lambda: False if self[2][0][3].get_val() else True)
        self[11].set_transauto(lambda: False if self[2][0][2].get_val() else True)
        self[12].set_transauto(lambda: False if self[2][0][1].get_val() else True)


#------------------------------------------------------------------------------#
# TODO:
# 10.1.18.2 Extended immediate assignment (A/Gb mode only)
# 10.1.18.3 Immediate assignment Type 2 (A/Gb mode only)
# 10.1.18.4 Immediate Assignment Type 3 (A/Gb mode only)
# 10.1.18.5 Immediate Assignment Type 4 (Iu mode only)
# 10.1.18.6 Immediate Assignment Type 5 (Iu mode only)
# 10.1.19 Immediate assignment extended (A/Gb mode only)
# 10.1.20.1 Immediate assignment reject type 1
# 10.1.20.2 Immediate assignment reject type 2
# 10.1.20.3 Extended immediate assignment reject (A/Gb mode only)
# 10.1.20.4 Position verification notify (A/Gb mode only)
# 10.1.20.4a Position verification notify Type 2 (Iu mode only)
# 10.1.20.5 Immediate Assignment Reject Type 3
# 10.1.20.6 Immediate Assignment Reject Type 4 (Iu mode only)
# 10.1.21 Measurement report (A/Gb mode only)
#------------------------------------------------------------------------------#


#------------------------------------------------------------------------------#
# Paging request type 1
# TS 101 376 04-08, section 10.1.22
#------------------------------------------------------------------------------#

class GMR1PagingReq1(Layer3):
    _GEN = (
        L2PseudoLength(),
        GMR1Header(val={'Type': 33}),
        Type1V('spare', val={'V': 0}),
        Type1V('PageMode', val={'V': 0}, dic=PageMode_dict),
        Type4LV('ID1', val={'V': b'\0'}, IE=ID()),
        Type4LV('ID2', val={'V': b'\0'}, IE=ID()),
        Type3V('PagingInfo1', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        Type3V('PagingInfo2', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        RestOctets('P1RestOctets')
        )


#------------------------------------------------------------------------------#
# Paging request type 2
# TS 44.018, section 10.1.23
#------------------------------------------------------------------------------#

class GMR1PagingReq2(Layer3):
    _GEN = (
        L2PseudoLength(),
        GMR1Header(val={'Type': 34}),
        Type1V('TMSIAvailMask', val={'V': 0}),
        Type1V('PageMode', val={'V': 0}, dic=PageMode_dict),
        Alt(GEN={
            1 : Type3V('ID1', val={'V': 4*b'\0'}, bl={'V': 32}, IE=TMSI()),
            0 : Type3V('GPSAlmanacData1', val={'V': 5*b'\0'}, bl={'V': 40}, IE=GPSAlmanacData())},
            sel=lambda self: self.get_env()[2][0].get_val() & 1),
        Alt(GEN={
            1 : Type3V('ID2', val={'V': 4*b'\0'}, bl={'V': 32}, IE=TMSI()),
            0 : Type3V('GPSAlmanacData2', val={'V': 5*b'\0'}, bl={'V': 40}, IE=GPSAlmanacData())},
            sel=lambda self: self.get_env()[2][0].get_val() & 2),
        Type4LV('ID3', val={'V': b'\0'}, IE=ID()),
        Type3V('PagingInfo1', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        Type3V('PagingInfo2', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        Type3V('PagingInfo3', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        RestOctets('P2RestOctets')
        )
    
    def __init__(self, *args, **kwargs):
        Layer3.__init__(self, *args, **kwargs)
        self[7].set_transauto(lambda: not self[2][0].get_val() & 1)
        self[8].set_transauto(lambda: not self[2][0].get_val() & 2)
    


#------------------------------------------------------------------------------#
# Paging request type 3
# TS 44.018, section 10.1.24
#------------------------------------------------------------------------------#

class GMR1PagingReq3(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value': 19}),
        GMR1Header(val={'Type': 36}),
        Type1V('TMSIAvailMask', val={'V': 0}),
        Type1V('PageMode', val={'V': 0}, dic=PageMode_dict),
        Alt(GEN={
            1 : Type3V('ID1', val={'V': 4*b'\0'}, bl={'V': 32}, IE=TMSI()),
            0 : Type3V('GPSAlmanacData1', val={'V': 5*b'\0'}, bl={'V': 40}, IE=GPSAlmanacData())},
            sel=lambda self: self.get_env()[2][0].get_val() & 1),
        Alt(GEN={
            1 : Type3V('ID2', val={'V': 4*b'\0'}, bl={'V': 32}, IE=TMSI()),
            0 : Type3V('GPSAlmanacData2', val={'V': 5*b'\0'}, bl={'V': 40}, IE=GPSAlmanacData())},
            sel=lambda self: self.get_env()[2][0].get_val() & 2),
        Alt(GEN={
            1 : Type3V('ID3', val={'V': 4*b'\0'}, bl={'V': 32}, IE=TMSI()),
            0 : Type3V('GPSAlmanacData3', val={'V': 5*b'\0'}, bl={'V': 40}, IE=GPSAlmanacData())},
            sel=lambda self: self.get_env()[2][0].get_val() & 4),
        Alt(GEN={
            1 : Type3V('ID4', val={'V': 4*b'\0'}, bl={'V': 32}, IE=TMSI()),
            0 : Type3V('GPSAlmanacData4', val={'V': 5*b'\0'}, bl={'V': 40}, IE=GPSAlmanacData())},
            sel=lambda self: self.get_env()[2][0].get_val() & 8),
        Type3V('PagingInfo1', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        Type3V('PagingInfo2', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        Type3V('PagingInfo3', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        Type3V('PagingInfo4', val={'V': b'\0'}, bl={'V': 8}, IE=PagingInfo()),
        )
    
    def __init__(self, *args, **kwargs):
        Layer3.__init__(self, *args, **kwargs)
        self[8].set_transauto(lambda: not self[2][0].get_val() & 1)
        self[9].set_transauto(lambda: not self[2][0].get_val() & 2)
        self[10].set_transauto(lambda: not self[2][0].get_val() & 4)
        self[11].set_transauto(lambda: not self[2][0].get_val() & 8)


#------------------------------------------------------------------------------#
# TODO:
# 10.1.25 Paging response (A/Gb mode only)
# 10.1.26 Partial release (A/Gb mode only)
# 10.1.27 Partial release complete (A/Gb mode only)
# 10.1.28 Physical information (A/Gb mode only)
# 10.1.29 RR status (A/Gb mode only)
# 10.1.30 Synchronization channel information (A/Gb mode only)
# 10.1.33 System information type 2bis (Iu mode only)
# 10.1.43 Alert request
# 10.1.44 Position update request (A/Gb mode only)
# 10.1.45 Position update accept (A/Gb mode only)
# 10.1.47 Guard time violation (A/Gb mode only)
# 10.1.48 Link correction (A/Gb mode only)
# 10.1.49 Power control parameters update (A/Gb mode only)
# 10.1.50 TtT signalling link failure (A/Gb mode only)
# 10.1.51 Information request (A/Gb mode only)
# 10.1.52 Information response version (A/Gb mode only)
# 10.1.53 Information response spot beam selection (A/Gb mode only)
# 10.1.54 Information response current beam (A/Gb mode only)
# 10.1.55 Information response power control (A/Gb mode only)
# 10.1.56 Information response position (A/Gb mode only)
# 10.1.57 Information response vendor specific (A/Gb mode only)
# 10.1.58 Information response error (A/Gb mode only)
# 10.1.59 DTMF tone generate request (A/Gb mode only)
# 10.1.60 DTMF tone generate acknowledge (A/Gb mode only)
# 10.1.61 GMPRS Resume Response (A/Gb mode only)
# 10.1.62 Paging Request Type 4 (Iu mode)
#------------------------------------------------------------------------------#


# List of defined GMR-1 RR message instances (except of CSN.1 defined ones)
_L3MsgInst = [
    GMR1AssignmentCmd1(),
    GMR1AssignmentCmd2(),
    GMR1AssignmentComplete(),
    GMR1AssignmentFailure(),
    GMR1ChannelModeModify(),
    GMR1ChannelModeModifyAck(),
    GMR1ChannelRelease(),
    GMR1ChannelReq(),
    GMR1ExtChannelReq(),
    GMR1ChannelReqType1AC(),
    GMR1ChannelReqType1D(),
    GMR1ChannelReqType2(),
    GMR1CipherModeCmd(),
    GMR1CipherModeComplete(),
    GMR1ImmediateAssignment(),
    GMR1PagingReq1(),
    GMR1PagingReq2(),
    GMR1PagingReq3(),
    ]

