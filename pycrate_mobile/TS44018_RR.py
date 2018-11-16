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
# * File Name : pycrate_mobile/TS44018_RR.py
# * Created : 2017-07-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 44.018 GSM / EDGE RRC protocol
# release 13 (d60)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007    import *
from .TS44018_IE import *
from .TS24008_IE import *


#------------------------------------------------------------------------------#
# RR header
# TS 44.018, section 10.4
#------------------------------------------------------------------------------#

GSMRRType_dict = {
    0:'SYSTEM INFORMATION TYPE 13',
    1:'SYSTEM INFORMATION TYPE 14',
    2:'SYSTEM INFORMATION TYPE 2 bis',
    3:'SYSTEM INFORMATION TYPE 2 ter',
    4:'SYSTEM INFORMATION TYPE 9',
    5:'SYSTEM INFORMATION TYPE 5 bis',
    6:'SYSTEM INFORMATION TYPE 5 ter',
    7:'SYSTEM INFORMATION TYPE 2 quater',
    9:'VGCS UPLINK GRANT',
    10:'PARTIAL RELEASE',
    13:'CHANNEL RELEASE',
    14:'UPLINK RELEASE',
    15:'PARTIAL RELEASE COMPLETE',
    16:'CHANNEL MODE MODIFY',
    17:'TALKER INDICATION',
    18:'RR STATUS',
    19:'CLASSMARK ENQUIRY',
    20:'FREQUENCY REDEFINITION',
    21:'MEASUREMENT REPORT',
    22:'CLASSMARK CHANGE',
    #22:'MBMS ANNOUNCEMENT',
    23:'CHANNEL MODE MODIFY ACKNOWLEDGE',
    24:'SYSTEM INFORMATION TYPE 8',
    25:'SYSTEM INFORMATION TYPE 1',
    26:'SYSTEM INFORMATION TYPE 2',
    27:'SYSTEM INFORMATION TYPE 3',
    28:'SYSTEM INFORMATION TYPE 4',
    29:'SYSTEM INFORMATION TYPE 5',
    30:'SYSTEM INFORMATION TYPE 6',
    31:'SYSTEM INFORMATION TYPE 7',
    32:'NOTIFICATION/NCH',
    33:'PAGING REQUEST TYPE 1',
    34:'PAGING REQUEST TYPE 2',
    36:'PAGING REQUEST TYPE 3',
    38:'NOTIFICATION/RESPONSE',
    39:'PAGING RESPONSE',
    40:'HANDOVER FAILURE',
    41:'ASSIGNMENT COMPLETE',
    42:'UPLINK BUSY',
    43:'HANDOVER COMMAND',
    44:'HANDOVER COMPLETE',
    45:'PHYSICAL INFORMATION',
    46:'ASSIGNMENT COMMAND',
    47:'ASSIGNMENT FAILURE',
    48:'CONFIGURATION CHANGE COMMAND',
    49:'CONFIGURATION CHANGE ACK',
    50:'CIPHERING MODE COMPLETE',
    51:'CONFIGURATION CHANGE REJECT',
    52:'GPRS SUSPENSION REQUEST',
    53:'CIPHERING MODE COMMAND',
    54:'EXTENDED MEASUREMENT REPORT',
    54:'SERVICE INFORMATION',
    55:'EXTENDED MEASUREMENT ORDER',
    56:'APPLICATION INFORMATION',
    57:'IMMEDIATE ASSIGNMENT EXTENDED',
    58:'IMMEDIATE ASSIGNMENT REJECT',
    59:'ADDITIONAL ASSIGNMENT',
    61:'SYSTEM INFORMATION TYPE 16',
    62:'SYSTEM INFORMATION TYPE 17',
    63:'IMMEDIATE ASSIGNMENT',
    64:'SYSTEM INFORMATION TYPE 18',
    65:'SYSTEM INFORMATION TYPE 19',
    66:'SYSTEM INFORMATION TYPE 20',
    67:'SYSTEM INFORMATION TYPE 15',
    68:'SYSTEM INFORMATION TYPE 13 alt',
    69:'SYSTEM INFORMATION TYPE 2 n',
    70:'SYSTEM INFORMATION TYPE 21',
    72:'DTM ASSIGNMENT FAILURE',
    73:'DTM REJECT',
    74:'DTM REQUEST',
    75:'PACKET ASSIGNMENT',
    76:'DTM ASSIGNMENT COMMAND',
    77:'DTM INFORMATION',
    78:'PACKET NOTIFICATION',
    96:'UTRAN CLASSMARK CHANGE',
    98:'CDMA2000 CLASSMARK CHANGE',
    99:'INTER SYSTEM TO UTRAN HANDOVER COMMAND',
    100:'INTER SYSTEM TO CDMA2000 HANDOVER COMMAND',
    101:'GERAN IU MODE CLASSMARK CHANGE',
    102:'INTER SYSTEM TO E-UTRAN HANDOVER COMMAND',
    #102:'PRIORITY UPLINK REQUEST',
    103:'DATA INDICATION',
    104:'DATA INDICATION 2',
    105:'IMMEDIATE PACKET ASSIGNMENT'
    }

class RRHeader(Envelope):
    _GEN = (
        Uint('SkipInd', bl=4),
        Uint('ProtDisc', val=6, bl=4, dic=ProtDisc_dict),
        Uint('Type', bl=8, dic=GSMRRType_dict),
        )

#------------------------------------------------------------------------------#
# ADDITIONAL ASSIGNMENT
# TS 44.018, section 9.1.1
#------------------------------------------------------------------------------#

class RRAdditionalAssign(Layer3):
    _GEN = (
        RRHeader(val={'Type':59}),
        Type3V('ChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type4TLV('MobileAlloc', val={'T':0x72, 'V':b'\0'}, IE=MobileAlloc()),
        Type3TV('StartingTime', val={'T':0x7C, 'V':b'\0\0'}, bl={'V':16}, IE=StartingTime()),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# ASSIGNMENT COMMAND
# TS 44.018, section 9.1.2
#------------------------------------------------------------------------------#

class RRAssignmentCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':46}),
        Type3V('FirstChanDescAfter', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc2()),
        Type3V('PowerCmd', val={'V':b'\0'}, bl={'V':8}, IE=PowerCmd()),
        Type4TLV('FreqListAfter', val={'T':0x5, 'V':b'\0\0'}, IE=FreqList()),
        Type3TV('CellChan', val={'T':0x62, 'V':16*b'\0'}, bl={'V':128}, IE=CellChan()),
        Type4TLV('MultislotAlloc', val={'T':0X10, 'V':b'\0'}, IE=MultislotAlloc()),
        Type3TV('ChanModeSet1', val={'T':0x63, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet2', val={'T':0x11, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet3', val={'T':0x13, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet4', val={'T':0x14, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet5', val={'T':0x15, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet6', val={'T':0x16, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet7', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet8', val={'T':0x18, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('SecondChanDescAfter', val={'T':0x64, 'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type3TV('SecondChanMode', val={'T':0x66, 'V':b'\0'}, bl={'V':8}, IE=ChanMode2()),
        Type4TLV('MobileAllocAfter', val={'T':0x72, 'V':b'\0'}, IE=MobileAlloc()),
        Type3TV('StartingTime', val={'T':0x7C, 'V':b'\0\0'}, bl={'V':16}, IE=StartingTime()),
        Type4TLV('FreqListBefore', val={'T':0x19, 'V':b'\0\0'}, IE=FreqList()),
        Type3V('FirstChanDescBefore', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc2()),
        Type3TV('SecondChanDescAfter', val={'T':0x64, 'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type3TV('FreqChanSeqBefore', val={'T':0x1E, 'V':9*b'\0'}, bl={'V':72}, IE=FreqChanSeq()),
        Type4TLV('MobileAllocBefore', val={'T':0x72, 'V':b'\0'}, IE=MobileAlloc()),
        Type1TV('CipherModeSetting', val={'T':0x9, 'V':0}, IE=CipherModeSetting()),
        Type4TLV('VGCSTargetModeInd', val={'T':0x1, 'V':b'\0'}, IE=VGCSTargetModeInd()),
        Type4TLV('MultirateConfig', val={'T':0x3, 'V':b'\0\0'}, IE=MultirateConfig()),
        Type4TLV('VGCSCipherParams', val={'T':0x4, 'V':b'\0'}, IE=VGCSCipherParams()),
        Type3TV('ExtTSCSetAfter', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet()),
        Type3TV('ExtTSCSetBefore', val={'T':0x6E, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# ASSIGNMENT COMPLETE
# TS 44.018, section 9.1.3
#------------------------------------------------------------------------------#

class RRAssignmentComplete(Layer3):
    _GEN = (
        RRHeader(val={'Type':41}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        )


#------------------------------------------------------------------------------#
# ASSIGNMENT FAILURE
# TS 44.018, section 9.1.4
#------------------------------------------------------------------------------#

class RRAssignmentFailure(Layer3):
    _GEN = (
        RRHeader(val={'Type':47}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause())
        )


#------------------------------------------------------------------------------#
# CHANNEL MODE MODIFY
# TS 44.018, section 9.1.5
#------------------------------------------------------------------------------#

class RRChannelModeModify(Layer3):
    _GEN = (
        RRHeader(val={'Type':16}),
        Type3V('ChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc2()),
        Type3V('ChanMode', val={'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type4TLV('VGCSTargetModeInd', val={'T':0x1, 'V':b'\0'}, IE=VGCSTargetModeInd()),
        Type4TLV('MultirateConfig', val={'T':0x3, 'V':b'\0\0'}, IE=MultirateConfig()),
        Type4TLV('VGCSCipherParams', val={'T':0x4, 'V':b'\0'}, IE=VGCSCipherParams()),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# CHANNEL MODE MODIFY ACKNOWLEDGE
# TS 44.018, section 9.1.6
#------------------------------------------------------------------------------#

class RRChannelModeModifyAck(Layer3):
    _GEN = (
        RRHeader(val={'Type':23}),
        Type3V('ChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc2()),
        Type3V('ChanMode', val={'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# CHANNEL RELEASE
# TS 44.018, section 9.1.7
#------------------------------------------------------------------------------#

class RRChannelRelease(Layer3):
    _GEN = (
        RRHeader(val={'Type':13}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        Type4TLV('BARange', val={'T':0x73, 'V':4*b'\0'}, IE=BARange()),
        Type4TLV('GroupChanDesc', val={'T':0x74, 'V':b'\0\0\0'}, IE=GroupChanDesc()),
        Type1TV('GroupCipherKeyNum', val={'T':0x8, 'V':1}),
        Type1TV('GPRSResumption', val={'T':0xC, 'V':1}, IE=GPRSResumption()),
        Type4TLV('BAListPref', val={'T':0x75, 'V':b'\0'}, IE=ba_list_pref),
        Type4TLV('UTRANFreqList', val={'T':0x76, 'V':b'\0'}, IE=utran_freq_list),
        Type3TV('CellChan', val={'T':0x62, 'V':16*b'\0'}, bl={'V':128}, IE=CellChan()),
        Type4TLV('CellSelInd', val={'T':0x77, 'V':b'\0\0'},
                 IE=cell_selection_indicator_after_release_of_all_tch_and_sdcch_value_part),
        Type1TV('EnhancedDTMCSRelInd', val={'T':0xA, 'V':0}),
        Type4TLV('VGCSCipherParams', val={'T':0x4, 'V':b'\0'}, IE=VGCSCipherParams()),
        Type4TLV('GroupChanDesc2', val={'T':0x78, 'V':11*b'\0'}, IE=GroupChanDesc2()),
        Type4TLV('TalkerId', val={'T':0x79, 'V':b'\0'}, IE=TalkerId()),
        Type4TLV('TalkerPriorityStat', val={'T':0x7A, 'V':b'\0'}, IE=TalkerPriorityStat()),
        Type4TLV('VGCSAMRConfig', val={'T':0x7B, 'V':b'\0'}),
        Type4TLV('IndivPriorities', val={'T':0x7C, 'V':b'\0'}, IE=individual_priorities)
        )


#------------------------------------------------------------------------------#
# CHANNEL REQUEST
# TS 44.018, section 9.1.8
#------------------------------------------------------------------------------#
# this is just 1 byte with an establishment cause and a random reference


#------------------------------------------------------------------------------#
# CIPHERING MODE COMMAND
# TS 44.018, section 9.1.9
#------------------------------------------------------------------------------#

class RRCipheringModeCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':53}),
        Type1V('CipherResp', val={'V':0}, IE=CipherResp()),
        Type1V('CipherModeSetting', val={'V':0}, IE=CipherModeSetting())
        )


#------------------------------------------------------------------------------#
# CIPHERING MODE COMPLETE
# TS 44.018, section 9.1.10
#------------------------------------------------------------------------------#

class RRCipheringModeComplete(Layer3):
    _GEN = (
        RRHeader(val={'Type':50}),
        Type4TLV('MEId', val={'T':0x17, 'V':b'\0'}, IE=ID())
        )


#------------------------------------------------------------------------------#
# CLASSMARK CHANGE
# TS 44.018, section 9.1.11
#------------------------------------------------------------------------------#

class RRClassmarkChange(Layer3):
    _GEN = (
        RRHeader(val={'Type':22}),
        Type4LV('MSCm2', val={'V':b'@\0\0'}, IE=MSCm2()),
        Type4TLV('MSCm3', val={'T':0x20, 'V':b''}, IE=classmark_3_value_part)
        )


#------------------------------------------------------------------------------#
# UTRAN CLASSMARK CHANGE
# TS 44.018, section 9.1.11a
#------------------------------------------------------------------------------#

class RRUTRANClassmarkChange(Layer3):
    _GEN = (
        RRHeader(val={'Type':96}),
        Type4LV('UTRANCm', val={'V':b'\0'}) # INTER RAT HANDOVER INFO from TS 25.331
        )


#------------------------------------------------------------------------------#
# CDMA2000 CLASSMARK CHANGE
# TS 44.018, section 9.1.11b
#------------------------------------------------------------------------------#

class RRCdma2000ClassmarkChange(Layer3):
    _GEN = (
        RRHeader(val={'Type':98}),
        Type4LV('TerminalInfo', val={'V':b''}),
        Type4LV('SecurityStat', val={'V':b''}),
        Type4LV('BandClassInfo', val={'V':b''}),
        Type4LV('PowerClassInfo', val={'V':b''}),
        Type4LV('OperatingModeInfo', val={'V':b''}),
        Type4LV('ServiceOptInfo', val={'V':b''}),
        Type4LV('MultiplexOptInfo', val={'V':b''}),
        Type4LV('PowerCtrlInfo', val={'V':b''}),
        Type4LV('CapInfo', val={'V':b''}),
        Type4LV('ChannelConfigCapInfo', val={'V':b''}),
        Type4LV('ExtMultiplexOptInfo', val={'V':b''}),
        Type4LV('BandSubclassInfo', val={'V':b''}),
        Type4LV('EncryptionCap', val={'V':b''})
        )


#------------------------------------------------------------------------------#
# GERAN IU Mode CLASSMARK CHANGE
# TS 44.018, section 9.1.11d
#------------------------------------------------------------------------------#

class RRUTRANClassmarkChange(Layer3):
    _GEN = (
        RRHeader(val={'Type':101}),
        Type4LV('GERANIuModeCm', val={'V':14*b'\0'}) # MS GERAN IU MODE RADIO ACCESS CAPABILITY from TS 44.118
        )


#------------------------------------------------------------------------------#
# CLASSMARK ENQUIRY
# TS 44.018, section 9.1.12
#------------------------------------------------------------------------------#

class RRClassmarkEnquiry(Layer3):
    _GEN = (
        RRHeader(val={'Type':19}),
        Type4TLV('CmEnquiryMask', val={'T':0x10, 'V':b'\0'}, IE=CmEnquiryMask())
        )


#------------------------------------------------------------------------------#
# CONFIGURATION CHANGE COMMAND
# TS 44.018, section 9.1.12b
#------------------------------------------------------------------------------#

class RRConfigChangeCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':48}),
        Type4LV('MultislotAlloc', val={'V':b'\0'}, IE=MultislotAlloc()),
        Type3TV('ChanModeSet1', val={'T':0x63, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet2', val={'T':0x11, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet3', val={'T':0x13, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet4', val={'T':0x14, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet5', val={'T':0x15, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet6', val={'T':0x16, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet7', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet8', val={'T':0x18, 'V':b'\0'}, bl={'V':8}, IE=ChanMode())
        )


#------------------------------------------------------------------------------#
# CONFIGURATION CHANGE ACK
# TS 44.018, section 9.1.12c
#------------------------------------------------------------------------------#

class RRConfigChangeAck(Layer3):
    _GEN = (
        RRHeader(val={'Type':49})
        )


#------------------------------------------------------------------------------#
# CONFIGURATION CHANGE REJECT
# TS 44.018, section 9.1.12d
#------------------------------------------------------------------------------#

class RRConfigChangeReject(Layer3):
    _GEN = (
        RRHeader(val={'Type':51}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        )


#------------------------------------------------------------------------------#
# DTM ASSIGNMENT COMMAND
# TS 44.018, section 9.1.12e
#------------------------------------------------------------------------------#

class RRDTMAssignmentCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':76}),
        Type3V('CSPowerCmd', val={'V':b'\0'}, bl={'V':8}, IE=PowerCmd()),
        Type3V('CSChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type4LV('GPRSBroadcastInfo', val={'V':6*b'\0'}, IE=gprs_broadcast_information_value_part),
        Type3TV('CellChan', val={'T':0x10, 'V':16*b'\0'}, bl={'V':128}, IE=CellChan()),
        Type3TV('ChanMode', val={'T':0x11, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type4TLV('FreqList', val={'T':0x12, 'V':b'\0\0'}, IE=FreqList()),
        Type4TLV('MobileAlloc', val={'T':0x13, 'V':b'\0'}, IE=MobileAlloc()),
        Type4TLV('PSULAssign', val={'T':0x15, 'V':b'\0'}, IE=rr_packet_uplink_assignment_value_part),
        Type4TLV('PSDLAssign', val={'T':0x16, 'V':b'\0'}, IE=rr_packet_downlink_assignment_value_part),
        Type4TLV('MultirateConfig', val={'T':0x17, 'V':b'\0\0'}, IE=MultirateConfig()),
        Type1TV('CipherModeSetting', val={'T':0x9, 'V':0}, IE=CipherModeSetting()),
        Type4TLV('MobileAllocC2', val={'T':0x18, 'V':b'\0'}, IE=MobileAlloc()),
        Type4TLV('FreqListC2', val={'T':0x19, 'V':b'\0\0'}, IE=FreqList()),
        Type4TLV('PSDLAssignType2', val={'T':0x16, 'V':b'\0'}, IE=rr_packet_downlink_assignment_type_2_value_part),
        Type3TV('ChanDescC2', val={'V':b'\0\0'}, bl={'V':16}, IE=ChanDesc3()),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# DTM ASSIGNMENT FAILURE
# TS 44.018, section 9.1.12f
#------------------------------------------------------------------------------#

class RRDTMAssignmentFailure(Layer3):
    _GEN = (
        RRHeader(val={'Type':72}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        )


#------------------------------------------------------------------------------#
# DTM INFORMATION
# TS 44.018, section 9.1.12g
#------------------------------------------------------------------------------#

class RRDTMInformation(Layer3):
    _GEN = (
        RRHeader(val={'Type':77}),
        Type3V('RAI', val={'V':b'\0\xf1\x10\0\0\0'}, bl={'V':48}, IE=RAI()),
        Type4LV('DTMInfoDetails', val={'V':b'\0\0\0'}, IE=dtm_information_details_value_part)
        )


#------------------------------------------------------------------------------#
# DTM REJECT
# TS 44.018, section 9.1.12h
#------------------------------------------------------------------------------#

class RRDTMReject(Layer3):
    _GEN = (
        RRHeader(val={'Type':73}),
        Type3V('DTMWaitInd', val={'V':b'\0'}, bl={'V':8}, IE=T3142())
        )


#------------------------------------------------------------------------------#
# DTM REQUEST
# TS 44.018, section 9.1.12i
#------------------------------------------------------------------------------#

class RRDTMReq(Layer3):
    _GEN = (
        RRHeader(val={'Type':74}),
        Type3V('TLLI', val={'V':4*b'\0'}, bl={'V':32}, IE=TLLI()),
        Type4LV('ChanReqDesc2', val={'V':4*b'\0'}, IE=channel_request_description_2_value_part)
        )


#------------------------------------------------------------------------------#
# FREQUENCY REDEFINITION
# TS 44.018, section 9.1.13
#------------------------------------------------------------------------------#

class RRFrequencyRedefinition(Layer3):
    _GEN = (
        RRHeader(val={'Type':20}),
        Type3V('ChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type4LV('MobileAlloc', val={'V':b'\0'}, IE=MobileAlloc()),
        Type3V('StartingTime', val={'V':b'\0\0'}, bl={'V':16}, IE=StartingTime()),
        Type3TV('CellChan', val={'T':0x62, 'V':16*b'\0'}, bl={'V':128}, IE=CellChan()),
        Type1TV('CarrierInd', val={'T':0x9, 'V':0}, IE=CarrierInd()),
        Type4TLV('MobileAllocC2', val={'T':0x11, 'V':b'\0'}, IE=MobileAlloc()),
        Type3TV('ChanDescC2', val={'T':0x12, 'V':b'\0\0'}, bl={'V':16}, IE=ChanDesc3()),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# GPRS SUSPENSION REQUEST
# TS 44.018, section 9.1.13b
#------------------------------------------------------------------------------#

class RRGPRSSuspensionReq(Layer3):
    _GEN = (
        RRHeader(val={'Type':52}),
        Type3V('TLLI', val={'V':4*b'\0'}, bl={'V':32}, IE=TLLI()),
        Type3V('RAI', val={'V':b'\0\xf1\x10\0\0\0'}, bl={'V':48}, IE=RAI()),
        Type3V('SuspensionCause', val={'V':b'\0'}, bl={'V':8}, IE=SuspensionCause()),
        Type3TV('ServiceSupport', val={'T':0x1, 'V':b'\0'}, bl={'V':8}, IE=ServiceSupport())
        )


#------------------------------------------------------------------------------#
# HANDOVER ACCESS
# TS 44.018, section 9.1.14
#------------------------------------------------------------------------------#
# this is just 1 byte with a random reference


#------------------------------------------------------------------------------#
# HANDOVER COMMAND
# TS 44.018, section 9.1.15
#------------------------------------------------------------------------------#

class RRHandoverCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':43}),
        Type3V('CellDesc', val={'V':b'\0\0'}, bl={'V':16}, IE=CellDesc()),
        Type3V('FirstChanDescAfter', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc2()),
        Type3V('HandoverRef', val={'V':b'\0'}, bl={'V':8}, IE=HandoverRef()),
        Type3V('PowerCmdAccType', val={'V':b'\0'}, bl={'V':8}, IE=PowerCmdAccType()),
        Type1TV('SynchInd', val={'T':0xD, 'V':0}, IE=SynchInd()),
        Type3TV('FreqShortListAfter', val={'T':0x2, 'V':9*b'\0'}, bl={'V':72}, IE=FreqShortList()),
        Type4TLV('FreqListAfter', val={'T':0x5, 'V':b'\0\0'}, IE=FreqList()),
        Type3TV('CellChan', val={'T':0x62, 'V':16*b'\0'}, bl={'V':128}, IE=CellChan()),
        Type4TLV('MultislotAlloc', val={'T':0X10, 'V':b'\0'}, IE=MultislotAlloc()),
        Type3TV('ChanModeSet1', val={'T':0x63, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet2', val={'T':0x11, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet3', val={'T':0x13, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet4', val={'T':0x14, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet5', val={'T':0x15, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet6', val={'T':0x16, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet7', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('ChanModeSet8', val={'T':0x18, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type3TV('SecondChanDescAfter', val={'T':0x64, 'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type3TV('SecondChanMode', val={'T':0x66, 'V':b'\0'}, bl={'V':8}, IE=ChanMode2()),
        Type3TV('FreqChanSeqAfter', val={'T':0x69, 'V':9*b'\0'}, bl={'V':72}, IE=FreqChanSeq()),
        Type4TLV('MobileAllocAfter', val={'T':0x72, 'V':b'\0'}, IE=MobileAlloc()),
        Type3TV('StartingTime', val={'T':0x7C, 'V':b'\0\0'}, bl={'V':16}, IE=StartingTime()),
        Type4TLV('RealTimeDiff', val={'T':0x7B, 'V':b'\0'}, IE=TimeDiff()),
        Type3TV('TimingAdvance', val={'T':0x7D, 'V':b'\0'}, bl={'V':8}, IE=TimingAdvance()),
        Type3TV('FreqShortListBefore', val={'T':0x12, 'V':9*b'\0'}, bl={'V':72}, IE=FreqShortList()),
        Type4TLV('FreqListBefore', val={'T':0x19, 'V':b'\0\0'}, IE=FreqList()),
        Type3TV('FirstChanDescBefore', val={'T':0x1C, 'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc2()),
        Type3TV('SecondChanDescBefore', val={'T':0x1D, 'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type3TV('FreqChanSeqBefore', val={'T':0x1E, 'V':9*b'\0'}, bl={'V':72}, IE=FreqChanSeq()),
        Type4TLV('MobileAllocBefore', val={'T':0x21, 'V':b'\0'}, IE=MobileAlloc()),
        Type1TV('CipherModeSetting', val={'T':0x9, 'V':0}, IE=CipherModeSetting()),
        Type4TLV('VGCSTargetModeInd', val={'T':0x1, 'V':b'\0'}, IE=VGCSTargetModeInd()),
        Type4TLV('MultirateConfig', val={'T':0x3, 'V':b'\0\0'}, IE=MultirateConfig()),
        Type4TLV('DynARFCNMapping', val={'T':0x76, 'V':4*b'\0'}, IE=dynamic_arfcn_mapping),
        Type4TLV('VGCSCipherParams', val={'T':0x4, 'V':b'\0'}, IE=VGCSCipherParams()),
        Type3TV('DedicatedServiceInfo', val={'T':0x51, 'V':b'\0'}, IE=DedicatedServiceInfo()),
        Type1TV('PLMNIndex', val={'T':0xA, 'V':0}, dic=PLMNIndex_dict),
        Type3TV('ExtTSCSetAfter', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet()),
        Type3TV('ExtTSCSetBefore', val={'T':0x6E, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# INTER SYSTEM TO UTRAN HANDOVER COMMANDd
# TS 44.018, section 9.1.15a
#------------------------------------------------------------------------------#

class RRInterSystemUTRANHOCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':99}),
        Type4LV('HOToUTRANCmd', val={'V':b'\0'}), # see TS 25.331
        Type4TLV('CNToMSTransparentInfo', val={'V':b'\0'}) # see TS 48.008
        )


#------------------------------------------------------------------------------#
# INTER SYSTEM TO CDMA2000 HANDOVER COMMAND
# TS 44.018, section 9.1.15b
#------------------------------------------------------------------------------#

class RRInterSystemCdma200HOCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':100}),
        Type4LV('HOToCdma2000Cmd', val={'V':b'\0\0\0'}) # see TIA/EIA/IS-2000
        )


#------------------------------------------------------------------------------#
# HANDOVER TO GERAN Iu MODE Command
# TS 44.018, section 9.1.15c
#------------------------------------------------------------------------------#
# This message has however no defined type


#------------------------------------------------------------------------------#
# INTER SYSTEM TO E-UTRAN HANDOVER COMMAND
# TS 44.018, section 9.1.15d
#------------------------------------------------------------------------------#

class RRInterSystemEUTRANHOCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':102}),
        Type4LV('DL-DCCH-Message', val={'V':b'\0'}), # see TS 36.331
        Type4TLV('CNToMSTransparentInfo', val={'V':b'\0'}) # see TS 48.008
        )


#------------------------------------------------------------------------------#
# HANDOVER COMPLETE
# TS 44.018, section 9.1.16
#------------------------------------------------------------------------------#

class RRHandoverComplete(Layer3):
    _GEN = (
        RRHeader(val={'Type':44}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        Type4TLV('MobileObservedTimeDiff', val={'V':b'\0\0\0'}, IE=MobileTimeDiff()),
        Type4TLV('MobileObservedTimeDiffHFLevel', val={'V':5*b'\0'}, IE=MobileTimeDiffHFLevel()),
        )


#------------------------------------------------------------------------------#
# HANDOVER FAILURE
# TS 44.018, section 9.1.17
#------------------------------------------------------------------------------#

class RRHandoverFailure(Layer3):
    _GEN = (
        RRHeader(val={'Type':40}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        Type1TV('PSCause', val={'T':0x9, 'V':0}, dic=PSCause_dict),
        )


#------------------------------------------------------------------------------#
# IMMEDIATE ASSIGNMENT
# TS 44.018, section 9.1.18
#------------------------------------------------------------------------------#

def get_tbf(l3msg):
    v = l3msg[2][0].get_val()
    if isinstance(v, str_types):
        if python_version:
            return v[0] & 1
        else:
            return ord(v[0]) & 1
    elif isinstance(v, list):
        return v[-1]
    else:
        return 0


class RRImmediateAssignment(Layer3):
    _GEN = (
        L2PseudoLength(excl=(0, 12)),
        RRHeader(val={'Type':63}),
        Type1V('DedicatedModeOrTBF', val={'V':0}, IE=DedicatedModeOrTBF()),
        Type1V('PageMode', val={'V':0}, dic=PageMode_dict),
        Alt(GEN={
            0: Type3V('ChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
            1: Type3V('PChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=packet_channel_description)},
            sel=lambda self: get_tbf(self.get_env())),
        Type3V('RequestRef', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('TimingAdvance', val={'V':b'\0'}, bl={'V':8}, IE=TimingAdvance()),
        Type4LV('MobileAlloc', val={'V':b'\0'}, IE=MobileAlloc()),
        Type3TV('StartingTime', val={'T':0x7C, 'V':b'\0\0'}, bl={'V':16}, IE=StartingTime()),
        RestOctets('IARestOctets', IE=ia_rest_octets),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# IMMEDIATE PACKET ASSIGNMENT
# TS 44.018, section 9.1.18b
#------------------------------------------------------------------------------#

class RRImmediatePacketAssignment(Layer3):
    _GEN = (
        L2PseudoLength(),
        RRHeader(val={'Type':105}),
        Type1V('FeatureInd', val={'V':0}, IE=FeatureInd()),
        Type1V('PageMode', val={'V':0}, dic=PageMode_dict),
        RestOctets('IPARestOctets', IE=ipa_rest_octets),
        Type3TV('RequestRef1', val={'T':0x5, 'V':b'\0\0\0\0'}, bl={'V':32}, IE=RequestRefAlt()),
        Type3TV('RequestRef2', val={'T':0x6, 'V':b'\0\0\0\0'}, bl={'V':32}, IE=RequestRefAlt()),
        Type3TV('RequestRef3', val={'T':0x7, 'V':b'\0\0\0\0'}, bl={'V':32}, IE=RequestRefAlt()),
        Type3TV('RequestRef4', val={'T':0x8, 'V':b'\0\0\0\0'}, bl={'V':32}, IE=RequestRefAlt()),
        )


#------------------------------------------------------------------------------#
# IMMEDIATE ASSIGNMENT EXTENDED
# TS 44.018, section 9.1.19
#------------------------------------------------------------------------------#

class RRImmediateAssignmentExt(Layer3):
    _GEN = (
        L2PseudoLength(),
        RRHeader(val={'Type':57}),
        Type1V('FeatureInd', val={'V':0}, IE=FeatureInd()),
        Type1V('PageMode', val={'V':0}, dic=PageMode_dict),
        Type3V('ChanDesc1', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type3V('RequestRef1', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('TimingAdvance1', val={'V':b'\0'}, bl={'V':8}, IE=TimingAdvance()),
        Type3V('ChanDesc2', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type3V('RequestRef2', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('TimingAdvance2', val={'V':b'\0'}, bl={'V':8}, IE=TimingAdvance()),
        Type4LV('MobileAlloc', val={'V':b'\0'}, IE=MobileAlloc()),
        Type3TV('StartingTime', val={'T':0x7C, 'V':b'\0\0'}, bl={'V':16}, IE=StartingTime()),
        RestOctets('IAXRestOctets', IE=iax_rest_octets)
        )


#------------------------------------------------------------------------------#
# IMMEDIATE ASSIGNMENT REJECT
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RRImmediateAssignmentReject(Layer3):
    _GEN = (
        L2PseudoLength(),
        RRHeader(val={'Type':58}),
        Type1V('FeatureInd', val={'V':0}, IE=FeatureInd()),
        Type1V('PageMode', val={'V':0}, dic=PageMode_dict),
        Type3V('RequestRef1', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('WaitInd1', val={'V':b'\0'}, bl={'V':8}, IE=T3122()),
        Type3V('RequestRef2', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('WaitInd2', val={'V':b'\0'}, bl={'V':8}, IE=T3122()),
        Type3V('RequestRef3', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('WaitInd3', val={'V':b'\0'}, bl={'V':8}, IE=T3122()),
        Type3V('RequestRef4', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('WaitInd4', val={'V':b'\0'}, bl={'V':8}, IE=T3122()),
        RestOctets('IARRestOctets', IE=iar_rest_octets)
        )

'''
#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )



#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Layer3):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )
'''


#------------------------------------------------------------------------------#
# PAGING RESPONSE
# TS 44.018, section 9.1.25
#------------------------------------------------------------------------------#

class RRPagingResponse(Layer3):
    _GEN = (
        RRHeader(val={'Type':39}),
        Uint('spare', bl=4),
        Type1V('CKSN', dic=CKSN_dict),
        Type4LV('MSCm2', val={'V':b'@\x00\x00'}, IE=MSCm2()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type1TV('AddUpdateParams', val={'T':0xC, 'V':0}, IE=AddUpdateParams())
        )

#------------------------------------------------------------------------------#
# RRC dispatcher
#------------------------------------------------------------------------------#

RRTypeClasses = {
    39 : RRPagingResponse,
    }

def get_rr_msg_instances():
    return {k: RRTypeClasses[k]() for k in RRTypeClasses}

