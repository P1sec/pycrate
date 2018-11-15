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
    98:'CDMA 2000 CLASSMARK CHANGE',
    99:'INTER SYSTEM TO UTRAN HANDOVER COMMAND',
    100:'INTER SYSTEM TO CDMA2000 HANDOVER COMMAND',
    101:'GERAN IU MODE CLASSMARK CHANGE',
    102:'PRIORITY UPLINK REQUEST',
    103:'DATA INDICATION',
    104:'DATA INDICATION 2'
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

class RRAdditionalAssign(Envelope):
    _GEN = (
        RRHeader(val={'Type':59}),
        Type3V('ChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type4TLV('MobAlloc', val={'T':0x72, 'V':b'\0'}, IE=MobAlloc()),
        Type3TV('StartingTime', val={'T':0x7C, 'V':b'\0\0'}, bl={'V':16}, IE=StartingTime()),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# ASSIGNMENT COMMAND
# TS 44.018, section 9.1.2
#------------------------------------------------------------------------------#

class RRAssignmentCmd(Envelope):
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
        Type4TLV('MobAllocAfter', val={'T':0x72, 'V':b'\0'}, IE=MobAlloc()),
        Type3TV('StartingTime', val={'T':0x7C, 'V':b'\0\0'}, bl={'V':16}, IE=StartingTime()),
        Type4TLV('FreqListBefore', val={'T':0x19, 'V':b'\0\0'}, IE=FreqList()),
        Type3V('FirstChanDescBefore', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc2()),
        Type3TV('SecondChanDescAfter', val={'T':0x64, 'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type3TV('FreqChanSeqBefore', val={'T':0x1E, 'V':9*b'\0'}, bl={'V':72}, IE=FreqChanSeq()),
        Type4TLV('MobAllocBefore', val={'T':0x72, 'V':b'\0'}, IE=MobAlloc()),
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

class RRAssignmentComplete(Envelope):
    _GEN = (
        RRHeader(val={'Type':41}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        )


#------------------------------------------------------------------------------#
# ASSIGNMENT FAILURE
# TS 44.018, section 9.1.4
#------------------------------------------------------------------------------#

class RRAssignmentFailure(Envelope):
    _GEN = (
        RRHeader(val={'Type':47}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause())
        )


#------------------------------------------------------------------------------#
# CHANNEL MODE MODIFY
# TS 44.018, section 9.1.5
#------------------------------------------------------------------------------#

class RRChannelModeModify(Envelope):
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

class RRChannelModeModifyAck(Envelope):
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

class RRChannelRelease(Envelope):
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
# this is just 1 bytes with an establishment cause and a random reference


#------------------------------------------------------------------------------#
# CIPHERING MODE COMMAND
# TS 44.018, section 9.1.9
#------------------------------------------------------------------------------#

class RRCipheringModeCmd(Envelope):
    _GEN = (
        RRHeader(val={'Type':53}),
        Type1V('CipherResp', val={'V':0}, IE=CipherResp()),
        Type1V('CipherModeSetting', val={'V':0}, IE=CipherModeSetting())
        )


#------------------------------------------------------------------------------#
# CIPHERING MODE COMPLETE
# TS 44.018, section 9.1.10
#------------------------------------------------------------------------------#

class RRCipheringModeComplete(Envelope):
    _GEN = (
        RRHeader(val={'Type':50}),
        Type4TLV('MEId', val={'T':0x17, 'V':b'\0'}, IE=ID())
        )


#------------------------------------------------------------------------------#
# CLASSMARK CHANGE
# TS 44.018, section 9.1.11
#------------------------------------------------------------------------------#

class RRClassmarkChange(Envelope):
    _GEN = (
        RRHeader(val={'Type':22}),
        Type4LV('MSCm2', val={'V':b'@\0\0'}, IE=MSCm2()),
        Type4TLV('MSCm3', val={'T':0x20, 'V':b''}, IE=classmark_3_value_part)
        )


#------------------------------------------------------------------------------#
# UTRAN CLASSMARK CHANGE
# TS 44.018, section 9.1.11a
#------------------------------------------------------------------------------#

class RRUTRANClassmarkChange(Envelope):
    _GEN = (
        RRHeader(val={'Type':96}),
        Type4LV('UTRANCm', val={'V':b'\0'}) # INTER RAT HANDOVER INFO from TS 25.331
        )


#------------------------------------------------------------------------------#
# cdma2000 CLASSMARK CHANGE
# TS 44.018, section 9.1.11b
#------------------------------------------------------------------------------#

class RRcdma2000ClassmarkChange(Envelope):
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

class RRUTRANClassmarkChange(Envelope):
    _GEN = (
        RRHeader(val={'Type':101}),
        Type4LV('GERANIuModeCm', val={'V':14*b'\0'}) # MS GERAN IU MODE RADIO ACCESS CAPABILITY from TS 44.118
        )


#------------------------------------------------------------------------------#
# CLASSMARK ENQUIRY
# TS 44.018, section 9.1.12
#------------------------------------------------------------------------------#

class RRClassmarkEnquiry(Envelope):
    _GEN = (
        RRHeader(val={'Type':19}),
        Type4TLV('CmEnquiryMask', val={'T':0x10, 'V':b'\0'}, IE=CmEnquiryMask())
        )


#------------------------------------------------------------------------------#
# CONFIGURATION CHANGE COMMAND
# TS 44.018, section 9.1.12b
#------------------------------------------------------------------------------#

class RRConfigChangeCmd(Envelope):
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

class RRConfigChangeAck(Envelope):
    _GEN = (
        RRHeader(val={'Type':49})
        )


#------------------------------------------------------------------------------#
# CONFIGURATION CHANGE REJECT
# TS 44.018, section 9.1.12d
#------------------------------------------------------------------------------#

class RRConfigChangeReject(Envelope):
    _GEN = (
        RRHeader(val={'Type':51}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        )


#------------------------------------------------------------------------------#
# DTM ASSIGNMENT COMMAND
# TS 44.018, section 9.1.12e
#------------------------------------------------------------------------------#

class RRDTMAssignmentCmd(Envelope):
    _GEN = (
        RRHeader(val={'Type':76}),
        Type3V('CSPowerCmd', val={'V':b'\0'}, bl={'V':8}, IE=PowerCmd()),
        Type3V('CSChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        Type4LV('GPRSBcastInfo', val={'V':6*b'\0'}, IE=gprs_broadcast_information_value_part),
        Type3TV('CellChan', val={'T':0x10, 'V':16*b'\0'}, bl={'V':128}, IE=CellChan()),
        Type3TV('ChanMode', val={'T':0x11, 'V':b'\0'}, bl={'V':8}, IE=ChanMode()),
        Type4TLV('FreqList', val={'T':0x12, 'V':b'\0\0'}, IE=FreqList()),
        Type4TLV('MobAlloc', val={'T':0x13, 'V':b'\0'}, IE=MobAlloc()),
        Type4TLV('PSULAssign', val={'T':0x15, 'V':b'\0'}, IE=rr_packet_uplink_assignment_value_part),
        Type4TLV('PSDLAssign', val={'T':0x16, 'V':b'\0'}, IE=rr_packet_downlink_assignment_value_part),
        Type4TLV('MultirateConfig', val={'T':0x17, 'V':b'\0\0'}, IE=MultirateConfig()),
        Type1TV('CipherModeSetting', val={'T':0x9, 'V':0}, IE=CipherModeSetting()),
        Type4TLV('MobAllocC2', val={'T':0x18, 'V':b'\0'}, IE=MobAlloc()),
        Type4TLV('FreqListC2', val={'T':0x19, 'V':b'\0\0'}, IE=FreqList()),
        Type4TLV('PSDLAssignType2', val={'T':0x16, 'V':b'\0'}, IE=rr_packet_downlink_assignment_type_2_value_part),
        Type3TV('ChanDescC2', val={'V':b'\0\0'}, bl={'V':16}, IE=ChanDesc3()),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


'''
#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Envelope):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Envelope):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Envelope):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Envelope):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )


#------------------------------------------------------------------------------#
#
# TS 44.018, section 9.1.
#------------------------------------------------------------------------------#

class RR(Envelope):
    _GEN = (
        RRHeader(val={'Type':}),
        
        )
'''


#------------------------------------------------------------------------------#
# PAGING RESPONSE
# TS 44.018, section 9.1.25
#------------------------------------------------------------------------------#

class RRPagingResponse(Envelope):
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

