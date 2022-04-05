# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI. P1sec.
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
# release 15 (f30)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007    import *
from .TS44018_IE import *

from pycrate_csn1dir.notification_facch                             import notification_facch
from pycrate_csn1dir.vbs_vgcs_reconfigure                           import vbs_vgcs_reconfigure
from pycrate_csn1dir.vbs_vgcs_reconfigure2                          import vbs_vgcs_reconfigure2
from pycrate_csn1dir.ec_system_information_type_1                   import ec_system_information_type_1
from pycrate_csn1dir.ec_system_information_type_2                   import ec_system_information_type_2
from pycrate_csn1dir.ec_system_information_type_3                   import ec_system_information_type_3
from pycrate_csn1dir.ec_system_information_type_4                   import ec_system_information_type_4
from pycrate_csn1dir.uplink_free                                    import uplink_free
from pycrate_csn1dir.vgcs_additional_info                           import vgcs_additional_info
from pycrate_csn1dir.vgcs_sms_information                           import vgcs_sms_information
from pycrate_csn1dir.system_information_type_10                     import system_information_type_10
from pycrate_csn1dir.system_information_type_10bis                  import system_information_type_10bis
from pycrate_csn1dir.system_information_type_10ter                  import system_information_type_10ter
from pycrate_csn1dir.measurement_information                        import measurement_information
from pycrate_csn1dir.enhanced_measurement_report                    import enhanced_measurement_report
from pycrate_csn1dir.vgcs_neighbour_cell_information                import vgcs_neighbour_cell_information
from pycrate_csn1dir.notify_application_data                        import notify_application_data
from pycrate_csn1dir.ec_immediate_assignment_type_2_message_content import ec_immediate_assignment_type_2_message_content
from pycrate_csn1dir.ec_immediate_assignment_reject_message_content import ec_immediate_assignment_reject_message_content
from pycrate_csn1dir.ec_dummy_message_content                       import ec_dummy_message_content
from pycrate_csn1dir.ec_paging_request_message_content              import ec_paging_request_message_content
from pycrate_csn1dir.ec_downlink_assignment_message_content         import ec_downlink_assignment_message_content
from pycrate_csn1dir.ec_immediate_assignment_type_4_message_content import ec_immediate_assignment_type_4_message_content
from pycrate_csn1dir.ec_downlink_assignment_message_type_2_content  import ec_downlink_assignment_message_type_2_content
from pycrate_csn1dir.ec_immediate_assignment_type_3_message_content import ec_immediate_assignment_type_3_message_content
from pycrate_csn1dir.ec_paging_indication                           import ec_paging_indication


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
    #22:'CLASSMARK CHANGE', # on uplink
    22:'MBMS ANNOUNCEMENT', # on downlink
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
    #54:'EXTENDED MEASUREMENT REPORT', # on SACCH, downlink
    54:'SERVICE INFORMATION', # on DCCH, downlink
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
    71:'SYSTEM INFORMATION TYPE 22',
    72:'DTM ASSIGNMENT FAILURE',
    73:'DTM REJECT',
    74:'DTM REQUEST',
    75:'PACKET ASSIGNMENT',
    76:'DTM ASSIGNMENT COMMAND',
    77:'DTM INFORMATION',
    78:'PACKET NOTIFICATION',
    79:'SYSTEM INFORMATION TYPE 23',
    96:'UTRAN CLASSMARK CHANGE',
    98:'CDMA2000 CLASSMARK CHANGE',
    99:'INTER SYSTEM TO UTRAN HANDOVER COMMAND',
    100:'INTER SYSTEM TO CDMA2000 HANDOVER COMMAND',
    101:'GERAN IU MODE CLASSMARK CHANGE',
    102:'INTER SYSTEM TO E-UTRAN HANDOVER COMMAND', # on downlink
    #102:'PRIORITY UPLINK REQUEST', # on uplink
    103:'DATA INDICATION',
    104:'DATA INDICATION 2',
    105:'IMMEDIATE PACKET ASSIGNMENT',
    106:'EC IMMEDIATE ASSIGNMENT TYPE 1'
    }

GSMRRTypeUL_dict = dict(GSMRRType_dict)
GSMRRTypeUL_dict.update({
    22 : 'CLASSMARK CHANGE', # on uplink
    102:'PRIORITY UPLINK REQUEST', # on uplink
    })

GSMRRTypeSACCH_dict = dict(GSMRRType_dict)
GSMRRTypeSACCH_dict.update({
    54:'EXTENDED MEASUREMENT REPORT', # UL on SACCH
    })


class RRHeader(Envelope):
    _GEN = (
        Uint('SkipInd', bl=4),
        Uint('ProtDisc', val=6, bl=4, dic=ProtDisc_dict),
        Uint('Type', bl=8, dic=GSMRRType_dict),
        )


class RRHeaderUL(Envelope):
    _GEN = (
        Uint('SkipInd', bl=4),
        Uint('ProtDisc', val=6, bl=4, dic=ProtDisc_dict),
        Uint('Type', bl=8, dic=GSMRRTypeUL_dict),
        )

class RRHeaderSACCH(Envelope):
    _GEN = (
        Uint('SkipInd', bl=4),
        Uint('ProtDisc', val=6, bl=4, dic=ProtDisc_dict),
        Uint('Type', bl=8, dic=GSMRRTypeSACCH_dict),
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
        RRHeaderUL(val={'Type':41}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        )


#------------------------------------------------------------------------------#
# ASSIGNMENT FAILURE
# TS 44.018, section 9.1.4
#------------------------------------------------------------------------------#

class RRAssignmentFailure(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':47}),
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
        RRHeaderUL(val={'Type':23}),
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
        RRHeaderUL(val={'Type':50}),
        Type4TLV('MEId', val={'T':0x17, 'V':b'\0'}, IE=ID())
        )


#------------------------------------------------------------------------------#
# CLASSMARK CHANGE
# TS 44.018, section 9.1.11
#------------------------------------------------------------------------------#

class RRClassmarkChange(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':22}),
        Type4LV('MSCm2', val={'V':b'@\0\0'}, IE=MSCm2()),
        Type4TLV('MSCm3', val={'T':0x20, 'V':b''}, IE=classmark_3_value_part)
        )


#------------------------------------------------------------------------------#
# UTRAN CLASSMARK CHANGE
# TS 44.018, section 9.1.11a
#------------------------------------------------------------------------------#

class RRUTRANClassmarkChange(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':96}),
        Type4LV('UTRANCm', val={'V':b'\0'}) # INTER RAT HANDOVER INFO from TS 25.331
        )


#------------------------------------------------------------------------------#
# CDMA2000 CLASSMARK CHANGE
# TS 44.018, section 9.1.11b
#------------------------------------------------------------------------------#

class RRCdma2000ClassmarkChange(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':98}),
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

class RRGERANIuClassmarkChange(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':101}),
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
        RRHeaderUL(val={'Type':49})
        )


#------------------------------------------------------------------------------#
# CONFIGURATION CHANGE REJECT
# TS 44.018, section 9.1.12d
#------------------------------------------------------------------------------#

class RRConfigChangeReject(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':51}),
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
        Type4TLV('PSDLAssignType2', val={'T':0x20, 'V':b'\0'}, IE=rr_packet_downlink_assignment_type_2_value_part),
        Type3TV('ChanDescC2', val={'T':0x21, 'V':b'\0\0'}, bl={'V':16}, IE=ChanDesc3()),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# DTM ASSIGNMENT FAILURE
# TS 44.018, section 9.1.12f
#------------------------------------------------------------------------------#

class RRDTMAssignmentFailure(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':72}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        )


#------------------------------------------------------------------------------#
# DTM INFORMATION
# TS 44.018, section 9.1.12g
#------------------------------------------------------------------------------#

class RRDTMInfo(Layer3):
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
        RRHeaderUL(val={'Type':52}),
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
# TODO: this message has no defined type in the TS 44.018

class RRHOGERANIuModeCmd(Layer3):
    _GEN = (
        RRHeader(val={'Type':0}),
        Type4LV('RadioBearerReconfig', val={'V':b'\0'}) # see TS 44.118
        )


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
        RRHeaderUL(val={'Type':44}),
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
        RRHeaderUL(val={'Type':40}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause()),
        Type1TV('PSCause', val={'T':0x9, 'V':0}, dic=PSCause_dict),
        )


#------------------------------------------------------------------------------#
# IMMEDIATE ASSIGNMENT
# TS 44.018, section 9.1.18
#------------------------------------------------------------------------------#
# Warning: the MTA Access Burst or Extended Access Burst Method structure is
# not implemented

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
        L2PseudoLength(),
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
# TS 44.018, section 9.1.20
#------------------------------------------------------------------------------#

class RRImmediateAssignmentReject(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':19}),
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
        RestOctets('IARRestOctets', bl={'V': 24}, IE=iar_rest_octets)
        )


#------------------------------------------------------------------------------#
# MEASUREMENT REPORT
# TS 44.018, section 9.1.21
#------------------------------------------------------------------------------#

class RRMeasurementReport(Layer3):
    _GEN = (
        RRHeaderSACCH(val={'Type':21}),
        Type3V('MeasurementResults', val={'V':16*b'\0'}, bl={'V':128}, IE=measurement_results_contents)
        )


#------------------------------------------------------------------------------#
# NOTIFICATION/FACCH
# TS 44.018, section 9.1.21a
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# notification_facch


#------------------------------------------------------------------------------#
# NOTIFICATION/NCH
# TS 44.018, section 9.1.21b
#------------------------------------------------------------------------------#

class RRNotificationNCH(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':32}),
        RestOctets('NTNRestOctets', bl={'V':160}, IE=ntn_rest_octets),
        )


#------------------------------------------------------------------------------#
# NOTIFICATION/RESPONSE
# TS 44.018, section 9.1.21d
#------------------------------------------------------------------------------#

class RRNotificationResponse(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':38}),
        Type4LV('MSCm2', val={'V':b'@\x00\x00'}, IE=MSCm2()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type3V('BroadcastCallRef', val={'V':5*b'\0'}, bl={'V':40}, IE=BroadcastCallRef())
        )


#------------------------------------------------------------------------------#
# PACKET ASSIGNMENT
# TS 44.018, section 9.1.21f
#------------------------------------------------------------------------------#

class RRPacketAssignment(Layer3):
    _GEN = (
        RRHeader(val={'Type':75}),
        Type4LV('GPRSBroadcastInfo', val={'V':6*b'\0'}, IE=gprs_broadcast_information_value_part),
        Type4TLV('PSULAssign', val={'T':0x22, 'V':b'\0'}, IE=rr_packet_uplink_assignment_value_part),
        Type4TLV('PSDLAssign', val={'T':0x23, 'V':b'\0'}, IE=rr_packet_downlink_assignment_value_part),
        Type4TLV('FreqListC2', val={'T':0x12, 'V':b'\0\0'}, IE=FreqList()),
        Type4TLV('MobileAllocC2', val={'T':0x13, 'V':b'\0'}, IE=MobileAlloc()),
        Type3TV('ChanDescC2', val={'T':0x14, 'V':b'\0\0'}, bl={'V':16}, IE=ChanDesc3()),
        Type4TLV('PSDLAssignType2', val={'T':0x24, 'V':b'\0'}, IE=rr_packet_downlink_assignment_type_2_value_part),
        Type3TV('ExtTSCSet', val={'T':0x6D, 'V':b'\0'}, bl={'V':8}, IE=ExtTSCSet())
        )


#------------------------------------------------------------------------------#
# PACKET NOTIFICATION
# TS 44.018, section 9.1.21g
#------------------------------------------------------------------------------#

class RRPacketNotification(Layer3):
    _GEN = (
        RRHeader(val={'Type':78}),
        Type3TV('PTMSI', val={'T':0x10, 'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        Type4TLV('ID', val={'T':0x11, 'V':b'\xf4\0\0\0\0'}, IE=ID())
        )


#------------------------------------------------------------------------------#
# VBS/VGCS RECONFIGURE
# TS 44.018, section 9.1.21h
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# vbs_vgcs_reconfigure


#------------------------------------------------------------------------------#
# VBS/VGCS RECONFIGURE 2
# TS 44.018, section 9.1.21i
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# vbs_vgcs_reconfigure2


#------------------------------------------------------------------------------#
# MBMS ANNOUNCEMENT
# TS 44.018, section 9.1.21j
#------------------------------------------------------------------------------#

class RRMBMSAnnouncement(Layer3):
    _GEN = (
        RRHeader(val={'Type':22}),
        Type4LV('TMGI', val={'V':b'\0\0\0'}, IE=TMGI()),
        Type3TV('MBMSSessionId', val={'T':0x1, 'V':b'\0'}, bl={'V':8}, IE=MBMSSessionId()),
        Type4TLV('MBMSCountChanDesc', val={'T':0x2, 'V':b'\0'}, IE=mprach_description_value_part),
        Type4TLV('MBMSPtMChanDesc', val={'T':0x3, 'V':b'\0\0'}, IE=mbms_p_t_m_channel_description_value_part),
        Type4TLV('MBMSSessionParams', val={'T':0x4, 'V':b'\0\0'}, IE=mbms_session_parameters_list_value_part),
        Type3TV('RestrictionTimer', val={'T':0x5, 'V':b'\0'}, bl={'V':8}, IE=RestrictionTimer())
        )


#------------------------------------------------------------------------------#
# PAGING REQUEST TYPE 1
# TS 44.018, section 9.1.22
#------------------------------------------------------------------------------#

class RRPagingReq1(Layer3):
    _GEN = (
        L2PseudoLength(),
        RRHeader(val={'Type':33}),
        Type1V('ChanNeeded', val={'V':0}, IE=ChanNeeded()),
        Type1V('PageMode', val={'V':0}, dic=PageMode_dict),
        Type4LV('ID1', val={'V':b'\0'}, IE=ID()),
        Type4TLV('ID2', val={'T':0x17, 'V':b'\0'}, IE=ID()),
        RestOctets('P1RestOctets', IE=p1_rest_octets)
        )


#------------------------------------------------------------------------------#
# PARING REQUEST TYPE 2
# TS 44.018, section 9.1.23
#------------------------------------------------------------------------------#

class RRPagingReq2(Layer3):
    _GEN = (
        L2PseudoLength(),
        RRHeader(val={'Type':34}),
        Type1V('ChanNeeded', val={'V':0}, IE=ChanNeeded()),
        Type1V('PageMode', val={'V':0}, dic=PageMode_dict),
        Type3V('ID1', val={'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        Type3V('ID2', val={'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        Type4TLV('ID3', val={'T':0x17, 'V':b'\0'}, IE=ID()),
        RestOctets('P2RestOctets', IE=p2_rest_octets)
        )


#------------------------------------------------------------------------------#
# PARING REQUEST TYPE 3
# TS 44.018, section 9.1.24
#------------------------------------------------------------------------------#

class RRPagingReq3(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':19}),
        RRHeader(val={'Type':36}),
        Type1V('ChanNeeded', val={'V':0}, IE=ChanNeeded()),
        Type1V('PageMode', val={'V':0}, dic=PageMode_dict),
        Type3V('ID1', val={'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        Type3V('ID2', val={'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        Type3V('ID3', val={'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        Type3V('ID4', val={'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        RestOctets('P3RestOctets', bl={'V':24}, IE=p3_rest_octets)
        )


#------------------------------------------------------------------------------#
# PAGING RESPONSE
# TS 44.018, section 9.1.25
#------------------------------------------------------------------------------#

class RRPagingResponse(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':39}),
        Uint('spare', bl=4),
        Type1V('CKSN', dic=CKSN_dict),
        Type4LV('MSCm2', val={'V':b'@\x00\x00'}, IE=MSCm2()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type1TV('AddUpdateParams', val={'T':0xC, 'V':0}, IE=AddUpdateParams())
        )


#------------------------------------------------------------------------------#
# PARTIAL RELEASE
# TS 44.018, section 9.1.26
#------------------------------------------------------------------------------#

class RRPartialRelease(Layer3):
    _GEN = (
        RRHeader(val={'Type':10}),
        Type3V('ChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc()),
        )


#------------------------------------------------------------------------------#
# PARTIAL RELEASE COMPLETE
# TS 44.018, section 9.1.27
#------------------------------------------------------------------------------#

class RRPartialReleaseComplete(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':15}),
        )


#------------------------------------------------------------------------------#
# PHYSICAL INFORMATION
# TS 44.018, section 9.1.28
#------------------------------------------------------------------------------#

class RRPhysicalInfo(Layer3):
    _GEN = (
        RRHeader(val={'Type':45}),
        Type3V('TimingAdvance', val={'V':b'\0'}, bl={'V':8}, IE=TimingAdvance())
        )


#------------------------------------------------------------------------------#
# RR STATUS
# TS 44.018, section 9.1.29
#------------------------------------------------------------------------------#

class RRStatus(Layer3):
    _GEN = (
        RRHeader(val={'Type':18}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause())
        )


#------------------------------------------------------------------------------#
# Synchronization channel information
# TS 44.018, section 9.1.30a
#------------------------------------------------------------------------------#
# not a standard L3 message


#------------------------------------------------------------------------------#
# COMPACT Synchronization channel information
# TS 44.018, section 9.1.30b
#------------------------------------------------------------------------------#
# not a standard L3 message


#------------------------------------------------------------------------------#
# EC-SCH INFORMATION
# TS 44.018, section 9.1.30b
#------------------------------------------------------------------------------#
# not a standard L3 message


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 1
# TS 44.018, section 9.1.31
#------------------------------------------------------------------------------#

class RRSystemInfo1(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':21}),
        RRHeader(val={'Type':25}),
        Type3V('CellChan', val={'V':16*b'\0'}, bl={'V':128}, IE=CellChan()),
        Type3V('RACHCtrl', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RACHCtrl()),
        RestOctets('SI1RestOctets', bl={'V':8}, IE=si1_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 2
# TS 44.018, section 9.1.32
#------------------------------------------------------------------------------#

class RRSystemInfo2(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':22}),
        RRHeader(val={'Type':26}),
        Type3V('BCCHFreqList', val={'V':16*b'\0'}, bl={'V':128}, IE=NeighbourCellChan()),
        Type3V('NCCPermitted', val={'V':b'\0'}, bl={'V':8}, IE=NCCPermitted()),
        Type3V('RACHCtrl', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RACHCtrl())
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 2bis
# TS 44.018, section 9.1.33
#------------------------------------------------------------------------------#

class RRSystemInfo2bis(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':21}),
        RRHeader(val={'Type':2}),
        Type3V('ExtBCCHFreqList', val={'V':16*b'\0'}, bl={'V':128}, IE=NeighbourCellChan()),
        Type3V('RACHCtrl', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RACHCtrl()),
        RestOctets('SI2bisRestOctets', bl={'V':8}, IE=si2bis_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 2ter
# TS 44.018, section 9.1.34
#------------------------------------------------------------------------------#

class RRSystemInfo2ter(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':18}),
        RRHeader(val={'Type':3}),
        Type3V('ExtBCCHFreqList', val={'V':16*b'\0'}, bl={'V':128}, IE=NeighbourCellChan2()),
        RestOctets('SI2terRestOctets', bl={'V':32}, IE=si2ter_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 2quater
# TS 44.018, section 9.1.34a
#------------------------------------------------------------------------------#

class RRSystemInfo2quater(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':7}),
        RestOctets('SI2quaterRestOctets', bl={'V':160}, IE=si2quater_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 2n
# TS 44.018, section 9.1.34b
#------------------------------------------------------------------------------#

class RRSystemInfo2n(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':69}),
        RestOctets('SI2nRestOctets', bl={'V':160}, IE=si2n_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 3
# TS 44.018, section 9.1.35
#------------------------------------------------------------------------------#

class RRSystemInfo3(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':18}),
        RRHeader(val={'Type':27}),
        Type3V('CellId', val={'V':b'\0\0'}, bl={'V':16}, IE=CellId()),
        Type3V('LAI', val={'V': b'\0\xf1\x10\0\0'}, bl={'V':40}, IE=LAI()),
        Type3V('CtrlChanDesc', val={'V':b'\0\0\0'}, bl={'V':24}, IE=CtrlChanDesc()),
        Type3V('CellOpt', val={'V':b'\0'}, bl={'V':8}, IE=CellOpt()),
        Type3V('CellSelParams', val={'V':b'\0\0'}, bl={'V':16}, IE=CellSelParams()),
        Type3V('RACHCtrl', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RACHCtrl()),
        RestOctets('SI3RestOctets', bl={'V':32}, IE=si3_rest_octet)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 4
# TS 44.018, section 9.1.36
#------------------------------------------------------------------------------#

class RRSystemInfo4(Layer3):
    _GEN = (
        L2PseudoLength(),
        RRHeader(val={'Type':28}),
        Type3V('LAI', val={'V': b'\0\xf1\x10\0\0'}, bl={'V':40}, IE=LAI()),
        Type3V('CellSelParams', val={'V':b'\0\0'}, bl={'V':16}, IE=CellSelParams()),
        Type3V('RACHCtrl', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RACHCtrl()),
        Type3TV('CBCHChanDesc', val={'T':0x64, 'V':b'\0\0\0'}, bl={'V':3}, IE=ChanDesc()),
        Type4TLV('CBCHMobileAlloc', val={'T':0x72}, IE=MobileAlloc()),
        RestOctets('SI4RestOctets', IE=si4_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 5
# TS 44.018, section 9.1.37
#------------------------------------------------------------------------------#

class RRSystemInfo5(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':18}),
        RRHeaderSACCH(val={'Type':29}),
        Type3V('BCCHFreqList', val={'V':16*b'\0'}, bl={'V':128}, IE=NeighbourCellChan())
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 5bis
# TS 44.018, section 9.1.38
#------------------------------------------------------------------------------#

class RRSystemInfo5bis(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':18}),
        RRHeaderSACCH(val={'Type':5}),
        Type3V('ExtBCCHFreqList', val={'V':16*b'\0'}, bl={'V':128}, IE=NeighbourCellChan())
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 5ter
# TS 44.018, section 9.1.39
#------------------------------------------------------------------------------#

class RRSystemInfo5ter(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':18}),
        RRHeaderSACCH(val={'Type':6}),
        Type3V('ExtBCCHFreqList', val={'V':16*b'\0'}, bl={'V':128}, IE=NeighbourCellChan2())
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 6
# TS 44.018, section 9.1.40
#------------------------------------------------------------------------------#

class RRSystemInfo6(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':11}),
        RRHeaderSACCH(val={'Type':30}),
        Type3V('CellId', val={'V':b'\0\0'}, bl={'V':16}, IE=CellId()),
        Type3V('LAI', val={'V': b'\0\xf1\x10\0\0'}, bl={'V':40}, IE=LAI()),
        Type3V('CellOpt', val={'V':b'\0'}, bl={'V':8}, IE=CellOpt()),
        Type3V('NCCPermitted', val={'V':b'\0'}, bl={'V':8}, IE=NCCPermitted()),
        RestOctets('SI6RestOctets', bl={'V':56}, IE=si6_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 7
# TS 44.018, section 9.1.41
#------------------------------------------------------------------------------#

class RRSystemInfo7(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':31}),
        RestOctets('SI7RestOctets', bl={'V':160}, IE=si4_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 8
# TS 44.018, section 9.1.42
#------------------------------------------------------------------------------#

class RRSystemInfo8(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':24}),
        RestOctets('SI7RestOctets', bl={'V':160}, IE=si4_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 9
# TS 44.018, section 9.1.43
#------------------------------------------------------------------------------#

class RRSystemInfo9(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':4}),
        Type3V('RACHCtrl', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RACHCtrl()),
        RestOctets('SI9RestOctets', bl={'V':136}, IE=si9_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 13
# TS 44.018, section 9.1.43a
#------------------------------------------------------------------------------#

class RRSystemInfo13(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':0}),
        RRHeader(val={'Type':0}),
        RestOctets('SI13RestOctets', bl={'V':160}, IE=si_13_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 16
# TS 44.018, section 9.1.43d
#------------------------------------------------------------------------------#

class RRSystemInfo16(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':61}),
        RestOctets('SI16RestOctets', bl={'V':160}, IE=si16_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 17
# TS 44.018, section 9.1.43d
#------------------------------------------------------------------------------#

class RRSystemInfo17(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':62}),
        RestOctets('SI17RestOctets', bl={'V':160}, IE=si17_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 19
# TS 44.018, section 9.1.43f
#------------------------------------------------------------------------------#

class RRSystemInfo19(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':65}),
        RestOctets('SI19RestOctets', bl={'V':160}, IE=si_19_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 18
# TS 44.018, section 9.1.43g
#------------------------------------------------------------------------------#

class RRSystemInfo18(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':64}),
        RestOctets('SI18RestOctets', bl={'V':160}, IE=si_18_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 20
# TS 44.018, section 9.1.43h
#------------------------------------------------------------------------------#

class RRSystemInfo20(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':66}),
        RestOctets('SI20RestOctets', bl={'V':160}, IE=si_18_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 14
# TS 44.018, section 9.1.43i
#------------------------------------------------------------------------------#

class RRSystemInfo14(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':18}), # this 44.018 spec does not make sens at all !!!
        RRHeaderSACCH(val={'Type':1}),
        RestOctets('SI14RestOctets', bl={'V':128}, IE=si14_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 15
# TS 44.018, section 9.1.43j
#------------------------------------------------------------------------------#

class RRSystemInfo15(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':1}),
        RRHeader(val={'Type':67}),
        RestOctets('SI15RestOctets', bl={'V':160}, IE=si15_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 13alt
# TS 44.018, section 9.1.43k
#------------------------------------------------------------------------------#

class RRSystemInfo13alt(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':0}),
        RRHeader(val={'Type':68}),
        RestOctets('SI13altRestOctets', bl={'V':160}, IE=si_13alt_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 21
# TS 44.018, section 9.1.43m
#------------------------------------------------------------------------------#

class RRSystemInfo21(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':2}),
        RRHeader(val={'Type':70}),
        RestOctets('SI21RestOctets', bl={'V':160}, IE=si_21_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 22
# TS 44.018, section 9.1.43n
#------------------------------------------------------------------------------#

class RRSystemInfo22(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':2}),
        RRHeader(val={'Type':71}),
        RestOctets('SI22RestOctets', bl={'V':160}, IE=si_22_rest_octets)
        )


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 23
# TS 44.018, section 9.1.43o
#------------------------------------------------------------------------------#

class RRSystemInfo23(Layer3):
    _GEN = (
        L2PseudoLength(val={'Value':2}),
        RRHeader(val={'Type':79}),
        RestOctets('SI23RestOctets', bl={'V':160}, IE=si_23_rest_octets)
        )


#------------------------------------------------------------------------------#
# EC SYSTEM INFORMATION TYPE 1
# TS 44.018, section 9.1.43p
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_system_information_type_1


#------------------------------------------------------------------------------#
# EC SYSTEM INFORMATION TYPE 2
# TS 44.018, section 9.1.43q
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_system_information_type_2


#------------------------------------------------------------------------------#
# EC SYSTEM INFORMATION TYPE 3
# TS 44.018, section 9.1.43r
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_system_information_type_3


#------------------------------------------------------------------------------#
# EC SYSTEM INFORMATION TYPE 4
# TS 44.018, section 9.1.43s
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_system_information_type_4


#------------------------------------------------------------------------------#
# TALKER INDICATION
# TS 44.018, section 9.1.44
#------------------------------------------------------------------------------#

class RRTalkerInd(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':17}),
        Type4LV('MSCm2', val={'V':b'@\x00\x00'}, IE=MSCm2()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type1TV('CKSN', val={'T':0xB, 'V':7}, dic=CKSN_dict),
        )


#------------------------------------------------------------------------------#
# PRIORITY UPLINK REQUEST
# TS 44.018, section 9.1.44a
#------------------------------------------------------------------------------#

class RRPriorityUplinkReq(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':102}),
        Type3V('EstabCauseRandomRef', val={'V':b'\0'}, bl={'V':8}, IE=EstabCauseRandomRef()),
        Type3V('Token', val={'V':4*b'\0'}, bl={'V':32}, IE=Token()),
        Type3V('ReducedBroadcastCallRef', val={'V':4*b'\0'}, bl={'V':32}, IE=ReducedBroadcastCallRef()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        )


#------------------------------------------------------------------------------#
# DATA INDICATION
# TS 44.018, section 9.1.44b
#------------------------------------------------------------------------------#

class RRDataInd(Layer3):
    _GEN = (
        RRHeader(val={'Type':103}),
        Type3V('ID', val={'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        Type3V('AppData', val={'V':9*b'\0'}, bl={'V':72}),
        Type3V('DataId', val={'V':b'\0'}, bl={'V':8}, IE=DataId())
        )


#------------------------------------------------------------------------------#
# DATA INDICATION 2
# TS 44.018, section 9.1.44c
#------------------------------------------------------------------------------#

class RRDataInd2(Layer3):
    _GEN = (
        RRHeader(val={'Type':104}),
        Type3V('ID', val={'V':4*b'\0'}, bl={'V':32}, IE=TMSI()),
        Type3V('ReducedBroadcastCallRef', val={'V':4*b'\0'}, bl={'V':32}, IE=ReducedBroadcastCallRef()),
        Type3V('AppData', val={'V':9*b'\0'}, bl={'V':72}),
        Type3V('DataId', val={'V':b'\0'}, bl={'V':8}, IE=DataId())
        )


#------------------------------------------------------------------------------#
# UPLINK ACCESS
# TS 44.018, section 9.1.45
#------------------------------------------------------------------------------#
# this is just 1 byte with a random reference


#------------------------------------------------------------------------------#
# UPLINK BUSY
# TS 44.018, section 9.1.46
#------------------------------------------------------------------------------#

class RRUplinkBusy(Layer3):
    _GEN = (
        RRHeader(val={'Type':42}),
        Type4TLV('TalkerPriorityStat', val={'T':0x31, 'V':b'\0'}, IE=TalkerPriorityStat()),
        Type3TV('Token', val={'T':0x32, 'V':4*b'\0'}, bl={'V':32}, IE=Token()),
        Type4TLV('TalkerId', val={'T':0x33, 'V':b'\0'}, IE=TalkerId()),
        Type1TV('UplinkAccessInd', val={'T':0x8, 'V':0}, IE=UplinkAccessInd())
        )


#------------------------------------------------------------------------------#
# UPLINK FREE
# TS 44.018, section 9.1.47
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# uplink_free


#------------------------------------------------------------------------------#
# UPLINK RELEASE
# TS 44.018, section 9.1.48
#------------------------------------------------------------------------------#

class RRUplinkRelease(Layer3):
    _GEN = (
        RRHeader(val={'Type':14}),
        Type3V('RRCause', val={'V':b'\0'}, bl={'V':8}, IE=RRCause())
        )


#------------------------------------------------------------------------------#
# VGCS UPLINK GRANT
# TS 44.018, section 9.1.49
#------------------------------------------------------------------------------#

class RRVGCSUplinkGrant(Layer3):
    _GEN = (
        RRHeader(val={'Type':9}),
        Type3V('RequestRef', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('TimingAdvance', val={'V':b'\0'}, bl={'V':8}, IE=TimingAdvance())
        )


#------------------------------------------------------------------------------#
# VGCS ADDITIONAL INFORMATION
# TS 44.018, section 9.1.49a
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# vgcs_additional_info


#------------------------------------------------------------------------------#
# VGCS SMS INFORMATION
# TS 44.018, section 9.1.49b
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# vgcs_sms_information


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 10 $(ASCI)$
# TS 44.018, section 9.1.50
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# system_information_type_10


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 10BIS $(ASCI)$
# TS 44.018, section 9.1.50a
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# system_information_type_10bis


#------------------------------------------------------------------------------#
# SYSTEM INFORMATION TYPE 10TER $(ASCI)$
# TS 44.018, section 9.1.50b
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# system_information_type_10ter


#------------------------------------------------------------------------------#
# EXTENDED MEASUREMENT ORDER
# TS 44.018, section 9.1.51
#------------------------------------------------------------------------------#

class RRExtMeasurementOrder(Layer3):
    _GEN = (
        RRHeaderSACCH(val={'Type':55}),
        Type3V('ExtMeasFreqList', val={'V':16*b'\0'}, bl={'V':128}, IE=ExtMeasFreqList())
        )


#------------------------------------------------------------------------------#
# EXTENDED MEASUREMENT REPORT
# TS 44.018, section 9.1.52
#------------------------------------------------------------------------------#

class RRExtMeasurementReport(Layer3):
    _GEN = (
        RRHeaderSACCH(val={'Type':54}),
        Type3V('ExtMeasRes', val={'V':16*b'\0'}, bl={'V':128}, IE=ExtMeasRes())
        )


#------------------------------------------------------------------------------#
# APPLICATION INFORMATION
# TS 44.018, section 9.1.53
#------------------------------------------------------------------------------#

class RRApplicationInfo(Layer3):
    _GEN = (
        RRHeader(val={'Type':56}),
        Type1V('APDUFlags', val={'V':0}, IE=APDUFlags()),
        Type1V('APDUID', val={'V':0}, dic=APDUID_dict),
        Type4LV('APDUData', val={'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# MEASUREMENT INFORMATION
# TS 44.018, section 9.1.54
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# measurement_information


#------------------------------------------------------------------------------#
# ENHANCED MEASUREMENT REPORT
# TS 44.018, section 9.1.55
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# enhanced_measurement_report


#------------------------------------------------------------------------------#
# SERVICE INFORMATION MESSAGE
# TS 44.018, section 9.1.56
#------------------------------------------------------------------------------#

class RRServiceInfo(Layer3):
    _GEN = (
        RRHeaderUL(val={'Type':54}),
        Type3V('TLLI', val={'V':4*b'\0'}, bl={'V':32}, IE=TLLI()),
        Type3V('RAI', val={'V':b'\0\xf1\x10\0\0\0'}, bl={'V':48}, IE=RAI()),
        Type3V('ServiceSupport', val={'V':b'\0'}, bl={'V':8}, IE=ServiceSupport())
        )


#------------------------------------------------------------------------------#
# VGCS NEIGHBOUR CELL INFORMATION MESSAGE
# TS 44.018, section 9.1.57
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# vgcs_neighbour_cell_information


#------------------------------------------------------------------------------#
# NOTIFY APPLICATION DATA
# TS 44.018, section 9.1.58
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# notify_application_data


#------------------------------------------------------------------------------#
# EC IMMEDIATE ASSIGNMENT TYPE 1
# TS 44.018, section 9.1.59
#------------------------------------------------------------------------------#

class RRECImmediateAssignment1(Layer3):
    _GEN = (
        L2PseudoLength(),
        RRHeader(val={'Type':106}),
        Type1V('FeatureInd', val={'V':0}, IE=FeatureInd()),
        Type1V('PageMode', val={'V':0}, dic=PageMode_dict),
        Type3V('RequestRef', val={'V':b'\0\0\0'}, bl={'V':24}, IE=RequestRef()),
        Type3V('ECPacketChannelDesc1', val={'V':b'\0\0'}, bl={'V':16}, IE=ec_packet_channel_description_type_1),
        Type3V('ECFixedUplinkAlloc', val={'V':4*b'\0'}, IE=ec_immediate_assignment_type_2_message_content),
        RestOctets('rest')
        )
    def __init__(self, *args, **kwargs):
        Layer3.__init__(self, *args, **kwargs)
        self[0][0].set_valauto(lambda: (64+self[6].get_bl())>>3)
        self[6][0].set_blauto(lambda: (self[0][0].get_val()<<3)-64)


#------------------------------------------------------------------------------#
# EC IMMEDIATE ASSIGNMENT TYPE 2
# TS 44.018, section 9.1.60
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_immediate_assignment_type_2_message_content


#------------------------------------------------------------------------------#
# EC IMMEDIATE ASSIGNMENT REJECT
# TS 44.018, section 9.1.61
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_immediate_assignment_reject_message_content


#------------------------------------------------------------------------------#
# EC DUMMY
# TS 44.018, section 9.1.62
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_dummy_message_content


#------------------------------------------------------------------------------#
# EC PAGING REQUEST
# TS 44.018, section 9.1.63
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_paging_request_message_content


#------------------------------------------------------------------------------#
# EC DOWNLINK ASSIGNMENT
# TS 44.018, section 9.1.64
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_downlink_assignment_message_content


#------------------------------------------------------------------------------#
# EC PACKET CHANNEL REQUEST
# TS 44.018, section 9.1.65
#------------------------------------------------------------------------------#
# not a standard L3 message


#------------------------------------------------------------------------------#
# EC IMMEDIATE ASSIGNMENT TYPE 4
# TS 44.018, section 9.1.66
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_immediate_assignment_type_4_message_content


#------------------------------------------------------------------------------#
# EC DOWNLINK ASSIGNMENT TYPE 2
# TS 44.018, section 9.1.67
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_downlink_assignment_message_type_2_content


#------------------------------------------------------------------------------#
# EC IMMEDIATE ASSIGNMENT TYPE 3
# TS 44.018, section 9.1.68
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_immediate_assignment_type_3_message_content


#------------------------------------------------------------------------------#
# EC PAGING INDICATION
# TS 44.018, section 9.1.69
#------------------------------------------------------------------------------#
# This is a special message with short PD and defined in CSN.1 only:
# ec_paging_request_message_content


#------------------------------------------------------------------------------#
# RRC dispatchers
#------------------------------------------------------------------------------#

RRDLTypeClasses = {
    #0  : RRHOGERANIuModeCmd, # no defined type
    9  : RRVGCSUplinkGrant,
    10 : RRPartialRelease,
    13 : RRChannelRelease,
    14 : RRUplinkRelease,
    16 : RRChannelModeModify,
    18 : RRStatus,
    19 : RRClassmarkEnquiry,
    20 : RRFrequencyRedefinition,
    22 : RRMBMSAnnouncement,
    42 : RRUplinkBusy,
    43 : RRHandoverCmd,
    45 : RRPhysicalInfo,
    46 : RRAssignmentCmd,
    48 : RRConfigChangeCmd,
    53 : RRCipheringModeCmd,
    55 : RRExtMeasurementOrder,
    56 : RRApplicationInfo,
    59 : RRAdditionalAssign,
    73 : RRDTMReject,
    75 : RRPacketAssignment,
    76 : RRDTMAssignmentCmd,
    77 : RRDTMInfo,
    78 : RRPacketNotification,
    99 : RRInterSystemUTRANHOCmd,
    100: RRInterSystemCdma200HOCmd,
    102: RRInterSystemEUTRANHOCmd,
    103: RRDataInd,
    104: RRDataInd2
    }

RRULTypeClasses = {
    14 : RRUplinkRelease,
    15 : RRPartialReleaseComplete,
    17 : RRTalkerInd,
    18 : RRStatus,
    21 : RRMeasurementReport,
    22 : RRClassmarkChange,
    23 : RRChannelModeModifyAck,
    38 : RRNotificationResponse,
    39 : RRPagingResponse,
    40 : RRHandoverFailure,
    41 : RRAssignmentComplete,
    44 : RRHandoverComplete,
    47 : RRAssignmentFailure,
    49 : RRConfigChangeAck,
    50 : RRCipheringModeComplete,
    51 : RRConfigChangeReject,
    52 : RRGPRSSuspensionReq,
    54 : RRServiceInfo,
    #54 : RRExtMeasurementReport,
    56 : RRApplicationInfo,
    72 : RRDTMAssignmentFailure,
    74 : RRDTMReq,
    96 : RRUTRANClassmarkChange,
    98 : RRCdma2000ClassmarkChange,
    101: RRGERANIuClassmarkChange,
    102: RRPriorityUplinkReq,
    103: RRDataInd,
    104: RRDataInd2
    }

# Warning: those are separate dict specific for SACCH
# because of the RRExtMeasurementReport which has the same type as RRServiceInfo
RRSACCHDLTypeClasses = {
    18 : RRStatus,
    55 : RRExtMeasurementOrder
    }

RRSACCHULTypeClasses = {
    18 : RRStatus,
    21 : RRMeasurementReport,
    54 : RRExtMeasurementReport
    }

# Warning: 
# SI5, SI5bis, SI5ter, SI6, SI14 (normally over SACCH) and
# Notification/NCH (normally over NCH) are handled through the RRBCCH dict
# because they have a L2PseudoLength prefix required for handling RestOctets
RRBCCHTypeClasses = {
    0  : RRSystemInfo13,
    1  : RRSystemInfo14,
    2  : RRSystemInfo2bis,
    3  : RRSystemInfo2ter,
    4  : RRSystemInfo9,
    5  : RRSystemInfo5bis,
    6  : RRSystemInfo5ter,
    7  : RRSystemInfo2quater,
    24 : RRSystemInfo8,
    25 : RRSystemInfo1,
    26 : RRSystemInfo2,
    27 : RRSystemInfo3,
    28 : RRSystemInfo4,
    29 : RRSystemInfo5,
    30 : RRSystemInfo6,
    31 : RRSystemInfo7,
    32 : RRNotificationNCH,
    33 : RRPagingReq1,
    34 : RRPagingReq2,
    36 : RRPagingReq3,
    57 : RRImmediateAssignmentExt,
    58 : RRImmediateAssignmentReject,
    61 : RRSystemInfo16,
    62 : RRSystemInfo17,
    63 : RRImmediateAssignment,
    64 : RRSystemInfo18,
    65 : RRSystemInfo19,
    66 : RRSystemInfo20,
    67 : RRSystemInfo15,
    68 : RRSystemInfo13alt,
    69 : RRSystemInfo2n,
    70 : RRSystemInfo21,
    71 : RRSystemInfo22,
    79 : RRSystemInfo23,
    105: RRImmediatePacketAssignment,
    106: RRECImmediateAssignment1
    }

# Warning, because of the few collisions within the several dispatchers
# hence RRTypeClasses / RRTypeMOClasses / RRTypeMTClasses do not reference
# absolutely all RR signalling message types

RRTypeMOClasses = {}
RRTypeMOClasses.update(RRSACCHULTypeClasses)
RRTypeMOClasses.update(RRULTypeClasses)

RRTypeMTClasses = {}
RRTypeMTClasses.update(RRSACCHDLTypeClasses)
RRTypeMTClasses.update(RRDLTypeClasses)
RRTypeMTClasses.update(RRBCCHTypeClasses)

RRTypeClasses = {}
RRTypeClasses.update(RRTypeMOClasses)
RRTypeClasses.update(RRTypeMTClasses)

def get_rr_msg_instances():
    return {k: RRTypeClasses[k]() for k in RRTypeClasses}


#------------------------------------------------------------------------------#
# RRC dispatchers for RR and EC messages with short protocol discriminator
#------------------------------------------------------------------------------#

RRShortPDTypeMsg = {
    0 : system_information_type_10.clone(),
    1 : notification_facch.clone(),
    2 : uplink_free.clone(),
    4 : enhanced_measurement_report.clone(), # UL
    5 : measurement_information.clone(), # DL
    6 : vbs_vgcs_reconfigure.clone(),
    7 : vbs_vgcs_reconfigure2.clone(),
    8 : vgcs_additional_info.clone(),
    9 : vgcs_sms_information.clone(),
    10: system_information_type_10bis.clone(),
    11: system_information_type_10ter.clone(),
    12: vgcs_neighbour_cell_information.clone(),
    13: notify_application_data.clone()
    }

RRShortPDECBCCHTypeMsg = {
    1 : ec_system_information_type_1.clone(),
    2 : ec_system_information_type_2.clone(),
    3 : ec_system_information_type_3.clone(),
    4 : ec_system_information_type_4.clone()
    }

RRShortPDECTypeMsg = {
    1 : ec_immediate_assignment_type_2_message_content.clone(),
    2 : ec_immediate_assignment_reject_message_content.clone(),
    3 : ec_dummy_message_content.clone(),
    4 : ec_downlink_assignment_message_content.clone(),
    5 : ec_immediate_assignment_type_3_message_content.clone(),
    6 : ec_downlink_assignment_message_type_2_content.clone(),
    7 : ec_immediate_assignment_type_4_message_content.clone(),
    8 : ec_paging_indication.clone(),
    9 : ec_paging_request_message_content.clone()
    }

