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

class RRAdditionalAssignment(Envelope):
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

class RRAssignmentCommand(Envelope):
    _GEN = (
        RRHeader(val={'Type':46}),
        Type3V('FirstChanDescAfter', val={'V':b'\0\0\0'}, bl={'V':24}, IE=ChanDesc2()),
        Type3V('PowerCmd', val={'V':b'\0'}, bl={'V':8}, IE=PowerCmd()),
        Type4TLV('FreqListAfter', val={'T':0x5, 'V':b'\0\0'}, IE=FreqList()),
        Type3TV('CellChanDesc', val={'V':16*b'\0'}, bl={'V':128}),
        Type4TLV('MultislotAlloc', val={'T':0X10, 'V':b'\0'}),
        Type3TV('ModeChanSet1', val={'T':0x63, 'V':b'\0'}, bl={'V':8}),
        Type3TV('ModeChanSet2', val={'T':0x11, 'V':b'\0'}, bl={'V':8}),
        Type3TV('ModeChanSet3', val={'T':0x13, 'V':b'\0'}, bl={'V':8}),
        Type3TV('ModeChanSet4', val={'T':0x14, 'V':b'\0'}, bl={'V':8}),
        Type3TV('ModeChanSet5', val={'T':0x15, 'V':b'\0'}, bl={'V':8}),
        Type3TV('ModeChanSet6', val={'T':0x16, 'V':b'\0'}, bl={'V':8}),
        Type3TV('ModeChanSet7', val={'T':0x17, 'V':b'\0'}, bl={'V':8}),
        Type3TV('ModeChanSet8', val={'T':0x18, 'V':b'\0'}, bl={'V':8}),
        Type3TV('SecondChanDescAfter', val={'T':0x64, 'V':b'\0\0\0'}, bl={'V':24}),
        Type3TV('ModeSecondChan', val={'T':0x66, 'V':b'\0'}, bl={'V':8}),
        
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

