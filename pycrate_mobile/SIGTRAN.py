# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# * Copyright 2018. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/SIGTRAN.py
# * Created : 2017-11-24
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils  import *
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.charpy import *


# http://www.iana.org/assignments/sigtran-adapt

# SIGTRAN messages class
MGMT  = 0
TRANS = 1
SSNM  = 2
ASPSM = 3
ASPTM = 4
QPTM  = 5
MAUP  = 6
CONLESS = 7
CONOR = 8
RKM   = 9
IIM   = 10
M2PA  = 11
SEC   = 12
BPT   = 13
V5PTM = 14

Class_dict = {
    MGMT  : 'Management Message',
    TRANS : 'Transfer Messages',
    SSNM  : 'SS7 Signalling Network Management Messages',
    ASPSM : 'ASP State Maintenance Messages',
    ASPTM : 'ASP Traffic Maintenance Messages',
    QPTM  : 'Q.921/Q.931 Boundary Primitives Transport Messages',
    MAUP  : 'MTP2 User Adaptation Messages',
    CONLESS : 'Connectionless Messages',
    CONOR : 'Connection-Oriented Messages',
    RKM   : 'Routing Key Management Messages',
    IIM   : 'Interface Identifier Management Messages',
    M2PA  : 'M2PA Messages',
    SEC   : 'Security Messages',
    BPT   : 'DPNSS/DASS2 Boundary Primitives Transport Messages',
    V5PTM : 'V5 Boundary Primitives Transport Messages',
    }

# SIGTRAN MGMT messages type
MGMT_ERR      = 0
MGMT_NTFY     = 1
MGMT_TEISREQ  = 2
MGMT_TEISCONF = 3
MGMT_TEISIND  = 4
MGMT_DLCSREQ  = 5
MGMT_DLCSCONF = 6
MGMT_DLCSIND  = 7
MGMT_TEIQREQ  = 8

TypeMGMT_dict = {
    MGMT_ERR      : 'Error',
    MGMT_NTFY     : 'Notify (NTFY)',
    MGMT_TEISREQ  : 'TEI Status Request (TEISREQ)',
    MGMT_TEISCONF : 'TEI Status Confirm (TEIS',
    MGMT_TEISIND  : 'TEI Status Indication',
    MGMT_DLCSREQ  : 'DLC Status Request',
    MGMT_DLCSCONF : 'DLC Status Confirm',
    MGMT_DLCSIND  : 'DLC Status Indication',
    MGMT_TEIQREQ  : 'TEI Query Request',
    }

# SIGTRAN TRANS message type
TRANS_DATA = 1

TypeTRANS_dict = {
    TRANS_DATA : 'Payload data'
    }

# SIGTRAN SSNM messages type
SSNM_DUNA = 1
SSNM_DAVA = 2
SSNM_DAUD = 3
SSNM_SCON = 4
SSNM_DPU  = 5
SSNM_DRST = 6

TypeSSNM_dict = {
    SSNM_DUNA : 'Destination Unavailable',
    SSNM_DAVA : 'Destination Available',
    SSNM_DAUD : 'Destination State Audit',
    SSNM_SCON : 'Signalling Congestion',
    SSNM_DPU  : 'Destination User Part Unavailable',
    SSNM_DRST : 'Destination Restricted'
    }

# SIGTRAN ASPSM messages type
ASPSM_UP      = 1
ASPSM_DOWN    = 2
ASPSM_BEAT    = 3
ASPSM_UPACK   = 4
ASPSM_DOWNACK = 5
ASPSM_BEATACK = 6

TypeASPSM_dict = {
    ASPSM_UP      : 'ASP Up',
    ASPSM_DOWN    : 'ASP Down',
    ASPSM_BEAT    : 'Heartbeat',
    ASPSM_UPACK   : 'ASP Up Ack',
    ASPSM_DOWNACK : 'ASP Down Ack',
    ASPSM_BEATACK : 'Heartbeat Ack'
    }

# SIGTRAN ASPTM messages type
ASPTM_ACTIVE      = 1
ASPTM_INACTIVE    = 2
ASPTM_ACTIVEACK   = 3
ASPTM_INACTIVEACK = 4

TypeASPTM_dict = {
    ASPTM_ACTIVE      : 'ASP Active',
    ASPTM_INACTIVE    : 'ASP Inactive',
    ASPTM_ACTIVEACK   : 'ASP Active Ack',
    ASPTM_INACTIVEACK : 'ASP Inactive Ack'
    }

# SIGTRAN QPTM messages type
QPTM_DATREQ  = 1
QPTM_DATIND  = 2
QPTM_UNITREQ = 3
QPTM_UNITIND = 4
QPTM_ESTREQ  = 5
QPTM_ESTCONF = 6
QPTM_ESTIND  = 7
QPTM_RELREQ  = 8
QPTM_RELCONF = 9
QPTM_RELIND  = 10

TypeQPTM_dict = {
    QPTM_DATREQ  : 'Data Request Message ',
    QPTM_DATIND  : 'Data Indication Message ',
    QPTM_UNITREQ : 'Unit Data Request Message',
    QPTM_UNITIND : 'Unit Data Indication Message',
    QPTM_ESTREQ  : 'Establish Request',
    QPTM_ESTCONF : 'Establish Confirm',
    QPTM_ESTIND  : 'Establish Indication',
    QPTM_RELREQ  : 'Release Request',
    QPTM_RELCONF : 'Release Confirm',
    QPTM_RELIND  : 'Release Indication'
    }

# SIGTRAN MAUP messages type
MAUP_DATA     = 1
MAUP_ESTREQ   = 2
MAUP_ESTCONF  = 3
MAUP_RELREQ   = 4
MAUP_RELCONF  = 5
MAUP_RELIND   = 6
MAUP_STATREQ  = 7
MAUP_STATCONF = 8
MAUP_STATIND  = 9
MAUP_RETRREQ  = 10
MAUP_RETRCONF = 11
MAUP_RETRIND  = 12
MAUP_RETRCOMP = 13
MAUP_CONG     = 14
MAUP_DATACK   = 15

TypeMAUP_dict = {
    MAUP_DATA     : 'Data',
    MAUP_ESTREQ   : 'Establish Request',
    MAUP_ESTCONF  : 'Establish Confirm',
    MAUP_RELREQ   : 'Release Request',
    MAUP_RELCONF  : 'Release Confirm',
    MAUP_RELIND   : 'Release Indication',
    MAUP_STATREQ  : 'State Request',
    MAUP_STATCONF : 'State Confirm',
    MAUP_STATIND  : 'State Indication',
    MAUP_RETRREQ  : 'Data Retrieval Request',
    MAUP_RETRCONF : 'Data Retrieval Confirm',
    MAUP_RETRIND  : 'Data Retrieval Indication',
    MAUP_RETRCOMP : 'Data Retrieval Complete Indication',
    MAUP_CONG     : 'Congestion Indication',
    MAUP_DATACK   : 'Data Acknowledge'
    }

# SIGTRAN CONLESS messages type
CONLESS_CLDT = 1
CONLESS_CLDR = 2

TypeCONLESS_dict = {
    CONLESS_CLDT : 'Connectionless Data Transfer',
    CONLESS_CLDR : 'Connectionless Data Response'
    }
   
# SIGTRAN CONOR messages type
CONOR_CORE  = 1
CONOR_COAK  = 2
CONOR_COREF = 3
CONOR_RELRE = 4
CONOR_RELCO = 5
CONOR_RESCO = 6
CONOR_RESRE = 7 
CONOR_CODT  = 8 
CONOR_CODA  = 9
CONOR_COERR = 10
CONOR_COIT  = 11

TypeCONOR_dict = {
    CONOR_CORE  : 'Connection Request',
    CONOR_COAK  : 'Connection Acknowledge',
    CONOR_COREF : 'Connection Refused',
    CONOR_RELRE : 'Release Request',
    CONOR_RELCO : 'Release Complete',
    CONOR_RESCO : 'Reset Confirm',
    CONOR_RESRE : 'Reset Request', 
    CONOR_CODT  : 'Connection Oriented Data Transfer', 
    CONOR_CODA  : 'Connection Oriented Data Acknowledge',
    CONOR_COERR : 'Connection Oriented Error',
    CONOR_COIT  : 'Inactivity Test'
    }

# SIGTRAN RKM messages type
RKM_REGREQ   = 1
RKM_REGRSP   = 2
RKM_DEREGREQ = 3
RKM_DEREGRSP = 4

TypeRKM_dict = {
    RKM_REGREQ   : 'Registration Request',
    RKM_REGRSP   : 'Registration Response',
    RKM_DEREGREQ : 'Deregistration Request',
    RKM_DEREGRSP : 'Deregistration Response'
    }

# SIGTRAN IIM messages type
IIM_REGREQ   = 1
IIM_REGRSP   = 2
IIM_DEREGREQ = 3
IIM_DEREGRSP = 4

TypeIIM_dict = {
    IIM_REGREQ   : 'Registration Request',
    IIM_REGRSP   : 'Registration Response',
    IIM_DEREGREQ : 'Deregistration Request',
    IIM_DEREGRSP : 'Deregistration Response'
    }

# SIGTRAN M2PA messages type
M2PA_DATA = 1
M2PA_STAT = 2

TypeM2PA_dict = {
    M2PA_DATA : 'User Data',
    M2PA_STAT : 'Link Status'
    }

# SIGTRAN SEC messages type
SEC_STLS    = 1
SEC_STLSACK = 2

TypeSEC_dict = {
    SEC_STLS     : 'STARTTLS message',
    SEC_STLSACK  : 'STARTTLS_ACK message'
    }

# SIGTRAN BPT messages type
BPT_DATREQ  = 1
BPT_DATIND  = 2
BPT_UNITREQ = 3
BPT_UNITIND = 4
BPT_ESTREQ  = 5
BPT_ESTCONF = 6
BPT_ESTIND  = 7
BPT_RELREQ  = 8
BPT_RELCONF = 9
BPT_RELIND  = 10

TypeBPT_dict = {
    BPT_DATREQ  : 'Data Request Message ',
    BPT_DATIND  : 'Data Indication Message ',
    BPT_UNITREQ : 'Unit Data Request Message',
    BPT_UNITIND : 'Unit Data Indication Message',
    BPT_ESTREQ  : 'Establish Request',
    BPT_ESTCONF : 'Establish Confirm',
    BPT_ESTIND  : 'Establish Indication',
    BPT_RELREQ  : 'Release Request',
    BPT_RELCONF : 'Release Confirm',
    BPT_RELIND  : 'Release Indication'
    }

# SIGTRAN V5PTM messages type
V5PTM_DATA      = 1
V5PTM_DATIND    = 2
V5PTM_UNITREQ   = 3
V5PTM_UNITIND   = 4
V5PTM_ESTREQ    = 5
V5PTM_ESTCONF   = 6
V5PTM_ESTIND    = 7
V5PTM_RELREQ    = 8
V5PTM_RELCONF   = 9
V5PTM_RELIND    = 10
V5PTM_LSSTART   = 11
V5PTM_LSSTOP    = 12
V5PTM_LSIND     = 13
V5PTM_SASETREQ  = 14
V5PTM_SASETCONF = 15
V5PTM_SASTATREQ = 16
V5PTM_SASTATIND = 17
V5PTM_ERRIND    = 18

TypeV5PTM_dict = {
    V5PTM_DATA      : 'Data Request Message ',
    V5PTM_DATIND    : 'Data Indication Message',
    V5PTM_UNITREQ   : 'Unit Data Request Message',
    V5PTM_UNITIND   : 'Unit Data Indication Message',
    V5PTM_ESTREQ    : 'Establish Request',
    V5PTM_ESTCONF   : 'Establish Confirm',
    V5PTM_ESTIND    : 'Establish Indication',
    V5PTM_RELREQ    : 'Release Request',
    V5PTM_RELCONF   : 'Release Confirm',
    V5PTM_RELIND    : 'Release Indication',
    V5PTM_LSSTART   : 'Link Status Start Reporting',
    V5PTM_LSSTOP    : 'Link Status Stop Reporting',
    V5PTM_LSIND     : 'Link Status Indication',
    V5PTM_SASETREQ  : 'Sa-Bit Set Request',
    V5PTM_SASETCONF : 'Sa-Bit Set Confirm',
    V5PTM_SASTATREQ : 'Sa-Bit Status Request',
    V5PTM_SASTATIND : 'Sa-Bit Status Indication',
    V5PTM_ERRIND    : 'Error Indication'
    }

# SIGTRAN message parameters
Params_dict = {
    0   : 'Reserved', # [RFC4233] [RFC3868] [RFC3331]
    1   : 'Interface Identifier', # [RFC4233] [RFC3331] [RFC4129] [RFC3807]
    2   : 'Reserved', # [RFC4233]
    3   : 'Interface Identifier', # [RFC4233] [RFC3331] [RFC4129] [RFC3807]
    4   : 'Info String', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    5   : 'DLCI', # [RFC4233] [RFC4129]
    6   : 'Routing Context', # [RFC4666] [RFC3868]
    7   : 'Diagnostic Information', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    8   : 'Interface Identifier', # [RFC4233] [RFC3331] [RFC4129] [RFC3807]
    9   : 'Heartbeat Data', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    10  : 'Reason', # [RFC4129] [RFC3807]
    11  : 'Traffic Mode Type', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    12  : 'Error Code', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    13  : 'Status Type/Information', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    14  : 'Protocol Data', # [RFC4233] [RFC4129] [RFC3807]
    15  : 'Release Reason', # [RFC4233] [RFC4129] [RFC3807]
    16  : 'Status', # [RFC4233] [RFC4129] [RFC3807]
    17  : 'ASP Identifier', # [RFC3331] [RFC4666] [RFC3868]
    18  : 'Affected Point Code', # [RFC4666] [RFC3868]
    19  : 'Correlation Id', # [RFC3331] [RFC4666] [RFC3868]
    20  : 'Registration Result', # [RFC3868]
    21  : 'Deregistration Result', # [RFC3868]
    22  : 'Registration Status', # [RFC3868]
    23  : 'Deregistration Status', # [RFC3868]
    24  : 'Local Routing Key Identifier', # [RFC3868]
    129 : 'DLCI/EFA', # [RFC3807]
    130 : 'Link Status', # [RFC3807]
    131 : 'Bit ID/Bit Value', # [RFC3807]
    132 : 'Error Reason', # [RFC3807]
    257 : 'SS7 Hop Counter', # [RFC3868]
    258 : 'Source Address', # [RFC3868]
    259 : 'Destination Address', # [RFC3868]
    260 : 'Source Reference Number', # [RFC3868]
    261 : 'Destination Reference Number', # [RFC3868]
    262 : 'SCCP Cause', # [RFC3868]
    263 : 'Sequence Number', # [RFC3868]
    264 : 'Receive Sequence Number', # [RFC3868]
    265 : 'ASP Capabilities', # [RFC3868]
    266 : 'Credit', # [RFC3868]
    267 : 'Data', # [RFC3868]
    268 : 'Cause / User', # [RFC3868]
    269 : 'Network Appearance', # [RFC3868]
    270 : 'Routing Key', # [RFC3868]
    271 : 'DRN Label', # [RFC3868]
    272 : 'TID Label', # [RFC3868]
    273 : 'Address Range', # [RFC3868]
    274 : 'SMI', # [RFC3868]
    275 : 'Importance', # [RFC3868]
    276 : 'Message Priority', # [RFC3868]
    277 : 'Protocol Class', # [RFC3868]
    278 : 'Sequence Control', # [RFC3868]
    279 : 'Segmentation', # [RFC3868]
    280 : 'Congestion Level', # [RFC3868]
    512 : 'Network Appearance', # [RFC4666]
    513 : 'Reserved', # [RFC4666]
    514 : 'Reserved', # [RFC4666]
    515 : 'Reserved', # [RFC4666]
    516 : 'User/Cause', # [RFC4666]
    517 : 'Congestion Indications', # [RFC4666]
    518 : 'Concerned Destination', # [RFC4666]
    519 : 'Routing Key', # [RFC4666]
    520 : 'Registration Result', # [RFC4666]
    521 : 'Deregistration Result', # [RFC4666]
    522 : 'Local_Routing Key Identifier', # [RFC4666]
    523 : 'Destination Point Code', # [RFC4666]
    524 : 'Service Indicators', # [RFC4666]
    525 : 'Reserved', # [RFC4666]
    526 : 'Originating Point Code List', # [RFC4666]
    527 : 'Circuit Range', # [RFC4666]
    528 : 'Protocol Data', # [RFC4666]
    529 : 'Reserved', # [RFC4666]
    530 : 'Registration Status', # [RFC4666]
    531 : 'Deregistration Status', # [RFC4666]
    768 : 'Protocol Data 1', # [RFC3331]
    769 : 'Protocol Data 2', # [RFC3331]
    770 : 'State Request', # [RFC3331]
    771 : 'State Event', # [RFC3331]
    772 : 'Congestion Status', # [RFC3331]
    773 : 'Discard Status', # [RFC3331]
    774 : 'Action', # [RFC3331]
    775 : 'Sequence Number', # [RFC3331]
    776 : 'Retrieval Result', # [RFC3331]
    777 : 'Link Key', # [RFC3331]
    778 : 'Local-LK-Identifier', # [RFC3331]
    779 : 'Signalling Data Terminal Identifier', # [RFC3331]
    780 : 'Signalling Data Link Identifier', # [RFC3331]
    781 : 'Registration Result', # [RFC3331]
    782 : 'Registration Status', # [RFC3331]
    783 : 'De-Registration Result', # [RFC3331]
    784 : 'De-Registration Status', # [RFC3331]
    32769 : 'Global Title', # [RFC3868]
    32770 : 'Point Code', # [RFC3868]
    32771 : 'Subsystem Number', # [RFC3868]
    32772 : 'IPv4 Address', # [RFC3868]
    32773 : 'Hostname', # [RFC3868]
    32774 : 'IPv6 Addresses', # [RFC3868]
    65535 : 'Reserved', # [RFC4233]
}

# SIGTRAN message structure
# works for both M2UA (RFC 3331) and M3UA (RFC 4666)

class Param(Envelope):
    _pad = b'\0'
    _GEN = (
        Uint16('Tag', dic=Params_dict),
        Uint16('Len'),
        Buf('Val', val=b'', rep=REPR_HEX),
        Buf('pad', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 4+self[2].get_len())
        self[2].set_blauto(lambda:  8*max(0, self[1].get_val()-4))
        self[3].set_valauto(lambda: (-self[2].get_len()%4) * self._pad)
        self[3].set_blauto(lambda:  8*(-self[2].get_len()%4))
    
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        self[2]._from_char(char)
        # this is to enable the decoding of some SIGTRAN implementations
        # were padding of the last parameter is omitted
        if not char.len_bit():
            self[3].set_trans(True)


class SIGTRAN(Envelope):

    # warning RFC 4666: the length must take padding into account, 
    # otherwise there will be a mismatch with `Len' fields in the sequence of
    # parameters
    # this class attribute enforces the Length field in the Header at decoding
    _LEN_ENFORCE = True
    
    _TypeUndef_dict = {}
    _Type_dict = {
        MGMT  : TypeMGMT_dict,
        TRANS : TypeTRANS_dict,
        SSNM  : TypeSSNM_dict,
        ASPSM : TypeASPSM_dict,
        ASPTM : TypeASPTM_dict,
        QPTM  : TypeQPTM_dict,
        MAUP  : TypeMAUP_dict,
        CONLESS : TypeCONLESS_dict,
        CONOR : TypeCONOR_dict,
        RKM   : TypeRKM_dict,
        IIM   : TypeIIM_dict,
        M2PA  : TypeM2PA_dict,
        SEC   : TypeSEC_dict,
        BPT   : TypeBPT_dict,
        V5PTM : TypeV5PTM_dict
        }
    _GEN = (
        Envelope('Header', GEN=(
            Uint8('Version', val=1),
            Uint8('spare'),
            Uint8('Class', val=TRANS, dic=Class_dict),
            Uint8('Type'),
            Uint32('Len')
            ), hier=0),
        Sequence('Params', GEN=Param(), hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][3].set_dicauto(lambda: self._Type_dict.get(self[0][2].get_val(), self._TypeUndef_dict))
        self[0][4].set_valauto(lambda: 8+self[1].get_len())
    
    def _from_char(self, char):
        self[0]._from_char(char)
        if self._LEN_ENFORCE:
            clen = char._len_bit
            char._len_bit = char._cur + 8*(max(0, self[0][4].get_val()-8))
            self[1]._from_char(char)
            char._len_bit = clen
        else:
            self[1]._from_char(char)


class M2PA(Envelope):
    # RFC 4165
    
    _GEN = (
        Envelope('Header', GEN=(
            Uint8('Version', val=1),
            Uint8('spare'),
            Uint8('Class', val=11, dic=Class_dict),
            Uint8('Type', val=1, dic={1:'User Data', 2:'Link Status'}),
            Uint32('Len')),
            hier=0),
        Envelope('M2PAHeader', GEN=(
            Uint8('unused'),
            Uint24('BSN'),
            Uint8('unused'),
            Uint24('FSN')),
            hier=0),
        Alt('Data', GEN={
            1: Envelope('UserData', GEN=(
                Uint('Priority', bl=2),
                Uint('spare', bl=6),
                Buf('Data', val=b'', rep=REPR_HEX))),
            2: Envelope('LinkStatus', GEN=(
                Uint8('State'),
                Buf('filler', val=b'', rep=REPR_HEX)))
            },
            DEFAULT=Buf('Data', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0][3].get_val(),
            hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][4].set_valauto(lambda: 16 + self[2].get_len() if not self[2].get_trans() else 16)
        self[2]._GEN[1][2].set_blauto(lambda: 8*(self[0][4].get_val()-18))
        self[2]._GEN[2][1].set_blauto(lambda: 8*(self[0][4].get_val()-17))
        self[2].DEFAULT.set_blauto(lambda: 8*(self[0][4].get_val()-16))
    
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        if self[0][4].get_val() > 16:
            self[2].set_trans(False)
            self[2]._from_char(char)
        else:
            self[2].set_trans(True)


MTP3SubServInd_dict = {
    0 : 'international network',
    1 : 'spare',
    2 : 'national network',
    3 : 'reserved for national use'
    }

MTP3ServInd_dict = {
    0 : 'Signalling network management messages',
    1 : 'Signalling network testing and maintenance messages',
    2 : 'Signaling Network Testing and Maintenance Special Messages (ANSI)',
    3 : 'Signalling Connection Control Part',
    4 : 'Telephone User Part',
    5 : 'ISDN User Part',
    6 : 'DUP (call and circuit-related messages)',
    7 : 'DUP (facility registration and cancellation)',
    8 : 'Reserved for MTP Testing User Part',
    9 : 'Broadband ISDN User Part',
    10: 'Satellite ISDN User Part',
    }


class MTP3(Envelope):
    # ITU-T Q.2210, peer-to-peer info of user parts
    
    _GEN = (
        Uint('SubServiceInd', bl=2, dic=MTP3SubServInd_dict),
        Uint('SubServiceSpare', bl=2),
        Uint('ServiceInd', bl=4, dic=MTP3ServInd_dict),
        Uint8('DPC_LSB'),
        Uint('OPC_LSB', bl=2),
        Uint('DPC_MSB', bl=6),
        Uint8('OPC_M'),
        Uint('SLS', bl=4),
        Uint('OPC_MSB', bl=4),
        Uint16('DPC', trans=True),
        Uint16('OPC', trans=True)
        )
    
    # additional class attribute for the size in bytes
    _SZ = 5
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[9].set_valauto( lambda: self[3].get_val() + (self[5].get_val()<<8))
        self[10].set_valauto(lambda: self[4].get_val() + (self[6].get_val()<<2) + \
                                    (self[8].get_val()<<10))
    
    def set_val(self, vals):
        if isinstance(vals, dict):
            if 'DPC' in vals:
                dpc = vals['DPC']
                del vals['DPC']
                self[3].set_val(dpc&0xff)
                self[5].set_val(dpc>>8)
            if 'OPC' in vals:
                opc = vals['OPC']
                del vals['OPC']
                self[4].set_val(opc&0x2)
                self[6].set_val((opc>>2)&0xff)
                self[8].set_val(opc>>10)
        if vals:
            Envelope.set_val(self, vals)


class MTP3_JPN(Envelope):
    # MTP3 Japanese variant : DPC / OPC are on 16 bits and SLS is on 8 bits
    
    _GEN = (
        Uint('SubServiceInd', bl=2, dic=MTP3SubServInd_dict),
        Uint('SubServiceSpare', bl=2),
        Uint('ServiceInd', bl=4, dic=MTP3ServInd_dict),
        Uint16LE('DPC'),
        Uint16LE('OPC'),
        Uint('SLSSpare', bl=4),
        Uint('SLS', bl=4)
        )
    
    # additional class attribute for the size in bytes
    _SZ = 6


class MTP3_ANSI(Envelope):
    # MTP3 ANSI T1.111.1 variant
    # Seems Chinese variant format has the same layout (with priority being spare)
    
    _GEN = (
        Uint('SubServiceInd', bl=2, dic=MTP3SubServInd_dict),
        Uint('SubServicePriority', bl=2),
        Uint('ServiceInd', bl=4, dic=MTP3ServInd_dict),
        Uint24('DPC'),
        Uint24('OPC'),
        Uint8('SLS')
        )
    
    # additional class attribute for the size in bytes
    _SZ = 8

