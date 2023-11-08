# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
# *
# * Copyright 2023. Laurent Ghigonis. P1Sec.
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
# * File Name : pycrate_mobile/TS48008_BSS.py
# * Created : 2023-01-09
# * Authors : Laurent Ghigonis
# *--------------------------------------------------------
#*/

from enum import IntEnum
from struct import unpack

from pycrate_core.elt   import Envelope, Sequence, Alt, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.utils import *
from pycrate_core.base  import *
from pycrate_core.repr  import *

from pycrate_mobile.TS24008_IE import (
    BufBCD,
    ID, IDTYPE_TMSI,
    PLMN,
    MSCm2, MSCm1,
    BroadcastCallRef,
    LAI,
    )
from pycrate_csn1dir.classmark_3_value_part import classmark_3_value_part


#------------------------------------------------------------------------------#
# BSS Management Application Part (BSSMAP) as defined in 3GPP TS 48.008
#------------------------------------------------------------------------------#
# Implementation notes
# TS48.008 https://www.etsi.org/deliver/etsi_ts/148000_148099/148008/13.02.00_60/ts_148008v130200p.pdf
#
# WARNING: this is yet a very partial and incomplete implementation of BSSMAP
# - only few BSSMAP Signalling Element are provided with specific structures
# - BSSMAP messages are not defined with explicit sequence of Signalling Element


#------------------------------------------------------------------------------#
# BSSMAP signalling elements
# TS 48.008, section 3.2.2
#------------------------------------------------------------------------------#

class BSSMAP_elm(IntEnum):
    CAUSE                = 0x04
    CELL_IDENTIFIER      = 0x05
    IMSI                 = 0x08
    TMSI                 = 0x09
    ENCRYPTION_INFO      = 0x0a
    MS_CLASSMARK_2       = 0x12
    MS_CLASSMARK_3       = 0x13
    LAYER_3_INFORMATION  = 0x17
    CELL_IDENTIFIER_LIST = 0x1a
    MS_CLASSMARK_1       = 0x1d
    MOBILE_IDENTITY      = 0x29
    GROUP_CALL_REF       = 0x37
    IMEI                 = 0x68
    MSISDN               = 0x7b
    SPEECH_CODEC_LIST    = 0x7d
    SELECTED_PLMNID      = 0x94
    LAST_EUTRAN_PLMNID   = 0x95
    OLD_LAI              = 0x96
    SELECTED_OPERATOR    = 0x98
    PS_REG_OPERATOR      = 0x99
    CS_REG_OPERATOR      = 0x9a


# 3.2.2.5 Cause
_CauseClass_dict = {
    0 : 'Normal event',
    1 : 'Normal event',
    2 : 'Resource unavailable',
    3 : 'Service or option not available, but implemented',
    4 : 'Service or option not implemented or currently disabled, i.e. not supported',
    5 : 'invalid message (eg parameter out of range)',
    6 : 'protocol error',
    7 : 'interworking',    
    }

_CauseValClass0_dict = {
    0 : 'Radio interface message failure',
    1 : 'Radio interface failure',
    2 : 'Uplink quality',
    3 : 'Uplink strength',
    4 : 'Downlink quality',
    5 : 'Downlink strength',
    6 : 'Distance',
    7 : 'O and M intervention',
    8 : 'Response to MSC invocation',
    9 : 'Call control',
    10 : 'Radio interface failure, reversion to old channel',
    11 : 'Handover successful',
    12 : 'Better Cell',
    13 : 'Directed Retry',
    14 : 'Joined group call channel',
    15 : 'Traffic',
    }

_CauseValClass1_dict = {
    0 : 'Reduce load in serving cell',
    1 : 'Traffic load in target cell higher than in source cell',
    2 : 'Relocation triggered NOTE',
    4 : 'Requested option not authorised',
    5 : 'Alternative channel configuration requested (NOTE)',
    6 : 'Response to an INTERNAL HANDOVER ENQUIRY message',
    7 : 'INTERNAL HANDOVER ENQUIRY reject',
    8 : 'Redundancy Level not adequate',
    }

_CauseValClass2_dict = {
    0 : 'Equipment failure',
    1 : 'No radio resource available',
    2 : 'Requested terrestrial resource unavailable',
    3 : 'CCCH overload',
    4 : 'Processor overload',
    5 : 'BSS not equipped',
    6 : 'MS not equipped',
    7 : 'Invalid cell',
    8 : 'Traffic Load',
    9 : 'Preemption',
    10 : 'DTM Handover - SGSN Failure',
    11 : 'DTM Handover - PS Allocation failure',
    }

_CauseValClass3_dict = {
    0 : 'Requested transcoding/rate adaption unavailable',
    1 : 'Circuit pool mismatch',
    2 : 'Switch circuit pool',
    3 : 'Requested speech version unavailable',
    4 : 'LSA not allowed',
    5 : 'Requested Codec Type or Codec Configuration unavailable',
    6 : 'Requested A-Interface Type unavailable',
    7 : 'Invalid CSG cell',
    15 : 'Requested Redundancy Level not available',
    }

_CauseValClass4_dict = {
    0 : 'Ciphering algorithm not supported',
    1 : 'GERAN Iu-mode failure',
    2 : 'Incoming Relocation Not Supported Due To PUESBINE Feature',
    3 : 'Access Restricted Due to Shared Networks (NOTE)',
    4 : 'Requested Codec Type or Codec Configuration not supported',
    5 : 'Requested A-Interface Type not supported',
    6 : 'Requested Redundancy Level not supported',
    }

_CauseValClass5_dict = {
    0 : 'Terrestrial circuit already allocated',
    1 : 'Invalid message contents',
    2 : 'Information element or field missing',
    3 : 'Incorrect value',
    4 : 'Unknown Message type',
    5 : 'Unknown Information Element',
    6 : 'DTM Handover - Invalid PS Indication',
    7 : 'Call Identifier already allocated',
    }

_CauseValClass6_dict = {
    0 : 'Protocol Error between BSS and MSC',
    1 : 'VGCS/VBS call non existent',
    2 : 'DTM Handover - Timer Expiry',
    }

_CauseVal_lut = {
    0 : _CauseValClass0_dict,
    1 : _CauseValClass1_dict,
    2 : _CauseValClass2_dict,
    3 : _CauseValClass3_dict,
    4 : _CauseValClass4_dict,
    5 : _CauseValClass5_dict,
    6 : _CauseValClass6_dict,
    7 : {}
    }


class BSSMAP_Cause:
    CALL_CONTROL      = (0, 0, 9)
    EQUIPMENT_FAILURE = (0, 2, 0)


class Cause(Envelope):
    _ID  = BSSMAP_elm.CAUSE
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Class', val=2, bl=3, dic=_CauseClass_dict),
        Uint('Val', val=0, bl=4)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Val'].set_dicauto(lambda: _CauseVal_lut[self['Class'].get_val()])


# 3.2.2.6
class IMSI(ID):
    _ID = BSSMAP_elm.IMSI


# 3.2.2.7
class TMSI(Uint32):
    _ID  = BSSMAP_elm.TMSI
    _rep = REPR_HEX


# 3.2.2.10
class _PermittedAlgs(Envelope):
    _GEN = (
        Uint('A57', val=0, bl=1),
        Uint('A56', val=0, bl=1),
        Uint('A55', val=0, bl=1),
        Uint('A54', val=0, bl=1),
        Uint('A53', val=1, bl=1),
        Uint('A52', val=1, bl=1),
        Uint('A51', val=1, bl=1),
        Uint('NoEncr', val=1, bl=1),
        )


class EncryptionInfo(Envelope):
    _ID  = BSSMAP_elm.ENCRYPTION_INFO
    _GEN = (
        _PermittedAlgs('PermittedAlgs'),
        Buf('Key', val=8*b'\0', rep=REPR_HEX)
        )


# 3.2.2.17
_CellIdentification_discriminator_dict = {
    0: 'The whole Cell Global Identification, CGI, is used to identify the cells',
    1: 'Location Area Code, LAC, and Cell Identify, CI, is used to identify the cells',
    2: 'Cell Identity, CI, is used to identify the cells',
    3: 'No cell is associated with the transaction',
    4: 'Location Area Identification, LAI, is used to identify all cells within a Location Area',
    5: 'Location Area Code, LAC, is used to identify all cells within a location area',
    6: 'All cells on the BSS are identified',
    8: 'Intersystem Handover to UTRAN or cdma2000 or E-UTRAN (CS to PS SRVCC to E-UTRAN). '\
       'PLMN-ID, LAC (or TAC), and RNC-ID (or Extended RNC-ID or Corresponding RNC-ID), are encoded to identify the target RNC or the target eNB',
    9: 'Intersystem Handover to UTRAN or cdma2000 or E-UTRAN (CS to PS SRVCC to E-UTRAN). '\
       'The RNC-ID (or Extended RNC-ID or Corresponding RNC-ID) is coded to identify the target RNC or the target eNB',
    10: '1010 Intersystem Handover to UTRAN or cdma2000 or E-UTRAN (CS to PS SRVCC to E-UTRAN). '\
        'LAC (or TAC) and RNC-ID (or Extended RNC-ID or Corresponding RNC-ID) are encoded to identify the target RNC or the target eNB'
    }

class _CellID0000(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint16('CI', rep=REPR_HEX),
        )

class _CellID0001(Envelope):
    _GEN = (
        Uint16('LAC', rep=REPR_HEX),
        Uint16('CI', rep=REPR_HEX),
        )

class _CellID1000(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint16('RNCID', rep=REPR_HEX),
        )

class _CellID1010(Envelope):
    _GEN = (
        Uint16('LAC', rep=REPR_HEX),
        Uint16('RNCID', rep=REPR_HEX),
        )

class _CellID1011(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint16('SAC', rep=REPR_HEX),
        )

class _CellID1100(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint16('RNCID', rep=REPR_HEX),
        Uint16('CI', rep=REPR_HEX),
        )


class CellIdentifier(Envelope):
    _ID  = BSSMAP_elm.CELL_IDENTIFIER
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Discriminator', val=0, bl=4, dic=_CellIdentification_discriminator_dict),
        Alt('CellID', GEN={
            0 : _CellID0000('Val'),
            1 : _CellID0001('Val'),
            2 : Uint16('CI', rep=REPR_HEX),
            8 : _CellID1000('Val'),
            9 : Uint16('RNCID', rep=REPR_HEX),
            10 : _CellID1010('Val'),
            11 : _CellID1011('Val'),
            12 : _CellID1100('Val')},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Discriminator'].get_val())
        )


# 3.2.2.19
class MSCm2(MSCm2):
    _ID = BSSMAP_elm.MS_CLASSMARK_2


# 3.2.2.20
# TODO: bind to CSN1List instance: classmark_3_value_part


# 3.2.2.27
class CellIdentifierList(Envelope):
    _ID  = BSSMAP_elm.CELL_IDENTIFIER_LIST
    _GEN = (
        Uint('spare', bl=4),
        Uint('Discriminator', bl=4, dic=_CellIdentification_discriminator_dict),
        Sequence('CellIDs', GEN=Alt('CellID', GEN={
            0 : _CellID0000('Val'),
            1 : _CellID0001('Val'),
            2 : Uint16('CI', rep=REPR_HEX),
            8 : _CellID1000('Val'),
            9 : Uint16('RNCID', rep=REPR_HEX),
            10 : _CellID1010('Val'),
            11 : _CellID1011('Val'),
            12 : _CellID1100('Val')},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env().get_env()['Discriminator'].get_val()))
        )


# 3.2.2.30
class MSCm1(MSCm1):
    _ID = BSSMAP_elm.MS_CLASSMARK_1


# 3.2.2.41
class MobileIdentity(ID):
    _ID = BSSMAP_elm.MOBILE_IDENTITY


# 3.2.2.55
class GroupCallRef(BroadcastCallRef):
    _ID = BSSMAP_elm.GROUP_CALL_REF


# 3.2.2.86
class IMEI(ID):
    _ID = BSSMAP_elm.IMEI


# 3.2.2.101
class MSISDN(BufBCD):
    _ID = BSSMAP_elm.MSISDN


# 3.2.2.103
class SpeechCodecElm(Envelope):
    _GEN = (
        # 3.2.2.104 Speech Codec
        Uint('FullIP', bl=1, dic={
            0: 'Compressed speech via RTP/UDP/IP is not selected for this Codec Type',
            1: 'AoIP with compressed speech via RTP/UDP/IP is selected for this Codec Type'}),
        Uint('PCMoIP', bl=1, dic={
            0: 'PCM over A interface with RTP/UDP/IP is not selected for this Codec Type',
            1: 'PCM over A-Interface via RTP/UPD/IP is selected for this Codec Type'}),
        Uint('PCMoTDM', bl=1, dic={
            0: 'PCM over A-Interface with TDM as transport is not selected for this Codec Type',
            1: 'PCM over A-Interface with TDM as transport is selected for this Codec Type'}),
        Uint('TFO', bl=1, dic={
            0: 'TFO Support is not selected for this Codec Type',
            1: 'TFO Support is selected for this Codec Type'}),
        # 3.2.2.103 Speech Codec List
        Uint('Type', bl=4, dic={
            0: 'GSM_FR',
            1: 'GSM_HR',
            2: 'GSM_EFR',
            3: 'FR_AMR',
            4: 'HR_AMR',
            9: 'FR_AMR-WB',
            11: 'OHR_AMR',
            12: 'OFR_AMR-WB',
            13: 'OHR_AMR-WB',
            15: 'CSData'}),
        # extension depending on the codecs supported
        Alt('Ext', GEN={
            0  : Buf('none', bl=0),
            1  : Buf('none', bl=0),
            2  : Buf('none', bl=0),
            3  : Uint16('CodecConfig', rep=REPR_HEX),
            4  : Uint16('CodecConfig', rep=REPR_HEX),
            9  : Uint8('CodecConfig', rep=REPR_HEX),
            11 : Uint16('CodecConfig', rep=REPR_HEX),
            12 : Uint8('CodecConfig', rep=REPR_HEX),
            13 : Uint8('CodecConfig', rep=REPR_HEX),
            15 : Envelope('CSData', GEN=(
                Uint8('ExtType'),
                Uint('R2', bl=1),
                Uint('R3', bl=1),
                Uint('spare', bl=6, rep=REPR_HEX)
                ))},
            DEFAULT=Buf('unk', bl=0),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


class SpeechCodecList(Sequence):
    _ID  = BSSMAP_elm.SPEECH_CODEC_LIST
    _GEN = SpeechCodecElm()


# 3.2.2.126
class SelectedPLMNID(PLMN):
    _ID = BSSMAP_elm.SELECTED_PLMNID


# 3.2.2.127
class LastEUTRANPLMNID(PLMN):
    _ID = BSSMAP_elm.LAST_EUTRAN_PLMNID


# 3.2.2.128
class OldLAI(LAI):
    _ID = BSSMAP_elm.OLD_LAI


# 3.2.2.130
class SelectedOperator(PLMN):
    _ID = BSSMAP_elm.SELECTED_OPERATOR


# 3.2.2.131
class PSRegisteredOperator(PLMN):
    _ID = BSSMAP_elm.PS_REG_OPERATOR


# 3.2.2.132
class CSRegisteredOperator(PLMN):
    _ID = BSSMAP_elm.CS_REG_OPERATOR


# 3.2.2.0
# Generic BSSMAP Signalling Element structure and automation

# global dict of BSSMAP SE ID: (SE name, length prefix ind, dedicated struct)
# length prefix ind:
#   >= 0 indicates no length prefix present and fixed length
#   == -1 indicates length prefix present
BSSMAPElm_dict = {
    1 : ('Circuit Identity Code', 2, None),
    3 : ('Resource Available', 20, None),
    4 : ('Cause', -1, Cause),
    5 : ('Cell Identifier', -1, CellIdentifier),
    6 : ('Priority', -1, None),
    7 : ('Layer 3 Header Information', -1, None),
    8 : ('IMSI', -1, IMSI),
    9 : ('TMSI', -1, TMSI),
    10 : ('Encryption Information', -1, EncryptionInfo),
    11 : ('Channel Type', -1, None),
    12 : ('Periodicity', 1, None),
    13 : ('Extended Resource Indicator', 1, None),
    14 : ('Number Of MSs', 1, None),
    18 : ('Classmark Information Type 2', -1, MSCm2),
    19 : ('Classmark Information Type 3', -1, None),
    20 : ('Interference Band To Be Used', 1, None),
    21 : ('RR Cause', 1, None),
    23 : ('Layer 3 Information', -1, None),
    24 : ('DLCI', 1, None),
    25 : ('Downlink DTX Flag', 1, None),
    26 : ('Cell Identifier List', -1, CellIdentifierList),
    27 : ('Response Request', 0, None),
    28 : ('Resource Indication Method', 1, None),
    29 : ('Classmark Information Type 1', 1, MSCm1),
    30 : ('Circuit Identity Code List', -1, None),
    31 : ('Diagnostic', -1, None),
    32 : ('Layer 3 Message Contents', -1, None),
    33 : ('Chosen Channel', 1, None),
    34 : ('Total Resource Accessible', 4, None),
    35 : ('Cipher Response Mode', 1, None),
    36 : ('Channel Needed', 1, None),
    37 : ('Trace Type', 1, None),
    38 : ('TriggerID', -1, None),
    39 : ('Trace Reference', 2, None),
    40 : ('TransactionID', -1, None),
    41 : ('Mobile Identity', -1, MobileIdentity),
    42 : ('OMCId', -1, None),
    43 : ('Forward Indicator', 1, None),
    44 : ('Chosen Encryption Algorithm', 1, None),
    45 : ('Circuit Pool', 1, None),
    46 : ('Circuit Pool List', -1, None),
    47 : ('Time Indication', 1, None),
    48 : ('Resource Situation', -1, None),
    49 : ('Current Channel type 1', 1, None),
    50 : ('Queueing Indicator', 1, None),
    64 : ('Speech Version', 1, None),
    51 : ('Assignment Requirement', 1, None),
    53 : ('Talker Flag', -1, None),
    54 : ('Connection Release Requested', 0, None),
    55 : ('Group Call Reference', -1, GroupCallRef),
    56 : ('eMLPP Priority', 1, None),
    57 : ('Configuration Evolution Indication', 1, None),
    58 : ('Old BSS to New BSS Information', -1, None),
    59 : ('LSA Identifier', -1, None),
    60 : ('LSA Identifier List', -1, None),
    61 : ('LSA Information', -1, None),
    62 : ('LCS QoS', -1, None),
    63 : ('LSA access control suppression', 1, None),
    67 : ('LCS Priority', -1, None),
    68 : ('Location Type', -1, None),
    69 : ('Location Estimate', -1, None),
    70 : ('Positioning Data', -1, None),
    71 : ('LCS Cause', -1, None),
    72 : ('LCS Client Type', -1, None),
    73 : ('APDU', -1, None),
    74 : ('Network Element Identity', -1, None),
    75 : ('GPS Assistance Data', -1, None),
    76 : ('Deciphering Keys', -1, None),
    77 : ('Return Error Request', -1, None),
    78 : ('Return Error Cause', -1, None),
    79 : ('Segmentation', -1, None),
    80 : ('Service Handover', -1, None),
    81 : ('Source RNC to target RNC transparent information (UMTS)', -1, None),
    82 : ('Source RNC to target RNC transparent information (cdma2000)', -1, None),
    83 : ('GERAN Classmark', -1, None),
    84 : ('GERAN BSC Container', -1, None),
    85 : ('Velocity Estimate', -1, None),
    97 : ('New BSS to Old BSS Information', -1, None),
    99 : ('Inter-System Information', -1, None),
    100 : ('SNA Access Information', -1, None),
    101 : ('VSTK_RAND Information', -1, None),
    102 : ('VSTK Information', -1, None),
    103 : ('Paging Information', 1, None),
    104 : ('IMEI', -1, IMEI),
    105 : ('VGCS Feature Flags', -1, None),
    106 : ('Talker Priority', 1, None),
    107 : ('Emergency Set Indication', 0, None),
    108 : ('Talker Identity', -1, None),
    109 : ('Cell Identifier List Segment', -1, None),
    110 : ('SMS to VGCS', -1, None),
    111 : ('VGCS Talker Mode', -1, None),
    112 : ('VGCS/VBS Cell Status', -1, None),
    113 : ('Cell Identifier List Segment for established cells', -1, None),
    114 : ('Cell Identifier List Segment for cells to be established', -1, None),
    115 : ('Cell Identifier List Segment for released cells - no user present', -1, None),
    116 : ('Cell Identifier List Segment for not established cells - no establishment possible', -1, None),
    117 : ('GANSS Assistance Data', -1, None),
    118 : ('GANSS Positioning Data', -1, None),
    119 : ('GANSS Location Type', -1, None),
    120 : ('Application Data', -1, None),
    121 : ('Data Identity', -1, None),
    122 : ('Application Data Information', -1, None),
    123 : ('MSISDN', -1, MSISDN),
    124 : ('AoIP Transport Layer Address', -1, None),
    125 : ('Speech Codec List', -1, SpeechCodecList),
    126 : ('Speech Codec', -1, None),
    127 : ('Call Identifier', 4, None),
    128 : ('Call Identifier List', -1, None),
    129 : ('A-Interface Selector for RESET', 1, None),
    131 : ('Kc128', 16, None),
    132 : ('CSG Identifier', -1, None),
    133 : ('Redirect Attempt Flag', 0, None),
    134 : ('Reroute Reject Cause ', 1, None),
    135 : ('Send Sequence Number', 1, None),
    136 : ('Reroute complete outcome', 1, None),
    137 : ('Global Call Reference', -1, None),
    138 : ('LCLS-Configuration', 1, None),
    139 : ('LCLS-Connection-Status-Control', 1, None),
    140 : ('LCLS-Correlation-Not-Needed', 0, None),
    141 : ('LCLS-BSS-Status', 1, None),
    142 : ('LCLS-Break-Request', 0, None),
    143 : ('CSFB Indication', 0, None),
    144 : ('CS to PS SRVCC', 0, None),
    145 : ('Source eNB to target eNB transparent information (E-UTRAN)', -1, None),
    146 : ('CS to PS SRVCC Indication', 0, None),
    147 : ('CN to MS transparent information', -1, None),
    148 : ('Selected PLMN ID', 3, SelectedPLMNID),
    149 : ('Last used E-UTRAN PLMN ID', -1, LastEUTRANPLMNID),
    150 : ('Old Location Area Identification', -1, OldLAI),
    151 : ('Attach Indicator', 0, None),
    152 : ('Selected Operator', 3, SelectedOperator),
    153 : ('PS Registered Operator', 3, PSRegisteredOperator),
    154 : ('CS Registered Operator', 3, CSRegisteredOperator),
    }


class BSSMAP_SE(Envelope):
    """BSSMAP Signalling Element
    TS 48.008, section 3.2.2
    """
    
    # LUT for SE ID -> SE name, length, structure
    _LUT = BSSMAPElm_dict
    
    _GEN = (
        Uint8('ID', val=BSSMAP_elm.CAUSE, dic={k: v[0] for k, v in BSSMAPElm_dict.items()}),
        Uint8('Len'), # transparent for fixed length element, otherwise value automated
        Buf('Val', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_transauto(lambda: self._get_selen() != -1)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self._set_val_bl())
    
    # Len value and Val length automation
    def _get_selen(self):
        se_id = self[0].get_val()
        try:
            return self._LUT[se_id][1]
        except KeyError:
            # for unknown SEs that could be defined in the future, we bet on variable length SE
            return -1
    
    def _set_val_bl(self):
        se_len = self._get_selen()
        if se_len == -1:
            return self['Len'].get_val()<<3
        else:
            return se_len<<3
    
    # generic / dedicated Val structure mgmt
    def _init_val_attr(self):
        if isinstance(self['Val'], Buf):
            self._val_raw = self['Val']
            self._val_cls = None
        else:
            self._val_raw = None
            self._val_cls = self['Val']
    
    def _set_val_raw(self):
        if not hasattr(self, '_val_raw'):
            self._init_val_attr()
        if self._val_raw is None:
            self._val_raw = Buf('Val', rep=REPR_HEX)
            self._val_raw.set_blauto(lambda: self._set_val_bl())
        if self['Val'] != self._val_raw:
            self.replace(self['Val'], self._val_raw)
    
    def _set_val_cls(self):
        if not hasattr(self, '_val_cls'):
            self._init_val_attr()
        se_id = self['ID'].get_val()
        if se_id in self._LUT and self._LUT[se_id][2] is not None \
        and (self._val_cls is None or self._val_cls._ID != se_id):
            # (re)set the appropriate SE dedicated structure
            # set the structure name to the SE top level, so that the internal structure
            # always stays uniform
            self._val_cls = self._LUT[se_id][2]('Val')
            self._name = self._val_cls.__class__.__name__
            if not hasattr(self._val_cls, '_bl') or self._val_cls._bl is None:
                self._val_cls.set_blauto(lambda: self._set_val_bl())
        if self._val_cls is not None and self['Val'] != self._val_cls:
            self.replace(self['Val'], self._val_cls)
    
    def _set_id_val(self, seid, val):
        if seid is not None:
            self['ID'].set_val(seid)
        if isinstance(val, bytes_types):
            self._set_val_raw()
            self['Val'].set_val(val)
        else:
            self._set_val_cls()
            if val:
                self['Val'].set_val(val)
    
    # set_val() method can be used with both type of values for Val:
    # - bytes, assigned to the Buf raw object
    # - dedicated type, assigned to the dedicated parameter structure
    def set_val(self, val):
        if isinstance(val, (tuple, list)) and len(val) == 3:
            self._set_id_val(val[0], val[2])
            if not self[1].get_trans():
                self[1].set_val(val[1])
        elif isinstance(val, dict):
            if 'Val' in val:
                if 'ID' in val:
                    self._set_id_val(val['ID'], val['Val'])
                else:
                    self._set_tag_val(None, val['Val'])
                if 'Len' in val:
                    self[1].set_val(val['Len'])
            else:
                Envelope.set_val(self, val)
                self._set_val_cls()
        else:
            Envelope.set_val(self, val)
    
    # _from_char() method attempts to decode Val with the dedicated parameter structure
    # and fallbacks to the Buf raw object if failing with the former.
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self[1]._from_char(char)
        # 1st try decoding with the structured Data
        char_cur = char._cur
        self._set_val_cls()
        try:
            self[2]._from_char(char)
        except PycrateErr as err:
            # 2nd try decoding as raw Data
            char._cur = char_cur
            self._set_val_raw()
            self[2]._from_char(char)


class BSSMAP_SES(Sequence):
    """Sequence of BSSMAP Signalling Element
    TS 48.008, section 3.2.2
    """
    
    _GEN = BSSMAP_SE()

    def get_elm_first(self, seid):
        """return the first element corresponding to the provided `seid', or None
        """
        for elm in self._content:
            if elm['ID'].get_val() == seid:
                return elm[2]
        return None


#------------------------------------------------------------------------------#
# BSSMAP messages
#------------------------------------------------------------------------------#

class BSSMAPType:
    CLEAR_REQUEST    = 0x22
    CLEAR_COMMAND    = 0x20
    CLEAR_COMPLETE   = 0x21
    COMMON_ID        = 0x2f
    RESET            = 0x30
    RESET_ACK        = 0x31
    PAGING           = 0x52
    COMPLETE_LAYER_3_INFORMATION = 0x57


_BSSMAPType_dict = {
    1 : 'ASSIGNMENT REQUEST',
    2 : 'ASSIGNMENT COMPLETE',
    3 : 'ASSIGNMENT FAILURE',
    8 : 'CHANNEL MODIFY REQUEST',
    16 : 'HANDOVER REQUEST ',
    17 : 'HANDOVER REQUIRED',
    18 : 'HANDOVER REQUEST ACKNOWLEDGE',
    19 : 'HANDOVER COMMAND',
    20 : 'HANDOVER COMPLETE',
    21 : 'HANDOVER SUCCEEDED',
    22 : 'HANDOVER FAILURE',
    23 : 'HANDOVER PERFORMED',
    24 : 'HANDOVER CANDIDATE ENQUIRE',
    25 : 'HANDOVER CANDIDATE RESPONSE',
    26 : 'HANDOVER REQUIRED REJECT',
    27 : 'HANDOVER DETECT',
    112 : 'INTERNAL HANDOVER REQUIRED',
    113 : 'INTERNAL HANDOVER REQUIRED REJECT',
    114 : 'INTERNAL HANDOVER COMMAND',
    115 : 'INTERNAL HANDOVER ENQUIRY',
    32 : 'CLEAR COMMAND',
    33 : 'CLEAR COMPLETE',
    34 : 'CLEAR REQUEST',
    37 : 'SAPI "N" REJECT',
    38 : 'CONFUSION',
    40 : 'SUSPEND',
    41 : 'RESUME',
    43 : 'PERFORM LOCATION REQUEST',
    44 : 'LSA INFORMATION ',
    45 : 'PERFORM LOCATION RESPONSE',
    46 : 'PERFORM LOCATION ABORT',
    47 : 'COMMON ID',
    120 : 'REROUTE COMMAND',
    121 : 'REROUTE COMPLETE',
    48 : 'RESET',
    49 : 'RESET ACKNOWLEDGE',
    50 : 'OVERLOAD',
    52 : 'RESET CIRCUIT',
    53 : 'RESET CIRCUIT ACKNOWLEDGE',
    54 : 'MSC INVOKE TRACE',
    55 : 'BSS INVOKE TRACE',
    58 : 'CONNECTIONLESS INFORMATION',
    61 : 'RESET IP RESOURCE',
    62 : 'RESET IP RESOURCE ACKNOWLEDGE',
    63 : 'MS REGISTRATION ENQUIRY',
    56 : 'MS REGISTRATION ENQUIRY RESPONSE',
    64 : 'BLOCK',
    65 : 'BLOCKING ACKNOWLEDGE',
    66 : 'UNBLOCK',
    67 : 'UNBLOCKING ACKNOWLEDGE',
    68 : 'CIRCUIT GROUP BLOCK',
    69 : 'CIRCUIT GROUP BLOCKING ACKNOWLEDGE',
    70 : 'CIRCUIT GROUP UNBLOCK',
    71 : 'CIRCUIT GROUP UNBLOCKING ACKNOWLEDGE',
    72 : 'UNEQUIPPED CIRCUIT',
    78 : 'CHANGE CIRCUIT',
    79 : 'CHANGE CIRCUIT ACKNOWLEDGE',
    80 : 'RESOURCE REQUEST',
    81 : 'RESOURCE INDICATION',
    82 : 'PAGING',
    83 : 'CIPHER MODE COMMAND',
    84 : 'CLASSMARK UPDATE',
    85 : 'CIPHER MODE COMPLETE',
    86 : 'QUEUING INDICATION',
    87 : 'COMPLETE LAYER 3 INFORMATION',
    88 : 'CLASSMARK REQUEST',
    89 : 'CIPHER MODE REJECT',
    90 : 'LOAD INDICATION',
    4 : 'VGCS/VBS SETUP',
    5 : 'VGCS/VBS SETUP ACK',
    6 : 'VGCS/VBS SETUP REFUSE',
    7 : 'VGCS/VBS ASSIGNMENT REQUEST',
    28 : 'VGCS/VBS ASSIGNMENT RESULT',
    29 : 'VGCS/VBS ASSIGNMENT FAILURE',
    30 : 'VGCS/VBS QUEUING INDICATION',
    59 : 'VGCS/VBS ASSIGNMENT STATUS',
    60 : 'VGCS/VBS AREA CELL INFO',
    31 : 'UPLINK REQUEST',
    39 : 'UPLINK REQUEST ACKNOWLEDGE',
    73 : 'UPLINK REQUEST CONFIRMATION',
    74 : 'UPLINK RELEASE INDICATION',
    75 : 'UPLINK REJECT COMMAND',
    76 : 'UPLINK RELEASE COMMAND',
    77 : 'UPLINK SEIZED COMMAND',
    96 : 'VGCS ADDITIONAL INFORMATION',
    97 : 'VGCS SMS',
    98 : 'NOTIFICATION DATA',
    99 : 'UPLINK APPLICATION DATA',
    116 : 'LCLS-CONNECT-CONTROL',
    117 : 'LCLS-CONNECT-CONTROL-ACK',
    118 : 'LCLS-NOTIFICATION',
    }


class BSSMAP(Envelope):
    """BSSMAP Message
    TS 48.008, section 3.2.1
    """
    _GEN = (
        Uint8('Type', val=BSSMAPType.CLEAR_REQUEST, dic=_BSSMAPType_dict),
        BSSMAP_SES('SES'),
        )

