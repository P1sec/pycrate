# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2016. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
# *
# *--------------------------------------------------------
# * File Name : pycrate_mobile/GSMTAP.py
# * Created : 2016-04-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.elt import Envelope, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base import *
from pycrate_core.repr import *

# GSMTAP header format:
# http://cgit.osmocom.org/libosmocore/tree/include/osmocom/core/gsmtap.h
#
#/* GSMTAP is a generic header format for GSM protocol captures,
# * it uses the IANA-assigned UDP port number 4729 and carries
# * payload in various formats of GSM interfaces such as Um MAC
# * blocks or Um bursts.
# *
# * Example programs generating GSMTAP data are airprobe
# * (http://airprobe.org/) or OsmocomBB (http://bb.osmocom.org/)
# */

Type_dict = {
    0x01 : "UM",
    0x02 : "ABIS",
    0x03 : "UM_BURST",
    0x04 : "SIM",
    0x05 : "TETRA_I1",
    0x06 : "TETRA_I1_BURST",
    0x07 : "WIMAX_BURST",
    0x08 : "GB_LLC",
    0x09 : "GB_SNDCP",
    0x0a : "GMR1_UM",
    0x0b : "UMTS_RLC_MAC",
    0x0c : "UMTS_RRC",
    0x0d : "LTE_RRC",
    0x0e : "LTE_MAC"
    }

TypeUMBurst_dict = {
    0x00 : "UNKNOWN",
    0x01 : "FCCH",
    0x02 : "PARTIAL_SCH",
    0x03 : "SCH",
    0x04 : "CTS_SCH",
    0x05 : "COMPACT_SCH",
    0x06 : "NORMAL",
    0x07 : "DUMMY",
    0x08 : "ACCESS",
    0x09 : "NONE"
    }

TypeWiMAXBurst_dict = {
    0x10 : "CDMA_CODE",
    0x11 : "FCH",
    0x12 : "FFB",
    0x13 : "PDU",
    0x14 : "HACK",
    0x15 : "PHY_ATTRIBUTES"
    }

TypeUM_dict = {
    0x00 : "UNKNOWN",
    0x01 : "BCCH",
    0x02 : "CCCH",
    0x03 : "RACH",
    0x04 : "AGCH",
    0x05 : "PCH",
    0x06 : "SDCCH",
    0x07 : "SDCCH4",
    0x08 : "SDCCH8",
    0x09 : "TCH_F",
    0x0a : "TCH_H",
    0x0b : "PACCH",
    0x0c : "CBCH52",
    0x0d : "PDCH",
    0x0e : "PTCCH",
    0x0f : "CBCH51",
    0x20 : "GPRS_CS_BASE",
    0x21 : "GPRS_CS_1",
    0x22 : "GPRS_CS_2",
    0x23 : "GPRS_CS_3",
    0x24 : "GPRS_CS_4",
    0x30 : "EGPRS_MCS_BASE",
    0x31 : "EGPRS_MCS_1",
    0x32 : "EGPRS_MCS_2",
    0x33 : "EGPRS_MCS_3",
    0x34 : "EGPRS_MCS_4",
    0x35 : "EGPRS_MCS_5",
    0x36 : "EGPRS_MCS_6",
    0x37 : "EGPRS_MCS_7",
    0x38 : "EGPRS_MCS_8",
    0x39 : "EGPRS_MCS_9",
    0x80 : "ACCH"
    }

TypeTETRA_dict = {
    0x01 : "BSCH",
    0x02 : "AACH",
    0x03 : "SCH_HU",
    0x04 : "SCH_HD",
    0x05 : "SCH_F",
    0x06 : "BNCH",
    0x07 : "STCH",
    0x08 : "TCH_F"
    }

TypeGMR_dict = {
    0x00 : "UNKNOWN",
    0x01 : "BCCH",
    0x02 : "CCCH",
    0x03 : "PCH",
    0x04 : "AGCH",
    0x05 : "BACH",
    0x06 : "RACH",
    0x07 : "CBCH",
    0x08 : "SDCCH",
    0x09 : "TACCH",
    0x0a : "GBCH",
    #0x01 : "GMR1_SACCH", # to be combined with _TCH{6,9}
    #0x02 : "GMR1_FACCH", # to be combines with _TCH{3,6,9}
    #0x03 : "GMR1_DKAB", # to be combined with _TCH3
    0x10 : "GMR1_TCH3",
    0x14 : "GMR1_TCH6",
    0x18 : "GMR1_TCH9"
    }

TypeUMTSRLC_dict = {
    0x01 : "PCCH",
    0x02 : "CCCH",
    0x03 : "DCCH",
    }

TypeUMTSRRC_dict = {
    0 : 'DL_DCCH_Message',
    1 : 'UL_DCCH_Message',
    2 : 'DL_CCCH_Message',
    3 : 'UL_CCCH_Message',
    4 : 'PCCH_Message',
    5 : 'DL_SHCCH_Message',
    6 : 'UL_SHCCH_Message',
    7 : 'BCCH_FACH_Message',
    8 : 'BCCH_BCH_Message',
    9 : 'MCCH_Message',
    10 : 'MSCH_Message',
    11 : 'HandoverToUTRANCommand',
    12 : 'InterRATHandoverInfo',
    13 : 'SystemInformation_BCH',
    14 : 'System_Information_Container',
    15 : 'UE_RadioAccessCapabilityInfo',
    16 : 'MasterInformationBlock',
    17 : 'SysInfoType1',
    18 : 'SysInfoType2',
    19 : 'SysInfoType3',
    20 : 'SysInfoType4',
    21 : 'SysInfoType5',
    22 : 'SysInfoType5bis',
    23 : 'SysInfoType6',
    24 : 'SysInfoType7',
    25 : 'SysInfoType8',
    26 : 'SysInfoType9',
    27 : 'SysInfoType10',
    28 : 'SysInfoType11',
    29 : 'SysInfoType11bis',
    30 : 'SysInfoType12',
    31 : 'SysInfoType13',
    32 : 'SysInfoType13_1',
    33 : 'SysInfoType13_2',
    34 : 'SysInfoType13_3',
    35 : 'SysInfoType13_4',
    36 : 'SysInfoType14',
    37 : 'SysInfoType15',
    38 : 'SysInfoType15bis',
    39 : 'SysInfoType15_1',
    40 : 'SysInfoType15_1bis',
    41 : 'SysInfoType15_2',
    42 : 'SysInfoType15_2bis',
    43 : 'SysInfoType15_2ter',
    44 : 'SysInfoType15_3',
    45 : 'SysInfoType15_3bis',
    46 : 'SysInfoType15_4',
    47 : 'SysInfoType15_5',
    48 : 'SysInfoType15_6',
    49 : 'SysInfoType15_7',
    50 : 'SysInfoType15_8',
    51 : 'SysInfoType16',
    52 : 'SysInfoType17',
    53 : 'SysInfoType18',
    54 : 'SysInfoType19',
    55 : 'SysInfoType20',
    56 : 'SysInfoType21',
    57 : 'SysInfoType22',
    58 : 'SysInfoTypeSB1',
    59 : 'SysInfoTypeSB2',
    60 : 'ToTargetRNC_Container',
    61 : 'TargetRNC_ToSourceRNC_Container'
    }

TypeLTERRC_dict = {
    0x01 : "BCCH",
    0x02 : "CCCH",
    0x03 : "DCCH",
    0x04 : "MCCH",
    0x05 : "PCCH",
    0x06 : "DTCH",
    0x07 : "MTCH"
    }

SubTypeDictLU_dict = {
    1 : TypeUM_dict,
    3 : TypeUMBurst_dict,
    5 : TypeTETRA_dict,
    7 : TypeWiMAXBurst_dict,
    10 : TypeGMR_dict,
    11 : TypeUMTSRLC_dict,
    12 : TypeUMTSRRC_dict,
    13 : TypeLTERRC_dict
    }


"""
Mapping of the osmocom / wireshark gsmtap header structure

see: http://cgit.osmocom.org/libosmocore/tree/include/osmocom/core/gsmtap.h

struct gsmtap_hdr {
    uint8_t version;	/*!< version, set to 0x01 currently */
    uint8_t hdr_len;	/*!< length in number of 32bit words */
    uint8_t type;		/*!< see GSMTAP_TYPE_* */
    uint8_t timeslot;	/*!< timeslot (0..7 on Um) */

    uint16_t arfcn;		/*!< ARFCN (frequency) */
    int8_t signal_dbm;	/*!< signal level in dBm */
    int8_t snr_db;		/*!< signal/noise ratio in dB */

    uint32_t frame_number;	/*!< GSM Frame Number (FN) */

    uint8_t sub_type;	/*!< Type of burst/channel, see above */
    uint8_t antenna_nr;	/*!< Antenna Number */
    uint8_t sub_slot;	/*!< sub-slot within timeslot */
    uint8_t res;		/*!< reserved for future use (RFU) */

} __attribute__((packed));
"""

class gsmtap_hdr(Envelope):
    _GEN = (
        Uint8('version', val=1),
        Uint8('hdr_len', val=4), # header length in 32-bit words
        Uint8('type', val=1, dic=Type_dict),
        Uint8('timeslot'), # GSM timeslot (0..7)
        Uint('PCS', bl=1),
        Uint('uplink', bl=1),
        Uint('arfcn', bl=14),
        Int8('signal_dbm'),
        Int8('snr_db'),
        Uint32('frame_number'), # GSM FN
        Uint8('sub_type'), # type of channel
        Uint8('antenna_nr'), # antenna number
        Uint8('sub_slot'), # sub-slot within timeslot
        Uint8('res')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[9].set_dicauto(self._set_subtype_dic)
    
    def _set_subtype_dic(self):
        return SubTypeDictLU_dict.get(self[2].get_val(), {})

