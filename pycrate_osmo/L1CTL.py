# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1sec.
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
# * File Name : pycrate_osmo/L1CTL.py
# * Created : 2020-01-14
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# osmocom-bb l1ctl_proto.h wrapper
# https://gerrit.osmocom.org/plugins/gitiles/osmocom-bb/+/master/include/l1ctl_proto.h
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *

from pycrate_mobile.TS48058_Abis import *

#------------------------------------------------------------------------------#
# Enumerations
#------------------------------------------------------------------------------#

# message types
L1CTL_NONE          = 0
L1CTL_FBSB_REQ      = 1
L1CTL_FBSB_CONF     = 2
L1CTL_DATA_IND      = 3
L1CTL_RACH_REQ      = 4
L1CTL_DM_EST_REQ    = 5
L1CTL_DATA_REQ      = 6
L1CTL_RESET_IND     = 7
L1CTL_PM_REQ        = 8 # power measurement
L1CTL_PM_CONF       = 9 # power measurement
L1CTL_ECHO_REQ      = 10
L1CTL_ECHO_CONF     = 11
L1CTL_RACH_CONF     = 12
L1CTL_RESET_REQ     = 13
L1CTL_RESET_CONF    = 14
L1CTL_DATA_CONF     = 15
L1CTL_CCCH_MODE_REQ = 16
L1CTL_CCCH_MODE_CONF = 17
L1CTL_DM_REL_REQ    = 18
L1CTL_PARAM_REQ     = 19
L1CTL_DM_FREQ_REQ   = 20
L1CTL_CRYPTO_REQ    = 21
L1CTL_SIM_REQ       = 22
L1CTL_SIM_CONF      = 23
L1CTL_TCH_MODE_REQ  = 24
L1CTL_TCH_MODE_CONF = 25
L1CTL_NEIGH_PM_REQ  = 26
L1CTL_NEIGH_PM_IND  = 27
L1CTL_TRAFFIC_REQ   = 28
L1CTL_TRAFFIC_CONF  = 29
L1CTL_TRAFFIC_IND   = 30
L1CTL_BURST_IND     = 31
# configure TBF for uplink/downlink (GPRS)
L1CTL_TBF_CFG_REQ   = 32
L1CTL_TBF_CFG_CONF  = 33
L1CTL_DATA_TBF_REQ  = 34
L1CTL_DATA_TBF_CONF = 35
# Extended (11-bit) RACH (see 3GPP TS 05.02, section 5.2.7)
L1CTL_EXT_RACH_REQ  = 36

L1CTLMsgType_dict = {
    0 : 'L1CTL_NONE',
    1 : 'L1CTL_FBSB_REQ',
    2 : 'L1CTL_FBSB_CONF',
    3 : 'L1CTL_DATA_IND',
    4 : 'L1CTL_RACH_REQ',
    5 : 'L1CTL_DM_EST_REQ',
    6 : 'L1CTL_DATA_REQ',
    7 : 'L1CTL_RESET_IND',
    8 : 'L1CTL_PM_REQ',
    9 : 'L1CTL_PM_CONF',
    10 : 'L1CTL_ECHO_REQ',
    11 : 'L1CTL_ECHO_CONF',
    12 : 'L1CTL_RACH_CONF',
    13 : 'L1CTL_RESET_REQ',
    14 : 'L1CTL_RESET_CONF',
    15 : 'L1CTL_DATA_CONF',
    16 : 'L1CTL_CCCH_MODE_REQ',
    17 : 'L1CTL_CCCH_MODE_CONF',
    18 : 'L1CTL_DM_REL_REQ',
    19 : 'L1CTL_PARAM_REQ',
    20 : 'L1CTL_DM_FREQ_REQ',
    21 : 'L1CTL_CRYPTO_REQ',
    22 : 'L1CTL_SIM_REQ',
    23 : 'L1CTL_SIM_CONF',
    24 : 'L1CTL_TCH_MODE_REQ',
    25 : 'L1CTL_TCH_MODE_CONF',
    26 : 'L1CTL_NEIGH_PM_REQ',
    27 : 'L1CTL_NEIGH_PM_IND',
    28 : 'L1CTL_TRAFFIC_REQ',
    29 : 'L1CTL_TRAFFIC_CONF',
    30 : 'L1CTL_TRAFFIC_IND',
    31 : 'L1CTL_BURST_IND',
    32 : 'L1CTL_TBF_CFG_REQ',
    33 : 'L1CTL_TBF_CFG_CONF',
    34 : 'L1CTL_DATA_TBF_REQ',
    35 : 'L1CTL_DATA_TBF_CONF',
    36 : 'L1CTL_EXT_RACH_REQ'
    }


# CCCH mode
L1CTL_CCCH_MODE_NONE = 0
L1CTL_CCCH_MODE_NON_COMBINED = 1
L1CTL_CCCH_MODE_COMBINED = 2
L1CTL_CCCH_MODE_COMBINED_CBCH = 3

L1CTLCCCHMode_dict = {
    0 : 'L1CTL_CCCH_MODE_NONE',
    1 : 'L1CTL_CCCH_MODE_NON_COMBINED',
    2 : 'L1CTL_CCCH_MODE_COMBINED',
    3 : 'L1CTL_CCCH_MODE_COMBINED_CBCH'
    }


# TCH mode (from gsm_04_08.h)
GSM48_CMODE_SIGN  = 0x00,
GSM48_CMODE_SPEECH_V1 = 0x01,
GSM48_CMODE_SPEECH_EFR = 0x21,
GSM48_CMODE_SPEECH_AMR = 0x41,
GSM48_CMODE_DATA_14k5 = 0x0f,
GSM48_CMODE_DATA_12k0 = 0x03,
GSM48_CMODE_DATA_6k0  = 0x0b,
GSM48_CMODE_DATA_3k6  = 0x23,

GSM48ChanMode_dict = {
    0 : 'GSM48_CMODE_SIGN',
    1 : 'GSM48_CMODE_SPEECH_V1',
    33: 'GSM48_CMODE_SPEECH_EFR',
    65: 'GSM48_CMODE_SPEECH_AMR',
    15: 'GSM48_CMODE_DATA_14k5',
    3 : 'GSM48_CMODE_DATA_12k0',
    11: 'GSM48_CMODE_DATA_6k0',
    35: 'GSM48_CMODE_DATA_3k6',
    }


# neighbour mode
L1CTL_NEIGH_MODE_NONE = 0
L1CTL_NEIGH_MODE_PM = 1
L1CTL_NEIGH_MODE_SB = 2

L1CTLNeighMode_dict = {
    0 : 'L1CTL_NEIGH_MODE_NONE',
    1 : 'L1CTL_NEIGH_MODE_PM',
    2 : 'L1CTL_NEIGH_MODE_SB'
    }


# Coding Scheme
L1CTL_CS_NONE       = 0
L1CTL_CS1           = 1
L1CTL_CS2           = 2
L1CTL_CS3           = 3
L1CTL_CS4           = 4
L1CTL_MCS1          = 5
L1CTL_MCS2          = 6
L1CTL_MCS3          = 7
L1CTL_MCS4          = 8
L1CTL_MCS5          = 9
L1CTL_MCS6          = 10
L1CTL_MCS7          = 11
L1CTL_MCS8          = 12
L1CTL_MCS9          = 13

L1CTLCodScheme_dict = {
    0 : 'L1CTL_CS_NONE',
    1 : 'L1CTL_CS1',
    2 : 'L1CTL_CS2',
    3 : 'L1CTL_CS3',
    4 : 'L1CTL_CS4',
    5 : 'L1CTL_MCS1',
    6 : 'L1CTL_MCS2',
    7 : 'L1CTL_MCS3',
    8 : 'L1CTL_MCS4',
    9 : 'L1CTL_MCS5',
    10: 'L1CTL_MCS6',
    11: 'L1CTL_MCS7',
    12: 'L1CTL_MCS8',
    13: 'L1CTL_MCS9',
    }


# baseband reset
L1CTL_RES_T_BOOT = 0
L1CTL_RES_T_FULL = 1
L1CTL_RES_T_SCHED = 2

L1CTLReset_dict = {
	0 : 'L1CTL_RES_T_BOOT',
	1 : 'L1CTL_RES_T_FULL',
	2 : 'L1CTL_RES_T_SCHED',
    }


class ARFCNFlags(Envelope):
    _GEN = (
        Uint('PCS', bl=1),
        Uint('Uplink', bl=1),
        Uint('spare', bl=6),
        )

class ARFCNBand(Envelope):
    _GEN = (
        ARFCNFlags('Flags'),
        Uint('ARFCN', bl=11),
        )


#------------------------------------------------------------------------------#
# Message parameters
#------------------------------------------------------------------------------#

###
# downlink info
# down from the BTS
###

class L1CTLInfoDL(Envelope):
    _GEN = (
        ChannelNumber(),    # GSM 08.58 channel number (9.3.1)
        LinkIdentifier(),   # GSM 08.58 link identifier (9.3.2)
        ARFCNBand('ARFCN'),
        Uint32('FrameNr'),
        Uint8('RxLevel'),   # 0 .. 63 in typical GSM notation (dBm+110)
        Uint8('SNR'),       # Signal/Noise Ration (dB)
        Uint8('NumBitErr'),
        Uint8('FireCRC'),
        )


# new CCCH was found. This is following the header
class L1CTLFBSBConf(Envelope):
    _GEN = (
        L1CTLInfoDL(),
        Uint16('InitialFreqErr'),
        Uint8('Result'),
        Uint8('BSIC')
        )


# CCCH mode was changed
class L1CTLCCCHModeConf(Envelope):
    _GEN = (
        Uint8('CCCHMode', dic=L1CTLCCCHMode_dict),
        Uint24('pad', rep=REPR_HEX)
        )


# TCH mode was changed
class L1CTLTCHModeConf(Envelope):
    _GEN = (
        L1CTLInfoDL(),
        Uint8('TCHMode', dic=GSM48ChanMode_dict),
        Uint8('AudioMode', ),
        Uint16('pad', rep=REPR_HEX)
        )


# data on the CCCH was found. This is following the header
class L1CTLDataInd(Envelope):
    _GEN = (
        L1CTLInfoDL(),
        Buf('Payload', bl=184, rep=REPR_HEX) # 23 bytes, GSM broadcast
        )


# traffic from the network
class L1CTLTrafficInd(Envelope):
    _GEN = (
        L1CTLInfoDL(),
        Buf('Payload', rep=REPR_HEX)
        )


###
# uplink info
###

class L1CTLInfoUL(Envelope):
    _GEN = (
        ChannelNumber(),    # GSM 08.58 channel number (9.3.1)
        LinkIdentifier(),   # GSM 08.58 link identifier (9.3.2)
        Uint16('pad', rep=REPR_HEX),
        Buf('Payload', rep=REPR_HEX)
        )


class L1CTLInfoULTBF(Envelope):
    _GEN = (
        Uint8('TBFNumber'),
        Uint8('CodingScheme', dic=L1CTLCodScheme_dict),
        Uint16('pad', rep=REPR_HEX),
        Buf('Payload', rep=REPR_HEX)
        )


# FBSB flags
class L1CTLFBSBFlags(Envelope):
    _GEN = (
        Uint('pad', bl=5, rep=REPR_HEX),
        Uint('SB', bl=1),
        Uint('FB1', bl=1),
        Uint('FB0', bl=1)
        )


# msg for FBSB_REQ
# the l1_info_ul header is in front
class L1CTLFBSBReq(Envelope):
    _GEN = (
        ARFCNBand('ARFCN'),
        Uint16('Timeout'),  # in TDMA frames
        Uint16('FreqErrThres1'),
        Uint16('FreqErrThres2'),
        Uint8('NumFreqErrAvg'),
        L1CTLFBSBFlags(),
        Uint8('SynchInfoIdx'),
        Uint8('CCCHMode', dic=L1CTLCCCHMode_dict),
        Uint8('RXLevExp')   # expected signal level
        )


# msg for CCCH_MODE_REQ
# the l1_info_ul header is in front
class L1CTLCCCHModeReq(Envelope):
    _GEN = (
        Uint8('CCCHMode', dic=L1CTLCCCHMode_dict),
        Uint24('pad', rep=REPR_HEX)
        )


# audio mode
class L1CTLAudioMode(Envelope):
    _GEN = (
        Uint('pad', bl=4),
        Uint('RXTrafficInd', bl=1),
        Uint('RXSpeaker', bl=1),
        Uint('TXTrafficReq', bl=1),
        Uint('TXMicrophone', bl=1)
        )


# msg for TCH_MODE_REQ
# the l1_info_ul header is in front
class L1CTLTCHModeReq(Envelope):
    _GEN = (
        L1CTLInfoUL(),
        Uint8('TCHMode', dic=GSM48ChanMode_dict),
        L1CTLAudioMode(),
        Uint16('pad', rep=REPR_HEX)
        )


# msg for RACH_REQ
# the l1_info_ul header is in front
class L1CTLRACHReq(Envelope):
    _GEN = (
        L1CTLInfoUL(),
        Uint8('RA'),
        Uint8('Combined'),
        Uint16('Offset')
        )

# RA: establishment cause + random ref
# 0b101xxxxx = emergency call
# 0b000xxxxx = LocUpdate (without NECI)
# 0b111xxxxx = SDCCH (without NECI)
# 0b0000xxxx = LocUpdate (with NECI)
# 0b0001xxxx = SDCCH (with NECI)


# msg for EXT_RACH_REQ
# the l1_info_ul header is in front
class L1CTLExtRACHReq(Envelope):
    _GEN = (
        L1CTLInfoUL(),
        Uint16('RA11'),
        Uint8('SynchSeq'),
        Uint8('Combined'),
        Uint16('Offset')
        )


# the l1_info_ul header is in front
class L1CTLParamReq(Envelope):
    _GEN = (
        L1CTLInfoUL(),
        Int8('TA'),
        Uint8('TXPower'),
        Uint16('pad', rep=REPR_HEX),
        )


class L1CTLDataReq(Envelope):
    _GEN = (
        L1CTLInfoUL(),
        Buf('Payload', rep=REPR_HEX)
        )


class L1CTL_H0(Envelope):
    _GEN = (
        ARFCNBand('ARFCN'),
        )


class L1CTL_H1(Envelope):
    _GEN = (
        Uint8('HSN'),
        Uint8('MAIO'),
        Uint8('N'),
        Uint8('pad', rep=REPR_HEX)
        ) + tuple(
        Uint16('MA_%i' % i) for i in range(64)
        )


class L1CTLDMEstReq(Envelope):
    _GEN = (
        Uint8('TSC'),
        Uint8('H'),
        Alt('L1CTL_H', GEN={
            0 : L1CTL_H0(),
            1 : L1CTL_H1()},
            DEFAULT=L1CTL_H0(),
            sel=lambda self: self.get_env()['H'].get_val()),
        Uint8('TCHMode', dic=GSM48ChanMode_dict),
        L1CTLAudioMode()
        )


class L1CTLDMFreqReq(Envelope):
    _GEN = (
        Uint16('FN'),
        Uint8('TSC'),
        Uint8('H'),
        Alt('L1CTL_H', GEN={
            0 : L1CTL_H0(),
            1 : L1CTL_H1()},
            DEFAULT=L1CTL_H0(),
            sel=lambda self: self.get_env()['H'].get_val()),
        )


# SIM auth computation
class L1CTLCryptoReq(Envelope):
    _GEN = (
        Uint8('Algo'),
        Uint8('KeyLen'),
        Buf('Key', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


# power measurement
class L1CTLPMReq(Envelope):
    _GEN = (
        Uint8('Type'),
        Uint24('pad', rep=REPR_HEX),
        Envelope('ARFCNRange', GEN=(
            ARFCNBand('ARFCNFrom'),
            ARFCNBand('ARFCNTo'))
        ))


class L1CTLPMConf(Array):
    _GEN = Envelope('ARFCNPM', GEN=(
        Uint16('ARFCN'),
        Uint8('PM'),
        Uint8('PM2')
        ))


# demodulated burst indicator
class L1CTLBurstInd(Envelope):
    _GEN = (
        Uint32('FrameNumber'),
        ARFCNBand('ARFCN'), # ARFCN + band + ul indicator
        ChannelNumber(),    # GSM 08.58 channel number (9.3.1)
        Uint8('Flags'),     # BI_FLG_xxx + burst_id = 2LSBs
        Uint8('RXLevel'),   # 0 .. 63 in typical GSM notation (dBm+110)
        Uint8('SNR'),       # Reported SNR >> 8 (0-255)
        Buf('Bits', bl=120, rep=REPR_HEX), # 114 bits + 2 steal bits. Filled MSB first
        )


# baseband reset
class L1CTLReset(Envelope):
    _GEN = (
        Uint8('Type', dic=L1CTLReset_dict),
        Uint24('pad', rep=REPR_HEX)
        )


# neighbour cell measurement
class L1CTLNeighPMReq(Envelope):
    _GEN = (
        Uint8('N'),
        Uint8('pad', rep=REPR_HEX),
        Array('ARFCNs', GEN=ARFCNBand('ARFCN'), num=64),
        Array('TNs', GEN=Uint8('TN'), num=64)
        )


class L1CTLNeighPMInd(Array):
    _GEN = Envelope('NeighPM', GEN=(
        ARFCNBand('ARFCN'),
        Uint8('PM'),
        Uint8('PM2'),
        Uint8('TN'),
        Uint8('pad', rep=REPR_HEX)
        ))


# traffic data to network
class L1CTLTrafficReq(Envelope):
    _GEN = (
        L1CTLInfoUL(),
        Buf('Payload', rep=REPR_HEX)
        )


# GPRS resources request
class L1CTLTBFCfgReq(Envelope):
    _GEN = (
        Uint8('TBFNumber'), # future support for multiple concurrent TBFs. 0 for now
        Uint8('IsUplink'),  # is this about an UL TBF (1) or DL (0)
        Uint16('pad', rep=REPR_HEX),
        Array('USFs', GEN=Uint8('USF', val=0xff), num=8) # one USF for each TN, or 255 for invalid/unused
        )


#------------------------------------------------------------------------------#
# L1CTL Message
#------------------------------------------------------------------------------#

class L1CTLHdr(Envelope):
    _GEN = (
        Uint8('Type', dic=L1CTLMsgType_dict),
        Uint8('Flags'),
        Uint16('pad', bl=16, rep=REPR_HEX)
        )


class L1CTLMsg(Envelope):
    _GEN = (
        L1CTLHdr(),
        Alt('Params', hier=1, GEN={
            1  : L1CTLFBSBReq(),
            2  : L1CTLFBSBConf(),
            3  : L1CTLDataInd(),
            4  : L1CTLRACHReq(),
            5  : L1CTLDMEstReq(),
            6  : L1CTLDataReq(),
            7  : L1CTLReset(),
            8  : L1CTLPMReq(),
            9  : L1CTLPMConf(),
            10 : Buf('Payload', rep=REPR_HEX),
            11 : Buf('Payload', rep=REPR_HEX),
            12 : L1CTLInfoDL('L1CTLRACHConf'),
            13 : L1CTLReset(),
            14 : L1CTLReset(),
            15 : L1CTLDataInd(),
            16 : L1CTLCCCHModeReq(),
            17 : L1CTLCCCHModeConf(),
            18 : Buf('none', rep=REPR_HEX), # ?
            19 : L1CTLParamReq(),
            20 : L1CTLDMFreqReq(),
            21 : L1CTLCryptoReq(),
            22 : Buf('APDU', rep=REPR_HEX),
            23 : Buf('APDU', rep=REPR_HEX),
            24 : L1CTLTCHModeReq(), 
            25 : L1CTLTCHModeConf(),
            26 : L1CTLNeighPMReq(),
            27 : L1CTLNeighPMInd(),
            28 : L1CTLTrafficReq(),
            29 : Buf('none', rep=REPR_HEX), # ?
            30 : L1CTLTrafficInd(),
            31 : L1CTLBurstInd(),
            32 : L1CTLTBFCfgReq(),
            33 : Buf('none', rep=REPR_HEX), # ?
            #34 : ???
            #35 : ???
            36 : L1CTLExtRACHReq()
            },
            DEFAULT=Buf('unk', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0][0].get_val())
        )




'''
    0 : 'L1CTL_NONE',
    1 : 'L1CTL_FBSB_REQ', #
    2 : 'L1CTL_FBSB_CONF', #
    3 : 'L1CTL_DATA_IND', #
    4 : 'L1CTL_RACH_REQ', #
    5 : 'L1CTL_DM_EST_REQ', #
    6 : 'L1CTL_DATA_REQ', #
    7 : 'L1CTL_RESET_IND', #
    8 : 'L1CTL_PM_REQ', #
    9 : 'L1CTL_PM_CONF', #
    10 : 'L1CTL_ECHO_REQ', #
    11 : 'L1CTL_ECHO_CONF', #
    12 : 'L1CTL_RACH_CONF', #
    13 : 'L1CTL_RESET_REQ', #
    14 : 'L1CTL_RESET_CONF', #
    15 : 'L1CTL_DATA_CONF', #
    16 : 'L1CTL_CCCH_MODE_REQ', #
    17 : 'L1CTL_CCCH_MODE_CONF', #
    18 : 'L1CTL_DM_REL_REQ', #
    19 : 'L1CTL_PARAM_REQ', #
    20 : 'L1CTL_DM_FREQ_REQ', #
    21 : 'L1CTL_CRYPTO_REQ', #
    22 : 'L1CTL_SIM_REQ', #
    23 : 'L1CTL_SIM_CONF', #
    24 : 'L1CTL_TCH_MODE_REQ', #
    25 : 'L1CTL_TCH_MODE_CONF', #
    26 : 'L1CTL_NEIGH_PM_REQ', #
    27 : 'L1CTL_NEIGH_PM_IND', #
    28 : 'L1CTL_TRAFFIC_REQ',
    29 : 'L1CTL_TRAFFIC_CONF',
    30 : 'L1CTL_TRAFFIC_IND',
    31 : 'L1CTL_BURST_IND',
    32 : 'L1CTL_TBF_CFG_REQ',
    33 : 'L1CTL_TBF_CFG_CONF',
    34 : 'L1CTL_DATA_TBF_REQ',
    35 : 'L1CTL_DATA_TBF_CONF',
    36 : 'L1CTL_EXT_RACH_REQ'
'''
