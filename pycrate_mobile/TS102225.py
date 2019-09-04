# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2019. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS102225.py
# * Created : 2019-07-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
#
# Implement parts of ETSI TS 102.225
# Secured Packet Structure for UICC


from pycrate_core.base import *
from pycrate_core.elt  import *
from pycrate_core.repr import *

from pycrate_mobile.TS31111_SAT import *


# 5.1.1 Coding of the SPI

SPI_cntt_dict = {
    0 : 'No counter available',
    1 : 'Counter available, no replay checking',
    2 : 'Process only if counter over receiver value',
    3 : 'Process only if counter by 1 over receiver value',
    }

SPI_ciph_dict = {
    0 : 'No ciphering',
    1 : 'Ciphering'
    }

SPI_intt_dict = {
    0 : 'No integrity check',
    1 : 'Redundancy check',
    2 : 'Cryptographic checksum',
    3 : 'Digital signature',
    }

SPI_sms_dict = {
    0 : 'PoR response using SMS-DELIVER-REPORT',
    1 : 'PoR response using SMS-SUBMIT',
    }

# PoR : Proof of Receipt
SPI_porc_dict = {
    0 : 'PoR response shall not be ciphered',
    1 : 'PoR response shall be ciphered'
    }

SPI_pori_dict = {
    0 : 'No integrity applied to PoR response',
    1 : 'Redundancy check applied to PoR response',
    2 : 'Cryptographic checksum applied to PoR response',
    3 : 'Digital signature applied to PoR response',
    }

SPI_porr_dict = {
    0 : 'No PoR response',
    1 : 'PoR to be sent',
    2 : 'PoR to be sent on error',
    3 : 'reserved',
    }


class SPI(Envelope):
    _GEN = (
        Uint('reserved', bl=3, rep=REPR_HEX),
        Uint('CounterType', bl=2, dic=SPI_cntt_dict),
        Uint('CipherType', bl=1, dic=SPI_ciph_dict),
        Uint('IntegrityType', bl=2, dic=SPI_intt_dict),
        Uint('reserved', bl=2, rep=REPR_HEX),
        Uint('SMSPoR', bl=1, dic=SPI_sms_dict), # TS 31.115
        Uint('PoRCipherType', bl=1, dic=SPI_porc_dict),
        Uint('PoRIntegrityType', bl=2, dic=SPI_pori_dict),
        Uint('PoRExpect', bl=2, dic=SPI_porr_dict)
        )


# 5.1.2 Coding of the KIc

KIc_alg_dict = {
    0 : 'Algorithm known implicitely',
    1 : 'DES',
    2 : 'AES',
    3 : 'proprietary',
    }

KIc_des_dict = {
    0 : 'DES in CBC mode', # before release 8
    1 : 'Triple-DES in outer-CBC mode with 2 keys',
    2 : 'Triple-DES in outer-CBC mode with 3 keys',
    3 : 'DES in ECB mode', # before release 8
    }

KIc_aes_dict = {
    0 : 'AES in CBC mode',
    1 : 'reserved',
    2 : 'reserved',
    3 : 'reserved',
    }

KIc_alg_sel_dict = {
    0 : {},
    1 : KIc_des_dict,
    2 : KIc_aes_dict,
    3 : {}
    }


class KIc(Envelope):
    _GEN = (
        Uint('Keys', bl=4, rep=REPR_HEX),
        Uint('AlgSubtype', bl=2),
        Uint('AlgType', bl=2, dic=KIc_alg_dict)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_dicauto(lambda: KIc_alg_sel_dict[self[2]()])


# 5.1.3.1 Coding of the KID for Cryptographic Checksum

KID_CC_alg_dict = {
    0 : 'Algorithm known implicitely',
    1 : 'DES',
    2 : 'AES',
    3 : 'proprietary',
    }

KID_CC_des_dict = {
    0 : 'DES in CBC mode', # before release 8
    1 : 'Triple-DES in outer-CBC mode with 2 keys',
    2 : 'Triple-DES in outer-CBC mode with 3 keys',
    3 : 'Reserved',
    }

KID_CC_aes_dict = {
    0 : 'AES in CMAC mode',
    1 : 'Reserved',
    2 : 'Reserved',
    3 : 'Reserved',
    }

KID_CC_alg_sel_dict = {
    0 : {},
    1 : KID_CC_des_dict,
    2 : KID_CC_aes_dict,
    3 : {}
    }


class KID_CC(Envelope):
    _GEN = (
        Uint('Keys', bl=4, rep=REPR_HEX),
        Uint('AlgSubtype', bl=2),
        Uint('AlgType', bl=2, dic=KID_CC_alg_dict)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_dicauto(lambda: KID_CC_alg_sel_dict[self[2]()])


# 5.1.3.2 Coding of the KID for Redundancy Check

KID_RC_alg_dict = {
    0 : 'Algorithm known implicitely',
    1 : 'CRC',
    2 : 'Reserved',
    3 : 'proprietary',
    }

KID_RC_crc_dict = {
    0 : 'CRC-16',
    1 : 'CRC-32',
    2 : 'Reserved',
    3 : 'Reserved',
    }

KID_RC_alg_sel_dict = {
    0 : {},
    1 : KID_RC_crc_dict,
    2 : {},
    3 : {}
    }


class KID_RC(Envelope):
    _GEN = (
        Uint('GPKeyVersNum', bl=4, rep=REPR_HEX),
        Uint('AlgSubtype', bl=2),
        Uint('AlgType', bl=2, dic=KID_RC_alg_dict)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_dicauto(lambda: KID_RC_alg_sel_dict[self[2]()])


# KID Digital Signature

class KID_DS(Envelope):
    _GEN = (
        Uint('GPKeyVersNum', bl=4, rep=REPR_HEX),
        Uint('AlgSubtype', bl=2),
        Uint('AlgType', bl=2)
        )


# 5.1 Command packet structure

class PacketCmd(Envelope):
    _GEN = (
        Uint8('CmdPacketId'),
        BERLen('CmdPacketLen'), # 1 or more bytes
        Uint8('CmdHeaderId'),
        BERLen('CmdHeaderLen'), # 1 or more bytes
        SPI(),                  # 2 bytes
        KIc(),                  # 1 byte
        Alt('KID', GEN={        # 1 byte
            0 : Uint8('NoIntegrity', val=0),
            1 : KID_RC(),
            2 : KID_CC(),
            3 : KID_DS()
            },
            DEFAULT=Uint8('NoIntegrity', val=0, bl=0),
            sel=lambda self: self.get_env()['SPI']['IntegrityType']()),
        Uint24('TAR', rep=REPR_HEX, dic=TAR_dict),
        Uint('CNTR', bl=40),
        Uint8('PCNTR'),
        Buf('IntegrityCheck', rep=REPR_HEX),
        Buf('Data', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 1 + self[3].get_len() + self[3]() + self[-1].get_len())
        self[3].set_valauto(lambda: 13 + self[-2].get_len())
        self[-2].set_blauto(lambda: max(0, self[3]() - 13))
        self[-1].set_blauto(lambda: max(0, self[1]() - self[3].get_len() - self[3]() - 1))


# 5.2 Response Packet structure 

RespStatus_dict = {
    0x00 : 'PoR OK',
    0x01 : 'RC/CC/DS failed',
    0x02 : 'CNTR low',
    0x03 : 'CNTR high',
    0x04 : 'CNTR Blocked',
    0x05 : 'Ciphering error',
    0x06 : 'Unidentified security error. This code is for the case where the Receiving Entity cannot correctly ' \
           'interpret the Command Header and the Response Packet is sent unciphered with no RC/CC/DS ',
    0x07 : 'Insufficient memory to process incoming message',
    0x08 : 'This status code "more time" should be used if the Receiving Entity/Application needs more time ' \
           'to process the Command Packet due to timing constraints. In this case a later Response Packet ' \
           'should be returned to the Sending Entity once processing has been completed',
    0x09 : 'TAR Unknown',
    0x0A : 'Insufficient security level',
    0x0B : 'Reserved for 3GPP (see TS 131 115 [5])',
    0x0C : 'Reserved for 3GPP (see TS 131 115 [5])',
    0x0D : 'to 0xBF Reserved for future use',
    0xC0 : 'to 0xFE Reserved for proprietary use',
    0xFF : 'Reserved for future use',
    }


class PacketResp(Envelope):
    _GEN = (
        Uint8('RespPacketId'),
        BERLen('RespPacketLen'),
        Uint8('RespHeaderId'),
        BERLen('RespHeaderLen'),
        Uint24('TAR', rep=REPR_HEX, dic=TAR_dict),
        Uint('CNTR', bl=40),
        Uint8('PCNTR'),
        Uint8('Status', dic=RespStatus_dict),
        Buf('IntegrityCheck', rep=REPR_HEX),
        Buf('Data', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: 1 + self[3].get_len() + self[3]() + self[-1].get_len())
        self[3].set_valauto(lambda: 10 + self[-2].get_len())
        self[-2].set_blauto(lambda: max(0, self[3]() - 10))
        self[-1].set_blauto(lambda: max(0, self[1]() - self[3].get_len() - self[3]() - 1))

