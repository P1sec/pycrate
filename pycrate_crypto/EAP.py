# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate 
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1Sec.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be usefu,
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
# * File Name : pycrate_crypto/EAP.py
# * Created : 2020-10-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/


from enum import IntEnum

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *


#------------------------------------------------------------------------------#
# Extensible Authentication Protocol
# IETF RFC 3748: https://tools.ietf.org/html/rfc3748
# IANA EAP Parameters: https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml
#------------------------------------------------------------------------------#


#------------------------------------------------------------------------------#
# EAP complete packet
# section 4 - EAP Packet Format
#------------------------------------------------------------------------------#

class EAPPacketCode(IntEnum):
    Request     = 1
    Response    = 2
    Success     = 3
    Failure     = 4
    Initiate    = 5
    Finish      = 6

EAPPacketCode_dict = {e.value: e.name for e in EAPPacketCode}


class EAPPacketType(IntEnum):
    Identity = 1
    Notification = 2
    Legacy_Nak = 3
    MD5_Challenge = 4
    One_Time_Password = 5
    Generic_Token_Card = 6
    RSA_Public_Key_Authentication = 9
    DSS_Unilateral = 10
    KEA = 11
    KEA_VALIDATE = 12
    EAP_TLS = 13
    Defender_Token = 14
    RSA_Security_SecurID_EAP = 15
    Arcot_Systems_EAP = 16
    EAP_Cisco_Wireless = 17
    EAP_SIM = 18
    SRP_SHA1 = 19
    EAP_TTLS = 21
    Remote_Access_Service = 22
    EAP_AKA = 23
    EAP_3Com_Wireless = 24
    PEAP = 25
    MS_EAP_Authentication = 26
    MAKE = 27
    CRYPTOCard = 28
    MSCHAPv2 = 29
    DynamID = 30
    Rob_EAP = 31
    Protected_One_Time_Password = 32
    MS_Authentication_TLV = 33
    SentriNET = 34
    EAP_Actiontec_Wireless = 35
    Cogent_Systems_Biometrics_Authentication_EAP = 36
    AirFortress_EAP = 37
    HTTP_Digest = 38
    SecureSuite_EAP = 39
    DeviceConnect_EAP = 40
    EAP_SPEKE = 41
    EAP_MOBAC = 42
    EAP_FAST = 43
    ZoneLabs_EAP = 44
    EAP_Link = 45
    EAP_PAX = 46
    EAP_PSK = 47
    EAP_SAKE = 48
    EAP_IKEv2 = 49
    EAP_AKA_prime = 50
    EAP_GPSK = 51
    EAP_pwd = 52
    EAP_EKE_V1 = 53
    EAP_for_PT_EAP = 54
    TEAP = 55

EAPPacketType_dict = {e.value: e.name for e in EAPPacketType}


class EAPDial(Envelope):
    _GEN = (
        Uint8('Type', val=EAPPacketType.Identity.value, dic=EAPPacketType_dict),
        Buf('Data', val=b'', rep=REPR_HEX)
        )


class EAP(Envelope):
    _GEN = (
        Uint8('Code', val=EAPPacketCode.Request.value, dic=EAPPacketCode_dict),
        Uint8('Ident', val=1),
        Uint16('Len'),
        Alt('Data', GEN={
            EAPPacketCode.Request.value  : EAPDial('Req'),
            EAPPacketCode.Response.value : EAPDial('Resp'),
            EAPPacketCode.Success.value  : Buf('none', bl=0, rep=REPR_HEX),
            EAPPacketCode.Failure.value  : Buf('none', bl=0, rep=REPR_HEX),
            EAPPacketCode.Initiate.value : EAPDial('Init'),
            EAPPacketCode.Finish.value   : EAPDial('Fin')},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Code'].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 4+self['Data'].get_len())
        self['Data'].set_blauto(lambda: (self['Len'].get_val()-4)<<3)


