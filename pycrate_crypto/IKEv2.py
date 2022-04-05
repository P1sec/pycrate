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
# * File Name : pycrate_crypto/IKEv2.py
# * Created : 2020-10-14
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/


from enum import IntEnum

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *
#
from pycrate_ether.IP   import IPProt_dict
from pycrate_crypto.EAP import EAP


#------------------------------------------------------------------------------#
# Internet Key Exchange v2
# IETF RFC 7296: https://tools.ietf.org/html/rfc7296
# IANA IKEv2 Parameters: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
#------------------------------------------------------------------------------#


#------------------------------------------------------------------------------#
# Security Association Payload
# section 3.3
#------------------------------------------------------------------------------#

class _AttributeLV(Envelope):
    _GEN = (
        Uint16('L'),
        Buf('V', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


class Attribute(Envelope):
    _GEN = (
        Uint('AF', bl=1),
        Uint('Type', bl=15),
        Alt('Attr', GEN={
            0: _AttributeLV('LV'),
            1: Buf('V', bl=16, rep=REPR_HEX)},
            sel=lambda self: self.get_env()['AF'].get_val()
            )
        )


class IKEv2TransType(IntEnum):
    ENCR = 1
    PRF = 2
    INTEG = 3
    DH = 4
    ESN = 5

IKEv2TransType_dict = {e.value: e.name for e in IKEv2TransType}

class IKEv2TransENCR(IntEnum):
    ENCR_DES_IV64 = 1
    ENCR_DES = 2
    ENCR_3DES = 3
    ENCR_RC5 = 4
    ENCR_IDEA = 5
    ENCR_CAST = 6
    ENCR_BLOWFISH = 7
    ENCR_3IDEA = 8
    ENCR_DES_IV32 = 9
    ENCR_NULL = 11
    ENCR_AES_CBC = 12
    ENCR_AES_CTR = 13
    ENCR_AES_CCM_8 = 14
    ENCR_AES_CCM_12 = 15
    ENCR_AES_CCM_16 = 16
    ENCR_AES_GCM_8 = 18
    ENCR_AES_GCM_12 = 19
    ENCR_AES_GCM_16 = 20
    ENCR_NULL_AUTH_AES_GMAC = 21
    ENCR_IEEE_P1619_XT_AES = 22
    ENCR_CAMELLIA_CBC = 23
    ENCR_CAMELLIA_CTR = 24
    ENCR_CAMELLIA_CCM_8 = 25
    ENCR_CAMELLIA_CCM_12 = 26
    ENCR_CAMELLIA_CCM_16 = 27
    ENCR_CHACHA20_POLY1305 = 28
    ENCR_AES_CCM_8_IIV = 29
    ENCR_AES_GCM_16_IIV = 30
    ENCR_CHACHA20_POLY1305_IIV = 31
    ENCR_KUZNYECHIK_MGM_KTREE = 32
    ENCR_MAGMA_MGM_KTREE = 33
    ENCR_KUZNYECHIK_MGM_MAC_KTREE = 34
    ENCR_MAGMA_MGM_MAC_KTREE = 35

IKEv2TransENCR_dict = {e.value: e.name for e in IKEv2TransENCR}

class IKEv2TransPRF(IntEnum):
    PRF_HMAC_MD5 = 1
    PRF_HMAC_SHA1 = 2
    PRF_HMAC_TIGER = 3
    PRF_AES128_XCBC = 4
    PRF_HMAC_SHA2_256 = 5
    PRF_HMAC_SHA2_384 = 6
    PRF_HMAC_SHA2_512 = 7
    PRF_AES128_CMAC = 8
    PRF_HMAC_STRIBOG_512 = 9

IKEv2TransPRF_dict = {e.value: e.name for e in IKEv2TransPRF}

class IKEv2TransAUTH(IntEnum):
    NONE = 0
    AUTH_HMAC_MD5_96 = 1
    AUTH_HMAC_SHA1_96 = 2
    AUTH_DES_MAC = 3
    AUTH_KPDK_MD5 = 4
    AUTH_AES_XCBC_96 = 5
    AUTH_HMAC_MD5_128 = 6
    AUTH_HMAC_SHA1_160 = 7
    AUTH_AES_CMAC_96 = 8
    AUTH_AES_128_GMAC = 9
    AUTH_AES_192_GMAC = 10
    AUTH_AES_256_GMAC = 11
    AUTH_HMAC_SHA2_256_128 = 12
    AUTH_HMAC_SHA2_384_192 = 13
    AUTH_HMAC_SHA2_512_256 = 14

IKEv2TransAUTH_dict = {e.value: e.name for e in IKEv2TransAUTH}

class IKEv2TransDH(IntEnum):
    NONE = 0
    MODP_Group_768 = 1
    MODP_Group_1024 = 2
    MODP_Group_1536 = 5
    MODP_Group_2048 = 14
    MODP_Group_3072 = 15
    MODP_Group_4096 = 16
    MODP_Group_6144 = 17
    MODP_Group_8192 = 18
    Random_ECP_Group_256 = 19
    Random_ECP_Group_384 = 20
    Random_ECP_Group_521 = 21
    MODP_Group_1024_Prime_Order_Subgroup_160 = 22
    MODP_Group_2048_Prime_Order_Subgroup_224 = 23
    MODP_Group_2048_Prime_Order_Subgroup_256 = 24
    Random_ECP_Group_192 = 25
    Random_ECP_Group_224 = 26
    BrainpoolP224r1 = 27
    BrainpoolP256r1 = 28
    BrainpoolP384r1 = 29
    BrainpoolP512r1 = 30
    Curve25519 = 31
    Curve448 = 32
    GOST3410_2012_256 = 33
    GOST3410_2012_512 = 34

IKEv2TransDH_dict = {e.value: e.name for e in IKEv2TransDH}

class IKEv2TransESN(IntEnum):
    NO_ESN = 0
    ESN = 1

IKEv2TransESN_dict = {e.value: e.name for e in IKEv2TransESN}

IKEv2TransID_dict = {
    1 : IKEv2TransENCR_dict,
    2 : IKEv2TransPRF_dict,
    3 : IKEv2TransAUTH_dict,
    4 : IKEv2TransDH_dict,
    5 : IKEv2TransESN_dict
    }


class Transform(Envelope):
    _GEN = (
        Uint8('Last'),
        Uint8('res'),
        Uint16('Len'),
        Uint8('Type', val=IKEv2TransType.ENCR.value, dic=IKEv2TransType_dict),
        Uint8('res'),
        Uint16('ID', val=1),
        Sequence('Attributes', GEN=Attribute())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Last'].set_valauto(lambda: 0 if self.get_next() is None else 3)
        self['Len'].set_valauto(lambda: 8 + self['Attributes'].get_len())
        self['ID'].set_dicauto(lambda: IKEv2TransID_dict.get(self['Type'].get_val(), {}))
        self['Attributes'].set_blauto(lambda: (self['Len'].get_val() - 8)<<3)


class IKEv2ProtID(IntEnum):
    IKE = 1
    AH  = 2
    ESP = 3

IKEv2ProtID_dict = {e.value: e.name for e in IKEv2ProtID}


class Proposal(Envelope):
    _GEN = (
        Uint8('Last'),
        Uint8('res'),
        Uint16('Len'),
        Uint8('Num'),
        Uint8('ProtID', val=IKEv2ProtID.IKE.value, dic=IKEv2ProtID_dict),
        Uint8('SPISize'), # 0 for initial IKE SA nego, then 4 (AH, ESP) or 8 (IKE)
        Uint8('NumTrans'),
        Buf('SPI', val=b'', rep=REPR_HEX),
        Sequence('Transforms', GEN=Transform())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Last'].set_valauto(lambda: 0 if self.get_next() is None else 2)
        self['Len'].set_valauto(lambda: 8 + self['SPI'].get_len() + self['Transforms'].get_len())
        self['Num'].set_valauto(lambda: self.get_env().index(self))
        self['SPISize'].set_valauto(lambda: self['SPI'].get_len())
        self['NumTrans'].set_valauto(lambda: self['Transforms'].get_num())
        self['SPI'].set_blauto(lambda: self['SPISize'].get_val()<<3)
        self['Transforms'].set_numauto(lambda: self['NumTrans'].get_val())
        self['Transforms'].set_blauto(lambda: (self['Len'].get_val() - self['SPISize'].get_val() - 8)<<3)


class PaySA(Sequence):
    _GEN = Proposal()


#------------------------------------------------------------------------------#
# Key Exchange Payload
# section 3.4
#------------------------------------------------------------------------------#

class PayKE(Envelope):
    _GEN = (
        Uint16('DHGroup', val=IKEv2TransDH.MODP_Group_1024.value, dic=IKEv2TransDH_dict),
        Uint16('res', rep=REPR_HEX),
        Buf('Data', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Identification Payloads
# section 3.5
#------------------------------------------------------------------------------#

class IKEv2IDType(IntEnum):
    ID_IPV4_ADDR = 1
    ID_FQDN = 2
    ID_RFC822_ADDR = 3
    ID_IPV6_ADDR = 5
    ID_DER_ASN1_DN = 9
    ID_DER_ASN1_GN = 10
    ID_KEY_ID = 11
    ID_FC_NAME = 12
    ID_NULL = 13

IKEv2IDType_dict = {e.value: e.name for e in IKEv2IDType}


class PayID(Envelope):
    _GEN = (
        Uint8('Type', val=IKEv2IDType.ID_IPV4_ADDR.value, dic=IKEv2IDType_dict),
        Uint24('res', rep=REPR_HEX),
        Buf('Data', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Certificate Payload
# section 3.6
# Certificate Request Payload
# section 3.7
#------------------------------------------------------------------------------#

class IKEv2CertEncoding(IntEnum):
    PKCS7_wrapped_X509_Cert = 1
    PGP_Cert = 2
    DNS_Signed_Key = 3
    X509_Cert_Signature = 4
    Kerberos_Token = 6
    Certificate_Revocation_List = 7
    Authority_Revocation_List = 8
    SPKI_Cert = 9
    X509_Cert_Attribute = 10
    Raw_RSA_Key = 11
    Hash_URL_X509_Cert = 12
    Hash_URL_X509_Bundle = 13
    OCSP_Content = 14
    Raw_Public_Key = 15

IKEv2CertEncoding_dict = {e.value: e.name for e in IKEv2CertEncoding}


class PayCert(Envelope):
    _GEN = (
        Uint8('Encoding', val=1, dic=IKEv2CertEncoding_dict),
        Buf('Data', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Authentication Payload
# section 3.8
#------------------------------------------------------------------------------#

class IKEv2AuthMethod(IntEnum):
    RSA_Digital_Signature = 1
    Shared_Key_Message_Integrity_Code = 2
    DSS_Digital_Signature = 3
    ECDSA_SHA256_P256 = 9
    ECDSA_SHA384_P384 = 10
    ECDSA_SHA512_P521 = 11
    Generic_Secure_Password = 12
    NULL = 13
    Digital_Signature = 14

IKEv2AuthMethod_dict = {e.value: e.name for e in IKEv2AuthMethod}


class PayAuth(Envelope):
    _GEN = (
        Uint8('Method', val=1, dic=IKEv2AuthMethod_dict),
        Uint24('res', rep=REPR_HEX),
        Buf('Data', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Nonce Payload
# section 3.9
#------------------------------------------------------------------------------#

class PayNonce(Envelope):
    _GEN = (
        Buf('Data', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# Notify Payload
# section 3.10
#------------------------------------------------------------------------------#

# error notifications
class IKEv2NotifTypeErr(IntEnum):
    UNSUPPORTED_CRITICAL_PAYLOAD = 1
    INVALID_IKE_SPI = 4
    INVALID_MAJOR_VERSION = 5
    INVALID_SYNTAX = 7
    INVALID_MESSAGE_ID = 9
    INVALID_SPI = 11
    NO_PROPOSAL_CHOSEN = 14
    INVALID_KE_PAYLOAD = 17
    AUTHENTICATION_FAILED = 24
    SINGLE_PAIR_REQUIRED = 34
    NO_ADDITIONAL_SAS = 35
    INTERNAL_ADDRESS_FAILURE = 36
    FAILED_CP_REQUIRED = 37
    TS_UNACCEPTABLE = 38
    INVALID_SELECTORS = 39
    UNACCEPTABLE_ADDRESSES = 40
    UNEXPECTED_NAT_DETECTED = 41
    USE_ASSIGNED_HoA = 42
    TEMPORARY_FAILURE = 43
    CHILD_SA_NOT_FOUND = 44
    INVALID_GROUP_ID = 45
    AUTHORIZATION_FAILED = 46

IKEv2NotifTypeErr_dict = {e.value: e.name for e in IKEv2NotifTypeErr}

# status notifications
class IKEv2NotifTypeStat(IntEnum):
    INITIAL_CONTACT = 16384
    SET_WINDOW_SIZE = 16385
    ADDITIONAL_TS_POSSIBLE = 16386
    IPCOMP_SUPPORTED = 16387
    NAT_DETECTION_SOURCE_IP = 16388
    NAT_DETECTION_DESTINATION_IP = 16389
    COOKIE = 16390
    USE_TRANSPORT_MODE = 16391
    HTTP_CERT_LOOKUP_SUPPORTED = 16392
    REKEY_SA = 16393
    ESP_TFC_PADDING_NOT_SUPPORTED = 16394
    NON_FIRST_FRAGMENTS_ALSO = 16395
    MOBIKE_SUPPORTED = 16396
    ADDITIONAL_IP4_ADDRESS = 16397
    ADDITIONAL_IP6_ADDRESS = 16398
    NO_ADDITIONAL_ADDRESSES = 16399
    UPDATE_SA_ADDRESSES = 16400
    COOKIE2 = 16401
    NO_NATS_ALLOWED = 16402
    AUTH_LIFETIME = 16403
    MULTIPLE_AUTH_SUPPORTED = 16404
    ANOTHER_AUTH_FOLLOWS = 16405
    REDIRECT_SUPPORTED = 16406
    REDIRECT = 16407
    REDIRECTED_FROM = 16408
    TICKET_LT_OPAQUE = 16409
    TICKET_REQUEST = 16410
    TICKET_ACK = 16411
    TICKET_NACK = 16412
    TICKET_OPAQUE = 16413
    LINK_ID = 16414
    USE_WESP_MODE = 16415
    ROHC_SUPPORTED = 16416
    EAP_ONLY_AUTHENTICATION = 16417
    CHILDLESS_IKEV2_SUPPORTED = 16418
    QUICK_CRASH_DETECTION = 16419
    IKEV2_MESSAGE_ID_SYNC_SUPPORTED = 16420
    IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED = 16421
    IKEV2_MESSAGE_ID_SYNC = 16422
    IPSEC_REPLAY_COUNTER_SYNC = 16423
    SECURE_PASSWORD_METHODS = 16424
    PSK_PERSIST = 16425
    PSK_CONFIRM = 16426
    ERX_SUPPORTED = 16427
    IFOM_CAPABILITY = 16428
    SENDER_REQUEST_ID = 16429
    IKEV2_FRAGMENTATION_SUPPORTED = 16430
    SIGNATURE_HASH_ALGORITHMS = 16431
    CLONE_IKE_SA_SUPPORTED = 16432
    CLONE_IKE_SA = 16433
    PUZZLE = 16434
    USE_PPK = 16435
    PPK_IDENTITY = 16436
    NO_PPK_AUTH = 16437
    INTERMEDIATE_EXCHANGE_SUPPORTED = 16438

IKEv2NotifTypeStat_dict = {e.value: e.name for e in IKEv2NotifTypeStat}

# all notifications
IKEv2NotifType_dict = dict(IKEv2NotifTypeErr_dict)
IKEv2NotifType_dict.update(IKEv2NotifTypeStat_dict)


class PayNotif(Envelope):
    _GEN = (
        Uint8('ProtID', val=IKEv2ProtID.IKE.value, dic=IKEv2ProtID_dict),
        Uint8('SPISize'), # 0 for initial IKE SA nego, then 4 (AH, ESP) or 8 (IKE)
        Uint16('Type', val=IKEv2NotifTypeErr.TEMPORARY_FAILURE.value, dic=IKEv2NotifType_dict),
        Buf('SPI', val=b'', rep=REPR_HEX),
        Buf('Data', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['SPISize'].set_valauto(lambda: self['SPI'].get_len())
        self['SPI'].set_blauto(lambda: self['SPISize'].get_val()<<3)


#------------------------------------------------------------------------------#
# Delete Payload
# section 3.11
#------------------------------------------------------------------------------#

class PayDelete(Envelope):
    _GEN = (
        Uint8('ProtID', val=IKEv2ProtID.IKE.value, dic=IKEv2ProtID_dict),
        Uint8('SPISize'), # 0 for initial IKE SA nego, then 4 (AH, ESP) or 8 (IKE)
        Uint8('NumSPIs'),
        Sequence('SPIs', GEN=Buf('SPI', rep=REPR_HEX))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['SPISize'].set_valauto(lambda: self['SPIs'][0].get_len() if self['SPIs'].get_num() else 0)
        self['NumSPIs'].set_valauto(lambda: self['SPIs'].get_num())
        self['SPIs'].set_numauto(lambda: self['NumSPIs'].get_val())
    
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        self[2]._from_char(char)
        self[3]._tmpl._bl = self[1].get_val()<<3
        self[3]._from_char(char)
        self[3]._tmpl._bl = None


#------------------------------------------------------------------------------#
# VendorID Payload
# section 3.12
#------------------------------------------------------------------------------#

class PayVID(Envelope):
    _GEN = (
        Buf('Data', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# Traffic Selector Payload
# section 3.13
#------------------------------------------------------------------------------#

class IKEv2TSType(IntEnum):
    IPV4_ADDR_RANGE = 7
    IPV6_ADDR_RANGE = 8

IKEv2TSType_dict = {e.value: e.name for e in IKEv2TSType}


class IKEv2TS(Envelope):
    _GEN = (
        Uint8('Type', val=IKEv2TSType.IPV4_ADDR_RANGE.value, dic=IKEv2TSType_dict),
        Uint8('IPProt', val=0, dic=IPProt_dict),
        Uint16('Len'),
        Uint16('PortStart', val=0),
        Uint16('PortEnd', val=0),
        Buf('AddrStart', val=b'', rep=REPR_HEX),
        Buf('AddrEnd', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 8 + self['AddrStart'].get_len() + self['AddrEnd'].get_len())
        self['AddrStart'].set_blauto(lambda: (self['Len'].get_val()-8)<<2)
        self['AddrEnd'].set_blauto(lambda: (self['Len'].get_val()-8)<<2)


class PayTS(Envelope):
    _GEN = (
        Uint8('NumTSs'),
        Uint24('res', rep=REPR_HEX),
        Sequence('TSs', GEN=IKEv2TS('TS'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NumTSs'].set_valauto(lambda: self['TSs'].get_num())
        self['TSs'].set_numauto(lambda: self['NumTSs'].get_val())


#------------------------------------------------------------------------------#
# Encrypted Payload
# section 3.14
#------------------------------------------------------------------------------#

# length of IV
# Warning: some of those values are not confirmed / tested / verified
IKEv2EncrIVLen_dict = {
    IKEv2TransENCR.ENCR_DES_IV64 : 8,
    IKEv2TransENCR.ENCR_DES : 8,
    IKEv2TransENCR.ENCR_3DES : 8,
    IKEv2TransENCR.ENCR_RC5 : 8,
    IKEv2TransENCR.ENCR_IDEA : 8,
    IKEv2TransENCR.ENCR_CAST : 8,
    IKEv2TransENCR.ENCR_BLOWFISH : 8,
    IKEv2TransENCR.ENCR_3IDEA : 8,
    IKEv2TransENCR.ENCR_DES_IV32 : 8,
    IKEv2TransENCR.ENCR_NULL : 0,
    IKEv2TransENCR.ENCR_AES_CBC : 16,
    IKEv2TransENCR.ENCR_AES_CTR : 16,
    IKEv2TransENCR.ENCR_AES_CCM_8 : 16,
    IKEv2TransENCR.ENCR_AES_CCM_12 : 16,
    IKEv2TransENCR.ENCR_AES_CCM_16 : 16,
    IKEv2TransENCR.ENCR_AES_GCM_8 : 16,
    IKEv2TransENCR.ENCR_AES_GCM_12 : 16,
    IKEv2TransENCR.ENCR_AES_GCM_16 : 16,
    IKEv2TransENCR.ENCR_NULL_AUTH_AES_GMAC : 16,
    IKEv2TransENCR.ENCR_IEEE_P1619_XT_AES : 16,
    IKEv2TransENCR.ENCR_CAMELLIA_CBC : 16,
    IKEv2TransENCR.ENCR_CAMELLIA_CTR : 16,
    IKEv2TransENCR.ENCR_CAMELLIA_CCM_8 : 16,
    IKEv2TransENCR.ENCR_CAMELLIA_CCM_12 : 16,
    IKEv2TransENCR.ENCR_CAMELLIA_CCM_16 : 16,
    IKEv2TransENCR.ENCR_CHACHA20_POLY1305 : 16,
    IKEv2TransENCR.ENCR_AES_CCM_8_IIV : 16,
    IKEv2TransENCR.ENCR_AES_GCM_16_IIV : 16,
    IKEv2TransENCR.ENCR_CHACHA20_POLY1305_IIV : 16,
    IKEv2TransENCR.ENCR_KUZNYECHIK_MGM_KTREE : 8,
    IKEv2TransENCR.ENCR_MAGMA_MGM_KTREE : 8,
    IKEv2TransENCR.ENCR_KUZNYECHIK_MGM_MAC_KTREE : 8,
    IKEv2TransENCR.ENCR_MAGMA_MGM_MAC_KTREE : 8,
    }



# length of ICS
IKEv2AuthICSLen_dict = {
    IKEv2TransAUTH.NONE : 0,
    IKEv2TransAUTH.AUTH_HMAC_MD5_96 : 12,
    IKEv2TransAUTH.AUTH_HMAC_SHA1_96 : 12,
    IKEv2TransAUTH.AUTH_DES_MAC : 8,
    IKEv2TransAUTH.AUTH_KPDK_MD5 : 16,
    IKEv2TransAUTH.AUTH_AES_XCBC_96 : 12,
    IKEv2TransAUTH.AUTH_HMAC_MD5_128 : 16,
    IKEv2TransAUTH.AUTH_HMAC_SHA1_160 : 20,
    IKEv2TransAUTH.AUTH_AES_CMAC_96 : 12,
    IKEv2TransAUTH.AUTH_AES_128_GMAC : 16,
    IKEv2TransAUTH.AUTH_AES_192_GMAC : 24,
    IKEv2TransAUTH.AUTH_AES_256_GMAC : 32,
    IKEv2TransAUTH.AUTH_HMAC_SHA2_256_128 : 16,
    IKEv2TransAUTH.AUTH_HMAC_SHA2_384_192 : 24,
    IKEv2TransAUTH.AUTH_HMAC_SHA2_512_256 : 32,
    }


class PayEncr(Envelope):
    
    # the configuration of the encryption and integrity checksum algorithms
    # is contextual
    ALG_ENCR = IKEv2TransENCR.ENCR_NULL
    ALG_AUTH = IKEv2TransAUTH.NONE
    
    _GEN = (
        Buf('IV', rep=REPR_HEX),
        Buf('Data', val=b'', rep=REPR_HEX),
        Buf('Pad', val=b'', rep=REPR_HEX),
        Uint8('PadLen'),
        Buf('ICS', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IV'].set_blauto(lambda: IKEv2EncrIVLen_dict.get(self.ALG_ENCR, 0))
        self['PadLen'].set_valauto(lambda: self['Pad'].get_len())
        self['ICS'].set_blauto(lambda: IKEv2AuthICSLen_dict.get(self.ALG_AUTH, 0))
    
    # TODO
    def encrypt(self, data, key):
        pass
    
    def decrypt(self, key):
        pass
    
    def ics_compute(self, key):
        pass
    
    def ics_verify(self, key):
        pass


#------------------------------------------------------------------------------#
# Configuration Payload
# section 3.15
#------------------------------------------------------------------------------#

class IKEv2AttrType(IntEnum):
    INTERNAL_IP4_ADDRESS = 1
    INTERNAL_IP4_NETMASK = 2
    INTERNAL_IP4_DNS = 3
    INTERNAL_IP4_NBNS = 4
    INTERNAL_IP4_DHCP = 6
    APPLICATION_VERSION = 7
    INTERNAL_IP6_ADDRESS = 8
    INTERNAL_IP6_DNS = 10
    INTERNAL_IP6_DHCP = 12
    INTERNAL_IP4_SUBNET = 13
    SUPPORTED_ATTRIBUTES = 14
    INTERNAL_IP6_SUBNET = 15
    MIP6_HOME_PREFIX = 16
    INTERNAL_IP6_LINK = 17
    INTERNAL_IP6_PREFIX = 18
    HOME_AGENT_ADDRESS = 19
    P_CSCF_IP4_ADDRESS = 20
    P_CSCF_IP6_ADDRESS = 21
    FTT_KAT = 22
    EXTERNAL_SOURCE_IP4_NAT_INFO = 23
    TIMEOUT_PERIOD_FOR_LIVENESS_CHECK = 24
    INTERNAL_DNS_DOMAIN = 25
    INTERNAL_DNSSEC_TA = 26

IKEv2AttrType_dict = {e.value: e.name for e in IKEv2AttrType}


class IKEv2Attr(Envelope):
    _GEN = (
        Uint('R', bl=1),
        Uint('Type', val=IKEv2AttrType.SUPPORTED_ATTRIBUTES.value, bl=15, dic=IKEv2AttrType_dict),
        Uint8('Len'),
        Buf('Value', val=b'', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Value'].get_len())
        self['Value'].set_blauto(lambda: self['Len'].get_val()<<3)


class IKEv2ConfigType(IntEnum):
    CFG_REQUEST = 1
    CFG_REPLY   = 2
    CFG_SET     = 3
    CFG_ACK     = 4

IKEv2ConfigType_dict = {e.value: e.name for e in IKEv2ConfigType}


class PayConfig(Envelope):
    _GEN = (
        Uint8('Type', val=IKEv2ConfigType.CFG_REQUEST.value, dic=IKEv2ConfigType_dict),
        Uint24('res', rep=REPR_HEX),
        Sequence('Attrs', GEN=IKEv2Attr('Attr'))
        )


#------------------------------------------------------------------------------#
# Extensible Authentication Protocol (EAP) Payload
# section 3.16
#------------------------------------------------------------------------------#

class PayEAP(Envelope):
    _GEN = (
        EAP(),
        )



#------------------------------------------------------------------------------#
# IKEv2 payload header
# section 3.2
#------------------------------------------------------------------------------#

class IKEv2PayType(IntEnum):
    NoNextPayload               = 0
    SecurityAssociation         = 33
    KeyExchange                 = 34
    IdentInitiator              = 35
    IdentResponder              = 36
    Certifiate                  = 37
    CertificateRequest          = 38
    Authentication              = 39
    Nonce                       = 40
    Notify                      = 41
    Delete                      = 42
    VendorID                    = 43
    TrafficSelectorInitiator    = 44
    TrafficSelectorResponder    = 45
    EncryptedAuthenticated      = 46
    Configuration               = 47
    EAP                         = 48
    GenericSecurePwdMethod      = 49
    GroupIdentification         = 50
    GroupSecurityAssociation    = 51
    KeyDownload                 = 52
    EncryptedAuthenticatedFrag  = 53
    PuzzleSolution              = 54

IKEv2PayType_dict = {e.value: e.name for e in IKEv2PayType}


class IKEv2Pay(Envelope):
    
    # LUT for payload
    LUTPay = {
        33 : PaySA('SA'),
        34 : PayKE('KE'),
        35 : PayID('IDi'),
        36 : PayID('IDr'),
        37 : PayCert('CERT'),
        38 : PayCert('CERTREQ'),
        39 : PayAuth('AUTH'),
        40 : PayNonce('NONCE'),
        41 : PayNotif('N'),
        42 : PayDelete('D'),
        43 : PayVID('V'),
        44 : PayTS('TSi'),
        45 : PayTS('TSr'),
        46 : PayEncr('SK'),
        47 : PayConfig('CP'),
        48 : PayEAP('EAP'),
        }
    
    _GEN = (
        Uint8('Next'),
        Uint('C', bl=1),
        Uint('res', bl=7, rep=REPR_HEX),
        Uint16('Len'),
        Buf('Pay', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        self.Type = 1
        Envelope.__init__(self, *args, **kwargs)
        self['Next'].set_valauto(lambda: getattr(self.get_next(), 'Type', 0))
        self['Len'].set_valauto(lambda: 4 + self[4].get_len())
        self['Pay'].set_blauto(lambda: (self[3].get_val() - 4)<<3)
    
    def set_val(self, val):
        if isinstance(val, dict) and 'Type' in val and val['Type'] in self.LUTPay:
            self.Type = val['Type']
            del val['Type']
            pay = self.LUTPay[val['Type']].clone()
            pay.set_blauto(lambda: (self[3].get_val() - 4)<<3)
            self.replace(self[4], pay)
        Envelope.set_val(self, val)
    
    def _from_char(self, char):
        e, n = self.get_env(), None
        if e is not None:
            if e.get_num():
                # get the last IKEv2Pay within the Payloads Sequence
                n = e[-1]
            else:
                e = e.get_env()
                if e is not None:
                     # get the IKEv2 header
                    n = e[0]
        if n is not None:
            next = n['Next'].get_val()
            if next in self.LUTPay:
                self.Type = next
                pay = self.LUTPay[next].clone()
                pay.set_blauto(lambda: (self[3].get_val() - 4)<<3)
                self.replace(self[4], pay)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# IKEv2 header
# section 3.1
#------------------------------------------------------------------------------#

class IKEv2ExchType(IntEnum):
    IKE_SA_INIT         = 34
    IKE_AUTH            = 35
    CREATE_CHILD_SA     = 36
    INFORMATIONAL       = 37
    IKE_SESSION_RESUME  = 38
    GSA_AUTH            = 39
    GSA_REGISTRATION    = 40
    GSA_REKEY           = 41
    IKE_INTERMEDIATE    = 43

IKEv2ExchType_dict = {e.value: e.name for e in IKEv2ExchType}


class IKEv2HdrFlags(Envelope):
    _GEN = (
        Uint('undef', bl=2, rep=REPR_HEX),
        Uint('R', bl=1),
        Uint('V', bl=1),
        Uint('I', bl=1),
        Uint('undef', bl=3, rep=REPR_HEX)
        )


class IKEv2Hdr(Envelope):
    _GEN = (
        Buf('SPIInitiator', bl=64, rep=REPR_HEX),
        Buf('SPIResponder', bl=64, rep=REPR_HEX),
        Uint8('Next'),
        Uint('VersMaj', val=2, bl=4),
        Uint('VersMin', val=0, bl=4),
        Uint8('ExchType', val=IKEv2ExchType.IKE_SA_INIT.value, dic=IKEv2ExchType_dict),
        IKEv2HdrFlags('Flags'),
        Uint32('MID', rep=REPR_HEX),
        Uint32('Len', val=28)
        )


#------------------------------------------------------------------------------#
# IKEv2 complete packet
#------------------------------------------------------------------------------#

class IKEv2(Envelope):
    _GEN = (
        IKEv2Hdr('Header'),
        Sequence('Payloads', GEN=IKEv2Pay(), hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0]['Next'].set_valauto(lambda: self[1][0].Type if self[1].get_num() else 0)
        self[0]['Len'].set_valauto(lambda: 28 + self[1].get_len())
        self[1].set_blauto(lambda: (self[0]['Len'].get_val()-28)<<3)

