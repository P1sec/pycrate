# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
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
# * File Name : pycrate_asn1c/specdir.py
# * Created : 2016-03-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# These are dictionnaries referencing all ASN.1 specifications that are supported 
# by the compiler in asnproc.py, and stored in the pycrate_asn1dir/ directory


# 3GPP RRLP (2G)
ASN_SPECS_2G = {
    'RRLP'      : '3GPP_GERAN_RRLP_44031',
    }

# 3GPP UTRAN (3G)
ASN_SPECS_3G = {
    'RRC3G'     : '3GPP_UTRAN_RRC_25331',
    'RANAP'     : '3GPP_UTRAN_RANAP_25413',
    'RNA'       : '3GPP_UTRAN_RNA_25471',
    'RNSAP'     : '3GPP_UTRAN_RNSAP_25423',
    'PCAP'      : '3GPP_UTRAN_PCAP_25453',
    'SABP'      : '3GPP_UTRAN_SABP_25419',
    'NBAP'      : '3GPP_UTRAN_NBAP_25433',
    'RUA'       : '3GPP_UTRAN_RUA_25468',
    'HNBAP'     : '3GPP_UTRAN_HNBAP_25469'
    }

# 3GPP EUTRAN (LTE)
ASN_SPECS_LTE = {
    'RRCLTE'    : '3GPP_EUTRAN_RRC_36331',
    'S1AP'      : '3GPP_EUTRAN_S1AP_36413',
    'X2AP'      : '3GPP_EUTRAN_X2AP_36423',
    #'LPP'       : '3GPP_EUTRAN_LPP_36355', # moved to 37355 starting with release 15
    'LPPa'      : '3GPP_EUTRAN_LPPa_36455',
    'M2AP'      : '3GPP_EUTRAN_M2AP_36443',
    'M3AP'      : '3GPP_EUTRAN_M3AP_36444',
    'SLmAP'     : '3GPP_EUTRAN_SLmAP_36459',
    'XwAP'      : '3GPP_EUTRAN_XwAP_36463'
    }

# 3GPP NR (5G)
ASN_SPECS_5G = {
    'RRCNR'     : '3GPP_NR_RRC_38331',
    'NGAP'      : '3GPP_NR_NGAP_38413',
    'XnAP'      : '3GPP_NR_XnAP_38423',
    'NRPPa'     : '3GPP_NR_NRPPa_38455',
    'E1AP'      : '3GPP_NR_E1AP_38463',
    'F1AP'      : '3GPP_NR_F1AP_38473'
    }

# 3GPP multi-techno
ASN_SPECS_MULT = {
    'LPP'       : '3GPP_MULT_LPP_37355',
    }

# ITU-T various recommendations
ASN_SPECS_ITUT = {
    # multimedia signaling
    'H225'      : 'ITUT_H225_2009-12',
    'H235'      : 'ITUT_H235_2014-01',
    'H245'      : 'ITUT_H245_2011-05',
    'H248'      : 'ITUT_H248_2013-03',
    'X509'      : 'ITUT_X509_2012-10',
    'X509_2016' : 'ITUT_X509_2016-10',
    'X520'      : 'ITUT_X520_2016-10',
    # teleconferencing
    'T124'      : 'ITUT_T124_2007-01',
    'T125'      : 'ITUT_T125_1998-02',
    'T128'      : 'ITUT_T128_1998-02'
    }

# IETF specs
# SNMP MIB has an unsupported syntax (because of the use of a MACRO),
# and many assignment splitted on multi-lines, hence it is not compiled
ASN_SPECS_IETF = {
    'LDAP'           : 'IETF_LDAP_RFC4511',
    'Kerberos'       : 'IETF_Kerberos_RFC4120',
    'SNMP'           : 'IETF_SNMP', # MIBs and OBJECT-TYPE macro are disabled
    'PKIXAttrCert'   : 'IETF_PKI_RFC3281',  
    'CMSAlgs'        : 'IETF_PKI_RFC3370',
    'PKCS1'          : 'IETF_PKI_RFC3447',
    'CMSAes'         : 'IETF_PKI_RFC3565',
    #'OAEP'           : 'IETF_PKI_RFC4055', # old-school 1988 ANY object
    'CMSFirmWrap'    : 'IETF_PKI_RFC4108',
    'ERS'            : 'IETF_PKI_RFC4998',
    'ExtSecServices' : 'IETF_PKI_RFC5035',
    'AuthEnvData'    : 'IETF_PKI_RFC5083',
    'AESCCMGCM'      : 'IETF_PKI_RFC5084',
    'PKIX1'          : 'IETF_PKI_RFC5280',
    'PKIXAlgo08'     : 'IETF_PKI_RFC5480',
    'CMS2004'        : 'IETF_PKI_RFC5652',
    'PKIXAttrCert08' : 'IETF_PKI_RFC5755',
    'RFC5911'        : 'IETF_PKI_RFC5911',
    'RFC5912'        : 'IETF_PKI_RFC5912',
    'AsymKeyPkg'     : 'IETF_PKI_RFC5958',
    'CMSAndPKIX08'   : 'IETF_PKI_RFC6268',
    #'PKCS12'         : 'IETF_PKI_RFC7292', # missing other PKCS modules
    # TODO: Pycrate X509-specific module, gather / combines modules from 5911, 5912 and 6268
    # and more recent algo params / subject / issuer / extensions OID and values
    #'PKI'            : 'Pycrate_PKI',
    }

# GSMA, ETSI and ITU-T core network telecom protocols
ASN_SPECS_CORE = {
    # ITU-T spec
    'TCAP'      : 'ITUT_Q773_1997-06',
    'TCAPExt'   : 'ITUT_Q775_1997-06',
    # ANSI spec
    'TCAP_ANSI' : 'ANSI_TCAP',
    # ETSI / 3GPP spec
    'MAP'       : '3GPP_MAP_29002',
    'CAP'       : '3GPP_CAP_29078',
    'CDR'       : '3GPP_CDR_32298',
    'LI3GPP'    : '3GPP_LI_33108',
    'LIX3GPP'   : '3GPP_LIX_33128',
    'LIETSI'    : 'ETSI_LI_101671',
    # old ETSI spec
    'MAPv2'     : 'ETSI_MAP_0902',
    # custom built spec from ETSI / 3GPP 29.002 and 24.080 standards
    'SS'        : '3GPP_SS_24080',
    # GSMA spec
    'TAP3'      : 'GSMA_TAP3_17102014',
    # Pycrate TCAP-specific modules
    'TCAP_RAW'      : 'Pycrate_TCAP',         # TCAP-only, with each component kept as OCTET STRING
    'TCAP_MAP'      : 'Pycrate_TCAP_MAP',     # MAPv3 and further (based on 3GPP specs)
    'TCAP_MAPv2'    : 'Pycrate_TCAP_MAPv2',   # MAPv1 and v2 (based on old ETSI specs)
    'TCAP_MAPv2v3'  : 'Pycrate_TCAP_MAPv2v3', # all MAPv1, v2, v3 and further into a single Python module
    'TCAP_CAP'      : 'Pycrate_TCAP_CAP',
    }

# ETSI Intelligent Transport System
ASN_SPECS_ITS = {
    'ITS_r1318'       : 'ETSI_ITS_r1318',     # Old all-in-one ITS release from ETSI
    'ITS_IEEE1609_2'  : 'ETSI_ITS_IEEE1609_2',
    #'ITS_IEEE1609_21' : 'ETSI_ITS_IEEE1609_2_1',
    'ITS_CAM_2'       : 'ETSI_ITS_CAM_EN302637_2',
    'ITS_DENM_3'      : 'ETSI_ITS_DENM_EN302637_3',
    'ITS_VAM_3'       : 'ETSI_ITS_VAM_TS103300_3',
    'ITS_IS'          : 'ETSI_ITS_IS_TS103301',
    }

# Open Mobile Alliance geolocation protocols
ASN_SPECS_OMA = {
    'ILP'       : 'OMA_ILP',
    'ULP'       : 'OMA_ULP',
    'LPPe'      : 'OMA_LPPe',
    }

# eUICC-related specs
ASN_SPECS_EUICC = {
    'eUICCPP_IFTv2' : 'TCA_eUICCPP_IFTv2',
    'eUICCPP_IFTv3' : 'TCA_eUICCPP_IFTv3',
    }

# various biotechnologies specs
ASN_SPECS_BIO = {
    'NCBI'     : ('NCBI_201702', 'autotags'),
    'NCBI_all' : ('NCBI_all_201702', 'autotags'),
    }

# proprietary specifications
_ASN_SPECS_PROP = {
    # BMW consortium for vehicule telematics
    'NGTP'      : 'NGTP-3',
    # automobile suff
    'J2735'     : 'J2735',
    # ICAO aeronautic
    'ICAO9303'  : 'ICAO_9303',
    # some RSA PKCS stuff
    'PKCS'      : 'RSA_PKCS'
    }

ASN_SPECS = dict()
ASN_SPECS.update( ASN_SPECS_2G )
ASN_SPECS.update( ASN_SPECS_3G )
ASN_SPECS.update( ASN_SPECS_LTE )
ASN_SPECS.update( ASN_SPECS_5G )
ASN_SPECS.update( ASN_SPECS_MULT )
ASN_SPECS.update( ASN_SPECS_ITUT )
ASN_SPECS.update( ASN_SPECS_IETF )
ASN_SPECS.update( ASN_SPECS_CORE )
ASN_SPECS.update( ASN_SPECS_ITS )
ASN_SPECS.update( ASN_SPECS_OMA )
ASN_SPECS.update( ASN_SPECS_EUICC )
ASN_SPECS.update( ASN_SPECS_BIO )
#ASN_SPECS.update( _ASN_SPECS_PROP )

