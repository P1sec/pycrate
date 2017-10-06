# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.2
# *
# * Copyright © 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_asn1c/err.py
# * Created : 2016-03-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# ASN.1 errors
#------------------------------------------------------------------------------#

# generic ASN.1 error
class ASN1Err(Exception):
    pass

# error when manipulating an existing ASN1 object
class ASN1ObjErr(ASN1Err):
    pass

# error when encountering an unsupported case
class ASN1NotSuppErr(ASN1Err):
    pass

# ASN.1 codecs errors: generic, ASN, PER, UPER, BER, CER, DER, GSER
class ASN1CodecErr(ASN1Err):
    pass

class ASN1ASNEncodeErr(ASN1CodecErr):
    pass

class ASN1ASNDecodeErr(ASN1CodecErr):
    pass

class ASN1PEREncodeErr(ASN1CodecErr):
    pass

class ASN1PERDecodeErr(ASN1CodecErr):
    pass

class ASN1BEREncodeErr(ASN1CodecErr):
    pass

class ASN1BERDecodeErr(ASN1CodecErr):
    pass

class ASN1CEREncodeErr(ASN1CodecErr):
    pass

class ASN1CERDecodeErr(ASN1CodecErr):
    pass

class ASN1DEREncodeErr(ASN1CodecErr):
    pass

class ASN1DERDecodeErr(ASN1CodecErr):
    pass

class ASN1GSEREncodeErr(ASN1CodecErr):
    pass

class ASN1GSERDecodeErr(ASN1CodecErr):
    pass

