# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
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
# * File Name : pycrate_asn1rt/err.py
# * Created : 2016-03-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# ASN.1 runtime errors
#------------------------------------------------------------------------------#

from pycrate_core.utils import PycrateErr


# generic ASN.1 error
class ASN1Err(PycrateErr):
    pass

# error when manipulating an existing ASN1 object
class ASN1ObjErr(ASN1Err):
    pass

# error when encountering an unsupported case
class ASN1NotSuppErr(ASN1Err):
    pass

# ASN.1 codecs errors: generic, ASN, PER, UPER, BER, CER, DER, JER, GSER
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

class ASN1JEREncodeErr(ASN1CodecErr):
    pass

class ASN1JERDecodeErr(ASN1CodecErr):
    pass

#class ASN1GSEREncodeErr(ASN1CodecErr):
#    pass
#
#class ASN1GSERDecodeErr(ASN1CodecErr):
#    pass

class ASN1OERDecodeErr(ASN1CodecErr):
    pass

class ASN1OEREncodeErr(ASN1CodecErr):
    pass
