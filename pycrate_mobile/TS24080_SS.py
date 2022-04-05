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
# * File Name : pycrate_mobile/TS24080_SS.py
# * Created : 2017-10-26
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'SSReleaseComplete',
    'SSFacility',
    'SSRegisterMO',
    'SSRegisterMT',
    'SSTypeMOClasses',
    'SSTypeMTClasses',
    'get_ss_msg_mo_instances',
    'get_ss_msg_mt_instances'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.080: Mobile radio interface layer 3 
# Supplementary services specification
# release 13 (d00)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007    import *
from .TS24008_IE import Cause


#------------------------------------------------------------------------------#
# Facility information element
# TS 24.080, section 3.6
#------------------------------------------------------------------------------#
# Facility is defined using the ASN.1 MAP module !

_WITH_ASN1 = True

if _WITH_ASN1:
    
    from threading       import Event
    from pycrate_asn1dir import SS
    from pycrate_asn1rt  import wrapper
    
    ASN_SS_READY = Event()
    ASN_SS_READY.set()
    _ACQUIRE_TO  = 0.005
    
    def asn_ss_acquire():
        if not ASN_SS_READY.is_set():
            ASN_SS_READY.wait(_ACQUIRE_TO)
            if not ASN_SS_READY.is_set():
                raise(PycrateErr('unable to acquire the SS ASN.1 module'))
        ASN_SS_READY.clear()
    
    def asn_ss_release():
        ASN_SS_READY.set()
    
    Facility = wrapper.gen_ber_wrapper(SS.SS_Facility.Facility, asn_ss_acquire, asn_ss_release)

else:
    
    class Facility(Buf):
        _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Supplementary service version indicator
# TS 24.080, section 3.7.2
#------------------------------------------------------------------------------#

_SSVersion_dict = {
    0 : 'phase 2 service, ellipsis notation, and phase 2 error handling is supported',
    1 : 'SS-Protocol version 3 is supported, and phase 2 error handling is supported'
    }

class SSVersion(Uint8):
    _dic = _SSVersion_dict


#------------------------------------------------------------------------------#
# Supplementary Services header
# TS 24.080, section 3.4
#------------------------------------------------------------------------------#

_SS_dict = {
    42 : 'Clearing message - RELEASE COMPLETE',
    58 : 'Misc - FACILITY',
    59 : 'Misc - REGISTER'
    }

class SSHeader(Envelope):
    _GEN = (
        TIPD(val={'ProtDisc': 11}),
        Uint('Seqn', bl=2),
        Uint('Type', val=58, bl=6, dic=_SS_dict)
        )


#------------------------------------------------------------------------------#
# Facility
# TS 24.080, section 2.3
#------------------------------------------------------------------------------#

class SSFacility(Layer3):
    _GEN = (
        SSHeader(val={'Type':58}),
        Type4LV('Facility', val={'V':b'\0'}, IE=Facility()),
        )


#------------------------------------------------------------------------------#
# Register (network to MS direction)
# TS 24.080, section 2.4.1
#------------------------------------------------------------------------------#

class SSRegisterMT(Layer3):
    _GEN = (
        SSHeader(val={'Type':59}),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}),
        )


#------------------------------------------------------------------------------#
# Register (MS to network direction)
# TS 24.080, section 2.4.2
#------------------------------------------------------------------------------#

class SSRegisterMO(Layer3):
    _GEN = (
        SSHeader(val={'Type':59}),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''}, IE=Facility()),
        Type4TLV('SSVersion', val={'T':0x7F, 'V':b'\0'}, IE=SSVersion())
        )


#------------------------------------------------------------------------------#
# Release complete
# TS 24.080, section 2.5
#------------------------------------------------------------------------------#

class SSReleaseComplete(Layer3):
    _GEN = (
        SSHeader(val={'Type':42}),
        Type4TLV('Cause', val={'T':0x8, 'V':b'\x80\x80'}, IE=Cause()),
        Type4TLV('Facility', val={'T':0x1C, 'V':b''})
        )


#------------------------------------------------------------------------------#
# SS dispatcher
#------------------------------------------------------------------------------#

SSTypeMOClasses = {
    42 : SSReleaseComplete,
    58 : SSFacility,
    59 : SSRegisterMO
    }

SSTypeMTClasses = {
    42 : SSReleaseComplete,
    58 : SSFacility,
    59 : SSRegisterMT
    }

def get_ss_msg_mo_instances():
    return {k: SSTypeMOClasses[k]() for k in SSTypeMOClasses}

def get_ss_msg_mt_instances():
    return {k: SSTypeMTClasses[k]() for k in SSTypeMTClasses}

