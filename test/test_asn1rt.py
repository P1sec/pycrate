# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
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
# * File Name : test/test_asn1rt.py
# * Created : 2016-02-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii import *
from timeit   import timeit

from pycrate_asn1rt.utils            import *
from pycrate_asn1rt.err              import *
from pycrate_asn1rt.glob             import make_GLOBAL, GLOBAL
from pycrate_asn1rt.dictobj          import ASN1Dict
from pycrate_asn1rt.refobj           import *
from pycrate_asn1rt.setobj           import *
from pycrate_asn1rt.asnobj_basic     import *
from pycrate_asn1rt.asnobj_str       import *
from pycrate_asn1rt.asnobj_construct import *
from pycrate_asn1rt.asnobj_class     import *
from pycrate_asn1rt.asnobj_ext       import *
#from pycrate_asn1rt.init             import init_modules
from pycrate_asn1rt.codecs           import _with_json


# do not print runtime warnings on screen
ASN1Obj._SILENT = True
# handle default values in PER the canonical way
ASN1CodecPER.GET_DEFVAL = True
ASN1CodecPER.CANONICAL  = True
# print ascii representation in comments when returning the ASN.1 textual encoding
# set to False to enable the parsing of the ASN.1 syntax generated
BIT_STR._ASN_WASC = False
OCT_STR._ASN_WASC = False


def _load_rt_base():
    #try:
    #    GLOBAL.clear()
    #except:
    #    pass
    from test import test_asn1rt_mod
    #print(list(GLOBAL.MOD.keys()))


def _test_rt_base():
    Mod = GLOBAL.MOD['Test-Asn1rt']
    
    # Boo01 ::= BOOLEAN
    Boo01 = Mod['Boo01']
    Boo01.from_asn1('TRUE')
    # encoding
    assert( Boo01.to_aper() == Boo01.to_aper_ws() == b'\x80' )
    assert( Boo01.to_uper() == Boo01.to_uper_ws() == b'\x80' )
    assert( Boo01.to_ber() == Boo01.to_ber_ws() == b'\x01\x01\xff' )
    assert( Boo01.to_cer() == Boo01.to_cer_ws() == b'\x01\x01\xff' )
    assert( Boo01.to_der() == Boo01.to_der_ws() == b'\x01\x01\xff' )
    assert( Boo01.to_oer() == Boo01.to_oer_ws() == b'\xff' )
    assert( Boo01.to_coer() == Boo01.to_coer_ws() == b'\xff' )
    # decoding
    Boo01.from_aper(b'\x80')
    assert( Boo01._val == True )
    Boo01.from_aper_ws(b'\x80')
    assert( Boo01._val == True )
    Boo01.from_uper(b'\x80')
    assert( Boo01._val == True )
    Boo01.from_uper_ws(b'\x80')
    assert( Boo01._val == True )
    Boo01.from_ber(b'\x01\x01\xff')
    assert( Boo01._val == True )
    Boo01.from_ber_ws(b'\x01\x01\xff')
    assert( Boo01._val == True )
    Boo01.from_cer(b'\x01\x01\xff')
    assert( Boo01._val == True )
    Boo01.from_cer_ws(b'\x01\x01\xff')
    assert( Boo01._val == True )
    Boo01.from_der(b'\x01\x01\xff')
    assert( Boo01._val == True )
    Boo01.from_der_ws(b'\x01\x01\xff')
    assert( Boo01._val == True )
    # jer
    if _with_json:
        assert( Boo01.to_jer() == 'true' )
        Boo01.from_jer( 'true' )
        assert( Boo01._val == True )
    # OER/COER
    Boo01.from_oer(b'\xff')
    assert( Boo01._val == True )
    Boo01.from_oer_ws(b'\xff')
    assert( Boo01._val == True )
    Boo01.from_coer(b'\xff')
    assert( Boo01._val == True )
    Boo01.from_coer_ws(b'\xff')
    assert( Boo01._val == True )

    # Int01 ::= INTEGER
    Int01 = Mod['Int01']
    Int01.from_asn1('0')
    # encoding
    assert( Int01.to_aper() == Int01.to_aper_ws() == b'\x01\x00' )
    assert( Int01.to_uper() == Int01.to_uper_ws() == b'\x01\x00' )
    assert( Int01.to_ber() == Int01.to_ber_ws() == b'\x02\x01\x00' )
    assert( Int01.to_cer() == Int01.to_cer_ws() == b'\x02\x01\x00' )
    assert( Int01.to_der() == Int01.to_der_ws() == b'\x02\x01\x00' )
    assert( Int01.to_oer() == Int01.to_oer_ws() == b'\x01\x00' )
    assert( Int01.to_coer() == Int01.to_coer_ws() == b'\x01\x00' )
    # decoding
    Int01.from_aper(b'\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_aper_ws(b'\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_uper(b'\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_uper_ws(b'\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_ber(b'\x02\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_ber_ws(b'\x02\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_cer(b'\x02\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_cer_ws(b'\x02\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_der(b'\x02\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_der_ws(b'\x02\x01\x00')
    assert( Int01._val == 0 )
    # jer
    if _with_json:
        assert( Int01.to_jer() == '0' )
        Int01.from_jer('0')
        assert( Int01._val == 0 )
    # OER/COER
    Int01.from_oer(b'\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_oer_ws(b'\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_coer(b'\x01\x00')
    assert( Int01._val == 0 )
    Int01.from_coer_ws(b'\x01\x00')
    assert( Int01._val == 0 )
    #
    Int01.from_asn1('4096')
    # encoding
    assert( Int01.to_aper() == Int01.to_aper_ws() == b'\x02\x10\x00' )
    assert( Int01.to_uper() == Int01.to_uper_ws() == b'\x02\x10\x00' )
    assert( Int01.to_ber() == Int01.to_ber_ws() == b'\x02\x02\x10\x00' )
    assert( Int01.to_cer() == Int01.to_cer_ws() == b'\x02\x02\x10\x00' )
    assert( Int01.to_der() == Int01.to_der_ws() == b'\x02\x02\x10\x00' )
    assert( Int01.to_oer() == Int01.to_oer_ws() == b'\x02\x10\x00' )
    assert( Int01.to_coer() == Int01.to_coer_ws() == b'\x02\x10\x00' )
    # decoding
    Int01.from_aper(b'\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_aper_ws(b'\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_uper(b'\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_uper_ws(b'\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_ber(b'\x02\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_ber_ws(b'\x02\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_cer(b'\x02\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_cer_ws(b'\x02\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_der(b'\x02\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_der_ws(b'\x02\x02\x10\x00')
    assert( Int01._val == 4096 )
    # jer
    if _with_json:
        assert( Int01.to_jer() == '4096' )
        Int01.from_jer('4096')
        assert( Int01._val == 4096 )
    # OER/COER
    Int01.from_oer(b'\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_oer_ws(b'\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_coer(b'\x02\x10\x00')
    assert( Int01._val == 4096 )
    Int01.from_coer_ws(b'\x02\x10\x00')
    assert( Int01._val == 4096 )
    
    # Int02 ::= INTEGER (MIN..65535)
    Int02 = Mod['Int02']
    Int02.from_asn1('127')
    # encoding
    assert( Int02.to_aper() == Int02.to_aper_ws() == b'\x01\x7f' )
    assert( Int02.to_uper() == Int02.to_uper_ws() == b'\x01\x7f' )
    assert( Int02.to_ber() == Int02.to_ber_ws() == b'\x02\x01\x7f' )
    assert( Int02.to_cer() == Int02.to_cer_ws() == b'\x02\x01\x7f' )
    assert( Int02.to_der() == Int02.to_der_ws() == b'\x02\x01\x7f' )
    assert( Int02.to_oer() == Int02.to_oer_ws() == b'\x01\x7f' )
    assert( Int02.to_coer() == Int02.to_coer_ws() == b'\x01\x7f' )
    # decoding
    Int02.from_aper(b'\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_aper_ws(b'\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_uper(b'\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_uper_ws(b'\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_ber(b'\x02\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_ber_ws(b'\x02\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_cer(b'\x02\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_cer_ws(b'\x02\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_der(b'\x02\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_der_ws(b'\x02\x01\x7f')
    assert( Int02._val == 127 )
    # jer
    if _with_json:
        assert( Int02.to_jer() == '127' )
        Int02.from_jer( '127' )
        assert( Int02._val == 127 )
    # OER/COER
    Int02.from_oer(b'\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_oer_ws(b'\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_coer(b'\x01\x7f')
    assert( Int02._val == 127 )
    Int02.from_coer_ws(b'\x01\x7f')
    assert( Int02._val == 127 )
    #
    Int02.from_asn1('-128')
    # encoding
    assert( Int02.to_aper() == Int02.to_aper_ws() == b'\x01\x80' )
    assert( Int02.to_uper() == Int02.to_uper_ws() == b'\x01\x80' )
    assert( Int02.to_ber() == Int02.to_ber_ws() == b'\x02\x01\x80' )
    assert( Int02.to_cer() == Int02.to_cer_ws() == b'\x02\x01\x80' )
    assert( Int02.to_der() == Int02.to_der_ws() == b'\x02\x01\x80' )
    assert( Int02.to_oer() == Int02.to_oer_ws() == b'\x01\x80' )
    assert( Int02.to_coer() == Int02.to_coer_ws() == b'\x01\x80' )
    # decoding
    Int02.from_aper(b'\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_aper_ws(b'\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_uper(b'\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_uper_ws(b'\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_ber(b'\x02\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_ber_ws(b'\x02\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_cer(b'\x02\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_cer_ws(b'\x02\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_der(b'\x02\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_der_ws(b'\x02\x01\x80')
    assert( Int02._val == -128 )
    # jer
    if _with_json:
        assert( Int02.to_jer() == '-128' )
        Int02.from_jer('-128')
        assert( Int02._val == -128 )
    # OER/COER
    Int02.from_oer(b'\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_oer_ws(b'\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_coer(b'\x01\x80')
    assert( Int02._val == -128 )
    Int02.from_coer_ws(b'\x01\x80')
    assert( Int02._val == -128 )
    #
    Int02.from_asn1('128')
    # encoding
    assert( Int02.to_aper() == Int02.to_aper_ws() == b'\x02\x00\x80' )
    assert( Int02.to_uper() == Int02.to_uper_ws() == b'\x02\x00\x80' )
    assert( Int02.to_ber() == Int02.to_ber_ws() == b'\x02\x02\x00\x80' )
    assert( Int02.to_cer() == Int02.to_cer_ws() == b'\x02\x02\x00\x80' )
    assert( Int02.to_der() == Int02.to_der_ws() == b'\x02\x02\x00\x80' )
    assert( Int02.to_oer() == Int02.to_oer_ws() == b'\x02\x00\x80' )
    assert( Int02.to_coer() == Int02.to_coer_ws() == b'\x02\x00\x80' )
    # decoding
    Int02.from_aper(b'\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_aper_ws(b'\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_uper(b'\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_uper_ws(b'\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_ber(b'\x02\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_ber_ws(b'\x02\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_cer(b'\x02\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_cer_ws(b'\x02\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_der(b'\x02\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_der_ws(b'\x02\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_oer(b'\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_oer_ws(b'\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_coer(b'\x02\x00\x80')
    assert( Int02._val == 128 )
    Int02.from_coer_ws(b'\x02\x00\x80')
    assert( Int02._val == 128 )
    
    # Int03 ::= INTEGER (-1..MAX)
    Int03 = Mod['Int03']
    Int03.from_asn1('4096')
    # encoding
    assert( Int03.to_aper() == Int03.to_aper_ws() == b'\x02\x10\x01' )
    assert( Int03.to_uper() == Int03.to_uper_ws() == b'\x02\x10\x01' )
    assert( Int03.to_ber() == Int03.to_ber_ws() == b'\x02\x02\x10\x00' )
    assert( Int03.to_cer() == Int03.to_cer_ws() == b'\x02\x02\x10\x00' )
    assert( Int03.to_der() == Int03.to_der_ws() == b'\x02\x02\x10\x00' )
    assert( Int03.to_oer() == Int03.to_oer_ws() == b'\x02\x10\x00' )
    assert( Int03.to_coer() == Int03.to_coer_ws() == b'\x02\x10\x00' )
    # decoding
    Int03.from_aper(b'\x02\x10\x01')
    assert( Int03._val == 4096 )
    Int03.from_aper_ws(b'\x02\x10\x01')
    assert( Int03._val == 4096 )
    Int03.from_uper(b'\x02\x10\x01')
    assert( Int03._val == 4096 )
    Int03.from_uper_ws(b'\x02\x10\x01')
    assert( Int03._val == 4096 )
    Int03.from_ber(b'\x02\x02\x10\x00')
    assert( Int03._val == 4096 )
    Int03.from_ber_ws(b'\x02\x02\x10\x00')
    assert( Int03._val == 4096 )
    Int03.from_cer(b'\x02\x02\x10\x00')
    assert( Int03._val == 4096 )
    Int03.from_cer_ws(b'\x02\x02\x10\x00')
    assert( Int03._val == 4096 )
    Int03.from_der(b'\x02\x02\x10\x00')
    assert( Int03._val == 4096 )
    Int03.from_der_ws(b'\x02\x02\x10\x00')
    assert( Int03._val == 4096 )
    # jer
    if _with_json:
        assert( Int03.to_jer() == '4096' )
        Int03.from_jer('4096')
        assert( Int03._val == 4096 )
    # OER/COER
    Int03.from_oer(b'\x02\x10\x00')
    assert( Int03._val == 4096 )
    Int03.from_oer_ws(b'\x02\x10\x00')
    assert( Int03._val == 4096 )
    Int03.from_coer(b'\x02\x10\x00')
    assert( Int03._val == 4096 )
    Int03.from_coer_ws(b'\x02\x10\x00')
    assert( Int03._val == 4096 )
    
    # Int04 ::= INTEGER (1..MAX)
    Int04 = Mod['Int04']
    Int04.from_asn1('1')
    # encoding
    assert( Int04.to_aper() == Int04.to_aper_ws() == b'\x01\x00' )
    assert( Int04.to_uper() == Int04.to_uper_ws() == b'\x01\x00' )
    assert( Int04.to_ber() == Int04.to_ber_ws() == b'\x02\x01\x01' )
    assert( Int04.to_cer() == Int04.to_cer_ws() == b'\x02\x01\x01' )
    assert( Int04.to_der() == Int04.to_der_ws() == b'\x02\x01\x01' )
    assert( Int04.to_oer() == Int04.to_oer_ws() == b'\x01\x01' )
    assert( Int04.to_coer() == Int04.to_coer_ws() == b'\x01\x01' )
    # decoding
    Int04.from_aper(b'\x01\x00')
    assert( Int04._val == 1)
    Int04.from_aper_ws(b'\x01\x00')
    assert( Int04._val == 1 )
    Int04.from_uper(b'\x01\x00')
    assert( Int04._val == 1 )
    Int04.from_uper_ws(b'\x01\x00')
    assert( Int04._val == 1 )
    Int04.from_ber(b'\x02\x01\x01')
    assert( Int04._val == 1 )
    Int04.from_ber_ws(b'\x02\x01\x01')
    assert( Int04._val == 1 )
    Int04.from_cer(b'\x02\x01\x01')
    assert( Int04._val == 1 )
    Int04.from_cer_ws(b'\x02\x01\x01')
    assert( Int04._val == 1 )
    Int04.from_der(b'\x02\x01\x01')
    assert( Int04._val == 1 )
    Int04.from_der_ws(b'\x02\x01\x01')
    assert( Int04._val == 1 )
    # jer
    if _with_json:
        assert( Int04.to_jer() == '1' )
        Int04.from_jer('1')
        assert( Int04._val == 1 )
    # OER/COER
    Int04.from_oer(b'\x01\x01')
    assert( Int04._val == 1)
    Int04.from_oer_ws(b'\x01\x01')
    assert( Int04._val == 1)
    Int04.from_coer(b'\x01\x01')
    assert( Int04._val == 1 )
    Int04.from_coer_ws(b'\x01\x01')
    assert( Int04._val == 1 )
    #
    Int04.from_asn1('127')
    # encoding
    assert( Int04.to_aper() == Int04.to_aper_ws() == b'\x01~' )
    assert( Int04.to_uper() == Int04.to_uper_ws() == b'\x01~' )
    assert( Int04.to_ber() == Int04.to_ber_ws() == b'\x02\x01\x7f' )
    assert( Int04.to_cer() == Int04.to_cer_ws() == b'\x02\x01\x7f' )
    assert( Int04.to_der() == Int04.to_der_ws() == b'\x02\x01\x7f' )
    assert( Int04.to_oer() == Int04.to_oer_ws() == b'\x01\x7f' )
    assert( Int04.to_coer() == Int04.to_coer_ws() == b'\x01\x7f' )
    # decoding
    Int04.from_aper(b'\x01~')
    assert( Int04._val == 127 )
    Int04.from_aper_ws(b'\x01~')
    assert( Int04._val == 127 )
    Int04.from_uper(b'\x01~')
    assert( Int04._val == 127 )
    Int04.from_uper_ws(b'\x01~')
    assert( Int04._val == 127 )
    Int04.from_ber(b'\x02\x01\x7f')
    assert( Int04._val == 127 )
    Int04.from_ber_ws(b'\x02\x01\x7f')
    assert( Int04._val == 127 )
    Int04.from_cer(b'\x02\x01\x7f')
    assert( Int04._val == 127 )
    Int04.from_cer_ws(b'\x02\x01\x7f')
    assert( Int04._val == 127 )
    Int04.from_der(b'\x02\x01\x7f')
    assert( Int04._val == 127 )
    Int04.from_der_ws(b'\x02\x01\x7f')
    assert( Int04._val == 127 )
    # jer
    if _with_json:
        assert( Int04.to_jer() == '127' )
        Int04.from_jer('127')
        assert( Int04._val == 127 )
    # OER/COER
    Int04.from_oer(b'\x01\x7f')
    assert( Int04._val == 127)
    Int04.from_oer_ws(b'\x01\x7f')
    assert( Int04._val == 127)
    Int04.from_coer(b'\x01\x7f')
    assert( Int04._val == 127 )
    Int04.from_coer_ws(b'\x01\x7f')
    assert( Int04._val == 127 )
    
    # Int05 ::= INTEGER (0..MAX)
    Int05 = Mod['Int05']
    Int05.from_asn1('128')
    # encoding
    assert( Int05.to_aper() == Int05.to_aper_ws() == b'\x01\x80' )
    assert( Int05.to_uper() == Int05.to_uper_ws() == b'\x01\x80' )
    assert( Int05.to_ber() == Int05.to_ber_ws() == b'\x02\x02\x00\x80' )
    assert( Int05.to_cer() == Int05.to_cer_ws() == b'\x02\x02\x00\x80' )
    assert( Int05.to_der() == Int05.to_der_ws() == b'\x02\x02\x00\x80' )
    assert( Int05.to_oer() == Int05.to_oer_ws() == b'\x01\x80' )
    assert( Int05.to_coer() == Int05.to_coer_ws() == b'\x01\x80' )
    # decoding
    Int05.from_aper(b'\x01\x80')
    assert( Int05._val == 128 )
    Int05.from_aper_ws(b'\x01\x80')
    assert( Int05._val == 128 )
    Int05.from_uper(b'\x01\x80')
    assert( Int05._val == 128 )
    Int05.from_uper_ws(b'\x01\x80')
    assert( Int05._val == 128 )
    Int05.from_ber(b'\x02\x02\x00\x80')
    assert( Int05._val == 128 )
    Int05.from_ber_ws(b'\x02\x02\x00\x80')
    assert( Int05._val == 128 )
    Int05.from_cer(b'\x02\x02\x00\x80')
    assert( Int05._val == 128 )
    Int05.from_cer_ws(b'\x02\x02\x00\x80')
    assert( Int05._val == 128 )
    Int05.from_der(b'\x02\x02\x00\x80')
    assert( Int05._val == 128 )
    Int05.from_der_ws(b'\x02\x02\x00\x80')
    assert( Int05._val == 128 )
    # jer
    if _with_json:
        assert( Int05.to_jer() == '128' )
        Int05.from_jer('128')
        assert( Int05._val == 128 )
    # OER/COER
    Int05.from_oer(b'\x01\x80')
    assert( Int05._val == 128 )
    Int05.from_oer_ws(b'\x01\x80')
    assert( Int05._val == 128 )
    Int05.from_coer(b'\x01\x80')
    assert( Int05._val == 128 )
    Int05.from_coer_ws(b'\x01\x80')
    assert( Int05._val == 128 )
    
    # Int06 ::= INTEGER (3..6)
    Int06 = Mod['Int06']
    Int06.from_asn1('3')
    # encoding
    assert( Int06.to_aper() == Int06.to_aper_ws() == b'\x00' )
    assert( Int06.to_uper() == Int06.to_uper_ws() == b'\x00' )
    assert( Int06.to_ber() == Int06.to_ber_ws() == b'\x02\x01\x03' )
    assert( Int06.to_cer() == Int06.to_cer_ws() == b'\x02\x01\x03' )
    assert( Int06.to_der() == Int06.to_der_ws() == b'\x02\x01\x03' )
    assert( Int06.to_oer() == Int06.to_oer_ws() == b'\x03' )
    assert( Int06.to_coer() == Int06.to_coer_ws() == b'\x03' )
    # decoding
    Int06.from_aper(b'\x00')
    assert( Int06._val == 3 )
    Int06.from_aper_ws(b'\x00')
    assert( Int06._val == 3 )
    Int06.from_uper(b'\x00')
    assert( Int06._val == 3 )
    Int06.from_uper_ws(b'\x00')
    assert( Int06._val == 3 )
    Int06.from_ber(b'\x02\x01\x03')
    assert( Int06._val == 3 )
    Int06.from_ber_ws(b'\x02\x01\x03')
    assert( Int06._val == 3 )
    Int06.from_cer(b'\x02\x01\x03')
    assert( Int06._val == 3 )
    Int06.from_cer_ws(b'\x02\x01\x03')
    assert( Int06._val == 3 )
    Int06.from_der(b'\x02\x01\x03')
    assert( Int06._val == 3 )
    Int06.from_der_ws(b'\x02\x01\x03')
    assert( Int06._val == 3 )
    Int06.from_oer(b'\x03')
    assert( Int06._val == 3 )
    Int06.from_oer_ws(b'\x03')
    assert( Int06._val == 3 )
    Int06.from_coer(b'\x03')
    assert( Int06._val == 3 )
    Int06.from_coer_ws(b'\x03')
    assert( Int06._val == 3 )
    #
    Int06.from_asn1('6')
    # encoding
    assert( Int06.to_aper() == Int06.to_aper_ws() == b'\xc0' )
    assert( Int06.to_uper() == Int06.to_uper_ws() == b'\xc0' )
    assert( Int06.to_ber() == Int06.to_ber_ws() == b'\x02\x01\x06' )
    assert( Int06.to_cer() == Int06.to_cer_ws() == b'\x02\x01\x06' )
    assert( Int06.to_der() == Int06.to_der_ws() == b'\x02\x01\x06' )
    assert( Int06.to_oer() == Int06.to_oer_ws() == b'\x06' )
    assert( Int06.to_coer() == Int06.to_coer_ws() == b'\x06' )
    # decoding
    Int06.from_aper(b'\xc0')
    assert( Int06._val == 6 )
    Int06.from_aper_ws(b'\xc0')
    assert( Int06._val == 6 )
    Int06.from_uper(b'\xc0')
    assert( Int06._val == 6 )
    Int06.from_uper_ws(b'\xc0')
    assert( Int06._val == 6 )
    Int06.from_ber(b'\x02\x01\x06')
    assert( Int06._val == 6 )
    Int06.from_ber_ws(b'\x02\x01\x06')
    assert( Int06._val == 6 )
    Int06.from_cer(b'\x02\x01\x06')
    assert( Int06._val == 6 )
    Int06.from_cer_ws(b'\x02\x01\x06')
    assert( Int06._val == 6 )
    Int06.from_der(b'\x02\x01\x06')
    assert( Int06._val == 6 )
    Int06.from_der_ws(b'\x02\x01\x06')
    assert( Int06._val == 6 )
    Int06.from_oer(b'\x06')
    assert( Int06._val == 6 )
    Int06.from_oer_ws(b'\x06')
    assert( Int06._val == 6 )
    Int06.from_coer(b'\x06')
    assert( Int06._val == 6 )
    Int06.from_coer_ws(b'\x06')
    assert( Int06._val == 6 )
    
    # Int07 ::= INTEGER (4000..4254)
    Int07 = Mod['Int07']
    Int07.from_asn1('4002')
    # encoding
    assert( Int07.to_aper() == Int07.to_aper_ws() == b'\x02' )
    assert( Int07.to_uper() == Int07.to_uper_ws() == b'\x02' )
    assert( Int07.to_ber() == Int07.to_ber_ws() == b'\x02\x02\x0f\xa2' )
    assert( Int07.to_cer() == Int07.to_cer_ws() == b'\x02\x02\x0f\xa2' )
    assert( Int07.to_der() == Int07.to_der_ws() == b'\x02\x02\x0f\xa2' )
    assert( Int07.to_oer() == Int07.to_oer_ws() == b'\x0f\xa2' )
    assert( Int07.to_coer() == Int07.to_coer_ws() == b'\x0f\xa2' )
    # decoding
    Int07.from_aper(b'\x02')
    assert( Int07._val == 4002 )
    Int07.from_aper_ws(b'\x02')
    assert( Int07._val == 4002 )
    Int07.from_uper(b'\x02')
    assert( Int07._val == 4002 )
    Int07.from_uper_ws(b'\x02')
    assert( Int07._val == 4002 )
    Int07.from_ber(b'\x02\x02\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_ber_ws(b'\x02\x02\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_cer(b'\x02\x02\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_cer_ws(b'\x02\x02\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_der(b'\x02\x02\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_der_ws(b'\x02\x02\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_oer(b'\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_oer_ws(b'\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_coer(b'\x0f\xa2')
    assert( Int07._val == 4002 )
    Int07.from_coer_ws(b'\x0f\xa2')
    assert( Int07._val == 4002 )
    #
    Int07.from_asn1('4129')
    # encoding
    assert( Int07.to_aper() == Int07.to_aper_ws() == b'\x81' )
    assert( Int07.to_uper() == Int07.to_uper_ws() == b'\x81' )
    assert( Int07.to_ber() == Int07.to_ber_ws() == b'\x02\x02\x10!' )
    assert( Int07.to_cer() == Int07.to_cer_ws() == b'\x02\x02\x10!' )
    assert( Int07.to_der() == Int07.to_der_ws() == b'\x02\x02\x10!' )
    assert( Int07.to_oer() == Int07.to_oer_ws() == b'\x10!' )
    assert( Int07.to_coer() == Int07.to_coer_ws() == b'\x10!' )
    # decoding
    Int07.from_aper(b'\x81')
    assert( Int07._val == 4129 )
    Int07.from_aper_ws(b'\x81')
    assert( Int07._val == 4129 )
    Int07.from_uper(b'\x81')
    assert( Int07._val == 4129 )
    Int07.from_uper_ws(b'\x81')
    assert( Int07._val == 4129 )
    Int07.from_ber(b'\x02\x02\x10!')
    assert( Int07._val == 4129 )
    Int07.from_ber_ws(b'\x02\x02\x10!')
    assert( Int07._val == 4129 )
    Int07.from_cer(b'\x02\x02\x10!')
    assert( Int07._val == 4129 )
    Int07.from_cer_ws(b'\x02\x02\x10!')
    assert( Int07._val == 4129 )
    Int07.from_der(b'\x02\x02\x10!')
    assert( Int07._val == 4129 )
    Int07.from_der_ws(b'\x02\x02\x10!')
    assert( Int07._val == 4129 )
    Int07.from_oer(b'\x10!')
    assert( Int07._val == 4129 )
    Int07.from_oer_ws(b'\x10!')
    assert( Int07._val == 4129 )
    Int07.from_coer(b'\x10!')
    assert( Int07._val == 4129 )
    Int07.from_coer_ws(b'\x10!')
    assert( Int07._val == 4129 )
    
    # Int08 ::= INTEGER (4000..4255)
    Int08 = Mod['Int08']
    Int08.from_asn1('4255')
    # encoding
    assert( Int08.to_aper() == Int08.to_aper_ws() == b'\xff' )
    assert( Int08.to_uper() == Int08.to_uper_ws() == b'\xff' )
    assert( Int08.to_ber() == Int08.to_ber_ws() == b'\x02\x02\x10\x9f' )
    assert( Int08.to_cer() == Int08.to_cer_ws() == b'\x02\x02\x10\x9f' )
    assert( Int08.to_der() == Int08.to_der_ws() == b'\x02\x02\x10\x9f' )
    assert( Int08.to_oer() == Int08.to_oer_ws() == b'\x10\x9f' )
    assert( Int08.to_coer() == Int08.to_coer_ws() == b'\x10\x9f' )
    # decoding
    Int08.from_aper(b'\xff')
    assert( Int08._val == 4255 )
    Int08.from_aper_ws(b'\xff')
    assert( Int08._val == 4255 )
    Int08.from_uper(b'\xff')
    assert( Int08._val == 4255 )
    Int08.from_uper_ws(b'\xff')
    assert( Int08._val == 4255 )
    Int08.from_ber(b'\x02\x02\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_ber_ws(b'\x02\x02\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_cer(b'\x02\x02\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_cer_ws(b'\x02\x02\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_der(b'\x02\x02\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_der_ws(b'\x02\x02\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_oer(b'\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_oer_ws(b'\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_coer(b'\x10\x9f')
    assert( Int08._val == 4255 )
    Int08.from_coer_ws(b'\x10\x9f')
    assert( Int08._val == 4255 )
    
    # Int09 ::= INTEGER (0..32000)
    Int09 = Mod['Int09']
    Int09.from_asn1('31000')
    # encoding
    assert( Int09.to_aper() == Int09.to_aper_ws() == b'y\x18' )
    assert( Int09.to_uper() == Int09.to_uper_ws() == b'\xf20' )
    assert( Int09.to_ber() == Int09.to_ber_ws() == b'\x02\x02y\x18' )
    assert( Int09.to_cer() == Int09.to_cer_ws() == b'\x02\x02y\x18' )
    assert( Int09.to_der() == Int09.to_der_ws() == b'\x02\x02y\x18' )
    assert( Int09.to_oer() == Int09.to_oer_ws() == b'y\x18' )
    assert( Int09.to_coer() == Int09.to_coer_ws() == b'y\x18' )
    # decoding
    Int09.from_aper(b'y\x18')
    assert( Int09._val == 31000 )
    Int09.from_aper_ws(b'y\x18')
    assert( Int09._val == 31000 )
    Int09.from_uper(b'\xf20')
    assert( Int09._val == 31000 )
    Int09.from_uper_ws(b'\xf20')
    assert( Int09._val == 31000 )
    Int09.from_ber(b'\x02\x02y\x18')
    assert( Int09._val == 31000 )
    Int09.from_ber_ws(b'\x02\x02y\x18')
    assert( Int09._val == 31000 )
    Int09.from_cer(b'\x02\x02y\x18')
    assert( Int09._val == 31000 )
    Int09.from_cer_ws(b'\x02\x02y\x18')
    assert( Int09._val == 31000 )
    Int09.from_der(b'\x02\x02y\x18')
    assert( Int09._val == 31000 )
    Int09.from_der_ws(b'\x02\x02y\x18')
    assert( Int09._val == 31000 )
    Int09.from_oer(b'y\x18')
    assert( Int09._val == 31000 )
    Int09.from_oer_ws(b'y\x18')
    assert( Int09._val == 31000 )
    Int09.from_coer(b'y\x18')
    assert( Int09._val == 31000 )
    Int09.from_coer_ws(b'y\x18')
    assert( Int09._val == 31000 )
    
    # Int10 ::= INTEGER (1..65538)
    Int10 = Mod['Int10']
    Int10.from_asn1('1')
    # encoding
    assert( Int10.to_aper() == Int10.to_aper_ws() == b'\x00\x00' )
    assert( Int10.to_uper() == Int10.to_uper_ws() == b'\x00\x00\x00' )
    assert( Int10.to_ber() == Int10.to_ber_ws() == b'\x02\x01\x01' )
    assert( Int10.to_cer() == Int10.to_cer_ws() == b'\x02\x01\x01' )
    assert( Int10.to_der() == Int10.to_der_ws() == b'\x02\x01\x01' )
    assert( Int10.to_oer() == Int10.to_oer_ws() == b'\x00\x00\x00\x01' )
    assert( Int10.to_coer() == Int10.to_coer_ws() == b'\x00\x00\x00\x01' )
    # decoding
    Int10.from_aper(b'\x00\x00')
    assert( Int10._val == 1 )
    Int10.from_aper_ws(b'\x00\x00')
    assert( Int10._val == 1 )
    Int10.from_uper(b'\x00\x00\x00')
    assert( Int10._val == 1 )
    Int10.from_uper_ws(b'\x00\x00\x00')
    assert( Int10._val == 1 )
    Int10.from_ber(b'\x02\x01\x01')
    assert( Int10._val == 1 )
    Int10.from_ber_ws(b'\x02\x01\x01')
    assert( Int10._val == 1 )
    Int10.from_cer(b'\x02\x01\x01')
    assert( Int10._val == 1 )
    Int10.from_cer_ws(b'\x02\x01\x01')
    assert( Int10._val == 1 )
    Int10.from_der(b'\x02\x01\x01')
    assert( Int10._val == 1 )
    Int10.from_der_ws(b'\x02\x01\x01')
    assert( Int10._val == 1 )
    Int10.from_oer(b'\x00\x00\x00\x01')
    assert( Int10._val == 1 )
    Int10.from_oer_ws(b'\x00\x00\x00\x01')
    assert( Int10._val == 1 )
    Int10.from_coer(b'\x00\x00\x00\x01')
    assert( Int10._val == 1 )
    Int10.from_coer_ws(b'\x00\x00\x00\x01')
    assert( Int10._val == 1 )
    #
    Int10.from_asn1('257')
    # encoding
    assert( Int10.to_aper() == Int10.to_aper_ws() == b'@\x01\x00' )
    assert( Int10.to_uper() == Int10.to_uper_ws() == b'\x00\x80\x00' )
    assert( Int10.to_ber() == Int10.to_ber_ws() == b'\x02\x02\x01\x01' )
    assert( Int10.to_cer() == Int10.to_cer_ws() == b'\x02\x02\x01\x01' )
    assert( Int10.to_der() == Int10.to_der_ws() == b'\x02\x02\x01\x01' )
    assert( Int10.to_oer() == Int10.to_oer_ws() == b'\x00\x00\x01\x01' )
    assert( Int10.to_coer() == Int10.to_coer_ws() == b'\x00\x00\x01\x01' )
    # decoding
    Int10.from_aper(b'@\x01\x00')
    assert( Int10._val == 257 )
    Int10.from_aper_ws(b'@\x01\x00')
    assert( Int10._val == 257 )
    Int10.from_uper(b'\x00\x80\x00')
    assert( Int10._val == 257 )
    Int10.from_uper_ws(b'\x00\x80\x00')
    assert( Int10._val == 257 )
    Int10.from_ber(b'\x02\x02\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_ber_ws(b'\x02\x02\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_cer(b'\x02\x02\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_cer_ws(b'\x02\x02\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_der(b'\x02\x02\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_der_ws(b'\x02\x02\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_oer(b'\x00\x00\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_oer_ws(b'\x00\x00\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_coer(b'\x00\x00\x01\x01')
    assert( Int10._val == 257 )
    Int10.from_coer_ws(b'\x00\x00\x01\x01')
    assert( Int10._val == 257 )
    #
    Int10.from_asn1('65538')
    # encoding
    assert( Int10.to_aper() == Int10.to_aper_ws() == b'\x80\x01\x00\x01' )
    assert( Int10.to_uper() == Int10.to_uper_ws() == b'\x80\x00\x80' )
    assert( Int10.to_ber() == Int10.to_ber_ws() == b'\x02\x03\x01\x00\x02' )
    assert( Int10.to_cer() == Int10.to_cer_ws() == b'\x02\x03\x01\x00\x02' )
    assert( Int10.to_der() == Int10.to_der_ws() == b'\x02\x03\x01\x00\x02' )
    assert( Int10.to_oer() == Int10.to_oer_ws() == b'\x00\x01\x00\x02' )
    assert( Int10.to_coer() == Int10.to_coer_ws() == b'\x00\x01\x00\x02' )
    # decoding
    Int10.from_aper(b'\x80\x01\x00\x01')
    assert( Int10._val == 65538 )
    Int10.from_aper_ws(b'\x80\x01\x00\x01')
    assert( Int10._val == 65538 )
    Int10.from_uper(b'\x80\x00\x80')
    assert( Int10._val == 65538 )
    Int10.from_uper_ws(b'\x80\x00\x80')
    assert( Int10._val == 65538 )
    Int10.from_ber(b'\x02\x03\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_ber_ws(b'\x02\x03\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_cer(b'\x02\x03\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_cer_ws(b'\x02\x03\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_der(b'\x02\x03\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_der_ws(b'\x02\x03\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_oer(b'\x00\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_oer_ws(b'\x00\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_coer(b'\x00\x01\x00\x02')
    assert( Int10._val == 65538 )
    Int10.from_coer_ws(b'\x00\x01\x00\x02')
    assert( Int10._val == 65538 )
    
    # Int12 ::= INTEGER (-1..MAX, ...)
    Int12 = Mod['Int12']
    Int12.from_asn1('-100')
    # encoding
    assert( Int12.to_aper() == Int12.to_aper_ws() == b'\x80\x01\x9c' )
    assert( Int12.to_uper() == Int12.to_uper_ws() == b'\x80\xce\x00' )
    assert( Int12.to_ber() == Int12.to_ber_ws() == b'\x02\x01\x9c' )
    assert( Int12.to_cer() == Int12.to_cer_ws() == b'\x02\x01\x9c' )
    assert( Int12.to_der() == Int12.to_der_ws() == b'\x02\x01\x9c' )
    assert( Int12.to_oer() == Int12.to_oer_ws() == b'\x01\x9c' )
    assert( Int12.to_coer() == Int12.to_coer_ws() == b'\x01\x9c' )
    # decoding
    Int12.from_aper(b'\x80\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_aper_ws(b'\x80\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_uper(b'\x80\xce\x00')
    assert( Int12._val == -100 )
    Int12.from_uper_ws(b'\x80\xce\x00')
    assert( Int12._val == -100 )
    Int12.from_ber(b'\x02\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_ber_ws(b'\x02\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_cer(b'\x02\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_cer_ws(b'\x02\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_der(b'\x02\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_der_ws(b'\x02\x01\x9c')
    assert( Int12._val == -100 )
    # jer
    if _with_json:
        assert( Int12.to_jer() == '-100' )
        Int12.from_jer('-100')
        assert( Int12._val == -100 )
    # OER/COER
    Int12.from_oer(b'\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_oer_ws(b'\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_coer(b'\x01\x9c')
    assert( Int12._val == -100 )
    Int12.from_coer_ws(b'\x01\x9c')
    assert( Int12._val == -100 )
    
    # Int13 ::= INTEGER (3..6, ...)
    # encoding untested against commercial tools (often bound to 32 bits integers)
    Int13 = Mod['Int13']
    Int13.from_asn1('1234567890123456789012345678901234567890')
    # encoding
    assert( Int13.to_aper() == Int13.to_aper_ws() == b'\x80\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2' )
    assert( Int13.to_uper() == Int13.to_uper_ws() == b'\x88\x81\xd0d\x90:\xe0m\xf9\xdcV^/\xcbg\x1f\x85i\x00' )
    assert( Int13.to_ber() == Int13.to_ber_ws() == b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2' )
    assert( Int13.to_cer() == Int13.to_cer_ws() == b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2' )
    assert( Int13.to_der() == Int13.to_der_ws() == b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2' )
    assert( Int13.to_oer() == Int13.to_oer_ws() == b'\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2' )
    assert( Int13.to_coer() == Int13.to_coer_ws() == b'\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2' )
    # decoding
    Int13.from_aper(b'\x80\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_aper_ws(b'\x80\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_uper(b'\x88\x81\xd0d\x90:\xe0m\xf9\xdcV^/\xcbg\x1f\x85i\x00')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_uper_ws(b'\x88\x81\xd0d\x90:\xe0m\xf9\xdcV^/\xcbg\x1f\x85i\x00')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_ber(b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_ber_ws(b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_cer(b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_cer_ws(b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_der(b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_der_ws(b'\x02\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    # jer
    if _with_json:
        assert( Int13.to_jer() == '1234567890123456789012345678901234567890' )
        Int13.from_jer('1234567890123456789012345678901234567890')
        assert( Int13._val == 1234567890123456789012345678901234567890 )
    # OER/COER
    Int13.from_oer(b'\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_oer_ws(b'\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_coer(b'\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    Int13.from_coer_ws(b'\x11\x03\xa0\xc9 u\xc0\xdb\xf3\xb8\xac\xbc_\x96\xce?\n\xd2')
    assert( Int13._val == 1234567890123456789012345678901234567890 )
    
    # Rea01 ::= REAL
    Rea01 = Mod['Rea01']
    Rea01.from_asn1('8.56323e215')
    assert( Rea01._val == (856323, 10, 210) )
    # encoding
    assert( Rea01.to_aper() == Rea01.to_aper_ws() == b'\x0c\x03856323.E210' )
    assert( Rea01.to_uper() == Rea01.to_uper_ws() == b'\x0c\x03856323.E210' )
    assert( Rea01.to_ber() == Rea01.to_ber_ws() == b'\t\x0c\x03856323.E210' )
    assert( Rea01.to_cer() == Rea01.to_cer_ws() == b'\t\x0c\x03856323.E210' )
    assert( Rea01.to_der() == Rea01.to_der_ws() == b'\t\x0c\x03856323.E210' )
    # decoding
    Rea01.from_aper(b'\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_aper_ws(b'\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_uper(b'\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_uper_ws(b'\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_ber(b'\t\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_ber_ws(b'\t\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_cer(b'\t\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_cer_ws(b'\t\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_der(b'\t\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    Rea01.from_der_ws(b'\t\x0c\x03856323.E210')
    assert( Rea01._val == (856323, 10, 210) )
    # jer
    if _with_json:
        assert( Rea01._to_jval() == {'base10Value': '856323e210'} )
        Rea01.from_jer('{"base10Value": "856323E210"}')
        assert( Rea01._val == (856323, 10, 210) )
    #
    Rea01.from_asn1('{mantissa 123456, base 2, exponent -53}')
    assert( Rea01._val == (123456, 2, -53) )
    # encoding
    assert( Rea01.to_aper() == Rea01.to_aper_ws() == b'\x04\x80\xd1\x07\x89')
    assert( Rea01.to_uper() == Rea01.to_uper_ws() == b'\x04\x80\xd1\x07\x89' )
    assert( Rea01.to_ber() == Rea01.to_ber_ws() == b'\t\x04\x80\xd1\x07\x89' )
    assert( Rea01.to_cer() == Rea01.to_cer_ws() == b'\t\x04\x80\xd1\x07\x89' )
    assert( Rea01.to_der() == Rea01.to_der_ws() == b'\t\x04\x80\xd1\x07\x89' )
    assert( Rea01.to_oer() == Rea01.to_oer_ws() == b'\x06\t\x04\x80\xd1\x07\x89' )
    assert( Rea01.to_coer() == Rea01.to_coer_ws() == b'\x06\t\x04\x80\xd1\x07\x89' )
    # decoding
    Rea01.from_aper(b'\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_aper_ws(b'\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_uper(b'\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_uper_ws(b'\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_ber(b'\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_ber_ws(b'\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_cer(b'\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_cer_ws(b'\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_der(b'\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_der_ws(b'\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    # jer
    if _with_json:
        # we are losing some precision here
        assert( Rea01._to_jval() == {'base10Value': '1.3706369372812333e-11'} )
        Rea01.from_jer( '{"base10Value": "1.3706369372812333e-11"}' )
        assert( Rea01._val == (13706369372812333, 10, -27) )
    # OER/COER
    Rea01.from_oer(b'\x06\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_oer_ws(b'\x06\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_coer(b'\x06\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    Rea01.from_coer_ws(b'\x06\t\x04\x80\xd1\x07\x89')
    assert( Rea01._val == (1929, 2, -47) )
    
    # Enu01 ::= ENUMERATED {cheese, cake, coffee, tea}
    Enu01 = Mod['Enu01']
    Enu01.from_asn1('coffee')
    # encoding
    assert( Enu01.to_aper() == Enu01.to_aper_ws() == b'\x80' )
    assert( Enu01.to_uper() == Enu01.to_uper_ws() == b'\x80' )
    assert( Enu01.to_ber() == Enu01.to_ber_ws() == b'\n\x01\x02' )
    assert( Enu01.to_cer() == Enu01.to_cer_ws() == b'\n\x01\x02' )
    assert( Enu01.to_der() == Enu01.to_der_ws() == b'\n\x01\x02' )
    assert( Enu01.to_oer() == Enu01.to_oer_ws() == b'\x02' )
    assert( Enu01.to_coer() == Enu01.to_coer_ws() == b'\x02' )
    # decoding
    Enu01.from_aper(b'\x80')
    assert( Enu01._val == 'coffee' )
    Enu01.from_aper_ws(b'\x80')
    assert( Enu01._val == 'coffee' )
    Enu01.from_uper(b'\x80')
    assert( Enu01._val == 'coffee' )
    Enu01.from_uper_ws(b'\x80')
    assert( Enu01._val == 'coffee' )
    Enu01.from_ber(b'\n\x01\x02')
    assert( Enu01._val == 'coffee' )
    Enu01.from_ber_ws(b'\n\x01\x02')
    assert( Enu01._val == 'coffee' )
    Enu01.from_cer(b'\n\x01\x02')
    assert( Enu01._val == 'coffee')
    Enu01.from_cer_ws(b'\n\x01\x02')
    assert( Enu01._val == 'coffee' )
    Enu01.from_der(b'\n\x01\x02')
    assert( Enu01._val == 'coffee' )
    Enu01.from_der_ws(b'\n\x01\x02')
    assert( Enu01._val == 'coffee' )
    # jer
    if _with_json:
        assert( Enu01.to_jer() == '"coffee"' )
        Enu01.from_jer('"coffee"')
        assert( Enu01._val == 'coffee' )
    # OER/COER
    Enu01.from_oer(b'\x02')
    assert( Enu01._val == 'coffee' )
    Enu01.from_oer_ws(b'\x02')
    assert( Enu01._val == 'coffee' )
    Enu01.from_coer(b'\x02')
    assert( Enu01._val == 'coffee' )
    Enu01.from_coer_ws(b'\x02')
    assert( Enu01._val == 'coffee' )
    
    # Enu04 ::= ENUMERATED {cheese, ..., cake, coffee, tea}
    Enu04 = Mod['Enu04']
    Enu04.from_asn1('tea')
    # encoding
    assert( Enu04.to_aper() == Enu04.to_aper_ws() == b'\x82' )
    assert( Enu04.to_uper() == Enu04.to_uper_ws() == b'\x82' )
    assert( Enu04.to_ber() == Enu04.to_ber_ws() == b'\n\x01\x03' )
    assert( Enu04.to_cer() == Enu04.to_cer_ws() == b'\n\x01\x03' )
    assert( Enu04.to_der() == Enu04.to_der_ws() == b'\n\x01\x03' )
    assert( Enu04.to_oer() == Enu04.to_oer_ws() == b'\x03' )
    assert( Enu04.to_coer() == Enu04.to_coer_ws() == b'\x03' )
    # decoding
    Enu04.from_aper(b'\x82')
    assert( Enu04._val == 'tea' )
    Enu04.from_aper_ws(b'\x82')
    assert( Enu04._val == 'tea' )
    Enu04.from_uper(b'\x82')
    assert( Enu04._val == 'tea' )
    Enu04.from_uper_ws(b'\x82')
    assert( Enu04._val == 'tea' )
    Enu04.from_ber(b'\n\x01\x03')
    assert( Enu04._val == 'tea' )
    Enu04.from_ber_ws(b'\n\x01\x03')
    assert( Enu04._val == 'tea' )
    Enu04.from_cer(b'\n\x01\x03')
    assert( Enu04._val == 'tea')
    Enu04.from_cer_ws(b'\n\x01\x03')
    assert( Enu04._val == 'tea' )
    Enu04.from_der(b'\n\x01\x03')
    assert( Enu04._val == 'tea' )
    Enu04.from_der_ws(b'\n\x01\x03')
    assert( Enu04._val == 'tea' )
    Enu04.from_oer(b'\x03')
    assert( Enu04._val == 'tea' )
    Enu04.from_oer_ws(b'\x03')
    assert( Enu04._val == 'tea' )
    Enu04.from_coer(b'\x03')
    assert( Enu04._val == 'tea' )
    Enu04.from_coer_ws(b'\x03')
    assert( Enu04._val == 'tea' )
    
    # Oid01 ::= OBJECT IDENTIFIER
    Oid01 = Mod['Oid01']
    Oid01.from_asn1('{iso member-body(2) fr(250) type-org(1)}')
    # encoding
    assert( Oid01.to_aper() == Oid01.to_aper_ws() == b'\x04*\x81z\x01' )
    assert( Oid01.to_uper() == Oid01.to_uper_ws() == b'\x04*\x81z\x01' )
    assert( Oid01.to_ber() == Oid01.to_ber_ws() == b'\x06\x04*\x81z\x01' )
    assert( Oid01.to_cer() == Oid01.to_cer_ws() == b'\x06\x04*\x81z\x01' )
    assert( Oid01.to_der() == Oid01.to_der_ws() == b'\x06\x04*\x81z\x01' )
    assert( Oid01.to_oer() == Oid01.to_oer_ws() == b'\x04*\x81z\x01' )
    assert( Oid01.to_coer() == Oid01.to_coer_ws() == b'\x04*\x81z\x01' )
    # decoding
    Oid01.from_aper(b'\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_aper_ws(b'\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_uper(b'\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_uper_ws(b'\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_ber(b'\x06\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_ber_ws(b'\x06\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_cer(b'\x06\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_cer_ws(b'\x06\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_der(b'\x06\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_der_ws(b'\x06\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    # jer
    if _with_json:
        assert( Oid01.to_jer() == '"1.2.250.1"' )
        Oid01.from_jer('"1.2.250.1"')
        assert( Oid01._val == (1, 2, 250, 1) )
    # OER/COER
    Oid01.from_oer(b'\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_oer_ws(b'\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_coer(b'\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    Oid01.from_coer_ws(b'\x04*\x81z\x01')
    assert( Oid01._val == (1, 2, 250, 1) )
    
    # Oid02 ::= RELATIVE-OID
    Oid02 = Mod['Oid02']
    Oid02.from_asn1('{43 12 20 7}')
    # encoding
    assert( Oid02.to_aper() == Oid02.to_aper_ws() == b'\x04+\x0c\x14\x07' )
    assert( Oid02.to_uper() == Oid02.to_uper_ws() == b'\x04+\x0c\x14\x07' )
    assert( Oid02.to_ber() == Oid02.to_ber_ws() == b'\r\x04+\x0c\x14\x07' )
    assert( Oid02.to_cer() == Oid02.to_cer_ws() == b'\r\x04+\x0c\x14\x07' )
    assert( Oid02.to_der() == Oid02.to_der_ws() == b'\r\x04+\x0c\x14\x07' )
    assert( Oid02.to_oer() == Oid02.to_oer_ws() == b'\x04+\x0c\x14\x07' )
    assert( Oid02.to_coer() == Oid02.to_coer_ws() == b'\x04+\x0c\x14\x07' )
    # decoding
    Oid02.from_aper(b'\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_aper_ws(b'\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_uper(b'\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_uper_ws(b'\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_ber(b'\r\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_ber_ws(b'\r\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_cer(b'\r\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_cer_ws(b'\r\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_der(b'\r\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_der_ws(b'\r\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_oer(b'\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_oer_ws(b'\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_coer(b'\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    Oid02.from_coer_ws(b'\x04+\x0c\x14\x07')
    assert( Oid02._val == (43, 12, 20, 7) )
    
    # Bst01 ::= BIT STRING
    Bst01 = Mod['Bst01']
    Bst01.from_asn1('\'001111001001011010\'B')
    # encoding
    assert( Bst01.to_aper() == Bst01.to_aper_ws() == b'\x12<\x96\x80' )
    assert( Bst01.to_uper() == Bst01.to_uper_ws() == b'\x12<\x96\x80' )
    assert( Bst01.to_ber() == Bst01.to_ber_ws() == b'\x03\x04\x06<\x96\x80' )
    assert( Bst01.to_cer() == Bst01.to_cer_ws() == b'\x03\x04\x06<\x96\x80' )
    assert( Bst01.to_der() == Bst01.to_der_ws() == b'\x03\x04\x06<\x96\x80' )
    assert( Bst01.to_oer() == Bst01.to_oer_ws() == b'\x04\x06<\x96\x80' )
    assert( Bst01.to_coer() == Bst01.to_coer_ws() == b'\x04\x06<\x96\x80' )
    # decoding
    Bst01.from_aper(b'\x12<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_aper_ws(b'\x12<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_uper(b'\x12<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_uper_ws(b'\x12<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_ber(b'\x03\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_ber_ws(b'\x03\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_cer(b'\x03\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_cer_ws(b'\x03\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_der(b'\x03\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_der_ws(b'\x03\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    # jer
    if _with_json:
        assert( Bst01._to_jval() == {'length': 18, 'value': '3c9680'} )
        Bst01.from_jer('{"length": 18, "value": "3c9680"}')
        assert(  Bst01._val == (62042, 18) )
    # OER/COER
    Bst01.from_oer(b'\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_oer_ws(b'\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_coer(b'\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    Bst01.from_coer_ws(b'\x04\x06<\x96\x80')
    assert( Bst01._val == (62042, 18) )
    
    # Bst03 ::= BIT STRING (SIZE (0..24, ...))
    Bst03 = Mod['Bst03']
    Bst03.from_asn1('\'00111100100101101010010100001111\'B')
    # encoding
    assert( Bst03.to_aper() == Bst03.to_aper_ws() == b'\x80 <\x96\xa5\x0f' )
    assert( Bst03.to_uper() == Bst03.to_uper_ws() == b'\x90\x1eKR\x87\x80' )
    assert( Bst03.to_ber() == Bst03.to_ber_ws() == b'\x03\x05\x00<\x96\xa5\x0f' )
    assert( Bst03.to_cer() == Bst03.to_cer_ws() == b'\x03\x05\x00<\x96\xa5\x0f' )
    assert( Bst03.to_der() == Bst03.to_der_ws() == b'\x03\x05\x00<\x96\xa5\x0f' )
    assert( Bst03.to_oer() == Bst03.to_oer_ws() == b'\x05\x00<\x96\xa5\x0f' )
    assert( Bst03.to_coer() == Bst03.to_coer_ws() == b'\x05\x00<\x96\xa5\x0f' )
    # decoding
    Bst03.from_aper(b'\x80 <\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_aper_ws(b'\x80 <\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_uper(b'\x90\x1eKR\x87\x80')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_uper_ws(b'\x90\x1eKR\x87\x80')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_ber(b'\x03\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_ber_ws(b'\x03\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_cer(b'\x03\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_cer_ws(b'\x03\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_der(b'\x03\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_der_ws(b'\x03\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    # jer
    if _with_json:
        assert( Bst03._to_jval() == {'length': 32, 'value': '3c96a50f'} )
        Bst03.from_jer('{"length": 32, "value": "3c96a50f"}')
        assert( Bst03._val == (1016505615, 32) )
    # OER/COER
    Bst03.from_oer(b'\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_oer_ws(b'\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_coer(b'\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    Bst03.from_coer_ws(b'\x05\x00<\x96\xa5\x0f')
    assert( Bst03._val == (1016505615, 32) )
    
    # Bst06 ::= BIT STRING (SIZE (16))
    Bst06 = Mod['Bst06']
    Bst06.from_asn1('\'0011110010010110\'B')
    # encoding
    assert( Bst06.to_aper() == Bst06.to_aper_ws() == b'<\x96' )
    assert( Bst06.to_uper() == Bst06.to_uper_ws() == b'<\x96' )
    assert( Bst06.to_ber() == Bst06.to_ber_ws() == b'\x03\x03\x00<\x96')
    assert( Bst06.to_cer() == Bst06.to_cer_ws() == b'\x03\x03\x00<\x96' )
    assert( Bst06.to_der() == Bst06.to_der_ws() == b'\x03\x03\x00<\x96')
    assert( Bst06.to_oer() == Bst06.to_oer_ws() == b'<\x96' )
    assert( Bst06.to_coer() == Bst06.to_coer_ws() == b'<\x96' )
    # decoding
    Bst06.from_aper(b'<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_aper_ws(b'<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_uper(b'<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_uper_ws(b'<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_ber(b'\x03\x03\x00<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_ber_ws(b'\x03\x03\x00<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_cer(b'\x03\x03\x00<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_cer_ws(b'\x03\x03\x00<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_der(b'\x03\x03\x00<\x96')
    assert( Bst06._val == (15510, 16) )
    Bst06.from_der_ws(b'\x03\x03\x00<\x96')
    assert( Bst06._val == (15510, 16) )
    # jer
    if _with_json:
        assert( Bst06._to_jval() == '3c96' )
        Bst06.from_jer('"3c96"')
        assert( Bst06._val == (15510, 16) )
    # OER/COER
    Bst06.from_oer(b'<\x96' )
    assert( Bst06._val == (15510, 16) )
    Bst06.from_oer_ws(b'<\x96' )
    assert( Bst06._val == (15510, 16) )
    Bst06.from_coer(b'<\x96' )
    assert( Bst06._val == (15510, 16) )
    Bst06.from_coer_ws(b'<\x96' )
    assert( Bst06._val == (15510, 16) )
    
    # Ost01 ::= OCTET STRING
    Ost01 = Mod['Ost01']
    Ost01.from_asn1('\'0123456789ABCDEFFEDCBA9876543210\'H')
    # encoding
    assert( Ost01.to_aper() == Ost01.to_aper_ws() == b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_uper() == Ost01.to_uper_ws() == b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_ber() == Ost01.to_ber_ws() == b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_cer() == Ost01.to_cer_ws() == b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_der() == Ost01.to_der_ws() == b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_oer() == Ost01.to_oer_ws() == b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_coer() == Ost01.to_coer_ws() == b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    # decoding
    Ost01.from_aper(b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_aper_ws(b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_uper(b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_uper_ws(b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_ber(b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_ber_ws(b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_cer(b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_cer_ws(b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_der(b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_der_ws(b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    # jer
    if _with_json:
        assert( Ost01.to_jer() == '"0123456789abcdeffedcba9876543210"' )
        Ost01.from_jer('"0123456789abcdeffedcba9876543210"')
        assert(  Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    # OER/COER
    Ost01.from_oer(b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_oer_ws(b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_coer(b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    Ost01.from_coer_ws(b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10')
    assert( Ost01._val == b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    
    # Ost06 ::= OCTET STRING (SIZE (16))
    Ost06 = Mod['Ost06']
    Ost06.from_asn1('\'01234567890123456789012345678901\'H')
    # encoding
    assert( Ost06.to_aper() == Ost06.to_aper_ws() == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06.to_uper() == Ost06.to_uper_ws() == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01' )
    assert( Ost06.to_ber() == Ost06.to_ber_ws() == b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06.to_cer() == Ost06.to_cer_ws() == b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06.to_der() == Ost06.to_der_ws() == b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01' )
    assert( Ost06.to_oer() == Ost06.to_oer_ws() == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01' )
    assert( Ost06.to_coer() == Ost06.to_coer_ws() == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01' )
    # decoding
    Ost06.from_aper(b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_aper_ws(b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_uper(b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_uper_ws(b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_ber(b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_ber_ws(b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_cer(b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_cer_ws(b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_der(b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_der_ws(b'\x04\x10\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    # jer
    if _with_json:
        assert( Ost06.to_jer() == '"01234567890123456789012345678901"')
        Ost06.from_jer('"01234567890123456789012345678901"')
        assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    # OER/COER
    Ost06.from_oer(b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_oer_ws(b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_coer(b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    Ost06.from_coer_ws(b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    assert( Ost06._val == b'\x01#Eg\x89\x01#Eg\x89\x01#Eg\x89\x01')
    
    # Nus01 ::= NumericString
    Nus01 = Mod['Nus01']
    Nus01.from_asn1('"01 02 03 04 05"')
    # encoding
    assert( Nus01.to_aper() == Nus01.to_aper_ws() == b'\x0e\x12\x010\x14\x01P\x16' )
    assert( Nus01.to_uper() == Nus01.to_uper_ws() == b'\x0e\x12\x010\x14\x01P\x16' )
    assert( Nus01.to_ber() == Nus01.to_ber_ws() == b'\x12\x0e01 02 03 04 05' )
    assert( Nus01.to_cer() == Nus01.to_cer_ws() == b'\x12\x0e01 02 03 04 05' )
    assert( Nus01.to_der() == Nus01.to_der_ws() == b'\x12\x0e01 02 03 04 05' )
    assert( Nus01.to_oer() == Nus01.to_oer_ws() == b'\x0e01 02 03 04 05' )
    assert( Nus01.to_coer() == Nus01.to_coer_ws() == b'\x0e01 02 03 04 05' )
    # decoding
    Nus01.from_aper(b'\x0e\x12\x010\x14\x01P\x16')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_aper_ws(b'\x0e\x12\x010\x14\x01P\x16')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_uper(b'\x0e\x12\x010\x14\x01P\x16')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_uper_ws(b'\x0e\x12\x010\x14\x01P\x16')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_ber(b'\x12\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_ber_ws(b'\x12\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_cer(b'\x12\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_cer_ws(b'\x12\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_der(b'\x12\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_der_ws(b'\x12\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' ) 
    # jer
    if _with_json:
        assert( Nus01.to_jer() == '"01 02 03 04 05"' )
        Nus01.from_jer('"01 02 03 04 05"')
        assert( Nus01._val == '01 02 03 04 05' )
    # OER/COER
    Nus01.from_oer(b'\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_oer_ws(b'\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_coer(b'\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    Nus01.from_coer_ws(b'\x0e01 02 03 04 05')
    assert( Nus01._val == '01 02 03 04 05' )
    
    # Nus02 ::= NumericString (FROM ("0123"))
    Nus02 = Mod['Nus02']
    Nus02.from_asn1('"00113322"')
    # encoding
    assert( Nus02.to_aper() == Nus02.to_aper_ws() == b'\x08\x05\xfa' )
    assert( Nus02.to_uper() == Nus02.to_uper_ws() == b'\x08\x05\xfa' )
    assert( Nus02.to_ber() == Nus02.to_ber_ws() == b'\x12\x0800113322' )
    assert( Nus02.to_cer() == Nus02.to_cer_ws() == b'\x12\x0800113322' )
    assert( Nus02.to_der() == Nus02.to_der_ws() == b'\x12\x0800113322' )
    assert( Nus02.to_oer() == Nus02.to_oer_ws() == b'\x0800113322' )
    assert( Nus02.to_coer() == Nus02.to_coer_ws() == b'\x0800113322' )
    # decoding
    Nus02.from_aper(b'\x08\x05\xfa')
    assert( Nus02._val == '00113322' )
    Nus02.from_aper_ws(b'\x08\x05\xfa')
    assert( Nus02._val == '00113322' )
    Nus02.from_uper(b'\x08\x05\xfa')
    assert( Nus02._val == '00113322' )
    Nus02.from_uper_ws(b'\x08\x05\xfa')
    assert( Nus02._val == '00113322' )
    Nus02.from_ber(b'\x12\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_ber_ws(b'\x12\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_cer(b'\x12\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_cer_ws(b'\x12\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_der(b'\x12\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_der_ws(b'\x12\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_oer(b'\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_oer_ws(b'\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_coer(b'\x0800113322')
    assert( Nus02._val == '00113322' )
    Nus02.from_coer_ws(b'\x0800113322')
    assert( Nus02._val == '00113322' )
    
    # Prs01 ::= PrintableString
    Prs01 = Mod['Prs01']
    Prs01.from_asn1('"ambiguite"')
    # encoding
    assert( Prs01.to_aper() == Prs01.to_aper_ws() == b'\tambiguite' )
    assert( Prs01.to_uper() == Prs01.to_uper_ws() == b'\t\xc3\xb7\x16\x9c\xfdt\xf4\xca' )
    assert( Prs01.to_ber() == Prs01.to_ber_ws() == b'\x13\tambiguite' )
    assert( Prs01.to_cer() == Prs01.to_cer_ws() == b'\x13\tambiguite' )
    assert( Prs01.to_der() == Prs01.to_der_ws() == b'\x13\tambiguite' )
    assert( Prs01.to_oer() == Prs01.to_oer_ws() == b'\tambiguite' )
    assert( Prs01.to_coer() == Prs01.to_coer_ws() == b'\tambiguite' )
    # decoding
    Prs01.from_aper(b'\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_aper_ws(b'\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_uper(b'\t\xc3\xb7\x16\x9c\xfdt\xf4\xca')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_uper_ws(b'\t\xc3\xb7\x16\x9c\xfdt\xf4\xca')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_ber(b'\x13\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_ber_ws(b'\x13\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_cer(b'\x13\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_cer_ws(b'\x13\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_der(b'\x13\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_der_ws(b'\x13\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_oer(b'\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_oer_ws(b'\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_coer(b'\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    Prs01.from_coer_ws(b'\tambiguite')
    assert( Prs01._val == 'ambiguite' )
    
    # Prs02 ::= PrintableString (FROM ("ATCG"))
    Prs02 = Mod['Prs02']
    Prs02.from_asn1('"ATCGATTGAGCTCTAGCG"')
    # encoding
    assert( Prs02.to_aper() == Prs02.to_aper_ws() == b"\x126>'r`" )
    assert( Prs02.to_uper() == Prs02.to_uper_ws() == b"\x126>'r`" )
    assert( Prs02.to_ber() == Prs02.to_ber_ws() == b'\x13\x12ATCGATTGAGCTCTAGCG' )
    assert( Prs02.to_cer() == Prs02.to_cer_ws() == b'\x13\x12ATCGATTGAGCTCTAGCG' )
    assert( Prs02.to_der() == Prs02.to_der_ws() == b'\x13\x12ATCGATTGAGCTCTAGCG' )
    assert( Prs02.to_oer() == Prs02.to_oer_ws() == b'\x12ATCGATTGAGCTCTAGCG' )
    assert( Prs02.to_coer() == Prs02.to_coer_ws() == b'\x12ATCGATTGAGCTCTAGCG' )
    # decoding
    Prs02.from_aper(b"\x126>'r`")
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_aper_ws(b"\x126>'r`")
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_uper(b"\x126>'r`")
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_uper_ws(b"\x126>'r`")
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_ber(b'\x13\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_ber_ws(b'\x13\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_cer(b'\x13\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_cer_ws(b'\x13\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_der(b'\x13\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_der_ws(b'\x13\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_oer(b'\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_oer_ws(b'\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_coer(b'\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    Prs02.from_coer_ws(b'\x12ATCGATTGAGCTCTAGCG')
    assert( Prs02._val == 'ATCGATTGAGCTCTAGCG' )
    
    # Ias01 ::= IA5String
    Ias01 = Mod['Ias01']
    Ias01.from_asn1('"ambiguite"')
    # encoding
    assert( Ias01.to_aper() == Ias01.to_aper_ws() == b'\tambiguite' )
    assert( Ias01.to_uper() == Ias01.to_uper_ws() == b'\t\xc3\xb7\x16\x9c\xfdt\xf4\xca' )
    assert( Ias01.to_ber() == Ias01.to_ber_ws() == b'\x16\tambiguite' )
    assert( Ias01.to_cer() == Ias01.to_cer_ws() == b'\x16\tambiguite' )
    assert( Ias01.to_der() == Ias01.to_der_ws() == b'\x16\tambiguite' )
    assert( Ias01.to_oer() == Ias01.to_oer_ws() == b'\tambiguite' )
    assert( Ias01.to_coer() == Ias01.to_coer_ws() == b'\tambiguite' )
    # decoding
    Ias01.from_aper(b'\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_aper_ws(b'\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_uper(b'\t\xc3\xb7\x16\x9c\xfdt\xf4\xca')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_uper_ws(b'\t\xc3\xb7\x16\x9c\xfdt\xf4\xca')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_ber(b'\x16\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_ber_ws(b'\x16\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_cer(b'\x16\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_cer_ws(b'\x16\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_der(b'\x16\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_der_ws(b'\x16\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_oer(b'\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_oer_ws(b'\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_coer(b'\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    Ias01.from_coer_ws(b'\tambiguite')
    assert( Ias01._val == 'ambiguite' )
    
    # Ias04 ::= IA5String (SIZE (32))
    Ias04 = Mod['Ias04']
    Ias04.from_asn1('"This is a sentence of 32 chars:)"')
    # encoding
    assert( Ias04.to_aper() == Ias04.to_aper_ws() == b'This is a sentence of 32 chars:)' )
    assert( Ias04.to_uper() == Ias04.to_uper_ws() == b'\xa9\xa3O4\x1ay\xa0\xc2\x83\x9e]\xdd2\xee\xc7\x95\x06\xfc\xc8\x19\xb2A\x8fF\x1e\\\xdd)' )
    assert( Ias04.to_ber() == Ias04.to_ber_ws() == b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04.to_cer() == Ias04.to_cer_ws() == b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04.to_der() == Ias04.to_der_ws() == b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04.to_oer() == Ias04.to_oer_ws() == b'This is a sentence of 32 chars:)')
    assert( Ias04.to_coer() == Ias04.to_coer_ws() == b'This is a sentence of 32 chars:)')
    # decoding
    Ias04.from_aper(b'This is a sentence of 32 chars:)')
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_aper_ws(b'This is a sentence of 32 chars:)')
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_uper(b'\xa9\xa3O4\x1ay\xa0\xc2\x83\x9e]\xdd2\xee\xc7\x95\x06\xfc\xc8\x19\xb2A\x8fF\x1e\\\xdd)')
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_uper_ws(b'\xa9\xa3O4\x1ay\xa0\xc2\x83\x9e]\xdd2\xee\xc7\x95\x06\xfc\xc8\x19\xb2A\x8fF\x1e\\\xdd)')
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_ber(b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_ber_ws(b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_cer(b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_cer_ws(b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_der(b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_der_ws(b'\x16 This is a sentence of 32 chars:)' )
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_oer(b'This is a sentence of 32 chars:)')
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_oer_ws(b'This is a sentence of 32 chars:)')
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_coer(b'This is a sentence of 32 chars:)')
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    Ias04.from_coer_ws(b'This is a sentence of 32 chars:)')
    assert( Ias04._val == 'This is a sentence of 32 chars:)' )
    
    # U8s01 ::= UTF8String
    U8s01 = Mod['U8s01']
    U8s01.from_asn1(u'"ambiguïté"')
    # encoding
    assert( U8s01.to_aper() == U8s01.to_aper_ws() == b'\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_uper() == U8s01.to_uper_ws() == b'\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_ber() == U8s01.to_ber_ws() == b'\x0c\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_cer() == U8s01.to_cer_ws() == b'\x0c\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_der() == U8s01.to_der_ws() == b'\x0c\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_oer() == U8s01.to_oer_ws() == b'\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_coer() == U8s01.to_coer_ws() == b'\x0bambigu\xc3\xaft\xc3\xa9' )
    # decoding
    U8s01.from_aper(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_aper_ws(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_uper(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_uper_ws(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_ber(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_ber_ws(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_cer(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_cer_ws(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_der(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_der_ws(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    # jer
    if _with_json:
        assert( U8s01.to_jer() == '"ambigu\\u00eft\\u00e9"' )
        U8s01.from_jer('"ambigu\\u00eft\\u00e9"')
        assert( U8s01._val == u'ambiguïté' )
    # OER/COER
    U8s01.from_oer(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_oer_ws(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_coer(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    U8s01.from_coer_ws(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == u'ambiguïté' )
    
    # Uns01 ::= UniversalString
    Uns01 = Mod['Uns01']
    Uns01.from_asn1(u'"ambiguïté"')
    # encoding
    assert( Uns01.to_aper() == Uns01.to_aper_ws() == b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_uper() == Uns01.to_uper_ws() == b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_ber() == Uns01.to_ber_ws() == b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_cer() == Uns01.to_cer_ws() == b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_der() == Uns01.to_der_ws() == b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_oer() == Uns01.to_oer_ws() == b'$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_coer() == Uns01.to_coer_ws() == b'$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    # decoding
    Uns01.from_aper(b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_aper_ws(b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_uper(b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_uper_ws(b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_ber(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_ber_ws(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_cer(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_cer_ws(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_der(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_der_ws(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_oer(b'$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_oer_ws(b'$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_coer(b'$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    Uns01.from_coer_ws(b'$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == u'ambiguïté' )
    
    # Uti01 ::= UTCTime
    Uti01 = Mod['Uti01']
    Uti01.from_asn1('"1705181130Z"')
    # encoding
    assert( Uti01.to_aper() == Uti01.to_aper_ws() == b'\r170518113000Z' )
    assert( Uti01.to_uper() == Uti01.to_uper_ws() == b'\rb\xdd\x83V.\x18\xb1f\xc1\x83\x0b@' )
    assert( Uti01.to_ber() == Uti01.to_ber_ws() == b'\x17\x0b1705181130Z' )
    assert( Uti01.to_cer() == Uti01.to_cer_ws() == b'\x17\r170518113000Z' )
    assert( Uti01.to_der() == Uti01.to_der_ws() == b'\x17\r170518113000Z' )
    # decoding
    Uti01.from_aper(b'\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_aper_ws(b'\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_uper(b'\rb\xdd\x83V.\x18\xb1f\xc1\x83\x0b@')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_uper_ws(b'\rb\xdd\x83V.\x18\xb1f\xc1\x83\x0b@')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_ber(b'\x17\x0b1705181130Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', None, 'Z') )
    Uti01.from_ber_ws(b'\x17\x0b1705181130Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', None, 'Z') )
    Uti01.from_cer(b'\x17\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_cer_ws(b'\x17\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_der(b'\x17\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_der_ws(b'\x17\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    
    # Gti01 ::= GeneralizedTime
    Gti01 = Mod['Gti01']
    Gti01.from_asn1('"20170518073512.012300-1130"')
    # encoding
    assert( Gti01.to_aper() == Gti01.to_aper_ws() == b'\x1420170518190512.0123Z' )
    assert( Gti01.to_uper() == Gti01.to_uper_ws() == b'\x14d\xc1\x8bv\rX\xb8b\xe5\x83V,\x970b\xc9\x9d\xa0' )
    assert( Gti01.to_ber() == Gti01.to_ber_ws() == b'\x18\x1a20170518073512.012300-1130' )
    assert( Gti01.to_cer() == Gti01.to_cer_ws() == b'\x18\x1420170518190512.0123Z' )
    assert( Gti01.to_der() == Gti01.to_der_ws() == b'\x18\x1420170518190512.0123Z' )
    # decoding
    Gti01.from_aper(b'\x1420170518190512.0123Z')
    assert( Gti01._val == ('2017', '05', '18', '19', '05', '12', '0123', 'Z') )
    Gti01.from_aper_ws(b'\x1420170518190512.0123Z')
    assert( Gti01._val == ('2017', '05', '18', '19', '05', '12', '0123', 'Z') )
    Gti01.from_uper(b'\x14d\xc1\x8bv\rX\xb8b\xe5\x83V,\x970b\xc9\x9d\xa0')
    assert( Gti01._val == ('2017', '05', '18', '19', '05', '12', '0123', 'Z') )
    Gti01.from_uper_ws(b'\x14d\xc1\x8bv\rX\xb8b\xe5\x83V,\x970b\xc9\x9d\xa0')
    assert( Gti01._val == ('2017', '05', '18', '19', '05', '12', '0123', 'Z') )
    Gti01.from_ber(b'\x18\x1a20170518073512.012300-1130')
    assert( Gti01._val == ('2017', '05', '18', '07', '35', '12', '012300', '-1130') )
    Gti01.from_ber_ws(b'\x18\x1a20170518073512.012300-1130')
    assert( Gti01._val == ('2017', '05', '18', '07', '35', '12', '012300', '-1130') )
    Gti01.from_cer(b'\x18\x1420170518190512.0123Z')
    assert( Gti01._val == ('2017', '05', '18', '19', '05', '12', '0123', 'Z') )
    Gti01.from_cer_ws(b'\x18\x1420170518190512.0123Z')
    assert( Gti01._val == ('2017', '05', '18', '19', '05', '12', '0123', 'Z') )
    Gti01.from_der(b'\x18\x1420170518190512.0123Z')
    assert( Gti01._val == ('2017', '05', '18', '19', '05', '12', '0123', 'Z') )
    Gti01.from_der_ws(b'\x18\x1420170518190512.0123Z')
    assert( Gti01._val == ('2017', '05', '18', '19', '05', '12', '0123', 'Z') )
    
    # Cho01 ::= CHOICE { --check test_asn1rt_mod.asn file-- }
    Cho01 = Mod['Cho01']
    Cho01.from_asn1('int: 2000')
    # encoding
    assert( Cho01.to_aper() == Cho01.to_aper_ws() == b' \x02\x07\xcf' )
    assert( Cho01.to_uper() == Cho01.to_uper_ws() == b' @\xf9\xe0' )
    assert( Cho01.to_ber() == Cho01.to_ber_ws() == b'\xaa\x07\x7fP\x04\x02\x02\x07\xd0' )
    assert( Cho01.to_cer() == Cho01.to_cer_ws() == b'\xaa\x80\x7fP\x80\x02\x02\x07\xd0\x00\x00\x00\x00' )
    assert( Cho01.to_der() == Cho01.to_der_ws() == b'\xaa\x07\x7fP\x04\x02\x02\x07\xd0' )
    assert( Cho01.to_oer() == Cho01.to_oer_ws() == b'\x8a\x02\x07\xd0' )
    assert( Cho01.to_coer() == Cho01.to_coer_ws() == b'\x8a\x02\x07\xd0' )
    # decoding
    Cho01.from_aper(b' \x02\x07\xcf')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_aper_ws(b' \x02\x07\xcf')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_uper(b' @\xf9\xe0')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_uper_ws(b' @\xf9\xe0')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_ber(b'\xaa\x07\x7fP\x04\x02\x02\x07\xd0')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_ber_ws(b'\xaa\x07\x7fP\x04\x02\x02\x07\xd0')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_cer(b'\xaa\x80\x7fP\x80\x02\x02\x07\xd0\x00\x00\x00\x00')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_cer_ws(b'\xaa\x80\x7fP\x80\x02\x02\x07\xd0\x00\x00\x00\x00')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_der(b'\xaa\x07\x7fP\x04\x02\x02\x07\xd0')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_der_ws(b'\xaa\x07\x7fP\x04\x02\x02\x07\xd0')
    assert( Cho01._val == ('int', 2000) )
    # jer
    if _with_json:
        assert( Cho01._to_jval() == {'int': 2000} )
        Cho01.from_jer('{"int": 2000}')
        assert( Cho01._val == ('int', 2000) )
    # OER/COER
    Cho01.from_oer(b'\x8a\x02\x07\xd0')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_oer_ws(b'\x8a\x02\x07\xd0')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_coer(b'\x8a\x02\x07\xd0')
    assert( Cho01._val == ('int', 2000) )
    Cho01.from_coer_ws(b'\x8a\x02\x07\xd0')
    assert( Cho01._val == ('int', 2000) )
    
    # Seq01 ::= SEQUENCE { --check test_asn1rt_mod.asn file-- }
    Seq01 = Mod['Seq01']
    Seq01.from_asn1('{boo FALSE, int 1024, enu cake}')
    S_val = {'boo': False, 'int': 1024, 'enu': 'cake'}
    # encoding
    assert( Seq01.to_aper() == Seq01.to_aper_ws() == b'`\x02\x03\xff@' )
    assert( Seq01.to_uper() == Seq01.to_uper_ws() == b'` ?\xf4' )
    assert( Seq01.to_ber() == Seq01.to_ber_ws() == b'0\x0e\x01\x01\x00\xbf\x81\x00\x04\x02\x02\x04\x00\n\x01\x01' )
    assert( Seq01.to_cer() == Seq01.to_cer_ws() == b'0\x80\x01\x01\x00\xbf\x81\x00\x80\x02\x02\x04\x00\x00\x00\n\x01\x01\x00\x00' )
    assert( Seq01.to_der() == Seq01.to_der_ws() == b'0\x0e\x01\x01\x00\xbf\x81\x00\x04\x02\x02\x04\x00\n\x01\x01' )
    assert( Seq01.to_oer() == Seq01.to_oer_ws() == b'`\x00\x02\x04\x00\x01' )
    assert( Seq01.to_coer() == Seq01.to_coer_ws() == b'`\x00\x02\x04\x00\x01' )
    # decoding
    Seq01.from_aper(b'`\x02\x03\xff@')
    assert( Seq01._val == S_val )
    Seq01.from_aper_ws(b'`\x02\x03\xff@')
    assert( Seq01._val == S_val )
    Seq01.from_uper(b'` ?\xf4')
    assert( Seq01._val == S_val )
    Seq01.from_uper_ws(b'` ?\xf4')
    assert( Seq01._val == S_val )
    Seq01.from_ber(b'0\x0e\x01\x01\x00\xbf\x81\x00\x04\x02\x02\x04\x00\n\x01\x01')
    assert( Seq01._val == S_val )
    Seq01.from_ber_ws(b'0\x0e\x01\x01\x00\xbf\x81\x00\x04\x02\x02\x04\x00\n\x01\x01')
    assert( Seq01._val == S_val )
    Seq01.from_cer(b'0\x80\x01\x01\x00\xbf\x81\x00\x80\x02\x02\x04\x00\x00\x00\n\x01\x01\x00\x00')
    assert( Seq01._val == S_val )
    Seq01.from_cer_ws(b'0\x80\x01\x01\x00\xbf\x81\x00\x80\x02\x02\x04\x00\x00\x00\n\x01\x01\x00\x00')
    assert( Seq01._val == S_val )
    Seq01.from_der(b'0\x0e\x01\x01\x00\xbf\x81\x00\x04\x02\x02\x04\x00\n\x01\x01')
    assert( Seq01._val == S_val )
    Seq01.from_der_ws(b'0\x0e\x01\x01\x00\xbf\x81\x00\x04\x02\x02\x04\x00\n\x01\x01')
    assert( Seq01._val == S_val )
    # jer
    if _with_json:
        assert( Seq01._to_jval() == {'boo': False, 'enu': 'cake', 'int': 1024} )
        Seq01.from_jer('{"boo": false, "enu": "cake", "int": 1024}')
        assert( Seq01._val == S_val )
    # OER/COER
    Seq01.from_oer(b'`\x00\x02\x04\x00\x01')
    assert( Seq01._val == S_val )
    Seq01.from_oer_ws(b'`\x00\x02\x04\x00\x01')
    assert( Seq01._val == S_val )
    Seq01.from_coer(b'`\x00\x02\x04\x00\x01')
    assert( Seq01._val == S_val )
    Seq01.from_coer_ws(b'`\x00\x02\x04\x00\x01')
    assert( Seq01._val == S_val )
    
    # Seq02 ::= SEQUENCE (SIZE (2..5)) OF Ias02
    Seq02 = Mod['Seq02']
    Seq02.from_asn1('{"un", "gros", "pterodactyle"}')
    S_val = ['un', 'gros', 'pterodactyle']
    # encoding
    assert( Seq02.to_aper() == Seq02.to_aper_ws() == b'Dun gros`pterodactyle' )
    assert( Seq02.to_uper() == Seq02.to_uper_ws() == b'E\xd7q3\xf2\xdf\xcd\x9c:e\xe5\xbf&\x1c}<\xec\xca' )
    assert( Seq02.to_ber() == Seq02.to_ber_ws() == b'0\x18\x16\x02un\x16\x04gros\x16\x0cpterodactyle' )
    assert( Seq02.to_cer() == Seq02.to_cer_ws() ==  b'0\x80\x16\x02un\x16\x04gros\x16\x0cpterodactyle\x00\x00' )
    assert( Seq02.to_der() == Seq02.to_der_ws() == b'0\x18\x16\x02un\x16\x04gros\x16\x0cpterodactyle' )
    assert( Seq02.to_oer() == Seq02.to_oer_ws() == b'\x01\x03\x02un\x04gros\x0cpterodactyle' )
    assert( Seq02.to_coer() == Seq02.to_coer_ws() == b'\x01\x03\x02un\x04gros\x0cpterodactyle' )
    # decoding
    Seq02.from_aper(b'Dun gros`pterodactyle')
    assert( Seq02._val == S_val )
    Seq02.from_aper_ws(b'Dun gros`pterodactyle')
    assert( Seq02._val == S_val )
    Seq02.from_uper(b'E\xd7q3\xf2\xdf\xcd\x9c:e\xe5\xbf&\x1c}<\xec\xca')
    assert( Seq02._val == S_val )
    Seq02.from_uper_ws(b'E\xd7q3\xf2\xdf\xcd\x9c:e\xe5\xbf&\x1c}<\xec\xca')
    assert( Seq02._val == S_val )
    Seq02.from_ber(b'0\x18\x16\x02un\x16\x04gros\x16\x0cpterodactyle')
    assert( Seq02._val == S_val )
    Seq02.from_ber_ws(b'0\x18\x16\x02un\x16\x04gros\x16\x0cpterodactyle')
    assert( Seq02._val == S_val )
    Seq02.from_cer( b'0\x80\x16\x02un\x16\x04gros\x16\x0cpterodactyle\x00\x00')
    assert( Seq02._val == S_val )
    Seq02.from_cer_ws( b'0\x80\x16\x02un\x16\x04gros\x16\x0cpterodactyle\x00\x00')
    assert( Seq02._val == S_val )
    Seq02.from_der(b'0\x18\x16\x02un\x16\x04gros\x16\x0cpterodactyle')
    assert( Seq02._val == S_val )
    Seq02.from_der_ws(b'0\x18\x16\x02un\x16\x04gros\x16\x0cpterodactyle')
    assert( Seq02._val == S_val )
    # jer
    if _with_json:
        assert( Seq02._to_jval() == ['un', 'gros', 'pterodactyle'] )
        Seq02.from_jer('["un", "gros", "pterodactyle"]')
        assert( Seq02._val == S_val )
    # OER/COER
    Seq02.from_oer(b'\x01\x03\x02un\x04gros\x0cpterodactyle')
    assert( Seq02._val == S_val )
    Seq02.from_oer_ws(b'\x01\x03\x02un\x04gros\x0cpterodactyle')
    assert( Seq02._val == S_val )
    Seq02.from_coer(b'\x01\x03\x02un\x04gros\x0cpterodactyle')
    assert( Seq02._val == S_val )
    Seq02.from_coer_ws(b'\x01\x03\x02un\x04gros\x0cpterodactyle')
    assert( Seq02._val == S_val )
    
    # Set01 ::= SET { --check test_asn1rt_mod.asn file-- }
    Set01 = Mod['Set01']
    Set01.from_asn1('{enu cheese, boo TRUE, int 5565, cho enu: cake}')
    S_val = {'boo': True, 'cho': ('enu', 'cake'), 'enu': 'cheese', 'int': 5565}
    # encoding
    assert( Set01.to_aper() == Set01.to_aper_ws() == b'r@\x02\x15\xbc' )
    assert( Set01.to_uper() == Set01.to_uper_ws() == b'r@\x85o\x00' )
    assert( Set01.to_ber() == Set01.to_ber_ws() == b'1\x0e\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd' )
    assert( Set01.to_cer() == Set01.to_cer_ws() == b'1\x80\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd\x00\x00' )
    assert( Set01.to_der() == Set01.to_der_ws() == b'1\x0e\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd' )
    assert( Set01.to_oer() == Set01.to_oer_ws() == b'`\xff\x00\x82\x01\x02\x15\xbd' )
    assert( Set01.to_coer() == Set01.to_coer_ws() == b'`\xff\x00\x82\x01\x02\x15\xbd' )
    # decoding
    Set01.from_aper(b'r@\x02\x15\xbc')
    assert( Set01._val == S_val )
    Set01.from_aper_ws(b'r@\x02\x15\xbc')
    assert( Set01._val == S_val )
    Set01.from_uper(b'r@\x85o\x00')
    assert( Set01._val == S_val )
    Set01.from_uper_ws(b'r@\x85o\x00')
    assert( Set01._val == S_val )
    Set01.from_ber(b'1\x0e\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd')
    assert( Set01._val == S_val )
    Set01.from_ber_ws(b'1\x0e\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd')
    assert( Set01._val == S_val )
    Set01.from_cer(b'1\x80\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd\x00\x00')
    assert( Set01._val == S_val )
    Set01.from_cer_ws(b'1\x80\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd\x00\x00')
    assert( Set01._val == S_val )
    Set01.from_der(b'1\x0e\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd')
    assert( Set01._val == S_val )
    Set01.from_der_ws(b'1\x0e\x01\x01\xff\n\x01\x00\x82\x01\x01\x9f@\x02\x15\xbd')
    assert( Set01._val == S_val )
    # jer
    if _with_json:
        assert( Set01._to_jval() == {'boo': True, 'cho': {'enu': 'cake'}, 'enu': 'cheese', 'int': 5565} )
        Set01.from_jer('{"boo": true, "cho": {"enu": "cake"}, "enu": "cheese", "int": 5565}')
        assert( Set01._val == S_val )
    # OER/COER
    Set01.from_oer(b'`\xff\x00\x82\x01\x02\x15\xbd')
    assert( Set01._val == S_val )
    Set01.from_oer_ws(b'`\xff\x00\x82\x01\x02\x15\xbd')
    assert( Set01._val == S_val )
    Set01.from_coer(b'`\xff\x00\x82\x01\x02\x15\xbd')
    assert( Set01._val == S_val )
    Set01.from_coer_ws(b'`\xff\x00\x82\x01\x02\x15\xbd')
    assert( Set01._val == S_val )
    
    return 0

def test_rt_base():
    _load_rt_base()
    _test_rt_base()


pkts_rrc3g = tuple(map(unhexlify, (
    # PagingType1 (PCCH)
    '4455c803999055c601b95855aa06b09e',
    '4255ba00047855840454b2',
    '4055c8039990',
    # ActiveSetUpdate (DL-DCCH)
    'd2f17f0cb000304a00880a014aa0',
    'c70b4b01f800384a0cf80b4348087980',
    # DownlinkDirectTransfer (DL-DCCH)
    'ca0d7d191940002061e0',
    'b8bd242d114e02e101300bc05f020e9fe02300be9c607b15e540258640400000',
    # PhysicalChannelReconfiguration (DL-DCCH)
    'adb98ce3d28000c01147c400466ff0707a2515459fcc008cdfe0e0f44a2a8b06bec002337f8383d128aa2a9433e02d0d3a300880a034a943cc0550d3c6',
    # RRCConnectionRelease (DL-DCCH)
    'c94874130bc800',
    # RadioBearerReconfiguration (DL-DCCH)
    '9576583b9b00000000881cfeb41648c1386c82cfe741648c1386c83cfe741648c1386c009700',
    # RadioBearerSetup (DL-DCCH), 
    # WNG: need ASN1CodecPER.GET_DEFVAL=True + ASN1CodecPER.CANONICAL=True,
    #      or ASN1CodecPER.GET_DEFVAL=False
    'd5956df0938204aa41d00804c42388303a80e2b8830428103388304a8124100b0120a4b4989352b95f83788120111d9b1c442880027020a20476688100ce111d5824401e0445ce0c73d7a487088000204e0414408ecd4810100ce111db8090803c088bc002607e013600',
    # SecurityModeCommand (DL-DCCH)
    'b81ea4c39c0e8001800128c0000101310008c00380990c02',
    'e7848cd48c0e0001800128c0000100f10000c002fdfa0b8b0040',
    # SignallingConnectionRelease (DL-DCCH)
    'bc9728229440',
    # InitialDirectTransfer (UL-DCCH)
    '15001700603138081ab8c5802fa5002f55fe00020a50',
    '15860a018040408017c083a8000880cf981159ffacb316288001f2b335e400c97ce799384018c02fa7d4144b09881faf08019010000600004ac0',
    '15001700602920a01ab8c5802fa5002f55fe0001caf0',
    # UplinkDirectTransfer (UL-DCCH)
    '97e91641aec002c1968401704800',
    # SecurityModeComplete (UL-DCCH)
    'a452ec578d31111111800002016200218000',
    # RadioBearerSetupComplete (UL-DCCH)
    'efd728f42bcc000024d0',
    # RadioBearerReconfigurationComplete (UL-DCCH)
    '847d9dc832c000',
    # ActiveSetUpdateComplete (UL-DCCH)
    'e431772f2800',
    # PhysicalChannelReconfigurationComplete (UL-DCCH)
    'f3e0b9537a4000',
    # RadioBearerReleaseFailure (UL-DCCH)
    '39a0',
    # RRCConnectionSetupComplete (UL-DCCH)
    '4b88000220000c64350aa0d4a8550d412808900030002b01981ab8c58218050908a2050a104035084a39f742cf4d76e509473ee859e9aedea128e7dd0b3d35db97010144109c38f5d0d0b3d35db400640740616378c24fd2845e1220d000',
    )))

pkts_rrc3g_nc = tuple(map(unhexlify, (
    # MeasurementControl (DL-DCCH)
    # WNG: here, the RNC encodes CellInfo.cellIndividualOffset component with its DEFAULT value (0),
    # need ASN1CodecPER.CANONICAL=False to reencode identically
    'a3549e989a008310c935be7be4ea51736ee514def25117afa51626fe516d20',
    'cdcc61022a010310c8ef8ce91bca2c55c4a2f65cca2485d4a2375dca2bf5e4a28d5eca298df4a2e15fca2f9c',
    '208803b8fc128a5d43288294528b154728825492883f4b28b3f4d288234f28b395128b435328a5b5528bcd5728bd959289215b288dd5d2888d5f28afd6128b316328a1d6528a356728a636928b856b28be76d289a16f2888371289357328b3d7528831772893f7928a3d7b28b637d288c97f289714c4585858b82180bb2b7510a0160293ecadd4ff9c20',
    )))

def _load_rrc3g():
    #try:
    #    GLOBAL.clear()
    #except:
    #    pass
    from pycrate_asn1dir import RRC3G

def _test_rrc3g():
    PCCH = GLOBAL.MOD['Class-definitions']['PCCH-Message']
    for p in pkts_rrc3g[:3]:
        PCCH.from_uper(p)
        val = PCCH()
        ret = PCCH.to_uper()
        assert( ret == p )
        PCCH.from_uper_ws(p)
        val_ws = PCCH()
        struct = PCCH._struct()
        ret = PCCH.to_uper_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( PCCH._struct() == struct )
        txt = PCCH.to_asn1()
        PCCH.from_asn1(txt)
        assert( PCCH() == val )
        # jer
        if _with_json:
            txt = PCCH.to_jer()
            PCCH.from_jer(txt)
            assert( PCCH() == val )
    #
    DLDCCH = GLOBAL.MOD['Class-definitions']['DL-DCCH-Message']
    for p in pkts_rrc3g[3:14]:
        DLDCCH.from_uper(p)
        val = DLDCCH()
        ret = DLDCCH.to_uper()
        assert( ret == p )
        DLDCCH.from_uper_ws(p)
        val_ws = DLDCCH()
        struct = DLDCCH._struct()
        ret = DLDCCH.to_uper_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( DLDCCH._struct() == struct )
        txt = DLDCCH.to_asn1()
        DLDCCH.from_asn1(txt)
        assert( DLDCCH() == val )
        # jer
        if _with_json:
            txt = DLDCCH.to_jer()
            DLDCCH.from_jer(txt)
            assert( DLDCCH() == val )
    #
    ULDCCH = GLOBAL.MOD['Class-definitions']['UL-DCCH-Message']
    for p in pkts_rrc3g[14:]:
        ULDCCH.from_uper(p)
        val = ULDCCH()
        ret = ULDCCH.to_uper()
        assert( ret == p )
        ULDCCH.from_uper_ws(p)
        val_ws = ULDCCH()
        struct = ULDCCH._struct()
        ret = ULDCCH.to_uper_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( ULDCCH._struct() == struct )
        txt = ULDCCH.to_asn1()
        ULDCCH.from_asn1(txt)
        assert( ULDCCH() == val )
        # jer
        if _with_json:
            txt = ULDCCH.to_jer()
            ULDCCH.from_jer(txt)
            assert( ULDCCH() == val )
    #
    ASN1CodecPER.GET_DEFVAL = False
    ASN1CodecPER.CANONICAL  = False
    #
    for p in pkts_rrc3g_nc:
        DLDCCH.from_uper(p)
        val = DLDCCH()
        ret = DLDCCH.to_uper()
        assert( ret == p )
        DLDCCH.from_uper_ws(p)
        val_ws = DLDCCH()
        struct = DLDCCH._struct()
        ret = DLDCCH.to_uper_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( DLDCCH._struct() == struct )
        txt = DLDCCH.to_asn1()
        DLDCCH.from_asn1(txt)
        assert( DLDCCH() == val )
        # jer
        if _with_json:
            txt = DLDCCH.to_jer()
            DLDCCH.from_jer(txt)
            assert( DLDCCH() == val )

def test_rrc3g():
    _load_rrc3g()
    _test_rrc3g()


pkts_s1ap = tuple(map(unhexlify, (
    '0011002d000004003b00080063f310001a2d00003c400a0380656e623161326430004000070000004063f3100089400140',
    '201100170000020069000b000063f3100000800100010057400132',
    '000c408083000005000800020001001a005b5a17e24564d9040741020bf663f3108001010000000104e060c04000210208d011d1271a8080211001000010810600000000830600000000000d00000a005263f31000015c0a003103e5e0341363f310000111035758a65d0100e0004300060063f3100001006440080063f3101a2d00100086400130',
    '000b4038000003000000020064000800020001001a002524075200c38bb94032cc40b533057327b25e335510a4f43c006d9c90017ed284accdaf768c',
    '000d403b000005000000020064000800020001001a001211171f524dde06075308b7ae79df8ece4200006440080063f3101a2d0010004340060063f3100001',
    '00090080b30000060000000200640008000200010042000a1805f5e1006002faf0800018006500003400604500093c0f807f00016403b9d2465127e0c3b4e302074202e0060063f310000100245208c101090807746573743132330501c0a80302270e8080210a0300000a8106c0a8fd01500bf663f310800101000000011363f310000123050400000001006b000518000c000000490020c9b9530a37fc57d7a7a66a476677cac689cf9cb4c713ba88da20b4fb8bb2bdd9',
    '00164050000003000000020064000800020001004a403d3c01d001037c5980060008208183930d1bf8fff1bf8fff1bf8fff1bf8fff1bf8fff1bf8fff1bf8ffeff9ffd75103004870ca74a92246058c0000000000',
    '200900220000030000400200640008400200010033400f000032400a0a1f7f0001014ca724db',
    '00124015000003000000020064000800020001000240020280',
    '001700110000020063000400640001000240020280',
    '2017000f000002000040020064000840020001'
    )))


pkts_x2ap = tuple(map(unhexlify, (
   # X2AP packets contributed by Alexandre DeOliveira, originally in libmich
   '000600808a000004001500080011f1110001013000140051020000330011f11101011010029011f111004c2c05dc330000340011f1110101102000a011f111004c2c05dc444000350011f1110101103000a011f111005eec189c3300010011f1110a0ab010002705dc001800060011f1118000a8dd4018000002100040030001031001400a0001c006001008020100',
    '0000007b000006000a00020001000540020000000b000800522018000000200017000700522018000102000e004100010000000000303132333435363738393031323334353637383930313233343536373839303120000000000004400e0000010a03e01401a8c000000002020000000f400c000052201800000021800003',
    # https://github.com/P1sec/pycrate/issues/84
    '001b008376000008006f0002078300f800051c000e000000cb0020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00cc000a184c096c70604c096c7000cd001f0000d1001a0a2000c0072d01f02a6d0fd4ea69f4fa03e00ac612798083809d00ce0082f982f718988169210229ce400000028ebc0606000002809049a3000481a0603100d00980406228040530805502c46d618c21a0c54083e500892d931541439f60478c73e618f28581c0e1e04fc0000003f00000000a00e0540b40f78e3087000a8f3f140453ed98aa9041e3c471e00438820c22a051fbf90202e3718120180a816826f1c610e00151e7e2808a7db31552083c788e3c0087104184540a3f7f20405c6e30240300020058030a80242080108c062023727802203014008000008818268000e7cc31e50b0302801000802320304d4000438820c22a0407c010040000040280000530058115ba400410000075d240400004000040150288aed40104800d028010a16000102030406070b0c11121318191b252627282d2f4146400542041f0220900834120e230000002220980802412e230000012201002c01854012104008460310118140f40a24e9d3b639f0e24e9d3b639f0c00044000100000080202004008800020100010000400801000907e568262acbde3802000003fcd4ff816e0c814f5c40b04431c55fc8120dc4e81fa6400018c304108502041e6d80835ba74ee20b1a0fcad01181f5d00000033636c9158b11b82010000008400d0146c0118219c0000003371b648b104400e30350f6643182f18437106fb34d0b163a420a08dc575c004048092616d40247fc0000000004001041c0dc2108003c4459483832081001102009000080a0202c3113a80038e0c00ca00080099aaa2400600082061300001990a0181000cc9500c100066528060c00332d40308001998a0100601821349a47493400800c10ec610dc41bc7fe851ce6293940a0802015c000200004000000000422b5515810c0004210003880b1c30060202208001c4058e18030201084000e202c7100181808820007101638800c108a950007101638204110030001020300400403809c001c704000000801000201400880a000802f000416e208208208208784ff907f8198cc00100000002a8000f00007e56820084000814230000102240ac0fc000000112928091409289f8fc5174d870116000100011700080013200614d09010',
    # https://github.com/P1sec/pycrate/issues/61
    '201b008203000004006f0002000800cf0002000d00d240360000d540310a003b81f00a6ce901001a001303e00a6ce901401b0017007c0a6ce901601b001300071f000001012e400140013740014000d30081b581b3186c0ce0440ccae2078e3190437630d061e6407c0204a83c430106b7509cc613349a9e0026933a800000620c65d26a0c0a500a201b4064d202680001886ae32e932a31000d6267bfe2e0049de15bc2c5876f0f1625bc4c58d6f1b15414c09a70300442a03a0093ffea1db600203805930165004048204004808009302071a232c08966113704030000080801a500a201b40646d40007fffc000000043b8621800004041b84218000100b2802024102002404004981038d12b88960709242c1c1821c200e065c089665462001ac4cf7fc5c0093bc2b7858b0ede1e2c4b7898b1ade362a8298134e35524940408221061028004a01a01198068086601803132f68104cbd80b132f6c8230308807235600007f4210840080402581c2490b070608708038940e000010af7a008001000007a00098801c0080c0600203115514010800c12ca007e4026b143810086200072084d40005c0c0451000390426a0002e0802188001c82135008170501144000e4109a804082000000a1860406080b0382b001f9628000000200400182e001809006600b400016488822cf1fffff83f0340050a06946fd7e39b8e614000000002104d4f000',
    )))


pkts_nbiot = tuple(map(unhexlify, (
    # https://github.com/P1sec/pycrate/issues/87
    '6040008090d20004345a20500ba010300e00',
    )))


def _load_lteran():
    #try:
    #    GLOBAL.clear()
    #except:
    #    pass
    from pycrate_asn1dir import S1AP
    from pycrate_asn1dir import X2AP
    from pycrate_asn1dir import RRCLTE

def _test_lteran():
    S1PDU = GLOBAL.MOD['S1AP-PDU-Descriptions']['S1AP-PDU']
    for p in pkts_s1ap:
        S1PDU.from_aper(p)
        val = S1PDU()
        S1PDU.reset_val()
        S1PDU.set_val(val)
        ret = S1PDU.to_aper()
        assert( ret == p )
        S1PDU.from_aper_ws(p)
        val_ws = S1PDU()
        struct = S1PDU._struct()
        ret = S1PDU.to_aper_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( S1PDU._struct() == struct )
        txt = S1PDU.to_asn1()
        S1PDU.from_asn1(txt)
        assert( S1PDU() == val )
        # jer
        if _with_json:
            txt = S1PDU.to_jer()
            S1PDU.from_jer(txt)
            assert( S1PDU() == val )
    #
    X2PDU = GLOBAL.MOD['X2AP-PDU-Descriptions']['X2AP-PDU']
    for p in pkts_x2ap:
        X2PDU.from_aper(p)
        val = X2PDU()
        X2PDU.reset_val()
        X2PDU.set_val(val)
        ret = X2PDU.to_aper()
        assert( ret == p )
        X2PDU.from_aper_ws(p)
        val_ws = X2PDU()
        struct = X2PDU._struct()
        ret = X2PDU.to_aper_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( X2PDU._struct() == struct )
        txt = X2PDU.to_asn1()
        X2PDU.from_asn1(txt)
        assert( X2PDU() == val )
        # jer
        if _with_json:
            txt = X2PDU.to_jer()
            X2PDU.from_jer(txt)
            assert( X2PDU() == val )
    #
    NBIoT_SIB1 = GLOBAL.MOD['NBIOT-RRC-Definitions']['BCCH-DL-SCH-Message-NB']
    for p in pkts_nbiot:
        NBIoT_SIB1.from_uper(p)
        val = NBIoT_SIB1()
        ret = NBIoT_SIB1.to_uper()
        assert( ret == p )
        NBIoT_SIB1.from_uper_ws(p)
        val_ws = NBIoT_SIB1()
        struct = NBIoT_SIB1._struct()
        ret = NBIoT_SIB1.to_uper_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( NBIoT_SIB1._struct() == struct )
        txt = NBIoT_SIB1.to_asn1()
        NBIoT_SIB1.from_asn1(txt)
        assert( NBIoT_SIB1() == val )
        # jer
        if _with_json:
            txt = NBIoT_SIB1.to_jer()
            NBIoT_SIB1.from_jer(txt)
            assert( NBIoT_SIB1() == val )

def test_lteran():
    _load_lteran()
    _test_lteran()


pkts_rrc_nr = tuple(map(unhexlify, (
    # https://github.com/P1sec/pycrate/issues/84, it seems this buffer does not correspond to an exact canonical structure from Rel.16
    '18988169210229ce400000028ebc0606000002809049a3000481a0603100d00980406228040530805502c46d618c21a0c54083e500892d931541439f60478c73e618f28581c0e1e04fc0000003f00000000a00e0540b40f78e3087000a8f3f140453ed98aa9041e3c471e00438820c22a051fbf90202e3718120180a816826f1c610e00151e7e2808a7db31552083c788e3c0087104184540a3f7f20405c6e30240300020058030a80242080108c062023727802203014008000008818268000e7cc31e50b0302801000802320304d4000438820c22a0407c010040000040280000530058115ba400410000075d240400004000040150288aed40104800d028010a16000102030406070b0c11121318191b252627282d2f4146400542041f0220900834120e230000002220980802412e230000012201002c01854012104008460310118140f40a24e9d3b639f0e24e9d3b639f0c00044000100000080202004008800020100010000400801000907e568262acbde3802000003fcd4ff816e0c814f5c40b04431c55fc8120dc4e81fa6400018c304108502041e6d80835ba74ee20b1a0fcad01181f5d00000033636c9158b11b82010000008400d0146c0118219c0000003371b648b104400e30350f6643182f18437106fb34d0b163a420a08dc575c004048092616d40247fc0000000004001041c0dc2108003c4459483832081001102009000080a0202c3113a80038e0c00ca00080099aaa2400600082061300001990a0181000cc9500c100066528060c00332d40308001998a0100601821349a47493400800c10ec610dc41bc7fe851ce6293940a0802015c000200004000000000422b5515810c0004210003880b1c30060202208001c4058e18030201084000e202c7100181808820007101638800c108a950007101638204110030001020300400403809c001c704000000801000201400880a000802f000416e208208208208784ff907f8198cc00100000002a8000f00007e56820084000814230000102240ac0fc000000112928091409289f8fc5174d87',
    )))


def _load_nrran():
    #try:
    #    GLOBAL.clear()
    #except:
    #    pass
    from pycrate_asn1dir import RRCNR
    from pycrate_asn1dir import NGAP
    from pycrate_asn1dir import XnAP

def _test_nrran():
    CGCfgInf = GLOBAL.MOD['NR-InterNodeDefinitions']['CG-ConfigInfo']
    for p in pkts_rrc_nr:
        CGCfgInf.from_uper(p)
        val = CGCfgInf()
        ret = CGCfgInf.to_uper()
        #assert( ret == p )
        CGCfgInf.from_uper_ws(p)
        val_ws = CGCfgInf()
        struct = CGCfgInf._struct()
        ret = CGCfgInf.to_uper_ws()
        #assert( ret == p )
        assert( val == val_ws )
        # TODO: BIT STRING / OCTET STRING (CONTAINING(...)) does not keep full structure 
        # of contained object during encoding
        #assert( CGCfgInf._struct() == struct )
        txt = CGCfgInf.to_asn1()
        CGCfgInf.from_asn1(txt)
        assert( CGCfgInf() == val )
        # jer
        if _with_json:
            txt = CGCfgInf.to_jer()
            CGCfgInf.from_jer(txt)
            assert( CGCfgInf() == val )

def test_nrran():
    _load_nrran()
    _test_nrran()


# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=gsm_map_with_ussd_string.pcap
pkts_tcap_map = tuple(map(unhexlify, (
    '626a48042f3b46026b3a2838060700118605010101a02d602b80020780a109060704000001001302be1a2818060704000001010101a00da00b80099656051124006913f66c26a12402010102013b301c04010f040eaa180da682dd6c31192d36bbdd468007917267415827f2',
    '626448046d5307026b1e281c060700118605010101a011600f80020780a1090607040000010001036c3ca13a0201000201023032040821431559116230f7810791907334250186040791907334250186a60880020780850205e0ad0a80086835613051868427',
    '624548049a37020e6b1e281c060700118605010101a011600f80020780a109060704000001001b036c1da11b020101020143a313040821038177392457f18107916005328636f5',
    '643d4904485a072d6b262824060700118605010101a0196117a109060704000001000103a203020100a305a1030201006c0da30b02010002012230030a0101',
    '6250480465424d9f6b1e281c060700118605010101a011600f80020780a1090607040000010020036c28a126020101020117301e040862002103576065f30407912143550903f9040504d7765924a0028300',
    '6581d74804102b2e0f4904100108736c81c8a181c50201020201073081bca781b9a309040111840105810101a309040112840105820102a30b0401418401053003830110a30b0401418401043003820110a30b0401418401043003820118a306040114840100a01d0401293018300683011084010430068201108401043006820118840104a01d04012a3018300683011084010430068201108401043006820118840104a01d04012b3018300683011084010430068201108401043006820118840104a015040121301030068301108401043006820110840104'
    )))

def _load_tcap_map():
    #try:
    #    GLOBAL.clear()
    #except:
    #    pass
    from pycrate_asn1dir import TCAP_MAP

def _test_tcap_map():
    M = GLOBAL.MOD['TCAP-MAP-Messages']['TCAP-MAP-Message']
    for p in pkts_tcap_map:
        M.from_ber(p)
        val = M()
        M.reset_val()
        M.set_val(val)
        ret = M.to_ber()
        # hopefully here, BER re-encoding does not diverge from the original packet
        assert( ret == p )
        M.from_ber_ws(p)
        val_ws = M()
        struct = M._struct()
        ret = M.to_ber_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( M._struct() == struct )
        txt = M.to_asn1()
        M.from_asn1(txt)
        assert( M() == val )
        # jer
        if _with_json:
            txt = M.to_jer()
            M.from_jer(txt)
            assert( M() == val )

def test_tcap_map():
    _load_tcap_map()
    _test_tcap_map()


# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=camel.pcap
# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=camel2.pcap
pkts_tcap_cap = tuple(map(unhexlify, (
    '628187480206f76b1e281c060700118605010101a011600f80020780a1090607040000010032016c61a15f020101020100305780012a830884111487095040f79c01029f32061487572586f9bf34148107913366020000f0a3098007313233343536379f3605a12345678f9f3707913366020000f09f3807111487085040f79f39080230900211223370',
    '6581be480213b8490206f76b2a2828060700118605010101a01d611b80020780a109060704000001003201a203020100a305a1030201006c8187a165020101020117305da05b300b800104810100a203800102300b800105810100a203800102300b800106810100a203800102300b800107810101a203800102300b800109810100a203800101300b800109810100a203800102300b80010a810101a203800101a116020102020123300e8007a0058003008ca0a203800101a10602010302011f',
    '651c480206f7490213b86c12a1100201020201183008800107a403800101',
    '653a4802ec0f49020d7c6c30a117020103020124040fa00da003810101a10380011a820100a115020104020118300d800109a303810101a403800100',
    '64124902ec0f6c0ca10a02010402011604028490',
    #
    '6281994804070004006b1a2818060700118605010101a00d600ba1090607040000010032016c75a173020101020100306b80016e8208839021721090000f830303975785010a8c06831407010900bb0580038090a39c01029d068314070109009e0203619f320806079209100491f9bf35038301119f360513fa3d3dea9f37069122705700709f39080250114231016500bf3b088106912270570070',
    '6581b24802047b4904070004006b2a2828060700118605010101a01d611b80020780a109060704000001003201a203020100a305a1030201006c7aa165020101020117305da05b300b800104810100a203800102300b800105810100a203800102300b800106810100a203800102300b800107810101a203800102300b800109810100a203800101300b800109810100a203800102300b80010a810101a203800101a1110201020201143009a00704050210792210',
    '65264804070004004902047b6c1aa1180201020201183010800104a206a20480028490a303810102',
    '64144904070004006c0ca10a02010302011604028495'
    )))

def _load_tcap_cap():
    #try:
    #    GLOBAL.clear()
    #except:
    #    pass
    from pycrate_asn1dir import TCAP_CAP

def _test_tcap_cap():
    M = GLOBAL.MOD['CAP-gsmSSF-gsmSCF-pkgs-contracts-acs']['GenericSSF-gsmSCF-PDUs']
    for p in pkts_tcap_cap:
        M.from_ber(p)
        val = M()
        M.reset_val()
        M.set_val(val)
        ret = M.to_ber()
        # hopefully here, BER re-encoding does not diverge from the original packet
        assert( ret == p )
        M.from_ber_ws(p)
        val_ws = M()
        struct = M._struct()
        ret = M.to_ber_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( M._struct() == struct )
        txt = M.to_asn1()
        M.from_asn1(txt)
        assert( M() == val )
        # jer
        if _with_json:
            txt = M.to_jer()
            M.from_jer(txt)
            assert( M() == val )

def test_tcap_cap():
    _load_tcap_cap()
    _test_tcap_cap()


pkts_X509 = tuple(map(unhexlify, (
'3082078a30820672a0030201020208657d462b1509b3b7300d06092a864886f70d01010b05003049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f72697479204732301e170d3137303832323136343232355a170d3137313131343136333030305a3066310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f676c6520496e633115301306035504030c0c2a2e676f6f676c652e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200045d105bb2427733023a751eb73901b97ee50ce862d3c0d1f40cf3ed34e52fd88cd8c0b6f43aec0f26ec458340bd561d73b219887f689f47c537d1f8151b071203a38205223082051e301d0603551d250416301406082b0601050507030106082b06010505070302300b0603551d0f040403020780308203e10603551d11048203d8308203d4820c2a2e676f6f676c652e636f6d820d2a2e616e64726f69642e636f6d82162a2e617070656e67696e652e676f6f676c652e636f6d82122a2e636c6f75642e676f6f676c652e636f6d82142a2e64623833333935332e676f6f676c652e636e82062a2e672e636f820e2a2e6763702e677674322e636f6d82162a2e676f6f676c652d616e616c79746963732e636f6d820b2a2e676f6f676c652e6361820b2a2e676f6f676c652e636c820e2a2e676f6f676c652e636f2e696e820e2a2e676f6f676c652e636f2e6a70820e2a2e676f6f676c652e636f2e756b820f2a2e676f6f676c652e636f6d2e6172820f2a2e676f6f676c652e636f6d2e6175820f2a2e676f6f676c652e636f6d2e6272820f2a2e676f6f676c652e636f6d2e636f820f2a2e676f6f676c652e636f6d2e6d78820f2a2e676f6f676c652e636f6d2e7472820f2a2e676f6f676c652e636f6d2e766e820b2a2e676f6f676c652e6465820b2a2e676f6f676c652e6573820b2a2e676f6f676c652e6672820b2a2e676f6f676c652e6875820b2a2e676f6f676c652e6974820b2a2e676f6f676c652e6e6c820b2a2e676f6f676c652e706c820b2a2e676f6f676c652e707482122a2e676f6f676c656164617069732e636f6d820f2a2e676f6f676c65617069732e636e82142a2e676f6f676c65636f6d6d657263652e636f6d82112a2e676f6f676c65766964656f2e636f6d820c2a2e677374617469632e636e820d2a2e677374617469632e636f6d820a2a2e677674312e636f6d820a2a2e677674322e636f6d82142a2e6d65747269632e677374617469632e636f6d820c2a2e75726368696e2e636f6d82102a2e75726c2e676f6f676c652e636f6d82162a2e796f75747562652d6e6f636f6f6b69652e636f6d820d2a2e796f75747562652e636f6d82162a2e796f7574756265656475636174696f6e2e636f6d82072a2e79742e6265820b2a2e7974696d672e636f6d821a616e64726f69642e636c69656e74732e676f6f676c652e636f6d820b616e64726f69642e636f6d821b646576656c6f7065722e616e64726f69642e676f6f676c652e636e821c646576656c6f706572732e616e64726f69642e676f6f676c652e636e8204672e636f8206676f6f2e676c8214676f6f676c652d616e616c79746963732e636f6d820a676f6f676c652e636f6d8212676f6f676c65636f6d6d657263652e636f6d8218736f757263652e616e64726f69642e676f6f676c652e636e820a75726368696e2e636f6d820a7777772e676f6f2e676c8208796f7574752e6265820b796f75747562652e636f6d8214796f7574756265656475636174696f6e2e636f6d820579742e6265306806082b06010505070101045c305a302b06082b06010505073002861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e636f6d2f6f637370301d0603551d0e04160414bb878d2e10f930b01fdea30a71ebcc9ab46e3b99300c0603551d130101ff04023000301f0603551d230418301680144add06161bbcf668b576f581b6bb621aba5a812f30210603551d20041a3018300c060a2b06010401d6790205013008060667810c01020230300603551d1f042930273025a023a021861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e63726c300d06092a864886f70d01010b050003820101004bb6a5e86b4dd533d6b6b995dadcb29a6685d112d3d7e268d92398deb2098004e4eaafb822f588f584583e39298e44907faa8231d7e32bd764124010b580047f07751786075825ee38f5d370a8fdc69fc0e2e43a816ba16121658d152e00bb1a488b06cd7f53e9962e737a9bdcea99a2b73bfe46c4c3270c3b344ed7d40f23c233ee7918edcf213cc9dc1f7973ae6567f1f00b6fbe8e0756a46721ed6005fafe70261d103d51a24818f4bc7539e7f9d778c0a93e989f9616174c9d801118e992878160d0a70265bcd6cd189ac8ca06437e87241ea3e842f2939a265c117359dc5069ef49abcc20ccd281bfe5dda77bd1d3dd4af482c667d3de2b788b646f60c0',
'308206863082056ea003020102021001ef2c413451abc78fcf56a49731f6e2300d06092a864886f70d01010b05003070310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d312f302d06035504031326446967694365727420534841322048696768204173737572616e636520536572766572204341301e170d3138313033313030303030305a170d3139313130353132303030305a30818a310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f31163014060355040a130d547769747465722c20496e632e3120301e060355040b0c177473615f6620506f696e74206f662050726573656e6365311430120603550403130b747769747465722e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100e71e085df0958d64c2c9c136a3c7626eb28b3bfa1d64a7ba775ec13f18f9e32f68336c718da28c191968086e555ff0f406c76b99ad32b6ae57a5f1626267a3fd7a3cc31b70557492d97424d98a48107b5dd45849b46d24aa298dea4a6032c905e6ce927f80187bcc7fc98d4231261d2263c4da62e0fff476e9961eab24a09582851fb6524312a4e56833e2cbf680108c9ea21e743ad4bb79a67d34c31c27a9a9f9f4dd7078ee10360648de72a4b0c92210793e1227f2b3ae6a128ee6fc1ccf259519d13cdcbba5f8bd6f30ab37fa9ada6d4fcf462ae8dd277996ccfe55bbed429f2e5ee6087b523f50c07c10446afd5a4dcb73aef5bfb05ad15fa7c8cd4474030203010001a38202ff308202fb301f0603551d230418301680145168ff90af0207753cccd9656462a212b859723b301d0603551d0e04160414d87ae9e5af9d5a1ee95ae020dffeaf600ffa843a30270603551d110420301e820b747769747465722e636f6d820f7777772e747769747465722e636f6d300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b0601050507030230750603551d1f046e306c3034a032a030862e687474703a2f2f63726c332e64696769636572742e636f6d2f736861322d68612d7365727665722d67362e63726c3034a032a030862e687474703a2f2f63726c342e64696769636572742e636f6d2f736861322d68612d7365727665722d67362e63726c304c0603551d2004453043303706096086480186fd6c0101302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020230818306082b0601050507010104773075302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304d06082b060105050730028641687474703a2f2f636163657274732e64696769636572742e636f6d2f446967694365727453484132486967684173737572616e636553657276657243412e637274300c0603551d130101ff0402300030820106060a2b06010401d6790204020481f70481f400f2007700a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc1000000166cb4dbf6b00000403004830460221008f9791d5570afcdc35b9cdd354ee61c745a5718e1f0fdabf3ba47d306f7ec2aa022100e97b2f722a31f76e51560f2b3cef01f49f9e32ea10e6659153a333ce66f08e670077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f00000166cb4dc0430000040300483046022100929cf7be6556192d3e909c183bc647b17240b8364f9edf8b9f887ea8f2b6b20e022100f4ac2585193df4b630854a3f9b0bbb6f4d4b8ad54379f5f19618c7849502f399300d06092a864886f70d01010b05000382010100342e9d3c8119a2733720b5c355817994d045024edad88cd74b4ad804f0a4e61b1d19a1c5674b95a45bb117b6e3db3c19eef6e2d356c1e8e6c6861fb6594834e0f0ceb01048839111346f4de80af3540467502a777197178c6f7251fcfd0979d7c131d89f45d494731ddb168ea57316cb1655e2fc4d83dd93fc15e04aed90bd7c6c629cc97b518e2889d6ee4e61d83674261480c227e1203de992ed62cb5c3a03f0f4772049d6782819d4ec3463cdeb7fe8fc11249e822fc00419d62f747264b5478cb53981e37bd30c036c973d25bc16eb00232a0cdec164e8b05986b4626fe65188c4a73967b9f6cded878df040ef61e92c49b4fb5ef9257f5fde0d9764d8ae',
'308208733082075ba00302010202100e5ecf181783006d9bac453611f54912300d06092a864886f70d01010b05003075310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313430320603550403132b4469676943657274205348413220457874656e6465642056616c69646174696f6e20536572766572204341301e170d3138303931383030303030305a170d3230313031343132303030305a3081d8311d301b060355040f0c1450726976617465204f7267616e697a6174696f6e31133011060b2b0601040182373c0201031302555331193017060b2b0601040182373c020102130844656c61776172653110300e0603550405130733333539333030310b3009060355040613025553311630140603550408130d4e65772048616d7073686972653112301006035504071309576f6c6665626f726f31233021060355040a131a507974686f6e20536f66747761726520466f756e646174696f6e311730150603550403130e7777772e707974686f6e2e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100f6ae81930dcfa6de0de645e21fee3e6bccba2f9e4dd9820bf2da45963270c1633da6eac83138bd6993322eed835ee27a07ed94729b438842365b0c895e07b48e180a03d8106ff8cbfbf47b5e749dddbe15f09a045e9e537107184371a54b0ce3550bd22bdc5b78eaeb8622b5e7281f0bd4a655ea1f08142d86dc665726d9301288d7766245cee46b28c462d1c2cf945eb4ba94484888f78e0f642b80fe7f4c58aec40026f2b4bdea91b0d43c6d73c4611f241b83da8fbace7a1dc5546c6b28e28da6823e915e84a8e54884963af7c3fb11b0cb1a31b6226f4fe95166c17a1d60067609315a325ac2d0596300efc529e40a476f6f8adb612ccbad71df809280c30203010001a382049930820495301f0603551d230418301680143dd350a5d6a0adeef34a600a65d321d4f8f8d60f301d0603551d0e04160414513b321c05d9cba7761d69fef0c64d521042904c308201420603551d110482013930820135820e7777772e707974686f6e2e6f7267820f646f63732e707974686f6e2e6f7267820f627567732e707974686f6e2e6f7267820f77696b692e707974686f6e2e6f7267820d68672e707974686f6e2e6f7267820f6d61696c2e707974686f6e2e6f7267820f707970692e707974686f6e2e6f726782147061636b6167696e672e707974686f6e2e6f726782106c6f67696e2e707974686f6e2e6f72678212646973637573732e707974686f6e2e6f7267820c75732e7079636f6e2e6f72678207707970692e696f820c646f63732e707970692e696f8208707970692e6f7267820d646f63732e707970692e6f7267820f646f6e6174652e707970692e6f7267821364657667756964652e707974686f6e2e6f726782137777772e627567732e707974686f6e2e6f7267820a707974686f6e2e6f7267300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b0601050507030230750603551d1f046e306c3034a032a030862e687474703a2f2f63726c332e64696769636572742e636f6d2f736861322d65762d7365727665722d67322e63726c3034a032a030862e687474703a2f2f63726c342e64696769636572742e636f6d2f736861322d65762d7365727665722d67322e63726c304b0603551d2004443042303706096086480186fd6c0201302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533007060567810c010130818806082b06010505070101047c307a302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d305206082b060105050730028646687474703a2f2f636163657274732e64696769636572742e636f6d2f446967694365727453484132457874656e64656456616c69646174696f6e53657276657243412e637274300c0603551d130101ff040230003082017f060a2b06010401d6790204020482016f0482016b0169007700ee4bbdb775ce60bae142691fabe19e66a30f7e5fb072d88300c47b897aa8fdcb00000165ee5dcc5b0000040300483046022100a9f00949f3871b8afc62fcd3919b2bf1c11715c9c5227b38d3e25755d818d2fb022100af9c1f98131b4c4505505ce35c825393b0862636060faedc8762c4e3fd7b9ae50077005614069a2fd7c2ecd3f5e1bd44b23ec74676b9bc99115cc0ef949855d689d0dd00000165ee5dcc7a0000040300483046022100817ac576a429575111c88af1a336cf573bd5e894f2a17f50265b978b047cb4d0022100f3bd2947d1dace877716066ccebf62b64f2c60f2e842357dfd610d9741d75c6c007500bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed18500000165ee5dcc33000004030046304402200788bdc6aa3c04c9ac2a37f9c7819556ecc8f25c0cf33b4062e96913c505db9002204735f72c04b69e952f5b5267d447456324ba13037f402408fca14ea2033aee1c300d06092a864886f70d01010b05000382010100c07e7e3d7a2e81fa39a8c54813ae437a2fc211be1a8597e832fbe5251bee34023f0115984121e1e88297771171204e61082fcd36d74071cd690a8676f8833fc747060631d97a04a38577d0cbec3bb707e0c9e4d235a955da3cca43462ffc9bdf23daa231d84441b7cba9a43a363fe3b3cbaf42a59feb0f32a3b840ccab358d317b5b2fdc33496fa8da1c0d66113a1015708fa348c2b095c2efef9c406ce66ac360f8f379a4422cd58fbc10d5f60fdd3af4c1fbc535ea0800f5172eb107884987580d21f94f4a12055f550dcfbf322d79c296148fb477d46936ea5cd47762a410b24af9cd6b52dc1b602f8985e922c6e8f0406f6e3d07704571ecd100347357da',
'308207fb30820764a003020102021008309462d1fea60ae0babff5ef8bc545300d06092a864886f70d01010b05003070310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d312f302d06035504031326446967694365727420534841322048696768204173737572616e636520536572766572204341301e170d3137313232313030303030305a170d3139303132343132303030305a3079310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f31233021060355040a131a57696b696d6564696120466f756e646174696f6e2c20496e632e3118301606035504030c0f2a2e77696b6970656469612e6f72673059301306072a8648ce3d020106082a8648ce3d03010703420004fdc06b1e5673e346198eaa48b37b13bf0b2c79b2059e1c707c97b7726da48b8223d232de50231c3dba6d2b7178f5028bb0840de136553ae4e504ad6e7a6e87dfa38205d2308205ce301f0603551d230418301680145168ff90af0207753cccd9656462a212b859723b301d0603551d0e041604146ead11b1ee671ceb54ddf22a6654c1bed03b2839308202f80603551d11048202ef308202eb820f2a2e77696b6970656469612e6f7267820d77696b6970656469612e6f726782112a2e6d2e77696b6970656469612e6f726782142a2e7a65726f2e77696b6970656469612e6f7267820d77696b696d656469612e6f7267820f2a2e77696b696d656469612e6f726782112a2e6d2e77696b696d656469612e6f726782162a2e706c616e65742e77696b696d656469612e6f7267820d6d6564696177696b692e6f7267820f2a2e6d6564696177696b692e6f726782112a2e6d2e6d6564696177696b692e6f7267820d77696b69626f6f6b732e6f7267820f2a2e77696b69626f6f6b732e6f726782112a2e6d2e77696b69626f6f6b732e6f7267820c77696b69646174612e6f7267820e2a2e77696b69646174612e6f726782102a2e6d2e77696b69646174612e6f7267820c77696b696e6577732e6f7267820e2a2e77696b696e6577732e6f726782102a2e6d2e77696b696e6577732e6f7267820d77696b6971756f74652e6f7267820f2a2e77696b6971756f74652e6f726782112a2e6d2e77696b6971756f74652e6f7267820e77696b69736f757263652e6f726782102a2e77696b69736f757263652e6f726782122a2e6d2e77696b69736f757263652e6f7267820f77696b69766572736974792e6f726782112a2e77696b69766572736974792e6f726782132a2e6d2e77696b69766572736974792e6f7267820e77696b69766f796167652e6f726782102a2e77696b69766f796167652e6f726782122a2e6d2e77696b69766f796167652e6f7267820e77696b74696f6e6172792e6f726782102a2e77696b74696f6e6172792e6f726782122a2e6d2e77696b74696f6e6172792e6f7267821777696b696d65646961666f756e646174696f6e2e6f726782192a2e77696b696d65646961666f756e646174696f6e2e6f7267821b2a2e6d2e77696b696d65646961666f756e646174696f6e2e6f72678212776d6675736572636f6e74656e742e6f726782142a2e776d6675736572636f6e74656e742e6f72678206772e77696b69300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b0601050507030230750603551d1f046e306c3034a032a030862e687474703a2f2f63726c332e64696769636572742e636f6d2f736861322d68612d7365727665722d67362e63726c3034a032a030862e687474703a2f2f63726c342e64696769636572742e636f6d2f736861322d68612d7365727665722d67362e63726c304c0603551d2004453043303706096086480186fd6c0101302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020230818306082b0601050507010104773075302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304d06082b060105050730028641687474703a2f2f636163657274732e64696769636572742e636f6d2f446967694365727453484132486967684173737572616e636553657276657243412e637274300c0603551d130101ff0402300030820106060a2b06010401d6790204020481f70481f400f2007700bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed185000001607a45bfcf0000040300483046022100980489c6f161ded7c3bdbda10f9c7c472d846a39c73bc221ba482c9b769cc24d0221008803ca3c5a82bcb11cdd98e2fada0633ddfceb088b92963667fbb97a61210ea00077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f000001607a45c0280000040300483046022100c489c8514a18f9429f4e241f710b7406af9157fa0a17a42f8af85fba5e39cf7c02210094805673169057465d69ba85d0f12dfbf469999ba87ca4310f9eb1729818b1d4300d06092a864886f70d01010b0500038181000a7ee30358296bc5ef3e56686988c704b75c0440090ca4b86add461ef697ac418deb0738b54452942f09d36495f6df4842643fc95c24e0e633181a9602a083364bc211b95e69dec436158451d1aa5739494f63e3a76294b471cb4c84e6118da518663b6a68c425cc89a716846d95bc381a225da8f3ec394897e227874998b40b',
)))

def _load_X509():
    #try:
    #    GLOBAL.clear()
    #except:
    #    pass
    from pycrate_asn1dir import RFC5912

def _test_X509():
    Cert = GLOBAL.MOD['PKIX1Explicit-2009']['Certificate']
    for i, p in enumerate(pkts_X509):
        Cert.from_der(p)
        val = Cert()
        ret = Cert.to_der()
        assert( ret == p )
        Cert.from_der_ws(p)
        val_ws = Cert()
        struct = Cert._struct()
        ret = Cert.to_der_ws()
        assert( ret == p )
        assert( val == val_ws )
        assert( Cert._struct() == struct )
        txt = Cert.to_asn1()
        Cert.from_asn1(txt)
        # such certs have unknown extension, hence making to conversion to ASN.1
        # text not compatible with DER tag-lengt-value structures and values
        #assert( Cert() == val )
        # jer
        if _with_json:
            txt = Cert.to_jer()
            Cert.from_jer(txt)
            #assert( Cert() == val )

def test_X509():
    _load_X509()
    _test_X509()


def test_perf_asn1rt():
    
    _load_rt_base()
    print('[+] ASN.1 base type encoding / decoding (BER, CER, DER, UPER, APER, OER, COER)')
    Ta = timeit(_test_rt_base, number=20)
    print('test_rt_base: {0:.4f}'.format(Ta))
    
    _load_rrc3g()
    print('[+] RRC 3G encoding / decoding (UPER)')
    Tb = timeit(_test_rrc3g, number=10)
    print('test_rrc3g: {0:.4f}'.format(Tb))
    
    _load_lteran()
    print('[+] LTE S1AP and X2AP encoding / decoding (APER)')
    Tc = timeit(_test_lteran, number=2)
    print('test_lteran: {0:.4f}'.format(Tc))
    
    _load_nrran()
    print('[+] NR RRC inter-node encoding / decoding (UPER)')
    Td = timeit(_test_nrran, number=20)
    print('test_lteran: {0:.4f}'.format(Td))
    
    _load_tcap_map()
    print('[+] TCAP MAP encoding / decoding (BER)')
    Te = timeit(_test_tcap_map, number=3)
    print('test_tcap_map: {0:.4f}'.format(Te))
    
    _load_tcap_cap()
    print('[+] TCAP CAP encoding / decoding (BER)')
    Tf = timeit(_test_tcap_cap, number=10)
    print('test_tcap_cap: {0:.4f}'.format(Tf))
    
    _load_X509()
    print('[+] X.509 encoding / decoding (DER)')
    Tg = timeit(_test_X509, number=10)
    print('test_x509: {0:.4f}'.format(Tg))
    
    print('[+] test_asn1rt total time: {0:.4f}'.format(Ta+Tb+Tc+Td+Te+Tf+Tg))

if __name__ == '__main__':
    test_perf_asn1rt()

