# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2016. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : test/test_asn1rt.py
# * Created : 2016-02-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii import *

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
from pycrate_asn1rt.init             import init_modules


# do not print runtime warnings on screen
ASN1Obj._SILENT = True
# handle default values in PER the canonical way
ASN1CodecPER.GET_DEFVAL = True
ASN1CodecPER.CANONICAL  = True
# print ascii representation in comments when returning the ASN.1 textual encoding
BIT_STR._ASN_WASC = False
OCT_STR._ASN_WASC = False


def test_rt_base():
    from test import test_asn1rt_mod
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
    
    # Int01 ::= INTEGER
    Int01 = Mod['Int01']
    Int01.from_asn1('4096')
    # encoding
    assert( Int01.to_aper() == Int01.to_aper_ws() == b'\x02\x10\x00' )
    assert( Int01.to_uper() == Int01.to_uper_ws() == b'\x02\x10\x00' )
    assert( Int01.to_ber() == Int01.to_ber_ws() == b'\x02\x02\x10\x00' )
    assert( Int01.to_cer() == Int01.to_cer_ws() == b'\x02\x02\x10\x00' )
    assert( Int01.to_der() == Int01.to_der_ws() == b'\x02\x02\x10\x00' )
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
    
    # Int02 ::= INTEGER (MIN..65535)
    Int02 = Mod['Int02']
    Int02.from_asn1('127')
    # encoding
    assert( Int02.to_aper() == Int02.to_aper_ws() == b'\x01\x7f' )
    assert( Int02.to_uper() == Int02.to_uper_ws() == b'\x01\x7f' )
    assert( Int02.to_ber() == Int02.to_ber_ws() == b'\x02\x01\x7f' )
    assert( Int02.to_cer() == Int02.to_cer_ws() == b'\x02\x01\x7f' )
    assert( Int02.to_der() == Int02.to_der_ws() == b'\x02\x01\x7f' )
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
    #
    Int02.from_asn1('-128')
    # encoding
    assert( Int02.to_aper() == Int02.to_aper_ws() == b'\x01\x80' )
    assert( Int02.to_uper() == Int02.to_uper_ws() == b'\x01\x80' )
    assert( Int02.to_ber() == Int02.to_ber_ws() == b'\x02\x01\x80' )
    assert( Int02.to_cer() == Int02.to_cer_ws() == b'\x02\x01\x80' )
    assert( Int02.to_der() == Int02.to_der_ws() == b'\x02\x01\x80' )
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
    #
    Int02.from_asn1('128')
    # encoding
    assert( Int02.to_aper() == Int02.to_aper_ws() == b'\x02\x00\x80' )
    assert( Int02.to_uper() == Int02.to_uper_ws() == b'\x02\x00\x80' )
    assert( Int02.to_ber() == Int02.to_ber_ws() == b'\x02\x02\x00\x80' )
    assert( Int02.to_cer() == Int02.to_cer_ws() == b'\x02\x02\x00\x80' )
    assert( Int02.to_der() == Int02.to_der_ws() == b'\x02\x02\x00\x80' )
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
    
    # Int03 ::= INTEGER (-1..MAX)
    Int03 = Mod['Int03']
    Int03.from_asn1('4096')
    # encoding
    assert( Int03.to_aper() == Int03.to_aper_ws() == b'\x02\x10\x01' )
    assert( Int03.to_uper() == Int03.to_uper_ws() == b'\x02\x10\x01' )
    assert( Int03.to_ber() == Int03.to_ber_ws() == b'\x02\x02\x10\x00' )
    assert( Int03.to_cer() == Int03.to_cer_ws() == b'\x02\x02\x10\x00' )
    assert( Int03.to_der() == Int03.to_der_ws() == b'\x02\x02\x10\x00' )
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
    
    # Int04 ::= INTEGER (1..MAX)
    Int04 = Mod['Int04']
    Int04.from_asn1('127')
    # encoding
    assert( Int04.to_aper() == Int04.to_aper_ws() == b'\x01~' )
    assert( Int04.to_uper() == Int04.to_uper_ws() == b'\x01~' )
    assert( Int04.to_ber() == Int04.to_ber_ws() == b'\x02\x01\x7f' )
    assert( Int04.to_cer() == Int04.to_cer_ws() == b'\x02\x01\x7f' )
    assert( Int04.to_der() == Int04.to_der_ws() == b'\x02\x01\x7f' )
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
    
    # Int05 ::= INTEGER (0..MAX)
    Int05 = Mod['Int05']
    Int05.from_asn1('128')
    # encoding
    assert( Int05.to_aper() == Int05.to_aper_ws() == b'\x01\x80' )
    assert( Int05.to_uper() == Int05.to_uper_ws() == b'\x01\x80' )
    assert( Int05.to_ber() == Int05.to_ber_ws() == b'\x02\x02\x00\x80' )
    assert( Int05.to_cer() == Int05.to_cer_ws() == b'\x02\x02\x00\x80' )
    assert( Int05.to_der() == Int05.to_der_ws() == b'\x02\x02\x00\x80' )
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
    
    # Int06 ::= INTEGER (3..6)
    Int06 = Mod['Int06']
    Int06.from_asn1('3')
    # encoding
    assert( Int06.to_aper() == Int06.to_aper_ws() == b'\x00' )
    assert( Int06.to_uper() == Int06.to_uper_ws() == b'\x00' )
    assert( Int06.to_ber() == Int06.to_ber_ws() == b'\x02\x01\x03' )
    assert( Int06.to_cer() == Int06.to_cer_ws() == b'\x02\x01\x03' )
    assert( Int06.to_der() == Int06.to_der_ws() == b'\x02\x01\x03' )
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
    #
    Int06.from_asn1('6')
    # encoding
    assert( Int06.to_aper() == Int06.to_aper_ws() == b'\xc0' )
    assert( Int06.to_uper() == Int06.to_uper_ws() == b'\xc0' )
    assert( Int06.to_ber() == Int06.to_ber_ws() == b'\x02\x01\x06' )
    assert( Int06.to_cer() == Int06.to_cer_ws() == b'\x02\x01\x06' )
    assert( Int06.to_der() == Int06.to_der_ws() == b'\x02\x01\x06' )
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
    
    # Int07 ::= INTEGER (4000..4254)
    Int07 = Mod['Int07']
    Int07.from_asn1('4002')
    # encoding
    assert( Int07.to_aper() == Int07.to_aper_ws() == b'\x02' )
    assert( Int07.to_uper() == Int07.to_uper_ws() == b'\x02' )
    assert( Int07.to_ber() == Int07.to_ber_ws() == b'\x02\x02\x0f\xa2' )
    assert( Int07.to_cer() == Int07.to_cer_ws() == b'\x02\x02\x0f\xa2' )
    assert( Int07.to_der() == Int07.to_der_ws() == b'\x02\x02\x0f\xa2' )
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
    #
    Int07.from_asn1('4129')
    # encoding
    assert( Int07.to_aper() == Int07.to_aper_ws() == b'\x81' )
    assert( Int07.to_uper() == Int07.to_uper_ws() == b'\x81' )
    assert( Int07.to_ber() == Int07.to_ber_ws() == b'\x02\x02\x10!' )
    assert( Int07.to_cer() == Int07.to_cer_ws() == b'\x02\x02\x10!' )
    assert( Int07.to_der() == Int07.to_der_ws() == b'\x02\x02\x10!' )
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
    
    # Int08 ::= INTEGER (4000..4255)
    Int08 = Mod['Int08']
    Int08.from_asn1('4255')
    # encoding
    assert( Int08.to_aper() == Int08.to_aper_ws() == b'\xff' )
    assert( Int08.to_uper() == Int08.to_uper_ws() == b'\xff' )
    assert( Int08.to_ber() == Int08.to_ber_ws() == b'\x02\x02\x10\x9f' )
    assert( Int08.to_cer() == Int08.to_cer_ws() == b'\x02\x02\x10\x9f' )
    assert( Int08.to_der() == Int08.to_der_ws() == b'\x02\x02\x10\x9f' )
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
    
    # Int09 ::= INTEGER (0..32000)
    Int09 = Mod['Int09']
    Int09.from_asn1('31000')
    # encoding
    assert( Int09.to_aper() == Int09.to_aper_ws() == b'y\x18' )
    assert( Int09.to_uper() == Int09.to_uper_ws() == b'\xf20' )
    assert( Int09.to_ber() == Int09.to_ber_ws() == b'\x02\x02y\x18' )
    assert( Int09.to_cer() == Int09.to_cer_ws() == b'\x02\x02y\x18' )
    assert( Int09.to_der() == Int09.to_der_ws() == b'\x02\x02y\x18' )
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
    
    # Int10 ::= INTEGER (1..65538)
    Int10 = Mod['Int10']
    Int10.from_asn1('1')
    # encoding
    assert( Int10.to_aper() == Int10.to_aper_ws() == b'\x00\x00' )
    assert( Int10.to_uper() == Int10.to_uper_ws() == b'\x00\x00\x00' )
    assert( Int10.to_ber() == Int10.to_ber_ws() == b'\x02\x01\x01' )
    assert( Int10.to_cer() == Int10.to_cer_ws() == b'\x02\x01\x01' )
    assert( Int10.to_der() == Int10.to_der_ws() == b'\x02\x01\x01' )
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
    #
    Int10.from_asn1('257')
    # encoding
    assert( Int10.to_aper() == Int10.to_aper_ws() == b'@\x01\x00' )
    assert( Int10.to_uper() == Int10.to_uper_ws() == b'\x00\x80\x00' )
    assert( Int10.to_ber() == Int10.to_ber_ws() == b'\x02\x02\x01\x01' )
    assert( Int10.to_cer() == Int10.to_cer_ws() == b'\x02\x02\x01\x01' )
    assert( Int10.to_der() == Int10.to_der_ws() == b'\x02\x02\x01\x01' )
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
    #
    Int10.from_asn1('65538')
    # encoding
    assert( Int10.to_aper() == Int10.to_aper_ws() == b'\x80\x01\x00\x01' )
    assert( Int10.to_uper() == Int10.to_uper_ws() == b'\x80\x00\x80' )
    assert( Int10.to_ber() == Int10.to_ber_ws() == b'\x02\x03\x01\x00\x02' )
    assert( Int10.to_cer() == Int10.to_cer_ws() == b'\x02\x03\x01\x00\x02' )
    assert( Int10.to_der() == Int10.to_der_ws() == b'\x02\x03\x01\x00\x02' )
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
    
    # Int12 ::= INTEGER (-1..MAX, ...)
    Int12 = Mod['Int12']
    Int12.from_asn1('-100')
    # encoding
    assert( Int12.to_aper() == Int12.to_aper_ws() == b'\x80\x01\x9c' )
    assert( Int12.to_uper() == Int12.to_uper_ws() == b'\x80\xce\x00' )
    assert( Int12.to_ber() == Int12.to_ber_ws() == b'\x02\x01\x9c' )
    assert( Int12.to_cer() == Int12.to_cer_ws() == b'\x02\x01\x9c' )
    assert( Int12.to_der() == Int12.to_der_ws() == b'\x02\x01\x9c' )
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
    #
    Rea01.from_asn1('{mantissa 123456, base 2, exponent -53}')
    assert( Rea01._val == (123456, 2, -53) )
    # encoding
    assert( Rea01.to_aper() == Rea01.to_aper_ws() == b'\x04\x80\xd1\x07\x89')
    assert( Rea01.to_uper() == Rea01.to_uper_ws() == b'\x04\x80\xd1\x07\x89' )
    assert( Rea01.to_ber() == Rea01.to_ber_ws() == b'\t\x04\x80\xd1\x07\x89' )
    assert( Rea01.to_cer() == Rea01.to_cer_ws() == b'\t\x04\x80\xd1\x07\x89' )
    assert( Rea01.to_der() == Rea01.to_der_ws() == b'\t\x04\x80\xd1\x07\x89' )
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
    
    # Enu01 ::= ENUMERATED {cheese, cake, coffee, tea}
    Enu01 = Mod['Enu01']
    Enu01.from_asn1('coffee')
    # encoding
    assert( Enu01.to_aper() == Enu01.to_aper_ws() == b'\x80' )
    assert( Enu01.to_uper() == Enu01.to_uper_ws() == b'\x80' )
    assert( Enu01.to_ber() == Enu01.to_ber_ws() == b'\n\x01\x02' )
    assert( Enu01.to_cer() == Enu01.to_cer_ws() == b'\n\x01\x02' )
    assert( Enu01.to_der() == Enu01.to_der_ws() == b'\n\x01\x02' )
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
    
    # Enu04 ::= ENUMERATED {cheese, ..., cake, coffee, tea}
    Enu04 = Mod['Enu04']
    Enu04.from_asn1('tea')
    # encoding
    assert( Enu04.to_aper() == Enu04.to_aper_ws() == b'\x82' )
    assert( Enu04.to_uper() == Enu04.to_uper_ws() == b'\x82' )
    assert( Enu04.to_ber() == Enu04.to_ber_ws() == b'\n\x01\x03' )
    assert( Enu04.to_cer() == Enu04.to_cer_ws() == b'\n\x01\x03' )
    assert( Enu04.to_der() == Enu04.to_der_ws() == b'\n\x01\x03' )
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
    
    # Oid01 ::= OBJECT IDENTIFIER
    Oid01 = Mod['Oid01']
    Oid01.from_asn1('{iso member-body(2) fr(250) type-org(1)}')
    # encoding
    assert( Oid01.to_aper() == Oid01.to_aper_ws() == b'\x04*\x81z\x01' )
    assert( Oid01.to_uper() == Oid01.to_uper_ws() == b'\x04*\x81z\x01' )
    assert( Oid01.to_ber() == Oid01.to_ber_ws() == b'\x06\x04*\x81z\x01' )
    assert( Oid01.to_cer() == Oid01.to_cer_ws() == b'\x06\x04*\x81z\x01' )
    assert( Oid01.to_der() == Oid01.to_der_ws() == b'\x06\x04*\x81z\x01' )
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
    
    # Oid02 ::= RELATIVE-OID
    Oid02 = Mod['Oid02']
    Oid02.from_asn1('{43 12 20 7}')
    # encoding
    assert( Oid02.to_aper() == Oid02.to_aper_ws() == b'\x04+\x0c\x14\x07' )
    assert( Oid02.to_uper() == Oid02.to_uper_ws() == b'\x04+\x0c\x14\x07' )
    assert( Oid02.to_ber() == Oid02.to_ber_ws() == b'\r\x04+\x0c\x14\x07' )
    assert( Oid02.to_cer() == Oid02.to_cer_ws() == b'\r\x04+\x0c\x14\x07' )
    assert( Oid02.to_der() == Oid02.to_der_ws() == b'\r\x04+\x0c\x14\x07' )
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
    
    # Bst01 ::= BIT STRING
    Bst01 = Mod['Bst01']
    Bst01.from_asn1('\'001111001001011010\'B')
    # encoding
    assert( Bst01.to_aper() == Bst01.to_aper_ws() == b'\x12<\x96\x80' )
    assert( Bst01.to_uper() == Bst01.to_uper_ws() == b'\x12<\x96\x80' )
    assert( Bst01.to_ber() == Bst01.to_ber_ws() == b'\x03\x04\x06<\x96\x80' )
    assert( Bst01.to_cer() == Bst01.to_cer_ws() == b'\x03\x04\x06<\x96\x80' )
    assert( Bst01.to_der() == Bst01.to_der_ws() == b'\x03\x04\x06<\x96\x80' )
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
    
    # Bst03 ::= BIT STRING (SIZE (0..24, ...))
    Bst03 = Mod['Bst03']
    Bst03.from_asn1('\'00111100100101101010010100001111\'B')
    # encoding
    assert( Bst03.to_aper() == Bst03.to_aper_ws() == b'\x80 <\x96\xa5\x0f' )
    assert( Bst03.to_uper() == Bst03.to_uper_ws() == b'\x90\x1eKR\x87\x80' )
    assert( Bst03.to_ber() == Bst03.to_ber_ws() == b'\x03\x05\x00<\x96\xa5\x0f' )
    assert( Bst03.to_cer() == Bst03.to_cer_ws() == b'\x03\x05\x00<\x96\xa5\x0f' )
    assert( Bst03.to_der() == Bst03.to_der_ws() == b'\x03\x05\x00<\x96\xa5\x0f' )
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
    
    # Ost01 ::= OCTET STRING
    Ost01 = Mod['Ost01']
    Ost01.from_asn1('\'0123456789ABCDEFFEDCBA9876543210\'H')
    # encoding
    assert( Ost01.to_aper() == Ost01.to_aper_ws() == b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_uper() == Ost01.to_uper_ws() == b'\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_ber() == Ost01.to_ber_ws() == b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_cer() == Ost01.to_cer_ws() == b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
    assert( Ost01.to_der() == Ost01.to_der_ws() == b'\x04\x10\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10' )
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
    
    # Nus01 ::= NumericString
    Nus01 = Mod['Nus01']
    Nus01.from_asn1('"01 02 03 04 05"')
    # encoding
    assert( Nus01.to_aper() == Nus01.to_aper_ws() == b'\x0e\x12\x010\x14\x01P\x16' )
    assert( Nus01.to_uper() == Nus01.to_uper_ws() == b'\x0e\x12\x010\x14\x01P\x16' )
    assert( Nus01.to_ber() == Nus01.to_ber_ws() == b'\x12\x0e01 02 03 04 05' )
    assert( Nus01.to_cer() == Nus01.to_cer_ws() == b'\x12\x0e01 02 03 04 05' )
    assert( Nus01.to_der() == Nus01.to_der_ws() == b'\x12\x0e01 02 03 04 05' )
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
    
    # Nus02 ::= NumericString (FROM ("0123"))
    Nus02 = Mod['Nus02']
    Nus02.from_asn1('"00113322"')
    # encoding
    assert( Nus02.to_aper() == Nus02.to_aper_ws() == b'\x08\x05\xfa' )
    assert( Nus02.to_uper() == Nus02.to_uper_ws() == b'\x08\x05\xfa' )
    assert( Nus02.to_ber() == Nus02.to_ber_ws() == b'\x12\x0800113322' )
    assert( Nus02.to_cer() == Nus02.to_cer_ws() == b'\x12\x0800113322' )
    assert( Nus02.to_der() == Nus02.to_der_ws() == b'\x12\x0800113322' )
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
    
    # Prs01 ::= PrintableString
    Prs01 = Mod['Prs01']
    Prs01.from_asn1('"ambiguite"')
    # encoding
    assert( Prs01.to_aper() == Prs01.to_aper_ws() == b'\tambiguite' )
    assert( Prs01.to_uper() == Prs01.to_uper_ws() == b'\t\xc3\xb7\x16\x9c\xfdt\xf4\xca' )
    assert( Prs01.to_ber() == Prs01.to_ber_ws() == b'\x13\tambiguite' )
    assert( Prs01.to_cer() == Prs01.to_cer_ws() == b'\x13\tambiguite' )
    assert( Prs01.to_der() == Prs01.to_der_ws() == b'\x13\tambiguite' )
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
    
    # Prs02 ::= PrintableString (FROM ("ATCG"))
    Prs02 = Mod['Prs02']
    Prs02.from_asn1('"ATCGATTGAGCTCTAGCG"')
    # encoding
    assert( Prs02.to_aper() == Prs02.to_aper_ws() == b"\x126>'r`" )
    assert( Prs02.to_uper() == Prs02.to_uper_ws() == b"\x126>'r`" )
    assert( Prs02.to_ber() == Prs02.to_ber_ws() == b'\x13\x12ATCGATTGAGCTCTAGCG' )
    assert( Prs02.to_cer() == Prs02.to_cer_ws() == b'\x13\x12ATCGATTGAGCTCTAGCG' )
    assert( Prs02.to_der() == Prs02.to_der_ws() == b'\x13\x12ATCGATTGAGCTCTAGCG' )
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
    
    # Ias01 ::= IA5String
    Ias01 = Mod['Ias01']
    Ias01.from_asn1('"ambiguite"')
    # encoding
    assert( Ias01.to_aper() == Ias01.to_aper_ws() == b'\tambiguite' )
    assert( Ias01.to_uper() == Ias01.to_uper_ws() == b'\t\xc3\xb7\x16\x9c\xfdt\xf4\xca' )
    assert( Ias01.to_ber() == Ias01.to_ber_ws() == b'\x16\tambiguite' )
    assert( Ias01.to_cer() == Ias01.to_cer_ws() == b'\x16\tambiguite' )
    assert( Ias01.to_der() == Ias01.to_der_ws() == b'\x16\tambiguite' )
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
    
    # U8s01 ::= UTF8String
    U8s01 = Mod['U8s01']
    U8s01.from_asn1('"ambiguïté"')
    # encoding
    assert( U8s01.to_aper() == U8s01.to_aper_ws() == b'\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_uper() == U8s01.to_uper_ws() == b'\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_ber() == U8s01.to_ber_ws() == b'\x0c\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_cer() == U8s01.to_cer_ws() == b'\x0c\x0bambigu\xc3\xaft\xc3\xa9' )
    assert( U8s01.to_der() == U8s01.to_der_ws() == b'\x0c\x0bambigu\xc3\xaft\xc3\xa9' )
    # decoding
    U8s01.from_aper(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_aper_ws(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_uper(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_uper_ws(b'\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_ber(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_ber_ws(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_cer(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_cer_ws(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_der(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    U8s01.from_der_ws(b'\x0c\x0bambigu\xc3\xaft\xc3\xa9')
    assert( U8s01._val == 'ambiguïté' )
    
    # Uns01 ::= UniversalString
    Uns01 = Mod['Uns01']
    Uns01.from_asn1('"ambiguïté"')
    # encoding
    assert( Uns01.to_aper() == Uns01.to_aper_ws() == b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_uper() == Uns01.to_uper_ws() == b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_ber() == Uns01.to_ber_ws() == b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_cer() == Uns01.to_cer_ws() == b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    assert( Uns01.to_der() == Uns01.to_der_ws() == b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9' )
    # decoding
    Uns01.from_aper(b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_aper_ws(b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_uper(b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_uper_ws(b'\t\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_ber(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_ber_ws(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_cer(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_cer_ws(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_der(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    Uns01.from_der_ws(b'\x1c$\x00\x00\x00a\x00\x00\x00m\x00\x00\x00b\x00\x00\x00i\x00\x00\x00g\x00\x00\x00u\x00\x00\x00\xef\x00\x00\x00t\x00\x00\x00\xe9')
    assert( Uns01._val == 'ambiguïté' )
    
    # Uti01 ::= UTCTime
    Uti01 = Mod['Uti01']
    Uti01.from_asn1('"1705181130Z"')
    # encoding
    assert( Uti01.to_aper() == Uti01.to_aper_ws() == b'\r170518113000Z' )
    assert( Uti01.to_uper() == Uti01.to_uper_ws() == b'\r170518113000Z' )
    assert( Uti01.to_ber() == Uti01.to_ber_ws() == b'\x17\x0b1705181130Z' )
    assert( Uti01.to_cer() == Uti01.to_cer_ws() == b'\x17\r170518113000Z' )
    assert( Uti01.to_der() == Uti01.to_der_ws() == b'\x17\r170518113000Z' )
    # decoding
    Uti01.from_aper(b'\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_aper_ws(b'\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_uper(b'\r170518113000Z')
    assert( Uti01._val == ('17', '05', '18', '11', '30', '00', 'Z') )
    Uti01.from_uper_ws(b'\r170518113000Z')
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
    assert( Gti01.to_aper() == Gti01.to_aper_ws() == b'\x1420170517200512.0123Z' )
    assert( Gti01.to_uper() == Gti01.to_uper_ws() == b'\x1420170517200512.0123Z' )
    assert( Gti01.to_ber() == Gti01.to_ber_ws() == b'\x18\x1a20170518073512.012300-1130' )
    assert( Gti01.to_cer() == Gti01.to_cer_ws() == b'\x18\x1420170517200512.0123Z' )
    assert( Gti01.to_der() == Gti01.to_der_ws() == b'\x18\x1420170517200512.0123Z' )
    # decoding
    Gti01.from_aper(b'\x1420170517200512.0123Z')
    assert( Gti01._val == ('2017', '05', '17', '20', '05', '12', '0123', 'Z') )
    Gti01.from_aper_ws(b'\x1420170517200512.0123Z')
    assert( Gti01._val == ('2017', '05', '17', '20', '05', '12', '0123', 'Z') )
    Gti01.from_uper(b'\x1420170517200512.0123Z')
    assert( Gti01._val == ('2017', '05', '17', '20', '05', '12', '0123', 'Z') )
    Gti01.from_uper_ws(b'\x1420170517200512.0123Z')
    assert( Gti01._val == ('2017', '05', '17', '20', '05', '12', '0123', 'Z') )
    Gti01.from_ber(b'\x18\x1a20170518073512.012300-1130')
    assert( Gti01._val == ('2017', '05', '18', '07', '35', '12', '012300', '-1130') )
    Gti01.from_ber_ws(b'\x18\x1a20170518073512.012300-1130')
    assert( Gti01._val == ('2017', '05', '18', '07', '35', '12', '012300', '-1130') )
    Gti01.from_cer(b'\x18\x1420170517200512.0123Z')
    assert( Gti01._val == ('2017', '05', '17', '20', '05', '12', '0123', 'Z') )
    Gti01.from_cer_ws(b'\x18\x1420170517200512.0123Z')
    assert( Gti01._val == ('2017', '05', '17', '20', '05', '12', '0123', 'Z') )
    Gti01.from_der(b'\x18\x1420170517200512.0123Z')
    assert( Gti01._val == ('2017', '05', '17', '20', '05', '12', '0123', 'Z') )
    Gti01.from_der_ws(b'\x18\x1420170517200512.0123Z')
    assert( Gti01._val == ('2017', '05', '17', '20', '05', '12', '0123', 'Z') )
    
    # Cho01 ::= CHOICE { --check test_asn1rt_mod.asn file-- }
    Cho01 = Mod['Cho01']
    Cho01.from_asn1('int: 2000')
    # encoding
    assert( Cho01.to_aper() == Cho01.to_aper_ws() == b' \x02\x07\xcf' )
    assert( Cho01.to_uper() == Cho01.to_uper_ws() == b' @\xf9\xe0' )
    assert( Cho01.to_ber() == Cho01.to_ber_ws() == b'\xaa\x07\x7fP\x04\x02\x02\x07\xd0' )
    assert( Cho01.to_cer() == Cho01.to_cer_ws() == b'\xaa\x80\x7fP\x80\x02\x02\x07\xd0\x00\x00\x00\x00' )
    assert( Cho01.to_der() == Cho01.to_der_ws() == b'\xaa\x07\x7fP\x04\x02\x02\x07\xd0' )
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
    
    return 0
    

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

def test_rrc3g():
    GLOBAL.clear()
    from pycrate_asn1dir import RRC3G
    #
    PCCH = RRC3G.Class_definitions.PCCH_Message
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
    #
    DLDCCH = RRC3G.Class_definitions.DL_DCCH_Message
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
    #
    ULDCCH = RRC3G.Class_definitions.UL_DCCH_Message
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

# X2AP packets contributed by Alexandre DeOliveira, originally in libmich
pkts_x2ap = tuple(map(unhexlify, (
    '000600808a000004001500080011f1110001013000140051020000330011f11101011010029011f111004c2c05dc330000340011f1110101102000a011f111004c2c05dc444000350011f1110101103000a011f111005eec189c3300010011f1110a0ab010002705dc001800060011f1118000a8dd4018000002100040030001031001400a0001c006001008020100',
    '0000007b000006000a00020001000540020000000b000800522018000000200017000700522018000102000e004100010000000000303132333435363738393031323334353637383930313233343536373839303120000000000004400e0000010a03e01401a8c000000002020000000f400c000052201800000021800003',
    )))

def test_lteran():
    GLOBAL.clear()
    from pycrate_asn1dir import S1AP
    from pycrate_asn1dir import X2AP
    #
    S1PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    for p in pkts_s1ap:
        S1PDU.from_aper(p)
        val = S1PDU()
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
    #
    X2PDU = X2AP.X2AP_PDU_Descriptions.X2AP_PDU
    for p in pkts_x2ap:
        X2PDU.from_aper(p)
        val = X2PDU()
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


# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=gsm_map_with_ussd_string.pcap
pkts_tcap_map = tuple(map(unhexlify, (
    '626a48042f3b46026b3a2838060700118605010101a02d602b80020780a109060704000001001302be1a2818060704000001010101a00da00b80099656051124006913f66c26a12402010102013b301c04010f040eaa180da682dd6c31192d36bbdd468007917267415827f2',
    )))

def test_tcap_map():
    GLOBAL.clear()
    from pycrate_asn1dir import TCAP_MAP
    #
    M = TCAP_MAP.TCAP_MAP_Messages.TCAP_MAP_Message
    for p in pkts_tcap_map:
        M.from_ber(p)
        val = M()
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

def test_tcap_cap():
    GLOBAL.clear()
    from pycrate_asn1dir import TCAP_CAP
    #
    M = TCAP_CAP.CAP_gsmSSF_gsmSCF_pkgs_contracts_acs.GenericSSF_gsmSCF_PDUs
    for p in pkts_tcap_cap:
        M.from_ber(p)
        val = M()
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


pkts_X509 = tuple(map(unhexlify, (
    # https://www.google.fr/
    b'3082078a30820672a0030201020208657d462b1509b3b7300d06092a864886f70d01010b05003049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f72697479204732301e170d3137303832323136343232355a170d3137313131343136333030305a3066310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f676c6520496e633115301306035504030c0c2a2e676f6f676c652e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200045d105bb2427733023a751eb73901b97ee50ce862d3c0d1f40cf3ed34e52fd88cd8c0b6f43aec0f26ec458340bd561d73b219887f689f47c537d1f8151b071203a38205223082051e301d0603551d250416301406082b0601050507030106082b06010505070302300b0603551d0f040403020780308203e10603551d11048203d8308203d4820c2a2e676f6f676c652e636f6d820d2a2e616e64726f69642e636f6d82162a2e617070656e67696e652e676f6f676c652e636f6d82122a2e636c6f75642e676f6f676c652e636f6d82142a2e64623833333935332e676f6f676c652e636e82062a2e672e636f820e2a2e6763702e677674322e636f6d82162a2e676f6f676c652d616e616c79746963732e636f6d820b2a2e676f6f676c652e6361820b2a2e676f6f676c652e636c820e2a2e676f6f676c652e636f2e696e820e2a2e676f6f676c652e636f2e6a70820e2a2e676f6f676c652e636f2e756b820f2a2e676f6f676c652e636f6d2e6172820f2a2e676f6f676c652e636f6d2e6175820f2a2e676f6f676c652e636f6d2e6272820f2a2e676f6f676c652e636f6d2e636f820f2a2e676f6f676c652e636f6d2e6d78820f2a2e676f6f676c652e636f6d2e7472820f2a2e676f6f676c652e636f6d2e766e820b2a2e676f6f676c652e6465820b2a2e676f6f676c652e6573820b2a2e676f6f676c652e6672820b2a2e676f6f676c652e6875820b2a2e676f6f676c652e6974820b2a2e676f6f676c652e6e6c820b2a2e676f6f676c652e706c820b2a2e676f6f676c652e707482122a2e676f6f676c656164617069732e636f6d820f2a2e676f6f676c65617069732e636e82142a2e676f6f676c65636f6d6d657263652e636f6d82112a2e676f6f676c65766964656f2e636f6d820c2a2e677374617469632e636e820d2a2e677374617469632e636f6d820a2a2e677674312e636f6d820a2a2e677674322e636f6d82142a2e6d65747269632e677374617469632e636f6d820c2a2e75726368696e2e636f6d82102a2e75726c2e676f6f676c652e636f6d82162a2e796f75747562652d6e6f636f6f6b69652e636f6d820d2a2e796f75747562652e636f6d82162a2e796f7574756265656475636174696f6e2e636f6d82072a2e79742e6265820b2a2e7974696d672e636f6d821a616e64726f69642e636c69656e74732e676f6f676c652e636f6d820b616e64726f69642e636f6d821b646576656c6f7065722e616e64726f69642e676f6f676c652e636e821c646576656c6f706572732e616e64726f69642e676f6f676c652e636e8204672e636f8206676f6f2e676c8214676f6f676c652d616e616c79746963732e636f6d820a676f6f676c652e636f6d8212676f6f676c65636f6d6d657263652e636f6d8218736f757263652e616e64726f69642e676f6f676c652e636e820a75726368696e2e636f6d820a7777772e676f6f2e676c8208796f7574752e6265820b796f75747562652e636f6d8214796f7574756265656475636174696f6e2e636f6d820579742e6265306806082b06010505070101045c305a302b06082b06010505073002861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e636f6d2f6f637370301d0603551d0e04160414bb878d2e10f930b01fdea30a71ebcc9ab46e3b99300c0603551d130101ff04023000301f0603551d230418301680144add06161bbcf668b576f581b6bb621aba5a812f30210603551d20041a3018300c060a2b06010401d6790205013008060667810c01020230300603551d1f042930273025a023a021861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e63726c300d06092a864886f70d01010b050003820101004bb6a5e86b4dd533d6b6b995dadcb29a6685d112d3d7e268d92398deb2098004e4eaafb822f588f584583e39298e44907faa8231d7e32bd764124010b580047f07751786075825ee38f5d370a8fdc69fc0e2e43a816ba16121658d152e00bb1a488b06cd7f53e9962e737a9bdcea99a2b73bfe46c4c3270c3b344ed7d40f23c233ee7918edcf213cc9dc1f7973ae6567f1f00b6fbe8e0756a46721ed6005fafe70261d103d51a24818f4bc7539e7f9d778c0a93e989f9616174c9d801118e992878160d0a70265bcd6cd189ac8ca06437e87241ea3e842f2939a265c117359dc5069ef49abcc20ccd281bfe5dda77bd1d3dd4af482c667d3de2b788b646f60c0',
    )))

def test_X509():
    GLOBAL.clear()
    from pycrate_asn1dir import RFC5912
    #
    Cert = RFC5912.PKIX1Explicit_2009.Certificate
    for p in pkts_X509:
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
        assert( Cert() == val )

