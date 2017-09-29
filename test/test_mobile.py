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
# * File Name : test/test_mobile.py
# * Created : 2016-04-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from timeit import timeit

from pycrate_mobile.GSMTAP      import *
from pycrate_mobile.TS24008_IE  import *
from pycrate_mobile.TS24008_MM  import *
from pycrate_mobile.TS24008_GMM import *
from pycrate_mobile.NAS         import *


nas_pdu_mo = map(unhexlify, (
    '05080200f11040005705f44c6a94c033035758a6', # LAUReq
    '080103e5e004010a0005f4fffa01f700f1104000100c0a53432b259ef989004000081705', # AttachReq
    ))


def test_nas_mo():
    for pdu in nas_pdu_mo:
        m, e = parse_L3_MO(pdu)
        if e != 0:
            assert()
        assert( m.to_bytes() == pdu )

