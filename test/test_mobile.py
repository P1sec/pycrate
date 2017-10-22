# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.2
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

# uplink messages
nas_pdu_mo = map(unhexlify, (
    # CS domain
    '05080200f11040005705f44c6a94c033035758a6', # MM LU Request
    '052401035758a605f4345b7129c2', # MM CM Service Request
    '0514a3c729e021042a92f637', # MM Auth Response
    '034504066004020005815e068160000000001502010040080402600400021f00', # CC Setup
    '8381', # CC Alert
    '834804066004020005811502010040080402600400021f00', # CC Call Confirmed
    '83c7', # CC Connect
    '03cf', # CC Connect Ack
    '036502e090', # CC Disconnect
    '032d', # CC Release
    '03aa', # CC Release Complete
    # PS domain
    '080103e5e004010a0005f4fffa01f700f1104000100c0a53432b259ef989004000081705', # GMM Attach Request
    '0803', # GMM Attach Complete
    '08086002f8108003c81c1a53432b259ef9890040009dd9c633120080013a332c66240100026019e6e82017051805f4c2c85e9a3103e5e034320220005804e060c0401a05f4c3e0732f1b0602f8107500015d0100', # GMM RAU Request
    '081300224b1e647b290457a2f017', # GMM Auth Cipher Response
    '080a', # GMM RAU Complete
    '080c2605f4f1c8e8bf32022000', # GMM Service Request
    '8a49', # SM Modify PDP Ctxt Accept
    ))

# downlink messages
nas_pdu_mt = map(unhexlify, (
    # CS domain
    '051201f6e3c095753f23a9194291c86395f4782010a322f1689dc5000030dcb7d5eaafafe3', # MM Auth Request
    '0521', # MM CM Service Accept
    '050202f8100404', # MM LU Accept
    '83011e02e2a0', # CC Alert
    '8302', # CC Call Proceeding
    '83071e02e281', # CC Connect
    '030f', # CC Connect Ack
    '832502e090', # CC Disconnect
    '830302e2a0', # CC Progress
    '832d0802e090', # CC Release
    '032a0802e090', # CC Release Complete
    '03050401a05c0811833306000000f0', # CC Setup
    # PS domain
    '0802095e0102f8100405011805f4ffc856602a012c3801e0', # GMM Attach Accept
    '08120000211f12d433eac66f821ce2dfaf54c2c43b802810ac537cb6940c00006a1ec8ee4e0c7c8e', # GMM Auth Cipher Request
    '08214308804f79d87d2e838c4508804f79d87d2e838c4771019190727480490101', # GMM Information
    '081503', # GMM Ident Request
    '0809805e02f8100404011805f4d4cbf2852a012c320220003801e0', # GMM RAU Accept
    ))


def test_nas_mo(nas_pdu=nas_pdu_mo):
    for pdu in nas_pdu:
        m, e = parse_L3_MO(pdu)
        assert( e == 0 )
        assert( m.to_bytes() == pdu )

def test_nas_mt(nas_pdu=nas_pdu_mt):
    for pdu in nas_pdu:
        m, e = parse_L3_MT(pdu)
        assert( e == 0 )
        assert( m.to_bytes() == pdu )
