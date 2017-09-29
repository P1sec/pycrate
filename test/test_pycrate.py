# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2016. Benoit Michau. ANSSI.
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
# * File Name : test/test_pycrate.py
# * Created : 2016-02-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import sys
import os
import importlib
import unittest

from test.test_core   import *
from test.test_media  import *
from test.test_ether  import *
from test.test_csn1   import *
from test.test_asn1rt import *
from test.test_mobile import *
from pycrate_asn1c.proc import compile_text, compile_spec, compile_all, \
                               generate_modules, PycrateGenerator, \
                               GLOBAL, ASN_SPECS
from pycrate_asn1rt.asnobj import ASN1Obj

Element._SAFE_STAT = True
Element._SAFE_DYN  = True
ASN1Obj._SAFE_INIT = True

# enabling the compilation of all ASN.1 modules from pycrate_asn1dir
# takes few minutes
#global TEST_ASN1C_ALL
TEST_ASN1C_ALL = False

class TestPycrate(unittest.TestCase):
    
    # core objects
    def test_core(self):
        print('[<>] testing pycrate_core')
        test_bitlist()
        test_bytes()
        test_bytelist()
        test_int()
        test_blb()
        test_pack()
        test_charpy()
        test_elt_1()
        test_elt_2()
    
    # fmt_media objects
    def test_media(self):
        print('[<>] testing pycrate_media')
        test_bmp('./test/res/bmp_test.bmp')
        test_png('./test/res/xkcd_wireless_signal.png')
        test_jpeg('./test/res/ESP8266.jpg')
        test_tiff('./test/res/xkcd_phone_2.tiff')
        test_gif('./test/res/nyancat.gif')
        test_mp4('./test/res/Simulation_of_Kepler_Supernova_Explosion.mp4')
        test_mp3('./test/res/snare.mp3')
    
    # fmt_ip objects
    def test_ether(self):
        print('[<>] testing pycrate_ether')
        test_ip(eth_frames)
    
    # asn1c
    def test_asn1c(self):
        print('[<>] testing pycrate_asn1c')
        # create an "asn" dir for storing compiled specifications
        if 'test_asn' not in os.listdir('.'):
            os.mkdir('test_asn')
        # compile and generate the Hardcore ASN.1 module
        fd = open('./test/res/Hardcore.asn', 'r')
        asntext = fd.read()
        fd.close()
        fd_init = open('./test_asn/__init__.py', 'w')
        fd_init.write('__all__ = [')
        compile_text(asntext)
        generate_modules(PycrateGenerator, './test_asn/Hardcore.py')
        GLOBAL.clear()
        fd_init.write('\'Hardcore\', ')
        if TEST_ASN1C_ALL:
            # compile and generate all specifications from the asndir
            for sn in ASN_SPECS:
                compile_spec(shortname=sn)
                generate_modules(PycrateGenerator, './test_asn/%s.py' % sn)
                GLOBAL.clear()
                fd_init.write('\'%s\',' % sn)
        fd_init.write(']\n')
        fd_init.close()
        print('[<>] all ASN.1 modules generated to ./test_asn/')
        # load all specification
        print('[<>] loading all compiled module')
        importlib.import_module('test_asn.Hardcore')
        del sys.modules['test_asn.Hardcore']
        if TEST_ASN1C_ALL:
            for sn in ASN_SPECS:
                importlib.import_module('test_asn.%s' % sn)
                del sys.modules['test_asn.%s' % sn]
        print('[<>] all ASN.1 modules loaded successfully from ./test_asn/')
    
    # asn1rt
    def test_asn1rt(self):
        print('[<>] testing pycrate_asn1rt')
        test_rt_base()
        test_rrc3g()
        test_lteran()
        test_tcap_map()
        test_tcap_cap()
        test_X509()
    
    # csn1
    def test_csn1(self):
        print('[<>] testing pycrate_csn1')
        test_msnetcap()
        test_msracap()
    
    # mobile
    def test_mobile(self):
        print('[<>] testing pycrate_mobile')
        test_nas_mo()


def test_perf_all():
    test_perf()
    test_perf_media('./test/res/bmp_test.bmp',
                    './test/res/xkcd_wireless_signal.png',
                    './test/res/ESP8266.jpg',
                    './test/res/xkcd_phone_2.tiff',
                    './test/res/nyancat.gif',
                    './test/res/Simulation_of_Kepler_Supernova_Explosion.mp4',
                    './test/res/snare.mp3'
                    )
    test_perf_ip(eth_frames)


if __name__ == '__main__':
    unittest.main()

