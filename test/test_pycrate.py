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
# * File Name : test/test_pycrate.py
# * Created : 2016-02-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import sys
import os
import importlib
import unittest
import time

from test.test_core   import *
from test.test_media  import *
from test.test_ether  import *
from test.test_csn1   import *
from test.test_asn1rt import *
from test.test_mobile import *
from test.test_gsmrr  import *
from pycrate_asn1c.specdir import ASN_SPECS
from pycrate_asn1c.asnproc import compile_text, compile_spec, compile_all, \
    generate_modules, PycrateGenerator, GLOBAL
from pycrate_asn1rt.asnobj import ASN1Obj

Element._SAFE_STAT = True
Element._SAFE_DYN  = True
ASN1Obj._SAFE_INIT = True

# enabling the compilation of all ASN.1 modules from pycrate_asn1dir, taking few minutes
TEST_ASN1C_ALL_COMP = False
# enabling the loading of all ASN.1 modules from pycrate_asn1dir
TEST_ASN1C_ALL_LOAD = False


class TestPycrate(unittest.TestCase):
    
    def runTest(self):
        pass
    
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
        test_elt_3()
        test_elt_4()
    
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
        test_ether(eth_frames)
    
    # asn1c
    def test_asn1c(self, test_all_comp=TEST_ASN1C_ALL_COMP, test_all_load=TEST_ASN1C_ALL_LOAD):
        print('[<>] testing pycrate_asn1c')
        # create an "asn" dir for storing compiled specifications
        if 'test_asn_todelete' not in os.listdir('.'):
            os.mkdir('test_asn_todelete')
        # compile and generate the Hardcore ASN.1 module
        fd = open('./test/res/Hardcore.asn', 'r')
        asntext = fd.read()
        fd.close()
        fd_init = open('./test_asn_todelete/__init__.py', 'w')
        fd_init.write('__all__ = [')
        compile_text(asntext)
        generate_modules(PycrateGenerator, './test_asn_todelete/Hardcore.py')
        GLOBAL.clear()
        fd_init.write('\'Hardcore\', ')
        if test_all_comp:
            print(ASN_SPECS)
            # compile and generate all specifications from the asndir
            for sn in ASN_SPECS:
                compile_spec(shortname=sn)
                generate_modules(PycrateGenerator, './test_asn_todelete/%s.py' % sn)
                GLOBAL.clear()
                fd_init.write('\'%s\',' % sn)
        fd_init.write(']\n')
        fd_init.close()
        print('[<>] all ASN.1 modules generated to ./test_asn_todelete/')
        # load all specification
        print('[<>] loading all compiled module')
        importlib.import_module('test_asn_todelete.Hardcore')
        del sys.modules['test_asn_todelete.Hardcore']
        if test_all_load:
            if test_all_comp:
                # test loading modules freshly compiled
                for sn in ASN_SPECS:
                    importlib.import_module('test_asn_todelete.%s' % sn)
                    del sys.modules['test_asn_todelete.%s' % sn]
                    print('  - loaded %s' % sn)
            else:
                for sn in ASN_SPECS:
                    importlib.import_module('pycrate_asn1dir.%s' % sn)
                    del sys.modules['pycrate_asn1dir.%s' % sn]
                    print('  - loaded %s' % sn)
        print('[<>] all ASN.1 modules loaded successfully')
        GLOBAL.clear()
    
    # asn1rt
    def test_asn1rt(self):
        print('[<>] testing pycrate_asn1rt')
        test_rt_base()
        test_rrc3g()
        test_lteran()
        test_nrran()
        test_tcap_map()
        test_tcap_cap()
        test_X509()
        GLOBAL.clear()
    
    # csn1
    def test_csn1(self):
        print('[<>] testing pycrate_csn1')
        test_msnetcap()
        test_mscm3()
        test_msracap()
        test_rcvnpdunumlist()
        test_msracap()
        test_si2qr()
        test_si13r()
    
    # mobile
    def test_mobile(self):
        print('[<>] testing pycrate_mobile')
        test_nas_mo()
        test_nas_mt()
        test_nas_5g()
        test_sigtran()
        test_sccp()
        test_isup()
        test_gtpu()
        test_gtpc()
        test_diameter()
        test_pfcp()
    
    # mobile / GSM RR
    def test_gsmrr(self):
        print('[<>] testing GSM RR in pycrate_mobile')
        test_gsmrr_mo()
        test_gsmrr_l2_mt()
        test_gsmrr_mt()


def test_perf_all():
    T0 = time.time()
    test_perf_core()
    test_perf_media('./test/res/bmp_test.bmp',
                    './test/res/xkcd_wireless_signal.png',
                    './test/res/ESP8266.jpg',
                    './test/res/xkcd_phone_2.tiff',
                    './test/res/nyancat.gif',
                    './test/res/Simulation_of_Kepler_Supernova_Explosion.mp4',
                    './test/res/snare.mp3'
                    )
    test_perf_ether()
    test_perf_asn1rt()
    test_perf_csn1()
    test_perf_mobile()
    test_perf_gsmrr()
    print('[<<<>>>] test_perf_all total time: %.4f' % (time.time() - T0))


if __name__ == '__main__':
    #unittest.main()
    test_perf_all()

