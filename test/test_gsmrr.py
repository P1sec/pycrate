# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2018. Benoit Michau. P1sec.
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
# * File Name : test/test_gsmrr.py
# * Created : 2018-11-21
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from timeit import timeit

#from pycrate_core.elt           import Element
#Element._SAFE_STAT = False
#Element._SAFE_DYN  = False

from pycrate_core.elt   import _with_json
from pycrate_mobile.NAS import *


rr_pdu_mo = tuple(map(unhexlify, (
    # SACCH
    '061524a420e5516f30d68dc8000000000000', # measurement report
    '061523a30123516f1b97586b81c000000000',
    # DCCH
    '062702035359a605f4312949c4', # paging response
    '0634c430946102f81003100106', # GPRS suspension req
    '0616035359a6200b601404ef6503b8878d2100', # classmark change
    '0632', # ciphering mode complete
    )))

rr_pdu_mt = tuple(map(unhexlify, (
    # DCCH
    '063505', # ciphering mode cmd
    '060d00', # channel release
    )))

rr_pdu_l2_mt = tuple(map(unhexlify, (
    # BCCH
    '2d063f110e600c7f1d3800004bc26b0284b510f32b2b2b', # immediate assignment
    '35063f0178b18207ec1704021fff2b2b2b2b2b2b2b2b2b',
    '2506212005f438e593af2b2b2b2b2b2b2b2b2b2b2b2b2b', # paging req type 1
    '490622a0c9585d282cf7eb861705f4df78a200cc8b2b2b', # paging req type 2
    '4d0624a0356c9f6bf1e09909ff402879d9304369d32b2b', # paging req type 3
    '5506198fe900200000000000000000000000007900002b', # SI type 1
    '55061900000000000000000001c00001ff80007900002b',
    '01060080005847eb4a93f51a298a16ab2b2b2b2b2b2b2b', # SI type 13
    '59061a10000000000000000000000000007effff790000', # SI type 2
    '550602afe85f7000000ba000000000000000007900002b', # SI type 2bis
    '05060700e046e508007e5170c1879fe259742c5e182d53', # SI type 2quater
    '010603cf8a30000000000000000000005000002b2b2b2b', # SI type 2ter
    '49061bfae102f8100310c8021e1785407900008000029b', # SI type 3
    '31061c02f810031085407900008000572b2b2b2b2b2b2b', # SI type 4
    # SACCH
    '49061d00000000000000000000000000007eff', # SI type 5
    '2d061e87e902f810031097ff2b2b2b2b2b2b2b', # SI type 6
    )))


def test_gsmrr_mo(rr_pdu=rr_pdu_mo):
    for pdu in rr_pdu:
        m, e = parse_NAS_MO(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )

def test_gsmrr_l2_mt(rr_pdu=rr_pdu_l2_mt):
    for pdu in rr_pdu:
        m, e = parse_NAS_MT(pdu, wl2=True)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )
    
def test_gsmrr_mt(rr_pdu=rr_pdu_mt):
    for pdu in rr_pdu:
        m, e = parse_NAS_MT(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )

def test_perf_gsmrr():
    
    print('[+] GSM RR MO decoding and re-encoding')
    Ta = timeit(test_gsmrr_mo, number=30)
    print('test_gsmrr_mo: {0:.4f}'.format(Ta))
    
    print('[+] GSM RR MT decoding and re-encoding')
    Tb = timeit(test_gsmrr_mt, number=200)
    print('test_gsmrr_mt: {0:.4f}'.format(Tb))
    
    print('[+] GSM RR L2 MT decoding and re-encoding')
    Tc = timeit(test_gsmrr_l2_mt, number=8)
    print('test_gsmrr_l2_mt: {0:.4f}'.format(Tc))
    
    print('[+] test_gsmrr total time: {0:.4f}'.format(Ta+Tb+Tc))


if __name__ == '__main__':
    test_perf_gsmrr()

