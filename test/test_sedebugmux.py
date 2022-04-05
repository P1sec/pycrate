# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2022. Vadim Yanitskiy
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
# * File Name : test/test_sedebugmux.py
# * Created : 2022-01-14
# * Authors : Vadim Yanitskiy
# *--------------------------------------------------------
#*/

from timeit import timeit

from pycrate_osmo.SEDebugMux import *

test_frames = (
    # Enquiry target identifier and available Data Providers
    b'\x42\x42' + b'\x05\x00' + b'\x01\x00' + b'e' + b'\x69\x3e',
    # Target identifier: Sony Ericsson K800, IMEI=359087010554925
    b'\x42\x42' + b'\x2b\x00' + b'\x00\x02' + b'f' +
        b'\xa6\x7e\xc6\x41\x21' + b'Sony Ericsson K800359087010554925' + b'\xd2\x5b',
    # Data Provider available: 'Tvp'
    b'\x42\x42' + b'\x0b\x00' + b'\x01\x02' + b'i' +
        b'\xe7\xb0\x03' + b'Tvp' + b'\x96\xc1',
    # Data Provider available: 'Print Server Channel'
    b'\x42\x42' + b'\x1c\x00' + b'\x02\x02' + b'i' +
        b'\xe8\xb0\x14' + b'Print Server Channel' + b'\x64\x1e',
    # ACKnowledge reception of the last three frames
    b'\x42\x42' + b'\x05\x00' + b'\xf1\x03' + b'q' + b'\x90\xce',
    )

def test_sedebugmux():
    for f in test_frames:
        # print('[+] Testing frame: %s' % f.hex())
        msg = DebugMuxFrame()
        msg.from_bytes(f)
        v = msg.get_val()
        msg.reautomate()
        assert( msg.get_val() == v )
        assert( msg.to_bytes() == f )

def test_perf_sedebugmux():
    print('[+] decoding and re-encoding SE DebugMux frames')
    Ta = timeit(test_sedebugmux, number=100)
    print('test_sedebugmux: {0:.4f}'.format(Ta))

if __name__ == '__main__':
    test_perf_sedebugmux()
