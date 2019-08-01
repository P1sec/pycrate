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
# * File Name : test/test_core.py
# * Created : 2016-02-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from timeit import timeit

from pycrate_core.utils  import *
from pycrate_core.charpy import *
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_core.elt    import _with_json


#------------------------------------------------------------------------------#
# conformance tests
#------------------------------------------------------------------------------#

bitlist_short = [0,1,0,0,1,1,0,1,0,1,1,0,1,0,0,1,1,1,1,1,1,0,0,1,0,1]
bitlist_long = bitlist_short * 100

bytelist_short = [77, 105, 249, 64]
bytelist_long = [77, 105, 249, 83, 90, 126, 84, 214, 159, 149, 53, 167, 229] * 25

bytes_short = b'Mi\xf9@'
bytes_long = b'Mi\xf9SZ~T\xd6\x9f\x955\xa7\xe5' * 25

# 26 bits
uint_short = 20293605
# 2600 bits
uint_long = 144068172919038696276512097660772492871539472382407015869876465346117973057911970042399398218425533172218624644863372571436692496041418634469778212758552880992388450646372196583720720584980192351813404561757801520631663058540451805913846745325868098515675957541509873801444135149683517064350637008564237486313783998184053392258399773414328232975386092659272086583304726444584494491123569825943558672389868600783917725848989607500552823045343609626247762890073771709008501854548284770884832299259140829889597215558554142629816642240805245766651816592114404616954435755090599020648668758566074976546050150705264913206490628811795639084150977381840681190119325913140188535527032391733306078772644591370008924741718786635919877809713538718489435264193826974478599510239850063656952113125

# 25 bits (bitlist_short[1:])
int_short = -13260827
# 2599 bits (bitlist_long[1:])
int_long = -94141136838495215517845299158555608229389097263134918110073512487708955074894041103365127264423945305271577005867478936082614938245678346728964536999279139705104690104363150525528273568565113823493879883233104270361656010638044577581715798516627421116222889091382678657530100032128576943334766421986106825810555303426623663044347347989020152483414048182544735470813676230102874577335838039740732627206077376237159289971299647616474728885750128680310936854166958449904303849320662357392686642026960960570187644354223267688035330320457581804781813075491042019209092270873160554464912166335902815195660914302873769868331964801183580904011140990770911521338170090090258007234942367640219969887034505319340041084444589385151241858497356760758906222992711343281818881774609542275450689563


def test_bitlist():
    
    assert( bytelist_to_bitlist(bytelist_short) == bitlist_short + [0,0,0,0,0,0] )
    assert( bytelist_to_bitlist(bytelist_long) == bitlist_long )
    
    assert( bitlist_to_bytelist(bitlist_short) == bytelist_short )
    assert( bitlist_to_bytelist(bitlist_long) == bytelist_long )
    
    assert( bytes_to_bitlist(bytes_short) == bitlist_short + [0,0,0,0,0,0] )
    assert( bytes_to_bitlist(bytes_long) == bitlist_long )
    
    assert( bitlist_to_bytes(bitlist_short) == bytes_short )
    assert( bitlist_to_bytes(bitlist_long) == bytes_long )


def test_bytes():
    
    assert( bytes_lshift(bytes_short, 5) == b'\xad?(\x00' )
    assert( bytes_lshift(bytes_long, 7) == b'\xb4\xfc\xa9\xad?*kO\xca\x9a\xd3\xf2\xa6'*24 + b'\xb4\xfc\xa9\xad?*kO\xca\x9a\xd3\xf2\x80' )
    
    assert( bytes_zero_last_bits(bytes_long, 2)[-1:] == b'\xe4' )
    assert( bytes_zero_last_bits(bytes_long, 7)[-1:] == b'\x80' )
    
    assert( bytes_to_bytelist(bytes_long) == bytelist_long )
    assert( bytelist_to_bytes(bytelist_long) == bytes_long )


def test_bytelist():
    
    assert( bytelist_lshift(bytelist_short, 4) == [214, 159, 148, 0] )
    assert( bytelist_lshift(bytelist_long, 6) == [90,126,84,214,159,149,53,167,229,77,105,249,83]*24 + [90,126,84,214,159,149,53,167,229,77,105,249,64] )
    
    assert( uint_to_bytelist(uint_short, 26) == bytelist_short )
    assert( uint_to_bytelist(uint_long, 2600) == bytelist_long )
    
    assert( bytelist_to_uint(bytelist_short, 26) == uint_short )
    assert( bytelist_to_uint(bytelist_long, 2600) == uint_long )


def test_int():
    
    assert( bytes_to_uint(bytes_short, 26) == uint_short )
    assert( bytes_to_uint(bytes_long, 2600) == uint_long )
    
    assert( uint_to_bytes(uint_short, 26) == bytes_short )
    assert( uint_to_bytes(uint_long, 2600) == bytes_long )
    
    assert( decompose_uint(13, 20293605) == [7, 6, 12, 6, 8, 2, 4] )


def test_blb():
    blb = bytes_lshift_bnd
    #
    assert( blb(b'\xff', 1, 1) == (1, b'', None) )
    assert( blb(b'\xff', 1, 2) == (2, b'', None) )
    assert( blb(b'\xff', 1, 3) == (4, b'', None) )
    assert( blb(b'\xff', 1, 4) == (8, b'', None) )
    assert( blb(b'\xff', 1, 5) == (16, b'', None) )
    assert( blb(b'\xff', 1, 6) == (32, b'', None) )
    assert( blb(b'\xff', 1, 7) == (64, b'', None) )
    #
    assert( blb(b'\xff', 5, 5) == (31, b'', None) )
    assert( blb(b'\xff', 5, 6) == (62, b'', None) )
    assert( blb(b'\xff', 5, 7) == (124, b'', None) )
    #
    assert( blb(b'\xff', 7, 1) == (1, b'', 252) )
    assert( blb(b'\xff', 7, 2) == (3, b'', 248) )
    assert( blb(b'\xff', 7, 3) == (7, b'', 240) )
    assert( blb(b'\xff', 7, 4) == (15, b'', 224) )
    assert( blb(b'\xff', 7, 5) == (31, b'', 192) )
    assert( blb(b'\xff', 7, 6) == (63, b'', 128) )
    #
    assert( blb(b'\xff\xff', 11, 4) == (15, b'', 254) )
    assert( blb(b'\xff\xff', 11, 5) == (31, b'', 252) )
    assert( blb(b'\xff\xff', 11, 6) == (63, b'', 248) )
    assert( blb(b'\xff\xff', 11, 7) == (127, b'', 240) )
    #
    assert( blb(b'\xff\xff\xff', 17, 1) == (1, b'\xff\xff', None) )
    assert( blb(b'\xff\xff\xff', 18, 2) == (3, b'\xff\xff', None) )
    assert( blb(b'\xff\xff\xff', 19, 3) == (7, b'\xff\xff', None) )
    assert( blb(b'\xff\xff\xff', 20, 4) == (15, b'\xff\xff', None) )
    assert( blb(b'\xff\xff\xff', 21, 5) == (31, b'\xff\xff', None) )
    assert( blb(b'\xff\xff\xff', 22, 6) == (63, b'\xff\xff', None) )
    assert( blb(b'\xff\xff\xff', 23, 7) == (127, b'\xff\xff', None) )
    #
    assert( blb(b'\xff\xff\xff\xff', 31, 1) == (1, b'\xff\xff\xff', 252) )
    assert( blb(b'\xff\xff\xff\xff', 31, 2) == (3, b'\xff\xff\xff', 248) )
    assert( blb(b'\xff\xff\xff\xff', 31, 3) == (7, b'\xff\xff\xff', 240) )
    assert( blb(b'\xff\xff\xff\xff', 31, 4) == (15, b'\xff\xff\xff', 224) )
    assert( blb(b'\xff\xff\xff\xff', 31, 5) == (31, b'\xff\xff\xff', 192) )
    assert( blb(b'\xff\xff\xff\xff', 31, 6) == (63, b'\xff\xff\xff', 128) )
    assert( blb(b'\xff\xff\xff\xff', 31, 7) == (127, b'\xff\xff\xff', None) )
    #
    assert( blb(b'\xff\xff\xff\xff', 25, 1) == (1, b'\xff\xff\xff', None) )
    assert( blb(b'\xff\xff\xff\xff', 25, 2) == (3, b'\xff\xff', 254) )
    assert( blb(b'\xff\xff\xff\xff', 25, 3) == (7, b'\xff\xff', 252) )
    assert( blb(b'\xff\xff\xff\xff', 25, 4) == (15, b'\xff\xff', 248) )
    assert( blb(b'\xff\xff\xff\xff', 25, 5) == (31, b'\xff\xff', 240) )
    assert( blb(b'\xff\xff\xff\xff', 25, 6) == (63, b'\xff\xff', 224) )
    assert( blb(b'\xff\xff\xff\xff', 25, 7) == (127, b'\xff\xff', 192) )


def test_pack():
    
    val0 = [(TYPE_BYTES, b'AAAA', 28),
             (TYPE_UINT, 100, 8),
             (TYPE_INT, -100, 8),
             (TYPE_UINT, 1024, 16),
             (TYPE_BYTES, b'BB', 12)]
    assert( pack_val(*val0) == (b'AAAFI\xc0@\x04$', 72) )
    
    val1 = [(TYPE_BYTES, b'AAAA\xC0', 34),
             (TYPE_UINT, 2500, 32),
             (TYPE_UINT, 10000000000, 64),
             (TYPE_INT, -1, 8),
             (TYPE_BYTES, b'bbbbbb', 48),
             (TYPE_INT, -2000, 54),
             (TYPE_UINT, 1, 2),
             (TYPE_BYTES, b'\0', 7)]
    assert( pack_val(*val1) == ( \
             b'AAAA\xc0\x00\x02q\x00\x00\x00\x00\x95\x02\xf9\x00?\xd8\x98\x98\x98\x98\x98\xbf\xff\xff\xff\xff\xf80@\x00',
             249) )
    
    val2 = [(TYPE_UINT, 1, 1),
             (TYPE_UINT, 0, 2),
             (TYPE_UINT, 2, 3),
             (TYPE_BYTES, b'AA', 15),
             (TYPE_INT, -20, 32),
             (TYPE_UINT, 0, 32),
             (TYPE_UINT, 8196, 32),
             (TYPE_INT, 2500, 64),
             (TYPE_UINT, 1, 2),
             (TYPE_BYTES, b'BBBBB', 40),
             (TYPE_BYTES, b'abcdef', 45),
             (TYPE_INT, -1000000000000000000000, 1024),
             (TYPE_UINT, 123456789123456789123456789, 1536),
             (TYPE_BYTES, 50*b'c', 50*8)]
    assert( pack_val(*val2) == ( \
             b'\x89\x05\x07\xff\xff\xff`\x00\x00\x00\x00\x00\x01\x00 \x00\x00\x00\x00\x00\x00N"\x84\x84\x84\x84\x84\xc2\xc4\xc6\xc8\xca\xcf\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfc\x9c\xa3e#\xa2\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06a\xef\xdf.;\x19\xf7\xc0E\xf1V66666666666666666666666666666666666666666666666660',
             3228) )


def test_charpy():
    
    A = Charpy(b'test')
    assert( A.to_bytes() == b'test' )
    assert( A.to_bitlist() == [0,1,1,1,0,1,0,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,0] )
    assert( A.to_bytelist() == [116, 101, 115, 116] )
    assert( A.to_uint() == 1952805748 )
    assert( A.to_int() == 1952805748 )
    A.forward(1)
    assert( A._cur == 1 )
    assert( A.to_bytes() == b'\xe8\xca\xe6\xe8' )
    assert( A.to_bitlist() == [1,1,1,0,1,0,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,0])
    assert( A.to_bytelist() == [232, 202, 230, 232] )
    assert( A.to_uint() == 1952805748 )
    assert( A.to_int() == -194677900 )
    assert( A[0] == 1 )
    assert( A[1] == 1 )
    assert( A[2] == 1 )
    assert( A[3] == 0 )
    assert( A[0:4] == [1, 1, 1, 0] )
    assert( A[1:5] == [1, 1, 0, 1] )
    assert( A[2:6] == [1, 0, 1, 0] )
    assert( A[3:7] == [0, 1, 0, 0] )
    A.rewind()
    assert( A.to_bytes() == b'test' )
    
    A.set_bitlist(bitlist_short)
    assert( A.to_bytes() == b'Mi\xf9@' )
    assert( A.to_bytelist() == [77, 105, 249, 64] )
    assert( A.to_uint() == 20293605 )
    assert( A.to_int() == 20293605 )
    assert( A.get_bitlist(1) == [0] )
    assert( A.to_int() == int_short )
    assert( A.get_bitlist(1) == [1] )
    assert( A.to_bytes() == b'5\xa7\xe5' )
    assert( A.to_bitlist() == bitlist_short[2:] )
    assert( A.to_bytelist() == [53, 167, 229] )
    assert( A.to_uint() == 3516389 )
    assert( A.to_int() == 3516389 )
    assert( A.get_bytes(3) == b'\x20' )
    assert( A._cur == 5 )
    assert( A.to_bytes() == b'\xad?(' )
    assert( A.to_uint() == 1419237 )
    assert( A.to_int() == -677915 )
    
    A.set_bytes( bytes_long, 2600 )
    assert( A.to_bytes() == bytes_long )
    assert( A.to_bytelist() == bytelist_long )
    assert( A.to_bitlist() == bitlist_long )
    assert( A.to_uint() == uint_long )
    assert( A.get_bytelist(1) == [0] )
    assert( A.to_int() == int_long )
    
    A.rewind()
    B = Charpy()
    for i in range(1, 8):
        A._cur = i
        B.set_bytes( A.to_bytes(), 2600-i )
        assert( B.to_bytes() == A.to_bytes() )
        assert( B.to_bitlist() == A.to_bitlist() )
        assert( B.to_uint() == A.to_uint() )
        assert( B.to_int() == A.to_int() )
    A.rewind()
    B.set_bytes( A.to_bytes() )
    assert( B.get_bitlist(1) == [0] )
    assert( B.to_bytes() == b'\x9a\xd3\xf2\xa6\xb4\xfc\xa9\xad?*kO\xca'*25 )
    assert( B.get_bitlist(1) == [1] )
    assert( B.to_bytes() == b'5\xa7\xe5Mi\xf9SZ~T\xd6\x9f\x95'*24 + b'5\xa7\xe5Mi\xf9SZ~T\xd6\x9f\x94' )
    assert( B.get_bitlist(1) == [0] )
    assert( B.to_bytes() == b'kO\xca\x9a\xd3\xf2\xa6\xb4\xfc\xa9\xad?*'*24 + b'kO\xca\x9a\xd3\xf2\xa6\xb4\xfc\xa9\xad?(' )
    assert( B.get_bitlist(1) == [0] )
    assert( B.to_bytes() == b'\xd6\x9f\x955\xa7\xe5Mi\xf9SZ~T'*24 + b'\xd6\x9f\x955\xa7\xe5Mi\xf9SZ~P' )
    assert( B.get_bitlist(1) == [1] )
    assert( B.to_bytes() == b'\xad?*kO\xca\x9a\xd3\xf2\xa6\xb4\xfc\xa9'*24 + b'\xad?*kO\xca\x9a\xd3\xf2\xa6\xb4\xfc\xa0' )
    assert( B.get_bitlist(1) == [1] )
    assert( B.to_bytes() == b'Z~T\xd6\x9f\x955\xa7\xe5Mi\xf9S'*24 + b'Z~T\xd6\x9f\x955\xa7\xe5Mi\xf9@' )
    assert( B.get_bitlist(1) == [0] )
    assert( B.to_bytes() == b'\xb4\xfc\xa9\xad?*kO\xca\x9a\xd3\xf2\xa6'*24 + b'\xb4\xfc\xa9\xad?*kO\xca\x9a\xd3\xf2\x80' )
    assert( B.get_bitlist(1) == [1] )
    assert( B.to_bytes() == bytes_long[1:] )
    
    A = Charpy(b'gros test')
    assert( A.to_uint_le() == 2148137492520041935463 )
    assert( A.to_int_le() == 2148137492520041935463 )
    A.forward(1)
    assert( A.to_uint_le() == 16630359939467896014 )
    assert( A.to_int_le() == -1816384134241655602 )
    A.set_uint_le(2148137492520041935463, 12*8)
    assert( A.to_bytes() == b'gros test\x00\x00\x00' )
    A.set_int_le(-1816384134241655602, 15*8)
    assert( A.to_bytes() == b'\xce\xe4\xde\xe6@\xe8\xca\xe6\xff\xff\xff\xff\xff\xff\xff' )


def test_elt_1():
    
    class Test(Envelope):
        
        _GEN = (
            Buf('s0', desc='string zero', val=b'abcd', bl=32),
            Uint('u0', desc='uint zero', val=10, bl=20),
            Uint('u1', desc='uint one', val=1024, bl=14),
            Int8('i0', desc='int zero', val=-64),
            Buf('s1', desc='string one', val=b'efghijklmnopqrs', bl=116),
            Uint('f', desc='flag', val=0, bl=1, trans=True)
            )
    
    t = Test('T')
    #return t
    buf = t.to_bytes()
    
    assert( buf == b'abcd\x00\x00\xa1\x000\x19Y\x99\xda\x1aZ\x9a\xdb\x1b[\x9b\xdc\x1c\\\x9c' )
    assert( t.to_uint() == 596964200264834337516354954544542937658015219270340253479 )
    assert( t.to_int() == 596964200264834337516354954544542937658015219270340253479 )
    assert( t.get_bl() == 190 )
    assert( t[0].to_bytes() == b'abcd' )
    assert( t[1].to_bytes() == b'\x00\x00\xa0' )
    assert( t[2].to_bytes() == b'\x10\x00' )
    assert( t[3].to_bytes() == b'\xc0' )
    assert( t[4].to_bytes() == b'efghijklmnopqrp' )
    assert( t[5].to_bytes() == b'' )
    assert( t['s0'].get_val() == b'abcd' )
    assert( t['u0'].get_val() == 10 )
    assert( t['i0'].get_val() == -64 )
    
    if _with_json:
        jv  = t._to_jval()
        jso = t.to_json()
        assert( jv == [{'s0': '61626364'}, {'u0': 10}, {'u1': 1024}, {'i0': -64}, {'s1': '65666768696a6b6c6d6e6f70717273'}] )
    
    t.set_val(None)
    t.from_bytes(buf)
    assert( t[0].to_bytes() == b'abcd' )
    assert( t[1].to_bytes() == b'\x00\x00\xa0' )
    assert( t[2].to_bytes() == b'\x10\x00' )
    assert( t[3].to_bytes() == b'\xc0' )
    assert( t[4].to_bytes() == b'efghijklmnopqrp' )
    assert( t[5].to_bytes() == b'' )
    
    if _with_json:
        t.set_val(None)
        t.from_json(jso)
        assert( t[0].to_bytes() == b'abcd' )
        assert( t[1].to_bytes() == b'\x00\x00\xa0' )
        assert( t[2].to_bytes() == b'\x10\x00' )
        assert( t[3].to_bytes() == b'\xc0' )
        assert( t[4].to_bytes() == b'efghijklmnopqrp' )
        assert( t[5].to_bytes() == b'' )
    
    buf = b'abcd' * 6
    t.set_val(None)
    t.from_bytes(buf)
    
    assert( t[0].get_val() == b'abcd' )
    assert( t[1].get_val() == 398886 )
    assert( t[2].get_val() == 3473 )
    assert( t[3].get_val() == -123 )
    assert( t[4].get_val() == b'\x89\x8d\x91\x85\x89\x8d\x91\x85\x89\x8d\x91\x85\x89\x8d\x90' )
    
    return t


def test_elt_2():
    
    class TestTLV(Envelope):
        
        _GEN = (
            Uint8('T', desc='Tag', rep=REPR_BIN, 
                 dic={0:'Reserved', 1:'Tag1', 2:'Tag2', 5:'Tag5'}),
            Uint('F1', desc='Flag1', val=0, bl=1),
            Uint('F2', desc='Flag2', val=1, bl=2),
            Uint('res', desc='Reserved', val=0, bl=13),
            # length in bytes (including header, excepted Tag)
            Uint8('L', desc='Length'),
            Buf('V', desc='Value', val=b'default value')
            )
    
    #return TestTLV
    t = TestTLV()
    t['T'].set_val(2)
    t['F1'].set_val(1)
    t['F2'].set_val(1)
    t['res'].set_val(0)
    t['L'].set_val(t['V'].get_bl())
    
    if python_version < 3:
        assert( repr(t) == "<TestTLV : <T [Tag] : 0b00000010 (Tag2)><F1 [Flag1] : 1><F2 [Flag2] : 1><res [Reserved] : 0><L [Length] : 104><V [Value] : 'default value'>>" )
    else:
        assert( repr(t) == "<TestTLV : <T [Tag] : 0b00000010 (Tag2)><F1 [Flag1] : 1><F2 [Flag2] : 1><res [Reserved] : 0><L [Length] : 104><V [Value] : b'default value'>>" )
    
    if _with_json:
        jv  = t._to_jval()
        jso = t.to_json()
        assert( jv == [{'T': 2}, {'F1': 1}, {'F2': 1}, {'res': 0}, {'L': 104}, {'V': '64656661756c742076616c7565'}] )
        t.set_val(None)
        t.from_json(jso)
        assert( t._to_jval() == jv )
    
    if python_version < 3:
        assert( repr(t) == "<TestTLV : <T [Tag] : 0b00000010 (Tag2)><F1 [Flag1] : 1><F2 [Flag2] : 1><res [Reserved] : 0><L [Length] : 104><V [Value] : 'default value'>>" )
    else:
        assert( repr(t) == "<TestTLV : <T [Tag] : 0b00000010 (Tag2)><F1 [Flag1] : 1><F2 [Flag2] : 1><res [Reserved] : 0><L [Length] : 104><V [Value] : b'default value'>>" )
    
    
    class TestTLV2(Envelope):
        
        _GEN = (
            Uint8('T', desc='Tag', rep=REPR_BIN, 
                 dic={0:'Reserved', 1:'Tag1', 2:'Tag2', 5:'Tag5'}),
            Uint('F1', desc='Flag1', val=0, bl=1),
            Uint('F2', desc='Flag2', val=1, bl=2),
            Uint('res', desc='Reserved', val=0, bl=13),
            # L: length in bytes of V
            Uint8('L', desc='Length'),
            Buf('V', desc='Value', val=b'default value')
            )
        
        def __init__(self, *args, **kwargs):
            Envelope.__init__(self, *args, **kwargs)
            self['L'].set_valauto(self._L_val)
            self['V'].set_blauto(self._V_bl)
        
        def _L_val(self):
            return self['V'].get_bl()>>3
        
        def _V_bl(self):
            return 8*self['L'].get_val()
    
    #return TestTLV2
    t = TestTLV2(val={'T':1, 'F1':0, 'F2':1, 'res':(2**13)-1, 'V':b'another default value'})
    assert( t.get_bl() == 200 )
    assert( t.to_bytes() == b'\x01?\xff\x15another default value' )
    assert( t['L']() == 21 )
    t.from_bytes(b'abcd'*30)
    assert( t['T']() == 97 )
    assert( t['F1']() == 0 )
    assert( t['F2']() == 3 )
    assert( t['res']() == 611 )
    assert( t['L']() == 100 )
    assert( t['V']() == 25*b'abcd' )
    
    if _with_json:
        jv  = t._to_jval()
        jso = t.to_json()
        assert( jv == [{'T': 97}, {'F1': 0}, {'F2': 3}, {'res': 611}, {'L': 100}, {'V': '61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364'}] )
        t.set_val(None)
        t.from_json(jso)
        assert( t._to_jval() == jv )
        assert( t['T']() == 97 )
        assert( t['F1']() == 0 )
        assert( t['F2']() == 3 )
        assert( t['res']() == 611 )
        assert( t['L']() == 100 )
        assert( t['V']() == 25*b'abcd' )
    
    
    class TestA(Envelope):
        
        _GEN = (
            Uint('T', desc='Tag', bl=6, 
                 dic={0:'Reserved', 1:'Tag1', 2:'Tag2', 5:'Tag5'}),
            Uint('F1', desc='Flag1', val=0, bl=4),
            Uint('F2', desc='Flag2', val=1, bl=2),
            # L: length in bytes of V
            Uint8('L', desc='Length'),
            Buf('V', desc='Value', val=b'default value')
            )
        
        def __init__(self, *args, **kwargs):
            Envelope.__init__(self, *args, **kwargs)
            self['L'].set_valauto(self._L_val)
            self['V'].set_blauto(self._V_bl)
        
        def _L_val(self):
            return self['V'].get_bl()>>3
        
        def _V_bl(self):
            return 8*self['L'].get_val()
    
    #return TestA
    t = TestA()
    
    
    class TestB(Envelope):
        
        _GEN = (
            Uint('T', desc='Tag', bl=6, rep=REPR_RAW, 
                 dic={0:'Reserved', 1:'Tag1', 2:'Tag2', 5:'Tag5'}),
            Uint('F1', desc='Flag1', val=0, bl=4),
            Uint('F2', desc='Flag2', val=1, bl=2),
            # L: length in bits of the 2 following elements
            Uint('L', desc='Length', bl=14),
            TestA(val={'T':1, 'V':b'super mega default value'}),
            TestA(val={'T':2, 'V':b'ultra colored'})
            )
        
        def __init__(self, *args, **kwargs):
            Envelope.__init__(self, *args, **kwargs)
            self[4].inc_hier()
            self[5].inc_hier()
            self['L'].set_valauto(self._len_v)
        
        def _len_v(self):
            return self[4].get_bl() + self[5].get_bl()
    
    #return TestB
    t = TestB()
    
    assert( t.get_bl() == 362 )
    assert( t.to_bytes() == b'\x00\x10T\x01\x04a\xcd\xd5\xc1\x95\xc8\x81\xb5\x95\x9d\x84\x81\x91\x95\x99\x85\xd5\xb1\xd0\x81\xd9\x85\xb1\xd5\x94 C][\x1d\x1c\x98H\x18\xdb\xdb\x1b\xdc\x99Y\x00' )
    t[1].set_bl(6)
    assert( t.to_bytes() == b'\x00\x04\x15\x00A\x18super mega default value\x08\x10\xd7V\xc7G&\x12\x066\xf6\xc6\xf7&V@' )
    t[-1][1].set_bl(8)
    assert( t.to_bytes() == b'\x00\x04\x15@A\x18super mega default value\x08\x01\rultra colored' )
    
    t1 = TestB('another_test_B', val={'T':5, 'F1':3, 'F2':0,
                                      4:{0:2, 4:b'un petit truc'},
                                      5:{'T':1, 'V':b'un gros machin'}})
    t2 = TestB('yet_another_test_B')
    t2.from_bytes( t1.to_bytes() )
    
    assert( t1.to_bytes() == b'\x14\xc0@\x02\x045\xd5\xb8\x81\xc1\x95\xd1\xa5\xd0\x81\xd1\xc9\xd5\x8c\x10C\x9d[\x88\x19\xdc\x9b\xdc\xc8\x1bXX\xda\x1a[\x80' )
    assert( t2.get_val() == [5, 3, 0, 256, [2, 0, 1, 13, b'un petit truc'], [1, 0, 1, 14, b'un gros machin']] )
    
    if _with_json:
        jv1, jso1 = t1._to_jval(), t1.to_json()
        jv2, jso2 = t2._to_jval(), t2.to_json()
        assert( jv1 == [{'T': 5}, {'F1': 3}, {'F2': 0}, {'L': 256},
            {'TestA': [{'T': 2}, {'F1': 0}, {'F2': 1}, {'L': 13}, {'V': '756e2070657469742074727563'}]},
            {'TestA': [{'T': 1}, {'F1': 0}, {'F2': 1}, {'L': 14}, {'V': '756e2067726f73206d616368696e'}]}] )
        assert( jv2 == jv1 )
        t2._from_jval(jv1)
        assert( t2._to_jval() == jv1 )
    
    
    class TestC(Array):
        _GEN = TestB()
    
    #return TestC
    t = TestC('pouet')
    t.set_val({0:{'T':5, 'F1':3, 'F2':0, 4:{'T':2, 'V':b'un petit truc'}, 5:{'T':1, 'V':b'un gros machin'}},
               3:{'T':1, 'F1':1, 'F2':1, 4:{'T':7, 'V':b'un gros truc'}, 5:{'T':3, 'V':b'un petit machin'}}})
    
    assert( t.to_bytes() == b"\x14\xc0@\x02\x045\xd5\xb8\x81\xc1\x95\xd1\xa5\xd0\x81\xd1\xc9\xd5\x8c\x10C\x9d[\x88\x19\xdc\x9b\xdc\xc8\x1bXX\xda\x1a[\x80\x04\x15\x00A\x18super mega default value\x08\x10\xd7V\xc7G&\x12\x066\xf6\xc6\xf7&V@\x01\x05@\x10F\x1c\xdd\\\x19\\\x88\x1bYY\xd8H\x19\x19Y\x98][\x1d\x08\x1d\x98[\x1dYB\x045\xd5\xb1\xd1\xc9\x84\x81\x8d\xbd\xb1\xbd\xc9\x95\x90\x11A\x00\x1c\x10\xc7V\xe2\x06w&\xf72\x07G'V0\xc1\x0fun petit machin" )
    
    t1 = TestC('prout')
    t1.from_bytes( t.to_bytes() )
    assert( t1.to_bytes() == b"\x14\xc0@\x02\x045\xd5\xb8\x81\xc1\x95\xd1\xa5\xd0\x81\xd1\xc9\xd5\x8c\x10C\x9d[\x88\x19\xdc\x9b\xdc\xc8\x1bXX\xda\x1a[\x80\x04\x15\x00A\x18super mega default value\x08\x10\xd7V\xc7G&\x12\x066\xf6\xc6\xf7&V@\x01\x05@\x10F\x1c\xdd\\\x19\\\x88\x1bYY\xd8H\x19\x19Y\x98][\x1d\x08\x1d\x98[\x1dYB\x045\xd5\xb1\xd1\xc9\x84\x81\x8d\xbd\xb1\xbd\xc9\x95\x90\x11A\x00\x1c\x10\xc7V\xe2\x06w&\xf72\x07G'V0\xc1\x0fun petit machin" )
    assert( t.get_val() == t1.get_val() )
    
    if _with_json:
        jv, jso = t._to_jval(), t.to_json()
        jv1, jso1 = t1._to_jval(), t1.to_json()
        assert( jv == jv1 )
        assert( jso[10:] == jso1[10:] )
        t.from_json(jso)
        assert( t._to_jval() == jv )
    
    return t


def test_elt_3():
    
    class TLV8(Envelope):
        _GEN = (
            Uint8('T'),
            Uint8('L'),
            Buf('V', rep=REPR_HEX)
            )
        def __init__(self, *args, **kwargs):
            Envelope.__init__(self, *args, **kwargs)
            self[1].set_valauto(lambda: self[2].get_len())
            self[2].set_blauto(lambda: self[1].get_val()<<3)
            
    class TLV16(Envelope):
        _GEN = (
            Uint16('T'),
            Uint16('L'),
            Buf('V', rep=REPR_HEX)
            )
        def __init__(self, *args, **kwargs):
            Envelope.__init__(self, *args, **kwargs)
            self[1].set_valauto(lambda: self[2].get_len())
            self[2].set_blauto(lambda: self[1].get_val()<<3)
    
    class TLVArray(Envelope):
        _GEN = (
            Uint8('Fmt', val=1),
            Alt('TLVs', GEN={
                1: Array('TLV8Seq', GEN=TLV8()),
                2: Array('TLV16Seq', GEN=TLV16())},
                sel=lambda self: self.get_env()[0].get_val())
            )
    
    t1 = TLVArray(val={'Fmt':1, 'TLVs':[{'T':1, 'V':b'aaa'}, {'T':18, 'V':b'BBBB'}]})
    v1 = [1, [[1, 3, b'aaa'], [18, 4, b'BBBB']]]
    b1 = b'\x01\x01\x03aaa\x12\x04BBBB'
    assert( t1.get_val()  == v1 )
    assert( t1.to_bytes() == b1 )
    
    if _with_json:
        jv1, jso1 = t1._to_jval(), t1.to_json() 
        assert( jv1 == [{'Fmt': 1}, {'TLVs': {'TLV8Seq': [{'TLV8': [{'T': 1}, {'L': 3}, {'V': '616161'}]},
                                                          {'TLV8': [{'T': 18}, {'L': 4}, {'V': '42424242'}]}]}}] )
        t1.set_val(None)
        t1.from_json(jso1)
        assert( t1._to_jval() == jv1 )
    
    t2 = TLVArray()
    #return t1, t2
    t2.from_bytes(b1)
    assert( t2.get_val()  == v1 )
    assert( t2.to_bytes() == b1 )
    
    if _with_json:
        assert( t2._to_jval() == jv1 )
        t2.set_val(None)
        t2.from_json(jso1)
        assert( t2.get_val()  == v1 )
        assert( t2.to_bytes() == b1 )
        assert( t2.to_json() == t1.to_json() )
    
    t3 = TLVArray(val={'Fmt':2, 'TLVs':[{'T':1, 'V':b'aaa'}, {'T':18, 'V':b'BBBB'}]})
    #return t1, t2, t3
    b3 = b'\x02\x00\x01\x00\x03aaa\x00\x12\x00\x04BBBB'
    assert( t3.get_val()[1] == v1[1] )
    assert( t3.to_bytes()   == b3 )
    
    t2.from_bytes(b3)
    assert( t2.get_val()[1] == v1[1] )
    assert( t2.to_bytes()   == b3 )


def test_elt_4():
    
    class LenStr(Envelope):
        _GEN = (
            Uint8('Len'),
            UTF8String('Str')
            )
        def __init__(self, *args, **kwargs):
            Envelope.__init__(self, *args, **kwargs)
            self[0].set_valauto(lambda: self[1].get_len())
            self[1].set_blauto(lambda: 8 * self[0].get_val())
    
    ls  = LenStr(val={'Str': u'über schön!'})
    lsv = [13, u'über schön!']
    lsb = b'\r\xc3\xbcber sch\xc3\xb6n!'
    assert( ls.get_val() == lsv )
    assert( ls.to_bytes() == lsb )
    ls.set_val(None)
    ls.from_bytes(lsb)
    assert( ls.get_val() == lsv )
    ls.reautomate()
    assert( ls.get_val() == lsv )
    
    if _with_json:
        lsj = ls.to_json()
        ls.set_val(None)
        ls.from_json(lsj)
        assert( ls.get_val() == lsv )
        ls.reautomate()
        assert( ls.get_val() == lsv )


#------------------------------------------------------------------------------#
# performance tests
#------------------------------------------------------------------------------#

def test_perf_bytes_uint():
    for i in range(1, 50):
        bytes_to_uint(bytes_long, i*48)
        uint_to_bytes(uint_long, i*44)

def test_perf_bytes_lshift():
    for i in range(1, 50):
        bytes_lshift(bytes_short, i//2)
        bytes_lshift(bytes_long, i)

_pack_val2 = [(TYPE_UINT, 1, 1),
             (TYPE_UINT, 0, 2),
             (TYPE_UINT, 2, 3),
             (TYPE_BYTES, b'AA', 15),
             (TYPE_INT, -20, 32),
             (TYPE_UINT, 0, 32),
             (TYPE_UINT, 8196, 32),
             (TYPE_INT, 2500, 64),
             (TYPE_UINT, 1, 2),
             (TYPE_BYTES, b'BBBBB', 40),
             (TYPE_BYTES, b'abcdef', 45),
             (TYPE_INT, -1000000000000000000000, 1024),
             (TYPE_UINT, 123456789123456789123456789, 1536),
             (TYPE_BYTES, 50*b'c', 50*8),
             (TYPE_INT, -2, 5)]
_pack_val3 = _pack_val2 * 20

def test_perf_pack_short():
    pack_val(*_pack_val2)

def test_perf_pack_long():
    pack_val(*_pack_val3)

def test_perf_charpy_short():
    A = Charpy(bytes_short)
    A.to_bytes()
    A.to_bitlist()
    A.to_bytelist()
    A.to_uint()
    A.to_int()
    A.forward(3)
    A.to_bytes()
    A.to_bitlist()
    A.to_bytelist()
    A.to_uint()
    A.to_int()

def test_perf_charpy_long():
    A = Charpy(bytes_long)
    A.to_bytes()
    A.to_bitlist()
    A.to_bytelist()
    A.to_uint()
    A.to_int()
    A.forward(3)
    A.to_bytes()
    A.to_bitlist()
    A.to_bytelist()
    A.to_uint()
    A.to_int()

def test_perf_core():
    
    print('[+] bytes - uint conversion')
    Ta = timeit(test_perf_bytes_uint, number=10000)
    print('test_perf_bytes_uint: {0:.4f}'.format(Ta))
    
    print('[+] bytes shifting')
    Tb = timeit(test_perf_bytes_lshift, number=2000)
    print('test_perf_bytes_lshift: {0:.4f}'.format(Tb))
    
    print('[+] packing few heterogeneous values')
    Tc = timeit(test_perf_pack_short, number=20000)
    print('test_perf_pack_short: {0:.4f}'.format(Tc))
    
    print('[+] packing many heterogeneous values')
    Td = timeit(test_perf_pack_long, number=1000)
    print('test_perf_pack_long: {0:.4f}'.format(Td))
    
    print('[+] charpy with short bytes')
    Te = timeit(test_perf_charpy_short, number=40000)
    print('test_perf_charpy_short: {0:.4f}'.format(Te))
    
    print('[+] charpy with long bytes')
    Tf = timeit(test_perf_charpy_long, number=5000)
    print('test_perf_charpy_long: {0:.4f}'.format(Tf))
    
    print('[+] elt test 1')
    Tg = timeit(test_elt_1, number=2000)
    print('test_elt_1: {0:.4f}'.format(Tg))
    
    print('[+] elt test 2')
    Th = timeit(test_elt_2, number=200)
    print('test_elt_2: {0:.4f}'.format(Th))
    
    print('[+] elt test 3')
    Ti = timeit(test_elt_3, number=700)
    print('test_elt_3: {0:.4f}'.format(Ti))
    
    print('[+] elt test 4')
    Tj = timeit(test_elt_3, number=500)
    print('test_elt_4: {0:.4f}'.format(Tj))
    
    print('[+] core total time: {0:.4f}'.format(Ta+Tb+Tc+Td+Te+Tf+Tg+Th+Ti+Tj))

if __name__ == '__main__':
    test_perf_core()

