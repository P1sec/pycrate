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
# * File Name : pycrate_gmr1_csn1/rlc_hfn_ie.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.3.92        RLC HFN IE
# top-level object: RLC HFN IE



# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

rlc_hfn_ie = CSN1List(name='rlc_hfn_ie', list=[
  CSN1Bit(name='rlc_hfn_length', bit=5),
  CSN1Alt(alt={
    '000': ('', [
    CSN1Bit(name='rlc_hfn', bit=21)]),
    '001': ('', [
    CSN1Bit(name='rlc_hfn', bit=26)]),
    '010': ('', [
    CSN1Bit(name='rlc_hfn', bit=25)]),
    '011': ('', [
    CSN1Bit(name='rlc_hfn', bit=27)]),
    '100': ('', [
    CSN1Bit(name='rlc_hfn', bit=21)]),
    '101': ('', [
    CSN1Bit(name='rlc_hfn', bit=27)]),
    '110': ('', [
    CSN1Bit(name='rlc_hfn', bit=27)])})])

