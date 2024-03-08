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
# * File Name : pycrate_gmr1_csn1/established_rabs_var.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 10.4.5        ESTABLISHED_RABS
# top-level object: ESTABLISHED_RABS VAR

# external references
from pycrate_gmr1_csn1.rb_identity_ie import rb_identity_ie
from pycrate_gmr1_csn1.rab_info_ie import rab_info_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

established_rabs_var = CSN1List(name='established_rabs_var', list=[
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='rab_information_list', bit=4),
    CSN1List(num=([1], lambda x: x + 1), list=[
      CSN1Ref(name='rab_info', obj=rab_info_ie),
      CSN1Bit(name='rb_information_list', bit=3),
      CSN1List(num=([1], lambda x: x + 1), list=[
        CSN1Ref(name='rb_identity', obj=rb_identity_ie),
        CSN1Bit(name='rb_started')])])])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='signalling_rb_information_list', bit=3),
    CSN1Bit(name='signalling_rb_started', num=([1], lambda x: x + 1))])})])
