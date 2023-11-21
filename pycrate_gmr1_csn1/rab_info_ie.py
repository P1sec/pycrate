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
# * File Name : pycrate_gmr1_csn1/rab_info_ie.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.3.73        RAB Info
# top-level object: RAB Info IE

# external references
from pycrate_gmr1_csn1.cn_domain_identity_ie import cn_domain_identity_ie
from pycrate_gmr1_csn1.nas_synchronization_info_ie import nas_synchronization_info_ie
from pycrate_gmr1_csn1.upper_layer_bearer_info_ie import upper_layer_bearer_info_ie
from pycrate_gmr1_csn1.re_establishment_timer_ie import re_establishment_timer_ie
from pycrate_gmr1_csn1.rab_info_to_relocate_ie import rab_info_to_relocate_ie
from pycrate_gmr1_csn1.rab_identity_ie import rab_identity_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

rab_info_ie = CSN1List(name='rab_info_ie', list=[
  CSN1Ref(name='rab_identity', obj=rab_identity_ie),
  CSN1Ref(name='cn_domain_identity', obj=cn_domain_identity_ie),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='nas_synchronization_indicator', obj=nas_synchronization_info_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='upper_layer_bearer_info', obj=upper_layer_bearer_info_ie)])}),
  CSN1Ref(name='re_establishment_timer', obj=re_establishment_timer_ie),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='rab_info_to_relocate', obj=rab_info_to_relocate_ie)])})])

