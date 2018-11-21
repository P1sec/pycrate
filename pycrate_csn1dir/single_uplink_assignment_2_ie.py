# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
# *
# * Copyright 2018. Benoit Michau. ANSSI. P1sec.
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
# * File Name : pycrate_csn1dir/single_uplink_assignment_2_ie.py
# * Created : 2018-11-21
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: TS 44.060 - d60
# section: 12.48a.3 Single Uplink Assignment 2
# top-level object: Single Uplink Assignment 2 IE

# external references
from pycrate_csn1dir.pulse_format_ie import pulse_format_ie
from pycrate_csn1dir.dynamic_allocation_2_ie import dynamic_allocation_2_ie
from pycrate_csn1dir.egprs_level_ie import egprs_level_ie
from pycrate_csn1dir.egprs_modulation_and_coding_scheme_ie import egprs_modulation_and_coding_scheme_ie
from pycrate_csn1dir.egprs_window_size_ie import egprs_window_size_ie
from pycrate_csn1dir.pdch_pairs_description_ie import pdch_pairs_description_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

single_uplink_assignment_2_ie = CSN1List(name='single_uplink_assignment_2_ie', list=[
  CSN1Ref(name='egprs_channel_coding_command', obj=egprs_modulation_and_coding_scheme_ie),
  CSN1Bit(name='resegment'),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='uplink_egprs_window_size', obj=egprs_window_size_ie)])}),
  CSN1Ref(name='uplink_egprs_level', obj=egprs_level_ie),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='reported_timeslots_c1', bit=8),
      CSN1Alt(alt={
        '0': ('', []),
        '1': ('', [
        CSN1Bit(name='reported_timeslots_c2', bit=8)])}),
      CSN1Bit(name='tsh', bit=2)])})])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='rtti_usf_mode'),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='uplink_assignment_pdch_pairs_description', obj=pdch_pairs_description_ie)])})])}),
  CSN1Ref(name='dynamic_allocation_2', obj=dynamic_allocation_2_ie),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='pfi', bit=7)])}),
  CSN1Bit(name='rlc_mode'),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='npm_transfer_time', bit=5)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='pulse_format', obj=pulse_format_ie)])})])

