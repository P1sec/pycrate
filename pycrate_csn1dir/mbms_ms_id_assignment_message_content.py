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
# * File Name : pycrate_csn1dir/mbms_ms_id_assignment_message_content.py
# * Created : 2018-11-21
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: TS 44.060 - d60
# section: 11.2.41 MBMS MS_ID Assignment
# top-level object: MBMS MS_ID Assignment message content

# external references
from pycrate_csn1dir.packet_timing_advance_ie import packet_timing_advance_ie
from pycrate_csn1dir.padding_bits import padding_bits
from pycrate_csn1dir.global_tfi_ie import global_tfi_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

mbms_ms_id_assignment_message_content = CSN1List(name='mbms_ms_id_assignment_message_content', list=[
  CSN1Bit(name='page_mode', bit=2),
  CSN1List(list=[
    CSN1Alt(alt={
      '0': ('', [
      CSN1Ref(name='global_tfi', obj=global_tfi_ie)]),
      '10': ('', [
      CSN1Bit(name='tlli_g_rnti', bit=32)])}),
    CSN1Alt(alt={
      '0': ('', [
      CSN1Bit(name='length_of_mbms_bearer_identity', bit=3),
      CSN1Bit(name='mbms_bearer_identity', bit=([1], lambda x: x)),
      CSN1Bit(name='ms_id', bit=([1], lambda x: -1 * (x + -5))),
      CSN1Ref(name='packet_timing_advance', obj=packet_timing_advance_ie),
      CSN1Alt(alt={
        '0': ('', []),
        '1': ('', [
        CSN1Bit(name='alpha', bit=4),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Bit(name='gamma', bit=5)])})])})]),
      '1': ('', [
      CSN1Bit(name='current_ms_id_expiry_time', bit=16),
      CSN1Alt(alt={
        '0': ('', []),
        '1': ('', [
        CSN1Bit(name='length_indicator_of_ms_id', bit=2),
        CSN1Bit(name='ms_id', bit=([1], lambda x: x + 1))])}),
      CSN1Alt(alt={
        '0': ('', []),
        '1': ('', [
        CSN1Ref(name='packet_timing_advance', obj=packet_timing_advance_ie),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Bit(name='alpha', bit=4),
          CSN1Alt(alt={
            '0': ('', []),
            '1': ('', [
            CSN1Bit(name='gamma', bit=5)])})])})])}),
      CSN1Ref(obj=padding_bits)])})])])

