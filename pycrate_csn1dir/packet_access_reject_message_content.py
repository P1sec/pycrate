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
# * File Name : pycrate_csn1dir/packet_access_reject_message_content.py
# * Created : 2018-11-21
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: TS 44.060 - d60
# section: 11.2.1 Packet Access Reject
# top-level object: Packet Access Reject message content

# external references
from pycrate_csn1dir.global_tfi_ie import global_tfi_ie
from pycrate_csn1dir.padding_bits import padding_bits
from pycrate_csn1dir.packet_request_reference_ie import packet_request_reference_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

iu_mode_reject_struct = CSN1List(name='iu_mode_reject_struct', list=[
  CSN1Bit(name='g_rnti_extension', bit=4),
  CSN1List(num=-1, list=[
    CSN1Val(name='', val='1'),
    CSN1Bit(name='rb_id', bit=5)]),
  CSN1Val(name='', val='0')])

a_gb_mode_reject_struct = CSN1List(name='a_gb_mode_reject_struct', list=[
  CSN1List(num=-1, list=[
    CSN1Val(name='', val='1'),
    CSN1Bit(name='pfi', bit=7)]),
  CSN1Val(name='', val='0')])

reject_struct = CSN1List(name='reject_struct', list=[
  CSN1Alt(alt={
    '0': ('', [
    CSN1Bit(name='tlli_g_rnti', bit=32)]),
    '1': ('', [
    CSN1Alt(alt={
      '0': ('', [
      CSN1Ref(name='packet_request_reference', obj=packet_request_reference_ie)]),
      '1': ('', [
      CSN1Ref(name='global_tfi', obj=global_tfi_ie)])})])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='wait_indication', bit=8),
    CSN1Bit(name='wait__indication_size')])})])

packet_access_reject_message_content = CSN1List(name='packet_access_reject_message_content', trunc=True, list=[
  CSN1Bit(name='page_mode', bit=2),
  CSN1Ref(name='reject', obj=reject_struct),
  CSN1List(list=[
    CSN1List(num=-1, list=[
      CSN1Val(name='', val='1'),
      CSN1Ref(name='additional_reject', obj=reject_struct)]),
    CSN1Val(name='', val='0'),
    CSN1Alt(alt={
      '0': ('', [
      CSN1Bit(bit=-1)]),
      '1': ('', [
      CSN1List(num=-1, list=[
        CSN1Val(name='', val='1'),
        CSN1Ref(name='iu_mode_reject', obj=iu_mode_reject_struct)]),
      CSN1Val(name='', val='0'),
      CSN1Alt(alt={
        '0': ('', [
        CSN1Bit(bit=-1)]),
        '1': ('', [
        CSN1List(num=-1, list=[
          CSN1Val(name='', val='1'),
          CSN1Ref(name='a_gb_mode_reject', obj=a_gb_mode_reject_struct)]),
        CSN1Val(name='', val='0')]),
        None: ('', [])}),
      CSN1Ref(obj=padding_bits)]),
      None: ('', [])})])])

