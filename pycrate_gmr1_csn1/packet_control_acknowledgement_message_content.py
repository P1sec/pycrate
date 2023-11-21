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
# * File Name : pycrate_gmr1_csn1/packet_control_acknowledgement_message_content.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-12
# section: 11.2.2          Packet control acknowledgement
# top-level object: Packet Control Acknowledgement message content

# external references
from pycrate_gmr1_csn1.global_tfi_ie import global_tfi_ie
from pycrate_gmr1_csn1.iu_mode_channel_request_description_ie import iu_mode_channel_request_description_ie
from pycrate_gmr1_csn1.padding_bits import padding_bits

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

receive_to_transmit_frame_offset_struct = CSN1List(name='receive_to_transmit_frame_offset_struct', list=[
  CSN1Bit(name='time_slot_offset', bit=5),
  CSN1Bit(name='symbol_offset', bit=12)])

packet_control_acknowledgement_message_content = CSN1List(name='packet_control_acknowledgement_message_content', list=[
  CSN1Alt(alt={
    '0': ('', [
    CSN1Bit(name='ttli_g_rnti', bit=32)]),
    '10': ('', [
    CSN1Ref(name='global_tfi', obj=global_tfi_ie)])}),
  CSN1Bit(name='ctrl_ack', bit=2),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='sqir', bit=6)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='sqi_standard_deviation', bit=6)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='rb_id', bit=5),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='forward_quality_indicator', bit=6)])})])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='iu_mode_channel_request_description', obj=iu_mode_channel_request_description_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='start_receive_frame_n_to_start_transmit_frame_n7', obj=receive_to_transmit_frame_offset_struct)])}),
  CSN1Ref(obj=padding_bits)])

