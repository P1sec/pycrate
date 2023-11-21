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
# * File Name : pycrate_gmr1_csn1/packet_channel_request_type_2_message_content.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-12
# section: 11.2.5a Packet Channel Request Type 2 (Iu mode only)
# top-level object: Packet Channel Request Type 2 Message Content



# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

rb_request_struct_ie = CSN1List(name='rb_request_struct_ie', list=[
  CSN1Bit(name='rb_id', bit=5),
  CSN1Bit(name='rlc_block_count', bit=6)])

packet_channel_request_type_2_message_content = CSN1Alt(name='packet_channel_request_type_2_message_content', alt={
  '0': ('rrc_cell_update', [
  CSN1List(list=[
    CSN1Bit(name='rid', bit=2),
    CSN1Bit(name='s_rnti', bit=20),
    CSN1Bit(name='cell_update_cause', bit=3),
    CSN1Ref(name='rb_info', obj=rb_request_struct_ie),
    CSN1Bit(name='spare', bit=3)])]),
  '1000': ('handover_access', [
  CSN1List(list=[
    CSN1Bit(name='rid', bit=2),
    CSN1Bit(name='handover_reference', bit=8),
    CSN1Ref(name='rb_info', obj=rb_request_struct_ie),
    CSN1Bit(name='spare', bit=15)])]),
  '1001': ('periodic_gra_update_procedure', [
  CSN1List(list=[
    CSN1Bit(name='rid', bit=2),
    CSN1Bit(name='s_rnti', bit=20),
    CSN1Bit(name='spare', bit=14)])]),
  '1010': ('initial_correction', [
  CSN1List(list=[
    CSN1Bit(name='rid', bit=2),
    CSN1Bit(name='s_rnti', bit=20),
    CSN1Bit(name='tfi', bit=8),
    CSN1Bit(name='spare', bit=6)])]),
  '1011': ('uplink_resource_request', [
  CSN1List(list=[
    CSN1Bit(name='rid', bit=2),
    CSN1Bit(name='s_rnti', bit=20),
    CSN1Ref(name='rb_info', obj=rb_request_struct_ie),
    CSN1Bit(name='spare', bit=3)])]),
  '1100': ('user_data_transfer_application_type_1', [
  CSN1List(list=[
    CSN1Bit(name='rid', bit=2),
    CSN1Bit(name='s_rnti', bit=20),
    CSN1Bit(name='rb_id', bit=5),
    CSN1Bit(name='user_data', bit=8),
    CSN1Bit(name='spare_bits')])]),
  '1101': ('talk_burst_request', [
  CSN1List(list=[
    CSN1Bit(name='reference_id', bit=2),
    CSN1Bit(name='retransmission'),
    CSN1Bit(name='s_rnti', bit=20),
    CSN1Bit(name='rb_id', bit=5),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='request_priority', bit=2)])}),
    CSN1Bit(name='spare_bits', bit=6)])])})

