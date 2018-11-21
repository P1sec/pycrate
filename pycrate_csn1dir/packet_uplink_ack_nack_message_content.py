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
# * File Name : pycrate_csn1dir/packet_uplink_ack_nack_message_content.py
# * Created : 2018-11-21
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: TS 44.060 - d60
# section: 11.2.28 Packet Uplink Ack/Nack
# top-level object: Packet Uplink Ack/Nack message content

# external references
from pycrate_csn1dir.padding_bits import padding_bits
from pycrate_csn1dir.egprs_ack_nack_description_ie import egprs_ack_nack_description_ie
from pycrate_csn1dir.power_control_parameters_ie import power_control_parameters_ie
from pycrate_csn1dir.ack_nack_description_ie import ack_nack_description_ie
from pycrate_csn1dir.packet_timing_advance_ie import packet_timing_advance_ie
from pycrate_csn1dir.extension_bits_ie import extension_bits_ie
from pycrate_csn1dir.egprs_modulation_and_coding_scheme_ie import egprs_modulation_and_coding_scheme_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

packet_uplink_ack_nack_message_content = CSN1List(name='packet_uplink_ack_nack_message_content', list=[
  CSN1Bit(name='page_mode', bit=2),
  CSN1List(list=[
    CSN1Val(name='', val='00'),
    CSN1Bit(name='uplink_tfi', bit=5),
    CSN1Alt(alt={
      '0': ('', [
      CSN1List(list=[
        CSN1Bit(name='channel_coding_command', bit=2),
        CSN1Ref(name='ack_nack_description', obj=ack_nack_description_ie),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Bit(name='contention_resolution_tlli', bit=32)])}),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Ref(name='packet_timing_advance', obj=packet_timing_advance_ie)])}),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Ref(name='power_control_parameters', obj=power_control_parameters_ie)])}),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Ref(name='extension_bits', obj=extension_bits_ie)])}),
        CSN1Val(name='', val='0'),
        CSN1Alt(alt={
          '0': ('', [
          CSN1Bit(bit=-1)]),
          '1': ('', [
          CSN1Alt(alt={
            '0': ('', []),
            '1': ('', [
            CSN1Bit(name='packet_extended_timing_advance', bit=2)])}),
          CSN1Bit(name='tbf_est'),
          CSN1Alt(alt={
            '0': ('', [
            CSN1Bit(bit=-1)]),
            '1': ('', [
            CSN1Alt(alt={
              '0': ('', []),
              '1': ('', [
              CSN1Bit(name='contention_resolution_identifier_extension', bit=4)])}),
            CSN1Alt(alt={
              '0': ('', []),
              '1': ('', [
              CSN1Bit(name='rb_id', bit=5)])}),
            CSN1Alt(alt={
              '0': ('', [
              CSN1Bit(bit=-1)]),
              '1': ('', [
              CSN1Alt(alt={
                '0': ('', []),
                '1': ('', [
                CSN1Bit(name='ci_dtr'),
                CSN1Bit(name='tn_pdch_pair_dtr', bit=3),
                CSN1Bit(name='dtr_blks', bit=2)])}),
              CSN1Ref(obj=padding_bits)]),
              None: ('', [])})]),
            None: ('', [])})]),
          None: ('', [])})])]),
      '1': ('', [
      CSN1List(list=[
        CSN1Val(name='', val='00'),
        CSN1List(trunc=True, list=[
          CSN1Ref(name='egprs_channel_coding_command', obj=egprs_modulation_and_coding_scheme_ie),
          CSN1Bit(name='resegment'),
          CSN1Bit(name='pre_emptive_transmission'),
          CSN1Bit(name='prr_retransmission_request'),
          CSN1Bit(name='arac_retransmission_request'),
          CSN1Alt(alt={
            '0': ('', []),
            '1': ('', [
            CSN1Bit(name='contention_resolution_tlli', bit=32)])}),
          CSN1Bit(name='tbf_est'),
          CSN1Alt(alt={
            '0': ('', []),
            '1': ('', [
            CSN1Ref(name='packet_timing_advance', obj=packet_timing_advance_ie)])}),
          CSN1Alt(alt={
            '0': ('', []),
            '1': ('', [
            CSN1Bit(name='packet_extended_timing_advance', bit=2)])}),
          CSN1Alt(alt={
            '0': ('', []),
            '1': ('', [
            CSN1Ref(name='power_control_parameters', obj=power_control_parameters_ie)])}),
          CSN1Alt(alt={
            '0': ('', []),
            '1': ('', [
            CSN1Ref(name='extension_bits', obj=extension_bits_ie)])}),
          CSN1List(list=[
            CSN1Ref(name='egprs_ack_nack_description', obj=egprs_ack_nack_description_ie),
            CSN1Val(name='', val='0')]),
          CSN1Alt(alt={
            '0': ('', [
            CSN1Bit(bit=-1)]),
            '1': ('', [
            CSN1Alt(alt={
              '0': ('', []),
              '1': ('', [
              CSN1Bit(name='contention_resolution_identifier_extension', bit=4)])}),
            CSN1Alt(alt={
              '0': ('', []),
              '1': ('', [
              CSN1Bit(name='rb_id', bit=5)])}),
            CSN1Alt(alt={
              '0': ('', [
              CSN1Bit(bit=-1)]),
              '1': ('', [
              CSN1Bit(name='pdan_coding'),
              CSN1Alt(alt={
                '0': ('', []),
                '1': ('', [
                CSN1Bit(name='tn_pdch_pair_dtr', bit=3),
                CSN1Bit(name='dtr_blks', bit=2)])}),
              CSN1Ref(obj=padding_bits)]),
              None: ('', [])})]),
            None: ('', [])})])])])})])])

