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
# * File Name : pycrate_gmr1_csn1/cell_update_confirm_message_content.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.2.3         CELL UPDATE CONFIRM
# top-level object: CELL UPDATE CONFIRM message content

# external references
from pycrate_gmr1_csn1.rrc_transaction_identifier_ie import rrc_transaction_identifier_ie
from pycrate_gmr1_csn1.ciphering_mode_info_ie import ciphering_mode_info_ie
from pycrate_gmr1_csn1.reference_ie import reference_ie
from pycrate_gmr1_csn1.activation_time_ie import activation_time_ie
from pycrate_gmr1_csn1.rb_ciphering_synchronization_ie import rb_ciphering_synchronization_ie
from pycrate_gmr1_csn1.rrc_state_indicator_ie import rrc_state_indicator_ie
from pycrate_gmr1_csn1.gra_identity_ie import gra_identity_ie
from pycrate_gmr1_csn1.cn_information_info_ie import cn_information_info_ie
from pycrate_gmr1_csn1.rb_information_to_reconfigure_ie import rb_information_to_reconfigure_ie
from pycrate_gmr1_csn1.rb_information_to_release_ie import rb_information_to_release_ie
from pycrate_gmr1_csn1.start_ie import start_ie
from pycrate_gmr1_csn1.physical_channel_configuration_ie import physical_channel_configuration_ie
from pycrate_gmr1_csn1.rb_with_pdcp_information_ie import rb_with_pdcp_information_ie
from pycrate_gmr1_csn1.rb_identity_ie import rb_identity_ie
from pycrate_gmr1_csn1.rrb_identity_ie import rrb_identity_ie
from pycrate_gmr1_csn1.integrity_protection_mode_info_ie import integrity_protection_mode_info_ie
from pycrate_gmr1_csn1.g_rnti_ie import g_rnti_ie
from pycrate_gmr1_csn1.pdcp_context_relocation_info_ie import pdcp_context_relocation_info_ie
from pycrate_gmr1_csn1.integrity_check_info_ie import integrity_check_info_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

downlink_counter_synchronization_info_struct = CSN1List(name='downlink_counter_synchronization_info_struct', list=[
  CSN1Bit(name='rb_with_pdcp_information_list', bit=5),
  CSN1List(num=([0], lambda x: x + 1), list=[
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='rb_with_pdcp_information', obj=rb_with_pdcp_information_ie)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='pdcp_context_relocation_info', obj=pdcp_context_relocation_info_ie)])})])])

network_response_times_struct = CSN1Val(name='network_response_times_struct', val='null')

cell_update_confirm_message_content = CSN1List(name='cell_update_confirm_message_content', list=[
  CSN1Val(name='', val='0'),
  CSN1List(list=[
    CSN1Ref(name='rrc_transaction_identifier', obj=rrc_transaction_identifier_ie),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='activation_time', obj=activation_time_ie)])}),
    CSN1Ref(name='rrc_state_indicator', obj=rrc_state_indicator_ie),
    CSN1Ref(name='request_reference', obj=reference_ie),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='integrity_check_info', obj=integrity_check_info_ie)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='integrity_protection_mode_info', obj=integrity_protection_mode_info_ie)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='ciphering_mode_info', obj=ciphering_mode_info_ie)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='new_g_rnti', obj=g_rnti_ie)])}),
    CSN1Bit(name='rlc_re_establishment_indicator_srb2_4'),
    CSN1Bit(name='rlc_re_establishment_indicator_rb5'),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='cn_information_info', obj=cn_information_info_ie)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='gra_identity', obj=gra_identity_ie)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='rb_information_to_release_list', bit=5),
      CSN1Ref(name='rb_information_to_release', obj=rb_information_to_release_ie, num=([1], lambda x: x + 1))])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='rb_information_to_reconfigure_list', bit=5),
      CSN1List(num=([1], lambda x: x + 1), list=[
        CSN1Ref(name='rb_information_to_reconfigure', obj=rb_information_to_reconfigure_ie),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Bit(name='rb_priority', bit=2)])}),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Ref(name='rrbid_identity', obj=rrb_identity_ie)])}),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Ref(name='physical_information', obj=physical_channel_configuration_ie)])}),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Ref(name='network_response_times', obj=network_response_times_struct)])})])])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='rb_information_for_setup_list', bit=5),
      CSN1List(num=([1], lambda x: x + 1), list=[
        CSN1Ref(name='rb_identity', obj=rb_identity_ie),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Ref(name='rrbid_identity', obj=rrb_identity_ie)])}),
        CSN1Alt(alt={
          '0': ('', []),
          '1': ('', [
          CSN1Bit(name='rb_priority', bit=2)])}),
        CSN1Ref(name='physical_information', obj=physical_channel_configuration_ie)])])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='downlink_counter_synchronization_info', obj=downlink_counter_synchronization_info_struct)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='startn', obj=start_ie)])}),
    CSN1List(num=-1, list=[
      CSN1Val(name='', val='1'),
      CSN1Alt(alt={
        '00': ('', [
        CSN1Bit(name='ciphering_key', bit=128)]),
        '01': ('', [
        CSN1Bit(name='aes_256_ciphering_key', bit=256)])}),
      CSN1Ref(name='rb_ciphering_synchronization', obj=rb_ciphering_synchronization_ie)]),
    CSN1Val(name='', val='0'),
    CSN1Bit(name='security_procedure_pending'),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='release_cause', bit=3, num=('# unresolved: RB Information to Release List', lambda: 0))])})])])

