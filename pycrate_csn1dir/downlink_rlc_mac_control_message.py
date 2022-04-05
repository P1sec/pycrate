# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
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
# * File Name : pycrate_csn1dir/downlink_rlc_mac_control_message.py
# * Created : 2018-11-21
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: TS 44.060 - d60
# section: 11.2.0.1 Downlink RLC/MAC messages
# top-level object: Downlink RLC/MAC control message

# external references
from pycrate_csn1dir.packet_neighbour_cell_data_message_content import packet_neighbour_cell_data_message_content
from pycrate_csn1dir.psi6_message_content import psi6_message_content
from pycrate_csn1dir.psi3_ter_message_content import psi3_ter_message_content
from pycrate_csn1dir.ps_handover_command_message_content import ps_handover_command_message_content
from pycrate_csn1dir.ec_packet_power_control_timing_advance_message_content import ec_packet_power_control_timing_advance_message_content
from pycrate_csn1dir.packet_queueing_notification_message_content import packet_queueing_notification_message_content
from pycrate_csn1dir.ec_packet_access_reject_message_content import ec_packet_access_reject_message_content
from pycrate_csn1dir.dtm_handover_command_message_content import dtm_handover_command_message_content
from pycrate_csn1dir.packet_cs_command_message_content import packet_cs_command_message_content
from pycrate_csn1dir.packet_uplink_ack_nack_message_content import packet_uplink_ack_nack_message_content
from pycrate_csn1dir.psi14_message_content import psi14_message_content
from pycrate_csn1dir.packet_downlink_assignment_message_content import packet_downlink_assignment_message_content
from pycrate_csn1dir.packet_pdch_release_message_content import packet_pdch_release_message_content
from pycrate_csn1dir.psi2_message_content import psi2_message_content
from pycrate_csn1dir.packet_cs_release_message_content import packet_cs_release_message_content
from pycrate_csn1dir.multiple_tbf_timeslot_reconfigure_message_content import multiple_tbf_timeslot_reconfigure_message_content
from pycrate_csn1dir.packet_cell_change_order_message_content import packet_cell_change_order_message_content
from pycrate_csn1dir.psi8_message_content import psi8_message_content
from pycrate_csn1dir.ec_packet_downlink_dummy_control_block_message_content import ec_packet_downlink_dummy_control_block_message_content
from pycrate_csn1dir.packet_tbf_release_message_content import packet_tbf_release_message_content
from pycrate_csn1dir.ec_packet_uplink_ack_nack_message_content import ec_packet_uplink_ack_nack_message_content
from pycrate_csn1dir.multiple_tbf_downlink_assignment_message_content import multiple_tbf_downlink_assignment_message_content
from pycrate_csn1dir.mbms_ms_id_assignment_message_content import mbms_ms_id_assignment_message_content
from pycrate_csn1dir.packet_access_reject_message_content import packet_access_reject_message_content
from pycrate_csn1dir.packet_uplink_assignment_message_content import packet_uplink_assignment_message_content
from pycrate_csn1dir.ec_packet_uplink_ack_nack_and_contention_resolution_message_content import ec_packet_uplink_ack_nack_and_contention_resolution_message_content
from pycrate_csn1dir.packet_cell_change_continue_message_content import packet_cell_change_continue_message_content
from pycrate_csn1dir.psi16_message_content import psi16_message_content
from pycrate_csn1dir.ec_packet_downlink_assignment_message_content import ec_packet_downlink_assignment_message_content
from pycrate_csn1dir.packet_timeslot_reconfigure_message_content import packet_timeslot_reconfigure_message_content
from pycrate_csn1dir.packet_measurement_order_message_content import packet_measurement_order_message_content
from pycrate_csn1dir.packet_downlink_dummy_control_block_message_content import packet_downlink_dummy_control_block_message_content
from pycrate_csn1dir.psi15_message_content import psi15_message_content
from pycrate_csn1dir.packet_power_control_timing_advance_message_content import packet_power_control_timing_advance_message_content
from pycrate_csn1dir.ec_packet_uplink_assignment_message_content import ec_packet_uplink_assignment_message_content
from pycrate_csn1dir.packet_physical_information_message_content import packet_physical_information_message_content
from pycrate_csn1dir.packet_serving_cell_si_message_content import packet_serving_cell_si_message_content
from pycrate_csn1dir.packet_application_information_message_content import packet_application_information_message_content
from pycrate_csn1dir.multiple_tbf_uplink_assignment_message_content import multiple_tbf_uplink_assignment_message_content
from pycrate_csn1dir.mbms_neighbouring_cell_information_message_content import mbms_neighbouring_cell_information_message_content
from pycrate_csn1dir.packet_serving_cell_data_message_content import packet_serving_cell_data_message_content
from pycrate_csn1dir.psi3_quater_message_content import psi3_quater_message_content
from pycrate_csn1dir.packet_mbms_announcement_message_content import packet_mbms_announcement_message_content
from pycrate_csn1dir.mbms_assignment_non_distribution_message_content import mbms_assignment_non_distribution_message_content
from pycrate_csn1dir.packet_dbpsch_assignment_message_content import packet_dbpsch_assignment_message_content
from pycrate_csn1dir.psi3_message_content import psi3_message_content
from pycrate_csn1dir.psi3_bis_message_content import psi3_bis_message_content
from pycrate_csn1dir.packet_prach_parameters_message_content import packet_prach_parameters_message_content
from pycrate_csn1dir.ec_packet_polling_request_message_content import ec_packet_polling_request_message_content
from pycrate_csn1dir.psi1_message_content import psi1_message_content
from pycrate_csn1dir.packet_polling_request_message_content import packet_polling_request_message_content
from pycrate_csn1dir.ec_packet_tbf_release_message_content import ec_packet_tbf_release_message_content
from pycrate_csn1dir.psi5_message_content import psi5_message_content
from pycrate_csn1dir.psi13_message_content import psi13_message_content
from pycrate_csn1dir.mbms_assignment_distribution_message_content import mbms_assignment_distribution_message_content
from pycrate_csn1dir.packet_paging_request_message_content import packet_paging_request_message_content

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

psi7_message_content = CSN1Ref(name='psi7_message_content', obj=psi6_message_content)

default_downlink_message_content = CSN1List(name='default_downlink_message_content', list=[
  CSN1Bit(name='page_mode', bit=2),
  CSN1Bit(bit=-1)])

downlink_rlc_mac_control_message = CSN1Alt(name='downlink_rlc_mac_control_message', alt={
  '000001': ('message_type', [
  CSN1Ref(obj=packet_cell_change_order_message_content)]),
  '000010': ('message_type', [
  CSN1Ref(obj=packet_downlink_assignment_message_content)]),
  '000011': ('message_type', [
  CSN1Ref(obj=packet_measurement_order_message_content)]),
  '000100': ('message_type', [
  CSN1Ref(obj=packet_polling_request_message_content)]),
  '000101': ('message_type', [
  CSN1Ref(obj=packet_power_control_timing_advance_message_content)]),
  '000110': ('message_type', [
  CSN1Ref(obj=packet_queueing_notification_message_content)]),
  '000111': ('message_type', [
  CSN1Ref(obj=packet_timeslot_reconfigure_message_content)]),
  '001000': ('message_type', [
  CSN1Ref(obj=packet_tbf_release_message_content)]),
  '001001': ('message_type', [
  CSN1Ref(obj=packet_uplink_ack_nack_message_content)]),
  '001010': ('message_type', [
  CSN1Ref(obj=packet_uplink_assignment_message_content)]),
  '001011': ('message_type', [
  CSN1Ref(obj=packet_cell_change_continue_message_content)]),
  '001100': ('message_type', [
  CSN1Ref(obj=packet_neighbour_cell_data_message_content)]),
  '001101': ('message_type', [
  CSN1Ref(obj=packet_serving_cell_data_message_content)]),
  '001110': ('message_type', [
  CSN1Ref(obj=packet_dbpsch_assignment_message_content)]),
  '001111': ('message_type', [
  CSN1Ref(obj=multiple_tbf_downlink_assignment_message_content)]),
  '010000': ('message_type', [
  CSN1Ref(obj=multiple_tbf_uplink_assignment_message_content)]),
  '010001': ('message_type', [
  CSN1Ref(obj=multiple_tbf_timeslot_reconfigure_message_content)]),
  '010011': ('message_type', [
  CSN1Ref(obj=mbms_ms_id_assignment_message_content)]),
  '010100': ('message_type', [
  CSN1Ref(obj=mbms_assignment_non_distribution_message_content)]),
  '010101': ('message_type', [
  CSN1Ref(obj=ps_handover_command_message_content)]),
  '010110': ('message_type', [
  CSN1Ref(obj=packet_physical_information_message_content)]),
  '010111': ('message_type', [
  CSN1Ref(obj=dtm_handover_command_message_content)]),
  '100000': ('message_type', [
  CSN1Ref(obj=packet_serving_cell_si_message_content)]),
  '100001': ('message_type', [
  CSN1Ref(obj=packet_access_reject_message_content)]),
  '100010': ('message_type', [
  CSN1Ref(obj=packet_paging_request_message_content)]),
  '100011': ('message_type', [
  CSN1Ref(obj=packet_pdch_release_message_content)]),
  '100100': ('message_type', [
  CSN1Ref(obj=packet_prach_parameters_message_content)]),
  '100101': ('message_type', [
  CSN1Ref(obj=packet_downlink_dummy_control_block_message_content)]),
  '100111': ('message_type', [
  CSN1Ref(obj=packet_cs_command_message_content)]),
  '101000': ('message_type', [
  CSN1Ref(obj=psi16_message_content)]),
  '101001': ('message_type', [
  CSN1Ref(obj=packet_cs_release_message_content)]),
  '101010': ('message_type', [
  CSN1Ref(obj=mbms_assignment_distribution_message_content)]),
  '101011': ('message_type', [
  CSN1Ref(obj=mbms_neighbouring_cell_information_message_content)]),
  '101100': ('message_type', [
  CSN1Ref(obj=packet_mbms_announcement_message_content)]),
  '101101': ('message_type', [
  CSN1Ref(obj=packet_application_information_message_content)]),
  '110000': ('message_type', [
  CSN1Ref(obj=psi6_message_content)]),
  '110001': ('message_type', [
  CSN1Ref(obj=psi1_message_content)]),
  '110010': ('message_type', [
  CSN1Ref(obj=psi2_message_content)]),
  '110011': ('message_type', [
  CSN1Ref(obj=psi3_message_content)]),
  '110100': ('message_type', [
  CSN1Ref(obj=psi3_bis_message_content)]),
  '110110': ('message_type', [
  CSN1Ref(obj=psi5_message_content)]),
  '110111': ('message_type', [
  CSN1Ref(obj=psi13_message_content)]),
  '111000': ('message_type', [
  CSN1Ref(obj=psi7_message_content)]),
  '111001': ('message_type', [
  CSN1Ref(obj=psi8_message_content)]),
  '111010': ('message_type', [
  CSN1Ref(obj=psi14_message_content)]),
  '111100': ('message_type', [
  CSN1Ref(obj=psi3_ter_message_content)]),
  '111101': ('message_type', [
  CSN1Ref(obj=psi3_quater_message_content)]),
  '111110': ('message_type', [
  CSN1Ref(obj=psi15_message_content)])})

default_downlink_message_content_on_ec_pacch = CSN1List(name='default_downlink_message_content_on_ec_pacch', list=[
  CSN1Bit(name='used_dl_coverage_class', bit=2),
  CSN1Bit(bit=-1)])

downlink_rlc_mac_control_message_on_ec_pacch = CSN1Alt(name='downlink_rlc_mac_control_message_on_ec_pacch', alt={
  '00001': ('message_type', [
  CSN1Ref(obj=ec_packet_downlink_assignment_message_content)]),
  '00010': ('message_type', [
  CSN1Ref(obj=ec_packet_polling_request_message_content)]),
  '00011': ('message_type', [
  CSN1Ref(obj=ec_packet_power_control_timing_advance_message_content)]),
  '00100': ('message_type', [
  CSN1Ref(obj=ec_packet_tbf_release_message_content)]),
  '00101': ('message_type', [
  CSN1Ref(obj=ec_packet_uplink_ack_nack_message_content)]),
  '00110': ('message_type', [
  CSN1Ref(obj=ec_packet_uplink_assignment_message_content)]),
  '00111': ('message_type', [
  CSN1Ref(obj=ec_packet_uplink_ack_nack_and_contention_resolution_message_content)]),
  '10001': ('message_type', [
  CSN1Ref(obj=ec_packet_access_reject_message_content)]),
  '10010': ('message_type', [
  CSN1Ref(obj=ec_packet_downlink_dummy_control_block_message_content)])})

