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
# * File Name : pycrate_gmr1_csn1/rrc_status_message_content.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.2.43          RRC STATUS
# top-level object: RRC STATUS message content

# external references
from pycrate_gmr1_csn1.rrc_transaction_identifier_ie import rrc_transaction_identifier_ie
from pycrate_gmr1_csn1.protocol_error_information_ie import protocol_error_information_ie
from pycrate_gmr1_csn1.integrity_check_info_ie import integrity_check_info_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

identification_of_received_message_struct = CSN1List(name='identification_of_received_message_struct', list=[
  CSN1Bit(name='received_message_type', bit=8),
  CSN1Ref(name='rrc_transaction_identifier', obj=rrc_transaction_identifier_ie)])

rrc_status_message_content = CSN1List(name='rrc_status_message_content', list=[
  CSN1Ref(name='protocol_error_information', obj=protocol_error_information_ie),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='integrity_check_info', obj=integrity_check_info_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='identification_of_received_message', obj=identification_of_received_message_struct)])})])

