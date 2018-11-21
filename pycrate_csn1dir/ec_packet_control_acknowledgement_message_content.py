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
# * File Name : pycrate_csn1dir/ec_packet_control_acknowledgement_message_content.py
# * Created : 2018-11-21
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: TS 44.060 - d60
# section: 11.2.50 EC Packet Control Acknowledgement
# top-level object: EC Packet Control Acknowledgement message content

# external references
from pycrate_csn1dir.padding_bits import padding_bits

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

ec_packet_control_acknowledgement_message_content = CSN1List(name='ec_packet_control_acknowledgement_message_content', list=[
  CSN1Bit(name='tlli', bit=32),
  CSN1Bit(name='ctrl_ack', bit=2),
  CSN1Bit(name='dl_cc_est', bit=4),
  CSN1Ref(obj=padding_bits)])

ec_packet_control_acknowledgement_11_bit_message = CSN1List(name='ec_packet_control_acknowledgement_11_bit_message', list=[
  CSN1Val(name='message_type', val='1110111'),
  CSN1Bit(name='dl_cc_est', bit=4)])

