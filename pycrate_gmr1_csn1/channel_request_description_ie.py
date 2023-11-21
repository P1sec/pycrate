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
# * File Name : pycrate_gmr1_csn1/channel_request_description_ie.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-12
# section: 12.7          Channel Request Description
# top-level object: channel request description IE



# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

channel_request_description_ie = CSN1List(name='channel_request_description_ie', list=[
  CSN1Bit(name='rid', bit=2),
  CSN1Bit(name='no_of_blocks', bit=6),
  CSN1Bit(name='peak_throughput_class', bit=4),
  CSN1Bit(name='radio_priority', bit=2),
  CSN1Bit(name='rlc_mode'),
  CSN1Bit(name='llc_pdu_type'),
  CSN1Bit(name='spare')])

iu_mode_channel_request_description_ie = CSN1List(name='iu_mode_channel_request_description_ie', list=[
  CSN1Bit(name='rb_id', bit=5),
  CSN1Bit(name='radio_priority', bit=2),
  CSN1Bit(name='rlc_block_count', bit=6),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1SelfRef()])})])

