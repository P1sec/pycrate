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
# * File Name : pycrate_csn1dir/egprs_channel_quality_report_ie.py
# * Created : 2018-11-21
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: TS 44.060 - d60
# section: 12.5.1 EGPRS Channel Quality Report
# top-level object: EGPRS Channel Quality Report IE

# external references
from pycrate_csn1dir.egprs_timeslot_link_quality_measurements_ie import egprs_timeslot_link_quality_measurements_ie
from pycrate_csn1dir.egprs_bep_link_quality_measurements_ie import egprs_bep_link_quality_measurements_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

egprs_channel_quality_report_ie = CSN1List(name='egprs_channel_quality_report_ie', list=[
  CSN1Ref(name='egprs_bep_link_quality_measurements', obj=egprs_bep_link_quality_measurements_ie),
  CSN1Bit(name='c_value', bit=6),
  CSN1Ref(name='egprs_timeslot_link_quality_measurements', obj=egprs_timeslot_link_quality_measurements_ie)])

