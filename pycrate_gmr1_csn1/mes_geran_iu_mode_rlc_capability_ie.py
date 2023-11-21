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
# * File Name : pycrate_gmr1_csn1/mes_geran_iu_mode_rlc_capability_ie.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.3.46        MES GERAN Iu mode RLC Capability
# top-level object: MES GERAN Iu mode RLC Capability IE



# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

spare_bit = CSN1Bit(name='spare_bit')
Spare_bit = spare_bit
Spare_Bit = spare_bit

mes_geran_iu_mode_rlc_capability_ie = CSN1List(name='mes_geran_iu_mode_rlc_capability_ie', list=[
  CSN1Bit(name='mes_geran_iu_mode_rlc_capability_length', bit=4),
  CSN1Bit(name='maximum_number_of_rlc_am_entities', bit=3),
  CSN1Bit(name='maximum_number_of_rlc_um_entities', bit=3),
  CSN1Bit(name='maximum_number_of_rlc_t_entities', bit=3),
  CSN1Ref(obj=spare_bit, num=-1)])

