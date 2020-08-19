# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS24519_TSNAF.py
# * Created : 2020-08-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.519:
# Time-Sensitive Networking (TSN) Application Function (AF) to Device-Side TSN Translator (DS-TT) 
# and Network-Side TSN Translator (NW-TT) protocol aspects
# release 16 (g10)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007       import *


#------------------------------------------------------------------------------#
# Information elements coding
# TS 24.519, section 9
#------------------------------------------------------------------------------#
# TODO


#------------------------------------------------------------------------------#
# Message functional definition and contents
# TS 24.519, section 8
#------------------------------------------------------------------------------#
# TODO


#------------------------------------------------------------------------------#
# 5G TSN-AF dispatcher
#------------------------------------------------------------------------------#

FGTSNAFTypeClasses = {
    
    }

def get_5gtsnaf_msg_instances():
    return {k: FGTSNAFTypeClasses[k]() for k in FGTSNAFTypeClasses}

