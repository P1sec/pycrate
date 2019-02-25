# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate 
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
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
# * File Name : pycrate_core/repr.py
# * Created : 2016-03-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
#

import sys
if sys.version_info[0] < 3:
    import __builtin__ as builtins
else:
    import builtins

from .elt    import Element
from .charpy import Charpy


def show(obj):
    if isinstance(obj, Element):
        print(obj.show())
    elif hasattr(obj, 'show') and callable(obj.show):
        print(obj.show())
    else:
        print(repr(obj))

def bin(obj):
    if isinstance(obj, Element):
        return obj.bin()
    elif hasattr(obj, '__bin__') and callable(obj.__bin__):
        return obj.__bin__()
    else:
        # will certainly raise
        return builtins.bin(obj)

def hex(obj):
    if isinstance(obj, Element):
        return obj.hex()
    elif hasattr(obj, '__hex__') and callable(obj.__hex__):
        return obj.__hex__()
    else:
        # will certainly raise
        return builtins.hex(obj)
