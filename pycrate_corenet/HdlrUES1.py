# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2017. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
# *
# *--------------------------------------------------------
# * File Name : pycrate_corenet/HdlrUES1.py
# * Created : 2017-07-11
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import *

class UES1d(SigStack):
    
    # reference to the UEd
    UE  = None
    # reference to the ENBd
    ENB = None
    
    def _log(self, logtype, msg):
        try:
            self.UE._log(logtype, '[UES1: %r] %s' % self.ID, msg)
        except:
            pass
    
    def __init__(self, ued, enbd, ctx_id):
        self.UE  = ued
        self.set_enb(enbd)
        self.set_ctx(ctx_id)
    
    def set_enb(self, enbd):
        self.ENB = enbd
    
    def unset_enb(self):
        del self.ENB
    
    def set_ctx(self, ctx_id):
        self.CtxId = ctx_id
    
    def unset_ctx(self):
        self.CtxId = -1


