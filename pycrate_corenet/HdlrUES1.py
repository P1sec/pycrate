# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.2
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
    
    # to keep track of all RANAP procedures
    TRACK_PROC = True
    
    # reference to the UEd
    UE  = None
    # reference to the ENBd
    ENB = None
    
    def _log(self, logtype, msg):
        self.UE._log(logtype, '[UES1d:   %3i] %s' % (self.CtxId, msg))
    
    def __init__(self, ued, enbd=None, ctx_id=-1):
        self.UE  = ued
        self.Server = ued.Server
        #
        # dict of ongoing S1AP procedures (indexed by their procedure code)
        self.Proc = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
        #
        # RANAP callback for NAS stacks
        self.S1apTx = None
        #
        # dict of available LTE security contexts, indexed by KSI
        # and current KSI in use
        self.SEC = {}
        self.reset_sec_ctx()
        #
        self.connected = Event()
        if enbd is not None:
            self.set_ran(enbd)
            self.set_ctx(ctx_id)
        else:
            self.unset_ctx()

    def set_ran(self, enbd):
        self.SEC['KSI'] = None
        self.ENB = enbd
        self.connected.set()
    
    def unset_ran(self):
        del self.ENB
        self.SEC['KSI'] = None
        self.connected.clear()
    
    def set_ran_unconnected(self, enbd):
        # required for paging
        self.SEC['KSI'] = None
        self.ENB = enbd
    
    def unset_ran_unconnected(self):
        # required for paging
        del self.ENB
        self.SEC['KSI'] = None
    
    def is_connected(self):
        #return self.RNC is not None
        return self.connected.is_set()
    
    def set_ctx(self, ctx_id):
        self.CtxId = ctx_id
    
    def unset_ctx(self):
        self.CtxId = -1
    
    def reset_sec_ctx(self):
        self.SEC.clear()
        self.SEC['KSI'] = None
