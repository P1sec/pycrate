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
# * File Name : pycrate_corenet/HdlrUESMS.py
# * Created : 2017-12-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import *


class UESMSd(SigStack):
    """UE SMS handler within a UEIuCSd or UES1d instance
    responsible for point-to-point Short Message Service procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE  = None
    # reference to the UEIuCSd / UES1d
    RAN = None
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    
    def _log(self, logtype, msg):
        self.RAN._log(logtype, '[SMS] %s' % msg)
    
    def __init__(self, ued, rand):
        self.UE = ued
        self.set_ran(rand)
        #
        # dict of ongoing SMS procedures (indexed by transaction identifier)
        self.Proc  = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_ran(self, rand):
        self.RAN = rand
    
    def process(self, SMSRx):
        """process a SMS-CP message (SMSRx) sent by the UE,
        and return a list (potentially empty) of SMS-CP messages back to the UE
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        # returns SMS CP ERROR, cause network failure
        return [Buf('SMS_CP_ERR', val=b'\x09\x0F\x11', bl=24)]
    
    def init_proc(self, ProcClass, encod=None):
        """initialize a CN-initiated SMS procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        assert() 
    
    def clear(self):
        """abort all running procedures
        """
        pass

