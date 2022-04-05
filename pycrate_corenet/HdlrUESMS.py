# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_corenet/HdlrUESMS.py
# * Created : 2017-12-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils     import *
from .ProcProto import *
from .ProcCNSMS import *


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
    
    # CP ack / err timer
    TC1star = 2
    
    # maximum Transaction Identifier value
    #   0x7f correspond to using the extended TI structure
    #   otherwise set it to 0x06 to always use the basic TI structure
    TI_MAX_VAL = 0x7f
    
    
    def _log(self, logtype, msg):
        self.RAN._log(logtype, '[SMS] %s' % msg)
    
    def __init__(self, ued, rand):
        self.UE   = ued
        self.SMSd = ued.Server.SMSd
        self.set_ran(rand)
        #
        # dict of ongoing SMS procedures indexed transaction identifier:
        # 0..127 : network-initiated, 128..255: UE-initiated
        self.Proc  = {}
        # next TID to be used
        self._tid  = 0
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_ran(self, rand):
        self.RAN  = rand
    
    def process(self, SMSRx):
        """process a SMS-CP message (SMSRx) sent by the UE,
        and return a list (potentially empty) of SMS-CP messages back to the UE
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(SMSRx)
        #
        if self.UE.TRACE_NAS_SMS:
            self.RAN._log('TRACE_NAS_SMS_UL', '\n' + SMSRx.show())
        #
        if SMSRx._name == 'CP_DATA':
            # new transaction
            CPProc = CMSMSProcUE(self)
            if self.TRACK_PROC:
                self._proc.append(CPProc)
            return CPProc.process(SMSRx)
        else:
            # completing transaction
            tipd = SMSRx[0][0]
            tif, ti = tipd[0].get_val(), tipd['TI'].get_val()
            if tif:
                # ti established by the CN
                tid = ti
            else:
                # ti established by the UE
                tid = 0x80 + ti
            if tid not in self.Proc:
                # error
                CPErr = NAS.CP_ERROR(val=[{'TIPD': {'TIFlag': (1, 0)[tif],
                                                    'TI'    : ti}},
                                          81])
                if self.UE.TRACE_NAS_SMS:
                    self._log('TRACE_NAS_SMS_DL', '\n' + CPErr.show())
                return [CPErr]
            else:
                CPProc = self.Proc[tid]
                return CPProc.process(SMSRx)
    
    def init_cpdata(self, cpud, tid=None):
        """initialize a CN-initiated SMS procedure with `cpud' as CP user data 
        and return the procedure
        """
        if tid is None:
            #TIFlag = 0
            tid = self._get_new_tid()
            if tid is None:
                # no transaction id available
                self._log('WNG', 'no TID available for starting a new procedure')
                return None
        elif tid in self.Proc:
            self._log('WNG', 'TID %i not available for starting a new procedure' % tid)
            return None
        CPProc = CMSMSProcCN(self, tid, cpud)
        self.Proc[tid] = CPProc
        if self.TRACK_PROC:
            self._proc.append( CPProc )
        return CPProc
    
    def clear(self, tid=None):
        """abort all running procedures, eventually for a single transaction ID
        """
        if tid is None:
            for tid, Proc in self.Proc.items():
                Proc.abort()
        elif tid in self.Proc:
            self.Proc[tid].abort()
    
    def _get_new_tid(self):
        tid, step = self._tid, 0
        while tid in self.Proc:
            tid  += 1
            step += 1
            if step == self.TI_MAX_VAL:
                # no TID available
                return None
            if tid > self.TI_MAX_VAL:
                tid = 0
        if tid == self.TI_MAX_VAL:
            self._tid = 0
        else:
            self._tid = 1 + tid
        return tid

