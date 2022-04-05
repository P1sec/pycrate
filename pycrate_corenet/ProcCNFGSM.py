# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2021. Benoit Michau. P1Sec.
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
# * File Name : pycrate_corenet/ProcCNFGSM.py
# * Created : 2021-04-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'FGSMSigProc',
    ]


from .utils      import *
from .ProcProto  import *
from .ProcCNNgap import *


TESTING = False

#------------------------------------------------------------------------------#
# NAS 5GS Session Management signalling procedure
# TS 24.501, version h21
# Core Network side
#------------------------------------------------------------------------------#

class FGSMSigProc(NASSigProc):
    """5GS Session Management signalling procedure handler
    
    instance attributes:
        - Name : procedure name
        - FGSM : reference to the UEFGSMd instance running this procedure
        - NG   : reference to the UENGd instance connecting the UE
        - Cont : 2-tuple of CN-initiated NAS message(s) and UE-initiated NAS 
                 message(s)
        - Timer: timer in sec. for this procedure
        - Encod: custom NAS message encoders with fixed values
        - Decod: custom NAS message decoders with transform functions
    """
    
    # tacking all exchanged NAS message within the procedure
    TRACK_PDU = True
    
    # potential timer
    Timer        = None
    TimerDefault = 2
    
    if TESTING:
        def __init__(self, encod=None):
            self._prepare(encod)
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            log('[TESTING] [%s] [FGSMSigProc] [%s] %s' % (logtype, self.Name, msg))
    
    else:
        def __init__(self, fgsmd, encod=None, sec=True, ebi=0, FGMMProc=None):
            self._prepare(encod)
            self.FGSM = fgsmd
            self.NG   = fgsmd.NG
            self.UE   = fgsmd.UE
            self._ebi = ebi
            self._FGMMProc = FGMMProc
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            self.FGSM._log(logtype, '[%s [%i]] %s' % (self.Name, self._ebi, msg))
    
    def decode_msg(self, msg, ret):
        NASSigProc.decode_msg(self, msg, ret)
        # add PDUSessionID and PTI into ret
        ret['PDUSessID'] = msg[0][1].get_val()
        ret['PTI'] = msg[0][2].get_val()
    
    def set_msg(self, pd, typ, **kw):
        """prepare a specific encoder dict for a given NAS message
        """
        # select the encoder and duplicate it
        try:
            Encod = self.Encod[(pd, typ)]
        except Exception:
            return
        FGSMHeader = {}
        if 'PDUSessID' in kw:
            FGSMHeader['PDUSessID'] = kw['PDUSessID']
            del kw['PDUSessID']
        if 'PTI' in kw:
            FGSMHeader['PTI'] = kw['PTI']
            del kw['PTI']
        if FGSMHeader:
            kw['FGSMHeader'] = FGSMHeader
        Encod.update(kw)
    
    def output(self):
        self._log('ERR', 'output() not implemented')
        return None
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        self._log('ERR', 'process() not implemented')
        return None
    
    def postprocess(self, Proc=None):
        self._log('ERR', 'postprocess() not implemented')
        self.rm_from_fgsm_stack()
        return None
    
    def abort(self):
        # abort this procedure, and all procedures started within this one
        ProcStack = self.FGSM.Proc[self._ebi]
        ind = ProcStack.index(self)
        if ind >= 0:
            for p in ProcStack[ind+1:]:
                p.abort()
            del ProcStack[ind:]
        self._log('INF', 'aborting')
    
    def rm_from_fgsm_stack(self):
        # remove the procedure from the FGSM stack of procedures
        try:
            ProcStack = self.FGSM.Proc[self._ebi]
            if ProcStack[-1] == self:
                del ProcStack[-1]
        except Exception:
            self._log('WNG', 'FGSM stack corrupted')
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.FGSM, self.Timer, self.TimerDefault)
            self.TimerStart = time()
            self.TimerStop  = self.TimerStart + self.TimerValue
    
    def get_timer(self):
        if self.Timer is None:
            return None
        else:
            return getattr(self.FGSM, self.Timer)
    
    #--------------------------------------------------------------------------#
    # common helpers
    #--------------------------------------------------------------------------#
    # None yet


#------------------------------------------------------------------------------#
# Network-requested 5G SM procedures: TS 24.501, section 6.3
#------------------------------------------------------------------------------#


#------------------------------------------------------------------------------#
# UE-requested 5G SM procedures: TS 24.501, section 6.4
#------------------------------------------------------------------------------#


