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
# * File Name : pycrate_corenet/ProcCNSMS.py
# * Created : 2017-12-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'CMSMSProcCN',
    'CMSMSProcUE'
    ]

from .utils       import *
from .ProcProto   import *

#------------------------------------------------------------------------------#
# Point-to-point SMS procedure
# TS 24.011, version d40
# Core Network side
#------------------------------------------------------------------------------#

class CMSMSProc(NASSigProc):
    """Connection Management sublayer procedure for point-to-point SMS
    
    instance attributes:
        - Name : procedure name
        - SMS  : reference to the UESMSd instance running this procedure
        - RAN  : reference to the UEIuCSd or UES1d instance connecting the UE
        - Cont : 2-tuple of CN-initiated CP message(s) and UE-initiated CP 
                 message(s)
        - Timer: timer in sec. for this procedure
        - Encod: custom CP message encoders with fixed values
        - Decod: custom CP message decoders with transform functions
    """
    
    # tacking all exchanged NAS message within the procedure
    TRACK_PDU = True
    
    # potential timer
    Timer        = 'TC1star'
    TimerDefault = 2
    
    def __init__(self, smsd, tid=None, cpud=None):
        self._prepare()
        self.SMS = smsd
        self.RAN = smsd.RAN
        self.TID = tid
        if tid is not None:
            self._tif  = tid >> 7
            self._ti   = tid & 0x7f
        self._cpud = cpud
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.SMS._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def abort(self):
        self.rm_from_sms_stack()
        self._log('INF', 'aborting')
    
    def rm_from_sms_stack(self):
        try:
            del self.SMS.Proc[self.TID]
        except Exception:
            pass
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.SMS, self.Timer, self.TimerDefault)
            self.TimerStart = time()
            self.TimerStop  = self.TimerStart + self.TimerValue
    
    def get_timer(self):
        if self.Timer is None:
            return None
        else:
            return getattr(self.SMS, self.Timer)


class CMSMSProcCN(CMSMSProc):
    """Core network initiated CP data transmission
    """
    Cont = (
        (TS24011_PPSMS.CP_DATA, ),
        (TS24011_PPSMS.CP_ACK, TS24011_PPSMS.CP_ERROR)
        )
    
    def output(self):
        self.set_msg(9, 1, CPHeader={'TIPD': {'TIFlag': self._tif, 'TI': self._ti}})
        self.encode_msg(9, 1)
        if isinstance(self._cpud, bytes_types):
            self._nas_tx[1][1].set_val(self._cpud)
        elif isinstance(self._cpud, NAS.SMS_RP):
            self._nas_tx.set_rp(self._cpud)
        else:
            self._log('WNG', 'no user data provided')
        if self.SMS.UE.TRACE_NAS_SMS:
            self.SMS.RAN._log('TRACE_NAS_SMS_DL', '\n' + self._nas_tx.show())
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.init_timer()
        return [self._nas_tx]
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self._nas_rx = pdu
        if pdu._name == 'CP_ERROR':
            self._log('INF', 'error cause, %r' % pdu[1])
            # check if it correspond to a DL RP-DATA
            if isinstance(self._cpud, NAS.SMS_RP):
                self.SMS.SMSd.discard_rp(self._cpud, self.SMS.UE.MSISDN)
        else:
            self._log('DBG', 'ack')
        self.rm_from_sms_stack()
        return []
    
    def abort(self):
        CMSMSProc.abort(self)
        if isinstance(self._cpud, NAS.SMS_RP):
            self.SMS.SMSd.discard_rp(self._cpud, self.SMS.UE.MSISDN)


class CMSMSProcUE(CMSMSProc):
    """UE initiated CP data transmission
    """
    Cont = (
        (TS24011_PPSMS.CP_ACK, TS24011_PPSMS.CP_ERROR),
        (TS24011_PPSMS.CP_DATA, )
        )
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self._nas_rx, tipd = pdu, pdu[0][0]
        self._tif, self._ti = tipd[0].get_val(), tipd['TI'].get_val()
        if self._tif:
            self.TID = self._ti
        else:
            self.TID = 128 + self._ti
        #
        errcause = None
        if self.TID in self.SMS.Proc:
            # invalid transaction ID
            errcause = 81
        elif not isinstance(pdu[1][1], NAS.SMS_RP):
            # missing / invalid mandatory IE
            errcause = 96
        if errcause:
            # CP ERROR
            self.set_msg(9, 16, CPHeader={'TIPD': {'TIFlag': (1, 0)[self._tif], 'TI': self._ti}},
                                CPCause=errcause)
            self.encode_msg(9, 16)
            if self.SMS.UE.TRACE_NAS_SMS:
                self.SMS.RAN._log('TRACE_NAS_SMS_DL', '\n' + self._nas_tx.show())
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            return [self._nas_tx]
        else:
            ret = []
            # CP ACK
            self.SMS.Proc[self.TID] = self
            self.set_msg(9, 4, CPHeader={'TIPD': {'TIFlag': (1, 0)[self._tif], 'TI': self._ti}})
            self.encode_msg(9, 4)
            if self.SMS.UE.TRACE_NAS_SMS:
                self.SMS.RAN._log('TRACE_NAS_SMS_DL', '\n' + self._nas_tx.show())
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            self.rm_from_sms_stack()
            #
            # get the RP response within a new transaction with same TID
            RPTx = self.SMS.SMSd.process_rp(pdu[1][1], self.SMS.UE.MSISDN)
            if RPTx:
                # RP-ACK / RP-ERROR
                CPProc = self.SMS.init_cpdata(RPTx, self.TID)
                if CPProc:
                    SMSTx = CPProc.output()[0]
                    return [self._nas_tx, SMSTx]
            return [self._nas_tx]


CMSMSProcCN.init(filter_init=1)
CMSMSProcUE.init(filter_init=1)

