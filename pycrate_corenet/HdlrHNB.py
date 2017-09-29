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
# * File Name : pycrate_corenet/HdlrHNB.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcCNHnbap import *
from .ProcCNRua   import *


class HNBd(SigStack):
    """HNB handler within a CorenetServer instance
    responsible for HNBAP, RUA and non-UE related RANAP signaling
    """
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level
    DEBUG            = ('ERR', 'WNG', 'INF', 'DBG')
    # to log HNBAP / RUA PDU
    TRACE_ASN_HNBAP  = False
    TRACE_ASN_RUA    = False
    TRACE_ASN_RANAP  = False
    # to keep track of all HNBAP / RUA procedures
    TRACK_PROC_HNBAP = True
    TRACK_PROC_RUA   = True
    TRACK_PROC_RANAP = True
    
    # Radio Access Technology remainder
    RAT = RAT_UTRA
    
    # ID: (PLMN, CellID)
    ID = (None, None)
    
    # SCTP socket
    SK   = None
    Addr = None
    
    # Server reference
    Server = None
    
    # All HNBs clients are given the same RNC-ID (uint16)
    RNC_ID = 0x0010
    
    # dict to link context-id -> UEd instance
    # should be the same context-id for HNBAP, IuCS and IuPS
    UE_HNBAP = {}
    UE_IuCS  = {}
    UE_IuPS  = {}
    
    
    def _log(self, logtype, msg):
        """HNBd logging facility
        
        DEBUG logtype: 'ERR', 'WNG', 'INF', 'DBG'
        TRACE logtype: 'TRACE_ASN_[HNBAP|RUA|RANAP]_[UL|DL]'
        """
        if logtype[:3] == 'TRA':
            log('[TRA] [HNB: %s.%s] [%s]\n%s%s%s'\
                % (self.ID[0], self.ID[1], logtype[6:], TRACE_COLOR_START, msg, TRACE_COLOR_END))
        elif logtype in self.DEBUG:
            log('[%s] [HNB: %s.%s] %s' % (logtype, self.ID[0], self.ID[1], msg))
    
    def __init__(self, server, sk):
        self.connect(server, sk)
        #
        # init HNB config dict
        self.Config = {}
        #
        # dict of ongoing RAN procedures (indexed by their procedure code)
        # they are populated only for request / response procedure
        # RUA has no request-response procedure
        # RANAP procedure handled here are non-UE related
        self.ProcHnbap = {}
        self.ProcRanap = {}
        # procedure code of the last procedure emitting a pdu toward the RAN
        self.ProcHnbapLast = None
        self.ProcRuaLast   = None
        self.ProcRanapLast = None
        # list of tracked procedures (requires TRACK_PROC_* = True)
        self._proc = []
        #
        # counter for UE context id
        self._ctx_id = 0
    
    #--------------------------------------------------------------------------#
    # network socket operations
    #--------------------------------------------------------------------------#
    
    def connect(self, server, sk):
        self.Server = server
        self.SK = sk
        self.Addr = sk.getpeername()
    
    def disconnect(self):
        del self.Server, self.SK, self.Addr
    
    def is_connected(self):
        return self.SK is not None
    
    #--------------------------------------------------------------------------#
    # handling of RAN link procedures
    #--------------------------------------------------------------------------#
    
    def process_hnbap_pdu(self, pdu):
        """process a HNBAP PDU sent by the HNB
        and return a list of HNBAP PDU(s) to be sent back to it
        """
        errcause = None
        if pdu[0] == 'initiatingMessage':
            # HNB-initiated procedure, instantiate it
            try:
                Proc = HNBAPProcHnbDispatcher[pdu[1]['procedureCode']](self)
            except:
                self._log('ERR', 'invalid HNBAP PDU, initiatingMessage, code %i'\
                          % pdu[1]['procedureCode'])
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = HNBAPErrorIndGW(self)
                Proc.encode_pdu('ini', Cause=errcause)
            else:
                # store the procedure, if no error ind
                self.ProcHnbap[Proc.Code] = Proc
            if self.TRACK_PROC_HNBAP:
                # keep track of the procedure
                self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu )
            if Proc.Cont['suc'] is not None or errcause is not None:
                # set the last procedure code
                self.ProcHnbapLast = Proc.Code
                # send back any potential response to the HNB
                # Proc.send() will take care to clean-up self.ProcHnbap
                return Proc.send()
            else:
                return []
        #
        else:
            # GW-initiated procedure, transfer the response PDU to it
            try:
                Proc = self.ProcHnbap[pdu[1]['procedureCode']]
            except:
                self._log('ERR', 'invalid HNBAP PDU, %s, code %i'\
                          % (pdu[0], pdu[1]['procedureCode']))
                errcause = ('protocol', 'message-not-compatible-with-receiver-state')
                Proc = HNBAPErrorIndGW(self)
                Proc.encode_pdu('ini', Cause=errcause)
                if self.TRACK_PROC_HNBAP:
                    # keep track of the procedure
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu )
            #
            if errcause is not None:
                # set the last procedure code
                self.ProcHnbapLast = Proc.Code
                # send back error ind to the HNB
                # Proc.send() will take care to clean-up self.ProcHnbap
                return Proc.send()
            else:
                # TODO: check in case some HNBAP would trigger() new HNBAP procedure
                return []
    
    def process_rua_pdu(self, pdu):
        """process a RUA PDU sent by the HNB
        and return a list of RUA PDU(s) to be sent back to it
        """
        # WNG: RUA is a symmetric protocol with initatingMessage-only procedures
        errcause = None
        if pdu[0] != 'initiatingMessage':
            self._log('ERR', 'invalid PDU, %s, code %i' % (pdu[0], pdu[1]['procedureCode']))
            errcause = ('protocol', 'abstract-syntax-error-reject')
            Proc = RUAErrorInd(self)
            Proc.encode_pdu('ini', Cause=errcause)
            self.ProcRuaLast = Proc.Code
        else:
            try:
                Proc = RUAProcDispatcher[pdu[1]['procedureCode']](self)
            except:
                self._log('ERR', 'invalid PDU, initiatingMessage, code %i'\
                          % pdu[1]['procedureCode'])
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = RUAErrorInd(self)
                Proc.encode_pdu('ini', Cause=errcause)
        if self.TRACK_PROC_RUA:
            # keep track of the procedure
            self._proc.append( Proc )
        # process the PDU within the procedure
        Proc.recv( pdu )
        if errcause is not None:
            # set the last procedure code
            self.ProcRuaLast = Proc.Code
            # send back error ind to the HNB
            # Proc.send() will take care to clean-up self.ProcHnbap
            return Proc.send()
        else:
            # potentially create new RUA procedures
            # as outcome of the one received
            snd = []
            for ProcRet in Proc.trigger():
                if self.TRACK_PROC_RUA:
                    # keep track of each procedure
                    self._proc.append( ProcRet )
                snd.extend( ProcRet.send() )
                # set the last procedure code
                self.ProcRuaLast = ProcRet.Code
            return snd
    
    def init_hnbap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated HNBAP procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        if ProcClass.Code in self.ProcHnbap:
            self._log('ERR', 'a HNBAP procedure %s is already ongoing, unable to start a new one'\
                      % ProcClass.__name__)
            return None
        Proc = ProcClass(self)
        # store the procedure
        self.ProcHnbap[Proc.Code] = Proc
        if self.TRACK_PROC_HNBAP:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
    
    def init_rua_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RUA procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        if ProcClass.Code in self.ProcHnbap:
            self._log('ERR', 'a RUA procedure %s is already ongoing, unable to start a new one'\
                      % ProcClass.__name__)
            return None
        Proc = ProcClass(self)
        if self.TRACK_PROC_RUA:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
    
    def start_hnbap_proc(self, ProcClass, **kw):
        """initialize a HNBAP procedure and send its initiatingMessage PDU over Iuh
        """
        Proc = self.init_hnbap_proc(ProcClass, **kw)
        if Proc is None:
            return
        self.ProcHnbapLast = Proc
        for pdu in Proc.send():
            ret = self.Server.send_hnbap_pdu(self, pdu)
    
    def start_rua_proc(self, ProcClass, **kw):
        """initialize a RUA procedure and send its initiatingMessage PDU over Iuh
        """
        Proc = self.init_rua_proc(ProcClass, **kw)
        if Proc is None:
            return
        self.ProcRuaLast = Proc
        for pdu in Proc.send():
            ret = self.Server.send_rua_pdu(self, pdu)
    
    #--------------------------------------------------------------------------#
    # handling of UE signaling procedures
    #--------------------------------------------------------------------------#
    
    def get_new_ctx_id(self):
        ctx_id = self._ctx_id
        self._ctx_id += 1
        if ctx_id >= 16777216:
            self._ctx_id = 0
        return ctx_id
    
    def set_ue_hnbap(self, ued):
        ctx_id = self.get_new_ctx_id()
        ued.set_ran(self, ctx_id)
        self.UE_HNBAP[ctx_id] = ued
    
    def set_ue_iucs(self, ued, ctx_id):
        self.UE_IuCS[ctx_id] = ued
    
    def set_ue_iups(self, ued, ctx_id):
        self.UE_IuPS[ctx_id] = ued
    
    def unset_ue_hnbap(self, ctx_id):
        try:
            del self.UE_HNBAP[ctx_id]
        except:
            self._log('WNG', 'no UE with HNBAP context-id %i to unset' % ctx_id)
    
    def unset_ue_iucs(self, ctx_id):
        try:
            del self.UE_IuCS[ctx_id]
        except:
            self._log('WNG', 'no UE with IuCS context-id %i to unset' % ctx_id)
    
    def unset_ue_iups(self, ctx_id):
        try:
            del self.UE_IuPS[ctx_id]
        except:
            self._log('WNG', 'no UE with IuPS context-id %i to unset' % ctx_id)

