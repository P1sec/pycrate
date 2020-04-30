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
# * File Name : pycrate_corenet/HdlrHNB.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcCNHnbap import *
from .ProcCNRua   import *
from .ProcCNRanap import *


class HNBd(SigStack):
    """HNB handler within a CorenetServer instance
    responsible for HNBAP, RUA and connection-less RANAP signaling
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
    
    #--------------------------------------------------------------------------#
    # UERegistration policy
    #--------------------------------------------------------------------------#
    # in case an IMSI is not allowed, send the following reject code (HNBAP-IEs.Cause)
    UEREG_NOTALLOWED = ('radioNetwork', 'uE-unauthorised')
    
    
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
        # dict to link context-id -> UEd instance
        # should be the same context-id for HNBAP, IuCS and IuPS
        self.UE_HNBAP = {}
        self.UE_IuCS  = {}
        self.UE_IuPS  = {}
        #
        # dict of ongoing resquest-response CN-initiated RAN procedures 
        # indexed by their procedure code
        # RUA has no request-response procedure
        # RANAP procedure handled here are only non-UE related
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
    # handling of HNBAP procedures
    #--------------------------------------------------------------------------#
    
    def process_hnbap_pdu(self, pdu_rx):
        """process a HNBAP PDU sent by the HNB
        and return a list of HNBAP PDU(s) to be sent back to it
        """
        errcause = None
        if pdu_rx[0] == 'initiatingMessage':
            # HNB-initiated procedure, instantiate it
            try:
                Proc = HNBAPProcHnbDispatcher[pdu_rx[1]['procedureCode']](self)
            except Exception:
                self._log('ERR', 'invalid HNBAP PDU, initiatingMessage, code %i'\
                          % pdu_rx[1]['procedureCode'])
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = self.init_hnbap_proc(HNBAPErrorIndGW, Cause=errcause)
            else:
                if self.TRACK_PROC_HNBAP:
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.Class == 2 and Proc.errcause:
                Err = self.init_hnbap_proc(HNBAPErrorIndGW, Cause=Proc.errcause)
                self.ProcHnbapLast = Err.Code
                return Err.send()
            elif Proc.Class == 1 or errcause:
                self.ProcHnbapLast = Proc.Code
                return Proc.send()
            else:
                # TODO: check in case some HNBAP would trigger() new HNBAP procedure
                return []
        #
        else:
            # GW-initiated procedure, transfer the response PDU to it
            try:
                Proc = self.ProcHnbap[pdu_rx[1]['procedureCode']]
            except Exception:
                self._log('ERR', 'invalid HNBAP PDU, %s, code %i'\
                          % (pdu_rx[0], pdu_rx[1]['procedureCode']))
                errcause = ('protocol', 'message-not-compatible-with-receiver-state')
                Proc = self.init_hnbap_proc(HNBAPErrorIndGW, Cause=errcause)
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.errcause:
                Err = self.init_hnbap_proc(HNBAPErrorIndGW, Cause=Proc.errcause)
                self.ProcHnbapLast = Err.Code
                return Err.send()
            elif errcause:
                self.ProcHnbapLast = Proc.Code
                return Proc.send()
            else:
                # TODO: check in case some HNBAP would trigger() new HNBAP procedure
                return []
    
    def init_hnbap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated HNBAP procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        if ProcClass.Code in self.ProcHnbap:
            self._log('ERR', 'a HNBAP procedure %s is already ongoing'\
                      % ProcClass.__name__)
            return None
        Proc = ProcClass(self)
        if Proc.Code in HNBAPProcGwDispatcher and Proc.Class == 1:
            # store the procedure, which requires a response from the HNB
            self.ProcHnbap[Proc.Code] = Proc
        if self.TRACK_PROC_HNBAP:
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
    
    def start_hnbap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated HNBAP procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and send the PDU to the
        HNB
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_hnbap_proc(ProcClass, **kw)
        if Proc is None:
            return 0
        self.ProcHnbapLast, cnt = Proc.Code, 0
        for pdu in Proc.send():
            if self.Server.send_hnbap_pdu(self, pdu):
                # send_hnbap_pdu() returns the number of bytes sent over the socket
                cnt += 1
        return cnt
    
    #--------------------------------------------------------------------------#
    # handling of RUA procedures
    #--------------------------------------------------------------------------#
    
    def process_rua_pdu(self, pdu_rx):
        """process a RUA PDU sent by the HNB
        and return a list of RUA PDU(s) to be sent back to it
        """
        # WNG: RUA is a symmetric protocol with initatingMessage-only procedures
        errcause = None
        if pdu_rx[0] != 'initiatingMessage':
            self._log('ERR', 'invalid RUA PDU, %s, code %i'\
                      % (pdu_rx[0], pdu_rx[1]['procedureCode']))
            errcause = ('protocol', 'abstract-syntax-error-reject')
            Proc = self.init_rua_proc(RUAErrorInd, Cause=errcause)
        else:
            try:
                Proc = RUAProcDispatcher[pdu_rx[1]['procedureCode']](self)
            except Exception:
                self._log('ERR', 'invalid RUA PDU, initiatingMessage, code %i'\
                          % pdu_rx[1]['procedureCode'])
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = self.init_rua_proc(RUAErrorInd, Cause=errcause)
        if self.TRACK_PROC_RUA:
            self._proc.append( Proc )
        # process the PDU within the procedure
        Proc.recv( pdu_rx )
        if errcause:
            self.ProcRuaLast = Proc.Code
            return Proc.send()
        else:
            # trig new RUA procedures, as outcome of the one received
            pdu_tx = []
            for ProcRet in Proc.trigger():
                pdu_tx.extend( ProcRet.send() )
                self.ProcRuaLast = ProcRet.Code
            return pdu_tx
    
    def init_rua_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RUA procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        Proc = ProcClass(self)
        if self.TRACK_PROC_RUA:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
    
    def start_rua_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RUA procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and send the PDU to the
        HNB
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_rua_proc(ProcClass, **kw)
        self.ProcRuaLast, cnt = Proc.Code, 0
        for pdu in Proc.send():
            if self.Server.send_rua_pdu(self, pdu):
                # send_rua_pdu() returns the number of bytes sent over the socket
                cnt += 1
        return cnt
    
    #--------------------------------------------------------------------------#
    # handling of RANAP procedures
    #--------------------------------------------------------------------------#    
    
    def _encode_ranap_pdu(self, pdus):
        ret = []
        if not asn_ranap_acquire():
            self._log('ERR', 'unable to acquire the RANAP module')
            return ret
        for pdu in pdus:
            try:
                PDU_RANAP.set_val(pdu)
            except Exception as err:
                self._log('ERR', 'unable to set the RANAP pdu value')
                self._errpdu = pdu
            else:
                if self.TRACE_ASN_RANAP:
                    self._log('TRACE_ASN_RANAP_DL', '\n' + PDU_RANAP.to_asn1())
                ret.append( PDU_RANAP.to_aper() )
        asn_ranap_release()
        return ret
    
    def process_ranap(self, buf):
        """process a RANAP PDU buffer sent by the HNB in connection-less transfer
        and return a list of RANAP PDU buffer(s) to be sent back to it
        """
        # decode the RANAP PDU
        if not asn_ranap_acquire():
            self._log('ERR', 'unable to acquire the RANAP module')
            return []
        try:
            PDU_RANAP.from_aper(buf)
        except Exception:
            asn_ranap_release()
            self._log('WNG', 'invalid RANAP PDU transfer-syntax: %s'\
                      % hexlify(buf).decode('ascii'))
            # error cause: protocol, transfer-syntax-error
            Proc = self.init_ranap_proc(RANAPErrorIndConlessCN, Cause=('protocol', 97))
            Proc.recv(buf)
            self.ProcRanapLast = Proc.Code
            return self._encode_ranap_pdu(Proc.send())
        #
        if self.TRACE_ASN_RANAP:
            self._log('TRACE_ASN_RANAP_UL', '\n' + PDU_RANAP.to_asn1())
        pdu_rx = PDU_RANAP()
        asn_ranap_release()
        #
        errcause = None
        if pdu_rx[0] == 'initiatingMessage':
            # RNC-initiated procedure, instantiate it
            try:
                Proc = RANAPConlessProcRncDispatcher[pdu_rx[1]['procedureCode']](self)
            except Exception:
                self._log('ERR', 'invalid connect-less RANAP PDU, initiatingMessage, code %i'\
                          % pdu_rx[1]['procedureCode'])
                # error cause: protocol, abstract-syntax-error-reject
                errcause = ('protocol', 100)
                Proc = self.init_ranap_proc(RANAPErrorIndConlessCN, Cause=errcause)
            else:
                if self.TRACK_PROC_RANAP:
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.Class == 2 and Proc.errcause:
                Err = self.init_ranap_proc(RANAPErrorIndConlessCN, Cause=Proc.errcause)
                self.ProcRanapLast = Err.Code
                return self._encode_ranap_pdu(Err.send())
            elif Proc.Class == 1 or errcause:
                self.ProcRanapLast = Proc.Code
                return self._encode_ranap_pdu(Proc.send())
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcRanapLast = ProcRet.Code
                return self._encode_ranap_pdu(pdu_tx)
        #
        else:
            # CN-initiated procedure, transfer the PDU to it
            try:
                Proc = self.ProcRanap[pdu_rx[1]['procedureCode']]
            except Exception:
                self._log('ERR', 'invalid connect-less RANAP PDU, %s, code %i'\
                          % (pdu_rx[0], pdu_rx[1]['procedureCode']))
                # error cause: protocol, message-not-compatible-with-receiver-state
                errcause = ('protocol', 99)
                Proc = self.init_ranap_proc(RANAPErrorIndConlessCN, Cause=errcause)
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.errcause:
                Err = self.init_ranap_proc(RANAPErrorIndConlessCN, Cause=Proc.errcause)
                self.ProcRanapLast = Err.Code
                return self._encode_ranap_pdu(Err.send())
            elif errcause:
                self.ProcRanapLast = Proc.Code
                return self._encode_ranap_pdu(Proc.send())
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcRanapLast = ProcRet.Code
                return self._encode_ranap_pdu(pdu_tx)
    
    def init_ranap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RANAP connection-less procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        if not issubclass(ProcClass, RANAPConlessSigProc):
            self._log('WNG', 'starting an invalid procedure over a RUA connection-less transfer')
        if ProcClass.Code in self.ProcRanap:
            self._log('ERR', 'a RANAP procedure %s is already ongoing' % ProcClass.__name__)
            return None
        Proc = ProcClass(self)
        if Proc.Code in RANAPConlessProcCnDispacther and Proc.Class == 1:
            # store the procedure, which requires a response from the HNB
            self.ProcRanap[Proc.Code] = Proc
        if self.TRACK_PROC_RANAP:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
        
    def start_ranap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RANAP connection-less procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and send the PDU to the HNB
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_ranap_proc(ProcClass, **kw)
        if Proc is None:
            return 0
        self.ProcRanapLast, cnt = Proc.Code, 0
        for buf in self._encode_ranap_pdu(Proc.send()):
            cnt += self.start_rua_proc(RUAConnectlessTransfer, RANAP_Message=buf)
        return cnt
    
    #--------------------------------------------------------------------------#
    # handling of UE connection-oriented signaling procedures
    #--------------------------------------------------------------------------#
    
    def get_new_ctx_id(self):
        ctx_id = self._ctx_id
        self._ctx_id += 1
        if ctx_id >= 16777216:
            self._ctx_id = 0
        return ctx_id
    
    def set_ue_hnbap(self, ued):
        ctx_id = self.get_new_ctx_id()
        self.UE_HNBAP[ctx_id] = ued
        return ctx_id
    
    def set_ue_iucs(self, ued, ctx_id):
        self.UE_IuCS[ctx_id] = ued
    
    def set_ue_iups(self, ued, ctx_id):
        self.UE_IuPS[ctx_id] = ued
    
    def unset_ue_hnbap(self, ctx_id):
        try:
            del self.UE_HNBAP[ctx_id]
        except Exception:
            self._log('WNG', 'no UE with HNBAP context-id %i to unset' % ctx_id)
    
    def unset_ue_iucs(self, ctx_id):
        try:
            del self.UE_IuCS[ctx_id]
        except Exception:
            self._log('WNG', 'no UE with IuCS context-id %i to unset' % ctx_id)
    
    def unset_ue_iups(self, ctx_id):
        try:
            del self.UE_IuPS[ctx_id]
        except Exception:
            self._log('WNG', 'no UE with IuPS context-id %i to unset' % ctx_id)
    
    #--------------------------------------------------------------------------#
    # CN-initiated RANAP connection-less signaling procedures
    #--------------------------------------------------------------------------#
    
    def send_error_ind(self, cause, **IEs):
        """start a RANAPErrorIndConlessCN with the given RANAP cause
        
        IEs can contain any of the optional or extended IEs
        """
        # send a RANAPErrorInd to the RNC
        IEs['Cause'] = cause
        # send to the RNC in connection-less signaling
        ret = self.start_ranap_proc(RANAPErrorIndConlessCN, **IEs)
        if not ret:
            self._log('ERR', 'send_error_ind: error')
        return True if ret else False
    
    def reset(self, dom, cause=('misc', 115), **IEs):
        """start a RANAPReset toward the RNC after having deleted all UE-related
        Iu resources for the given domain
        
        IEs can contain any of the optional or extended IEs
        """
        # reset all UE connections for the given domain
        if dom in ('ps', 'PS'):
            for ctx_id, ue in self.UE_IuPS.items():
                ue.IuPS.unset_ran()
                ue.IuPS.unset_ctx()
            self.UE_IuPS.clear()
            IEs['CN_DomainIndicator'] = 'ps-domain'
        else:
            for ctx_id, ue in self.UE_IuCS.items():
                ue.IuCS.unset_ran()
                ue.IuCS.unset_ctx()
            self.UE_IuCS.clear()
            IEs['CN_DomainIndicator'] = 'cs-domain'
        # send a RANAPReset to the RNC
        IEs['Cause'] = cause
        # send to the RNC in connection-less signaling
        ret = self.start_ranap_proc(RANAPResetCN, **IEs)
        if not ret:
            self._log('ERR', 'reset: error')
        return True if ret else False
    
    def reset_resource(self, dom, reslist=[], cause=('misc', 115), **IEs):
        """start a RANAPResetResource toward the RNC after having deleted the UE-related
        Iu resources for the given domain with with the given list of context identifiers
        
        IEs can contain any of the optional or extended IEs
        """
        # IE ResetResourceList is a sequence of ProtocolIE-Container
        # which is a sequence of ProtocolIE-Field
        # with {id: 78, crit: reject, val: ResetResourceItem}
        # IE ResetResourceItem is a sequence {IuSignallingConnectionIdentifier (BIT STRING of size 24)}
        RResList = []
        # reset the UE connected for the given domain and context ids
        if dom in ('ps', 'PS'):
            for ctx_id in reslist:
                try:
                    ue = self.UE_IuPS[ctx_id]
                except Exception:
                    pass
                else:
                    ue.IuPS.unset_ran()
                    ue.IuPS.unset_ctx()
                    del self.UE_IuPS[ctx_id]
                    RResList.append({'id': 78, 'criticality': 'reject',
                                     'value': ('ResetResourceItem', {'iuSigConId': (ctx_id, 24)})})
            IEs['CN_DomainIndicator'] = 'ps-domain'
        else:
            for ctx_id in reslist:
                try:
                    ue = self.UE_IuCS[ctx_id]
                except Exception:
                    pass
                else:
                    ue.IuCS.unset_ran()
                    ue.IuCS.unset_ctx()
                    del self.UE_IuCS[ctx_id]
                    RResList.append({'id': 78, 'criticality': 'reject',
                                     'value': ('ResetResourceItem', {'iuSigConId': (ctx_id, 24)})})
            IEs['CN_DomainIndicator'] = 'cs-domain'
        # send a RANAPResetResource to the RNC
        IEs['Cause'] = cause
        IEs['ResetResourceList'] = [RResList]
        # send to the RNC in connection-less signaling
        ret = self.start_ranap_proc(RANAPResetResourceCN, **IEs)
        if not ret:
            self._log('ERR', 'reset: error')
        return True if ret else False
    
    def page(self, **IEs):
        """start a RANAPPaging toward the RNC
        
        IEs should be set by the UE handler stack
        """
        ret = self.start_ranap_proc(RANAPPaging, **IEs)
        if not ret:
            self._log('ERR', 'page: error')
        return True if ret else False

