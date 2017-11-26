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
    
    # dict to link context-id -> UEd instance
    # should be the same context-id for HNBAP, IuCS and IuPS
    UE_HNBAP = {}
    UE_IuCS  = {}
    UE_IuPS  = {}
    
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
    
    def process_ranap(self, buf):
        """process a RANAP PDU buffer sent by the HNB in connection-less transfer
        and return a list of RANAP PDU(s) to be sent back to it
        """
        # decode the RANAP PDU
        if not asn_ranap_acquire():
            self._log('ERR', 'unable to acquire the RANAP module')
            return []
        try:
            PDU_RANAP.from_aper(buf)
        except:
            # unable to decode APER-encoded buffer
            self._log('WNG', 'invalid RANAP PDU transfer-syntax: %s'\
                      % hexlify(buf).decode('ascii'))
            # returns a RANAP error ind: protocol, transfer-syntax-error
            Proc = self.init_ranap_proc(RANAPErrorIndConlessCN, Cause=('protocol', 97))
            Proc.recv(buf)
            self.ProcRanapLast = Proc.Code
            return self._encode_pdu(Proc.send())
        #
        if self.TRACE_ASN_RANAP:
            self._log('TRACE_ASN_RANAP_UL', '\n' + PDU_RANAP.to_asn1())
        pdu = PDU_RANAP()
        asn_ranap_release()
        errcause = None
        #
        if pdu[0] == 'initiatingMessage':
            # RNC-initiated procedure, create it through the dispatcher
            try:
                Proc = RANAPConlessProcRncDispatcher[pdu[1]['procedureCode']](self)
            except:
                self._log('ERR', 'invalid connect-less RANAP PDU, initiatingMessage, code %i'\
                          % pdu[1]['procedureCode'])
                # returns a RANAP error ind: protocol, abstract-syntax-error-reject
                errcause = ('protocol', 100)
                Proc = self.init_ranap_proc(RANAPErrorIndConlessCN, Cause=errcause)
            else:
                # store the procedure, if no error ind
                self.ProcRanap[Proc.Code] = Proc
                if self.TRACK_PROC_RANAP:
                    # keep track of the procedure
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu )
            #
            if Proc.Cont['suc'] is not None or errcause is not None:
                # set the last procedure code
                self.ProcRanapLast = Proc.Code
                # send back any potential response to the RNC
                # Proc.send() will take care to clean-up self.Proc
                return self._encode_pdu(Proc.send())
            else:
                # potentially create new RANAP procedures, 
                # as outcome of the one received
                snd = []
                for ProcRet in Proc.trigger():
                    # all those procedures must have been initiated with self.init_ranap_proc()
                    # hence, they are already set in self.ProcRanap
                    # and tracked in self._proc
                    snd.extend( ProcRet.send() )
                    # set the last procedure code
                    self.ProcRanapLast = ProcRet.Code
                return self._encode_pdu(snd)
        #
        else:
            # CN-initiated procedure, already existing in self.ProcRanap
            # transfer the PDU to it
            try:
                Proc = self.ProcRanap[pdu[1]['procedureCode']]
            except:
                self._log('ERR', 'invalid RANAP PDU, %s, code %i' % (pdu[0], pdu[1]['procedureCode']))
                # returns a RANAP error ind: protocol, message-not-compatible-with-receiver-state
                errcause = ('protocol', 99)
                Proc = self.init_ranap_proc(RANAPErrorIndConlessCN, Cause=errcause)
            # process the PDU within the procedure
            Proc.recv( pdu )
            #
            if errcause is not None:
                # set the last procedure code
                self.ProcRanapLast = Proc.Code
                # send back any potential response to the RNC
                # Proc.send() will take care to clean-up self.Proc
                return self._encode_pdu(Proc.send())
            else:
                # potentially create new RANAP procedures, as outcome of the one received
                snd = []
                for ProcRet in Proc.trigger():
                    # all those procedures must have been initiated with self.init_ranap_proc()
                    # hence, they are already set in self.Proc
                    # and tracked in self._proc
                    snd.extend( ProcRet.send() )
                    # set the last procedure code
                    self.ProcRanapLast = ProcRet.Code
                return self._encode_pdu(snd)
    
    def _encode_pdu(self, pdus):
        ret, cnt = [], 0
        if not asn_ranap_acquire():
            self._log('ERR', 'unable to acquire the RANAP module')
            return cnt
        for pdu in pdus:
            try:
                PDU_RANAP.set_val(pdu)
            except Exception as err:
                self._log('ERR', 'unable to set the RANAP pdu value')
                self._errpdu = pdu
            else:
                self._log('TRACE_ASN_RANAP_DL', '\n' + PDU_RANAP.to_asn1())
                ret.append( PDU_RANAP.to_aper() )
        asn_ranap_release()
        return ret
    
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
    
    def init_ranap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RANAP connection-less procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        if not issubclass(ProcClass, RANAPConlessSigProc):
            self._log('WNG', 'starting a connection-oriented RANAP procedure '\
                             'over a RUA connection-less transfer')
        if ProcClass.Code in self.ProcRanap:
            self._log('ERR', 'a RANAP procedure %s is already ongoing, unable to start a new one'\
                      % ProcClass.__name__)
            return None
        Proc = ProcClass(self)
        # store the procedure
        self.ProcRanap[Proc.Code] = Proc
        if self.TRACK_PROC_RANAP:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
    
    def start_hnbap_proc(self, ProcClass, **kw):
        """initialize a HNBAP procedure and send its initiatingMessage PDU over Iuh
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_hnbap_proc(ProcClass, **kw)
        if Proc is None:
            return 0
        self.ProcHnbapLast, cnt = Proc, 0
        for pdu in Proc.send():
            if self.Server.send_hnbap_pdu(self, pdu):
                # send_hnbap_pdu() returns the number of bytes sent over the socket
                cnt += 1
        return cnt
    
    def start_rua_proc(self, ProcClass, **kw):
        """initialize a RUA procedure and send its initiatingMessage PDU over Iuh
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_rua_proc(ProcClass, **kw)
        if Proc is None:
            return 0
        self.ProcRuaLast, cnt = Proc, 0
        for pdu in Proc.send():
            if self.Server.send_rua_pdu(self, pdu):
                # send_rua_pdu() returns the number of bytes sent over the socket
                cnt += 1
        return cnt
    
    def start_ranap_proc(self, ProcClass, **kw):
        """initialize a RANAP connection-less procedure and send its initiatingMessage PDU 
        over RUA / Iuh
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        #
        Proc = self.init_ranap_proc(ProcClass, **kw)
        if Proc is None:
            return
        self.ProcRanapLast, cnt, pdus = Proc, 0, []
        #
        # encode the RANAP PDU(s)
        if not asn_ranap_acquire():
            self._log('ERR', 'unable to acquire the RANAP module')
            return 0
        for pdu in Proc.send():
            try:
                PDU_RANAP.set_val(pdu)
            except Exception as err:
                self._log('ERR', 'unable to set the RANAP pdu value')
                self._errpdu = pdu
            else:
                if self.TRACE_ASN_RANAP:
                    self._log('TRACE_ASN_RANAP_DL', '\n' + PDU_RANAP.to_asn1())
                pdus.append( PDU_RANAP.to_aper() )
        asn_ranap_release()
        #
        for buf in pdus:
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
    
    #--------------------------------------------------------------------------#
    # handling of RANAP connection-less signaling procedures
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
            self._log('ERR', 'send_error_ind: invalid IEs')
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
            self._log('ERR', 'reset: invalid IEs')
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
                except:
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
                except:
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
            self._log('ERR', 'reset: invalid IEs')
        return True if ret else False
    
    def page(self, **IEs):
        """start a RANAPPaging toward the RNC
        
        IEs should be set by the UE handler stack
        """
        ret = self.start_ranap_proc(RANAPPaging, **IEs)
        if not ret:
            self._log('ERR', 'page: invalid IEs')
        return True if ret else False
