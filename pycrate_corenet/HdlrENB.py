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
# * File Name : pycrate_corenet/HdlrENB.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import *
from .ProcCNS1ap import *


class ENBd(object):
    """eNB handler within a CorenetServer instance
    responsible for S1AP signalling
    """
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level
    DEBUG           = ('ERR', 'WNG', 'INF', 'DBG')
    # to log S1AP PDU
    TRACE_ASN_S1AP  = False
    # to keep track of all S1AP procedures
    TRACK_PROC_S1AP = True
    
    # Radio Access Technology remainder
    RAT = RAT_EUTRA
    
    # ID: (PLMN, CellID)
    ID = (None, None)
    
    # SCTP socket
    SK    = None
    SKSid = 0
    Addr  = None
    
    # Server reference
    Server = None
    
    
    def _log(self, logtype, msg):
        """ENBd logging facility
        
        DEBUG logtype: 'ERR', 'WNG', 'INF', 'DBG'
        TRACE logtype: 'TRACE_ASN_S1AP_[UL|DL]'
        """
        if logtype[:3] == 'TRA':
            log('[TRA] [ENB: %s.%s] [%s]\n%s%s%s'\
                % (self.ID[0], self.ID[1], logtype[6:], TRACE_COLOR_START, msg, TRACE_COLOR_END))
        elif logtype in self.DEBUG:
            log('[%s] [ENB: %s.%s] %s' % (logtype, self.ID[0], self.ID[1], msg))
    
    def __init__(self, server, sk, sid):
        self.connect(server, sk, sid)
        #
        # init ENB config dict
        self.Config = {}
        # dict to link context-id -> UEd instance
        self.UE = {}
        # dict of warning message id -> warning message IEs
        self.WARN = {}
        #
        # dict of ongoing S1AP procedures (indexed by their procedure code)
        self.Proc     = {}
        # procedure code of the last procedure emitting a pdu toward the RAN
        self.ProcLast = None
        # list of tracked procedures (requires TRACK_PROC_S1AP = True)
        self._proc        = []
        #
        # counter for UE context id
        self._ctx_id = 0
    
    #--------------------------------------------------------------------------#
    # network socket operations
    #--------------------------------------------------------------------------#
    
    def connect(self, server, sk, sid):
        self.Server = server
        self.SK     = sk
        self.SKSid  = sid
        self.Addr   = sk.getpeername()
    
    def disconnect(self):
        del self.Server, self.SK, self.Addr, self.SKSid
    
    def is_connected(self):
        return self.SK is not None
    
    #--------------------------------------------------------------------------#
    # handling of non-UE-associated S1AP signalling procedures
    #--------------------------------------------------------------------------#
    
    def process_s1ap_pdu(self, pdu_rx):
        """process an S1AP PDU sent by the eNB for non-UE-associated signalling
        and return a list of S1AP PDU(s) to be sent back to it
        """
        errcause = None
        if pdu_rx[0] == 'initiatingMessage':
            # eNB-initiated procedure, instantiate it
            try:
                Proc = S1APNonUEProcEnbDispatcher[pdu_rx[1]['procedureCode']](self)
            except Exception:
                self._log('ERR', 'invalid S1AP PDU, initiatingMessage, code %i'\
                          % pdu_rx[1]['procedureCode'])
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = self.init_s1ap_proc(S1APErrorIndNonUECN, Cause=errcause)
            else:
                if self.TRACK_PROC_S1AP:
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.Class == 2 and Proc.errcause:
                Err = self.init_s1ap_proc(S1APErrorIndNonUECN, Cause=Proc.errcause)
                self.ProcLast = Err.Code
                return Err.send()
            elif Proc.Class == 1 or errcause:
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcLast = ProcRet.Code
                return pdu_tx
        #
        else:
            # CN-initiated procedure, transfer the PDU to it
            try:
                Proc = self.Proc[pdu_rx[1]['procedureCode']]
            except Exception:
                self._log('ERR', 'invalid S1AP PDU, %s, code %i'\
                          % (pdu_rx[0], pdu_rx[1]['procedureCode']))
                errcause = ('protocol', 'message-not-compatible-with-receiver-state')
                Proc = self.init_s1ap_proc(S1APErrorIndNonUECN, Cause=errcause)
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.errcause:
                Err = self.init_s1ap_proc(S1APErrorIndNonUECN, Cause=Proc.errcause)
                self.ProcLast = Err.Code
                return Err.send()
            elif errcause:
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcLast = ProcRet.Code
                return pdu_tx
    
    def init_s1ap_proc(self, ProcClass, **IEs):
        """initialize a CN-initiated S1AP procedure of class `ProcClass' for 
        non-UE-associated signalling, encode the initiatingMessage PDU with given 
        **IEs and return the procedure
        """
        if not issubclass(ProcClass, S1APNonUESigProc):
            self._log('WNG', 'initializing an invalid S1AP procedure, %s' % ProcClass.__name__)
        if ProcClass.Code in self.Proc:
            self._log('ERR', 'an S1AP procedure %s is already ongoing, unable to start a new one'\
                      % ProcClass.__name__)
            return None
        Proc = ProcClass(self)
        if Proc.Code in S1APNonUEProcCnDispatcher and Proc.Class == 1:
            # store the procedure, which requires a response from the eNB
            self.Proc[Proc.Code] = Proc
        if self.TRACK_PROC_S1AP:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **IEs)
        return Proc
    
    def start_s1ap_proc(self, ProcClass, **IEs):
        """initialize a CN-initiated S1AP procedure of class `ProcClass' for 
        non-UE-associated signalling, encode the initiatingMessage PDU with given 
        **IEs and send the PDU generated by the procedure to the eNB
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_s1ap_proc(ProcClass, **IEs)
        if Proc is None:
            return 0
        self.ProcLast, cnt = Proc.Code, 0
        for pdu_tx in Proc.send():
            if self.Server.send_s1ap_pdu(self, pdu_tx, self.SKSid):
                cnt += 1
        return cnt
    
    def get_s1setup_ies_from_cfg(self):
        """return the dict of IEs for the S1SetupResponse from the Config dict
        """
        return {'MMEname'            : self.Server.ConfigS1['MMEname'],
                'RelativeMMECapacity': self.Server.ConfigS1['RelativeMMECapacity'],
                'ServedGUMMEIs'      : cplist(self.Server.ConfigS1['ServedGUMMEIs'])}
    
    #--------------------------------------------------------------------------#
    # handling of UE-associated S1AP signalling procedures
    #--------------------------------------------------------------------------#
    
    def process_s1ap_ue_pdu(self, pdu_rx, sid):
        """process an S1AP PDU sent by the eNB for UE-associated signalling with
        a given SCTP stream id
        and return a list of S1AP PDU(s) to be sent back to it
        """
        if pdu_rx[0] == 'initiatingMessage' and pdu_rx[1]['procedureCode'] == 12:
            # initialUEMessage, retrieve / create the UE instance 
            ue, ctx_id = self.get_ued(pdu_rx)
            if ue is None:
                self._log('ERR', 'unknown UE trying to connect')
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = self.init_s1ap_proc(S1APErrorIndNonUECN, Cause=errcause)
                Proc.recv( pdu_rx )
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                self.set_ue_s1(ue, ctx_id)
                try:
                    ue.set_ran(self, ctx_id, sid)
                except Exception as err:
                    self._log('ERR', 'UE connected to several RAN, %r' % err)
                    return []
        else:
            ctx_id = self.get_enb_ue_ctx_id(pdu_rx)
        if ctx_id is None:
            self._log('ERR', 'no eNB UE context id provided')
            errcause = ('protocol', 'abstract-syntax-error-reject')
            Proc = self.init_s1ap_proc(S1APErrorIndNonUECN, Cause=errcause)
            Proc.recv( pdu_rx )
            self.ProcLast = Proc.Code
            return Proc.send()
        else:
            try:
                ue = self.UE[ctx_id]
            except Exception:
                self._log('ERR', 'invalid eNB UE context id provided')
                errcause = ('radioNetwork', 'unknown-enb-ue-s1ap-id')
                Proc = self.init_s1ap_proc(S1APErrorIndNonUECN, Cause=errcause)
                Proc.recv( pdu_rx )
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                return ue.S1.process_s1ap_pdu(pdu_rx)
    
    def set_ue_s1(self, ued, ctx_id):
        self.UE[ctx_id] = ued
    
    def unset_ue_s1(self, ctx_id):
        try:
            del self.UE[ctx_id]
        except Exception:
            self._log('WNG', 'no UE with S1 context-id %i to unset' % ctx_id)
    
    def get_ued(self, pdu_rx):
        enb_ue_id, nas_pdu, tai, s_tmsi = None, None, None, None
        for ie in pdu_rx[1]['value'][1]['protocolIEs']:
            if ie['id'] == 8:
                # ENB-UE-S1AP-ID
                enb_ue_id = ie['value'][1]
            elif ie['id'] == 26:
                # NAS-PDU
                nas_pdu = ie['value'][1]
            elif ie['id'] == 67:
                # TAI
                tai = ie['value'][1]
            elif ie['id'] == 96:
                # S-TMSI
                s_tmsi = ie['value'][1]
        if enb_ue_id is None or not nas_pdu or not tai:
            # missing mandatory IE
            return None, enb_ue_id
        #plmn = plmn_buf_to_str(tai['pLMNidentity'])
        if s_tmsi:
            # use the S1AP S-TMSI
            return self.Server.get_ued(mtmsi=bytes_to_uint(s_tmsi['m-TMSI'], 32)), enb_ue_id
        else:
            # use the EPSID within the NAS PDU
            TS24007.IE.DECODE_INNER = False
            NasRx, err = NAS.parse_NASLTE_MO(nas_pdu, inner=False)
            TS24007.IE.DECODE_INNER = True
            if err:
                return None, enb_ue_id
            sh = NasRx[0]['SecHdr'].get_val()
            if sh in (1, 3):
                TS24007.IE.DECODE_INNER = False
                NasRx, err = NAS.parse_NASLTE_MO(NasRx['NASMessage'].get_val(), inner=False)
                TS24007.IE.DECODE_INNER = True
                if err:
                    return None, enb_ue_id
                sh = NasRx[0]['SecHdr'].get_val()
            if sh == 0:
                # clear-text NAS PDU
                if 'EPSID' in NasRx._by_name:
                    epsid = NasRx['EPSID'][-1].get_val()
                elif 'OldGUTI' in NasRx._by_name:
                    epsid = NasRx['OldGUTI'][-1].get_val()
                else:
                    return None, enb_ue_id
                EpsId = NAS.EPSID()
                EpsId.from_bytes(epsid)
                ident = EpsId.decode()
                if ident[0] == NAS.IDTYPE_IMSI:
                    return self.Server.get_ued(imsi=ident[1]), enb_ue_id
                elif ident[0] == NAS.IDTYPE_GUTI:
                    # TODO: ensure PLMN, MME group, MMEC correspond
                    return self.Server.get_ued(mtmsi=ident[4]), enb_ue_id
                else:
                    return None, enb_ue_id
            else:
                return None, enb_ue_id
    
    def get_enb_ue_ctx_id(self, pdu_rx):
        enb_ue_id = None
        for ie in pdu_rx[1]['value'][1]['protocolIEs']:
            if ie['id'] == 8:
                # ENB-UE-S1AP-ID
                enb_ue_id = ie['value'][1]
                break
        return enb_ue_id
    
    #--------------------------------------------------------------------------#
    # CN-initiated non-UE-associated S1AP signalling procedures
    #--------------------------------------------------------------------------#
    
    def page(self, **IEs):
        """start an S1APPaging toward the eNB
        
        IEs should be set by the UE handler stack
        """
        ret = self.start_s1ap_proc(S1APPaging, **IEs)
        if not ret:
            self._log('ERR', 'page: error')
        return True if ret else False
    
    def send_error_ind(self, cause, **IEs):
        """start a S1APErrorIndNonUECN with the given S1AP cause
        
        IEs can contain any of the optional or extended IEs
        """
        # send an S1APErrorInd to the eNB
        IEs['Cause'] = cause
        # send to the eNB
        ret = self.start_s1ap_proc(S1APErrorIndNonUECN, **IEs)
        if not ret:
            self._log('ERR', 'send_error_ind: error')
        return True if ret else False
    
    def reset(self, reslist=None, cause=('misc', 115)):
        """start an S1APResetCN toward the eNB after having deleted some or all 
        UE-related S1 resources
        
        If reslist is None, all UE-associated S1 resources will be reset
        otherwise, reslist must be a list of UE context id to be reset
        """
        # send an S1APResetCN to the eNB
        IEs = {'Cause': cause}
        if isinstance(reslist, (tuple, list)):
            ue_res_list = []
            for uectx in reslist:
                if uectx in self.UE:
                    ue = self.UE[uectx]
                    ue.S1.unset_ran()
                    ue.S1.unset_ctx()
                    ue_res_list.append({
                        'id': 91,
                        'criticality': 'ignore',
                        'value': ('UE-associatedLogicalS1-ConnectionItem',
                                  {'mME-UE-S1AP-ID': uectx,
                                   'eNB-UE-S1AP-ID': uectx})})
                else:
                    ue_res_list.append({
                        'id': 91,
                        'criticality': 'ignore',
                        'value': ('UE-associatedLogicalS1-ConnectionItem',
                                  {'eNB-UE-S1AP-ID': uectx})})
            IEs = {'ResetType': ('partOfS1-Interface', ue_res_list)}
        else:
            IEs = {'ResetType': ('s1-Interface', 'reset-all')}
        # send to the eNB
        ret = self.start_s1ap_proc(S1APResetCN, **IEs)
        if not ret:
            self._log('ERR', 'reset: error')
        return True if ret else False
    
    def bcast_warn_set(self, msgid, sernum, rep=10, num=10, **IEs):
        """set a warning message to be broacasted by the eNodeB, by using the
        S1APWriteReplaceWarning procedure
        
        In case of successful procedure, self.WARN is extended with the warning
        message parameters
        
        mandatory parameters:
            msgid: uint16, type of warning message
            sernum: uint16, unique identifier of the message for the given type
            rep: 0..4095, repetition duration in sec
            num: 0..65535, number of repetitions
        IEs can contain:
          - WarningAreaList
          - WarningType
          - WarningSecurityInfo
          - DataCodingScheme
          - WarningMessageContents
          - ConcurrentWarningMessageIndicator
          - ExtendedRepetitionPeriod 
        """
        #
        IEs['MessageIdentifier'] = (msgid, 16)
        IEs['SerialNumber']      = (sernum, 16)
        IEs['RepetitionPeriod']  = rep
        IEs['NumberofBroadcastRequest'] = num
        #
        ret = self.start_s1ap_proc(S1APWriteReplaceWarning, **IEs)
        if not ret:
            self._log('ERR', 'bcast_warn_set: error')
        return True if ret else False
    
    def bcast_warn_unset(self, msgid=None, sernum=0, **IEs):
        """disable a warning message broacasted by the eNodeB, by using the
        S1APKill procedure
        
        If msgid is None, all messages will be disabled, otherwise the given
        message will be disabled
        
        mandatory parameters:
            msg: None or uint16, type of warning message
            sernum: uint16, unique identifier of the message for the given type
        IEs can contain:
            WarningAreaList
        """
        if msgid is None:
            msgid, sernum = 0, 0
            IEs['KillAllWarningMessages'] = 'true'
        IEs['MessageIdentifier'] = (msgid, 16)
        IEs['SerialNumber']      = (sernum, 16)
        #
        ret = self.start_s1ap_proc(S1APKill, **IEs)
        if not ret:
            self._log('ERR', 'bcast_warn_unset: error')
            return False
        else:
            if IEs['KillAllWarningMessages'] == 'true':
                self.WARN.clear()
            else:
                try:
                    del self.WARN[msgid]
                except Exception:
                    pass
            return True
    
