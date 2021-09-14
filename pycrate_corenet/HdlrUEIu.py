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
# * File Name : pycrate_corenet/HdlrUEIu.py
# * Created : 2017-07-11
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcCNRua   import *
from .ProcCNRanap import *


# WNG: all procedures that call .require_smc() method need to be set in this LUT
ProcAbbrLUT = {
    'MMLocationUpdating'       : 'LU',
    'MMConnectionEstablishment': 'CON',
    'RRPagingResponse'         : 'PAG',
    'GMMAttach'                : 'ATT',
    'GMMRoutingAreaUpdating'   : 'RAU',
    'GMMServiceRequest'        : 'SER',
    }


class UEIuSigStack(SigStack):
    
    # to keep track of all RANAP procedures
    TRACK_PROC = True
    
    # reference to the UEd
    UE  = None
    # reference to the RNCd / HNBd
    RNC = None
    
    # core network domain (CS or PS)
    DOM = None
    
    # for pure RANAP procedure (no NAS trafic, neither RAB-oriented stuff)
    # should we page the UE to run the procedure successfully when UE is idle
    RANAP_FORCE_PAGE = False
    
    
    def _log(self, logtype, msg):
        self.UE._log(logtype, '[%s: %3i] %s' % (self.__class__.__name__, self.CtxId, msg))
    
    def __init__(self, ued, rncd, ctx_id):
        self.UE = ued
        self.Server = ued.Server
        if self.DOM == 'PS':
            self._cndomind = 'ps-domain'
        else:
            self._cndomind = 'cs-domain'
        #
        # dict of ongoing RANAP procedures (indexed by their procedure code)
        self.Proc     = {}
        self.ProcLast = None
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc    = []
        #
        # dict of available 2G / 3G security contexts, indexed by CKSN
        # and current CKSN in use
        self.SEC = {}
        self.reset_sec_ctx()
        #
        self.connected = Event()
        if rncd is not None:
            self.set_ran(rncd)
            self.set_ctx(ctx_id)
        else:
            self.unset_ctx()
    
    def set_ran(self, rncd):
        # TODO: handle mobility from 1 RNC to another, and inter-RAT
        self.SEC['CKSN'] = None
        self.RNC = rncd
        self.connected.set()
    
    def unset_ran(self):
        del self.RNC
        self.SEC['CKSN'] = None
        self.clear()
        self.connected.clear()
    
    def set_ran_unconnected(self, rncd):
        # required for paging
        self.SEC['CKSN'] = None
        self.RNC = rncd
    
    def unset_ran_unconnected(self):
        # required for paging
        del self.RNC
        self.SEC['CKSN'] = None
    
    def is_connected(self):
        #return self.RNC is not None
        return self.connected.is_set()
    
    def set_ctx(self, ctx_id):
        self.CtxId = ctx_id
    
    def unset_ctx(self):
        self.CtxId = -1
    
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
                if self.DOM == 'CS' and self.UE.TRACE_ASN_RANAP_CS:
                    self._log('TRACE_ASN_RANAP_CS_DL', '\n' + PDU_RANAP.to_asn1())
                elif self.DOM == 'PS' and self.UE.TRACE_ASN_RANAP_PS:
                    self._log('TRACE_ASN_RANAP_PS_DL', '\n' + PDU_RANAP.to_asn1())
                ret.append( PDU_RANAP.to_aper() )
        asn_ranap_release()
        return ret
    
    def process_ranap(self, buf):
        """process a RANAP PDU buffer sent by the RNC for a connected UE
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
            Proc = self.init_ranap_proc(RANAPErrorIndCN, Cause=('protocol', 97))
            Proc.recv(buf)
            self.ProcLast = Proc.Code
            return self._encode_ranap_pdu(Proc.send())
        #
        if self.DOM == 'CS' and self.UE.TRACE_ASN_RANAP_CS:
            self._log('TRACE_ASN_RANAP_CS_UL', '\n' + PDU_RANAP.to_asn1())
        elif self.DOM == 'PS' and self.UE.TRACE_ASN_RANAP_PS:
            self._log('TRACE_ASN_RANAP_PS_UL', '\n' + PDU_RANAP.to_asn1())
        pdu_rx = PDU_RANAP()
        asn_ranap_release()
        #
        errcause = None
        if pdu_rx[0] == 'initiatingMessage':
            # RNC-initiated procedure, instantiate it
            try:
                Proc = RANAPProcRncDispatcher[pdu_rx[1]['procedureCode']](self)
            except Exception:
                self._log('ERR', 'invalid RANAP PDU, initiatingMessage, code %i'\
                          % pdu_rx[1]['procedureCode'])
                # error cause: protocol, abstract-syntax-error-reject
                errcause = ('protocol', 100)
                Proc = self.init_ranap_proc(RANAPErrorIndCN, Cause=errcause)
                if not Proc:
                    return []
            else:
                if self.TRACK_PROC:
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.Class == 2 and Proc.errcause:
                Err = self.init_ranap_proc(RANAPErrorIndCN, Cause=Proc.errcause)
                self.ProcLast = Err.Code
                return self._encode_ranap_pdu(Err.send())
            elif Proc.Class == 1 or errcause:
                self.ProcLast = Proc.Code
                return self._encode_ranap_pdu(Proc.send())
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcLast = ProcRet.Code
                return self._encode_ranap_pdu(pdu_tx)
        #
        else:
            # CN-initiated procedure, transfer the PDU to it
            try:
                Proc = self.Proc[pdu_rx[1]['procedureCode']]
            except Exception:
                self._log('ERR', 'invalid RANAP PDU, %s, code %i'\
                          % (pdu_rx[0], pdu_rx[1]['procedureCode']))
                # error cause: protocol, message-not-compatible-with-receiver-state
                errcause = ('protocol', 99)
                Proc = self.init_ranap_proc(RANAPErrorIndCN, Cause=errcause)
                if not Proc:
                    return []
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.errcause:
                Err = self.init_ranap_proc(RANAPErrorIndCN, Cause=Proc.errcause)
                self.ProcLast = Err.Code
                return self._encode_ranap_pdu(Err.send())
            elif errcause:
                self.ProcLast = Proc.Code
                return self._encode_ranap_pdu(Proc.send())
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcLast = ProcRet.Code
                return self._encode_ranap_pdu(pdu_tx)
    
    def init_ranap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RANAP procedure of class `ProcClass' for a connected UE,
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        if not issubclass(ProcClass, RANAPSigProc):
            self._log('WNG', 'starting an invalid procedure over a RUA connection-oriented transfer')
        if ProcClass.Code in self.Proc:
            self._log('ERR', 'a RANAP procedure %s is already ongoing' % ProcClass.__name__)
            return None
        try:
            Proc = ProcClass(self)
        except Exception:
            # no active Iu link
            self._log('ERR', 'no active Iu link to initialize the RANAP procedure %s'\
                      % ProcClass.__name__)
            return None
        if Proc.Code in RANAPProcCnDispatcher and Proc.Class == 1:
            # store the procedure, which requires a response from the RNC
            self.Proc[Proc.Code] = Proc
        if self.TRACK_PROC:
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
    
    def clear(self):
        # clears all running RANAP CS/PS procedures
        for Proc in list(self.Proc.values()):
            Proc.abort()
    
    #--------------------------------------------------------------------------#
    # SMC and security-related methods
    #--------------------------------------------------------------------------#
    
    def require_smc(self, Proc):
        # check if a RANAPSecurityModeControl procedure is required
        if self.SEC_DISABLED or self.SMC_DISABLED:
            return False
        #
        elif ProcAbbrLUT[Proc.Name] in self.SMC_DISABLED_PROC:
            return False
        #
        elif self.SEC['CKSN'] is None or self.SEC['CKSN'] not in self.SEC:
            # no security context established, cannot run an smc
            self._log('WNG', 'require_smc: no CKSN set, unable to run an SMC')
            return False
        #
        else:
            return True
    
    def get_smc_ies(self, cksn=None, newkey=False):
        # if CKSN is None, take the 1st available
        if cksn is None:
            cksn = self._get_any_cksn()
        try:
            secctx = self.SEC[cksn]
        except KeyError:
            # no security ctxt available at all
            self._log('WNG', 'no security context available, using SMC_DUMMY')
            secctx = self.SMC_DUMMY
        # prepare the IEs for encoding the SMC
        IEs = {}
        if self.SMC_UIA is not None:
            IEs['IntegrityProtectionInformation'] = \
                {'permittedAlgorithms': self.SMC_UIA,
                 'key': (bytes_to_uint(secctx['IK'], 128), 128)}
        if self.SMC_UEA is not None:
            IEs['EncryptionInformation'] = \
                {'permittedAlgorithms': self.SMC_UEA,
                 'key': (bytes_to_uint(secctx['CK'], 128), 128)}
        if newkey:
            # taking a new context into use, i.e. just after an auth
            IEs['KeyStatus'] = 'new'
        else:
            IEs['KeyStatus'] = 'old'
        #
        return IEs
    
    def _get_any_cksn(self):
        cur = self.SEC['CKSN']
        if cur is not None:
            if cur in self.SEC:
                return cur
            else:
                # given CKSN not available anymore
                self.SEC['CKSN'] = None
        #
        for i in range(0, 7):
            if i in self.SEC:
                self.SEC['CKSN'] = i
                return i
        return None
    
    def get_new_cksn(self):
        for i in range(0, 7):
            if i not in self.SEC:
                return i
        # all CKSN have been used, clear all of them except the current one
        cur = self.SEC['CKSN']
        for i in range(0, 7):
            if i != cur:
                del self.SEC[i]
        if cur == 0:
            return 1
        else:
            return 0
    
    def set_sec_ctx(self, cksn, ctx, vect):
        if ctx == 3:
            # 3G sec ctx
            secctx = {'VEC': vect,
                      'CTX': ctx,
                      'CK' : vect[3],
                      'IK' : vect[4],
                      'UEA': self.SMC_UEA,
                      'UIA': self.SMC_UIA}
        else:
            # ctx == 2, 2G sec ctx
            # convert 2G Kc to 3G Ck, Ik
            CK, IK = conv_102_C4(vect[2]), conv_102_C5(vect[2])
            secctx = {'VEC': vect,
                      'CTX': ctx,
                      'Kc' : vect[2],
                      'CK' : CK,
                      'IK' : IK,
                      'UEA': self.SMC_UEA,
                      'UIA': self.SMC_UIA}
        self.SEC[cksn]   = secctx
        self.SEC['CKSN'] = cksn
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    def _send_to_rnc(self, buf):
        if not self.RNC:
            self._log('WNG', 'no RNC set, unable to send data')
            return False
        elif self.CtxId < 0:
            self._log('WNG', 'no Iu context-id set, unable to send data in connected mode')
            return False
        else:
            # start a RUADirectTransfer
            ret = self.RNC.start_rua_proc(RUADirectTransfer, Context_ID=(self.CtxId, 24),
                                                             RANAP_Message=buf,
                                                             CN_DomainIndicator=self._cndomind)
            return True if ret else False
    
    def _send_to_rnc_ranap(self, RanapProcs):
        ret = []
        for RanapProc in RanapProcs:
            # encode the RANAP PDU and send it over RUA
            pdus = self._encode_ranap_pdu(RanapProc.send())
            if not pdus:
                self._log('ERR', '_send_to_rnc_ranap: %s, invalid RANAP IEs' % RanapProc.Name)
                return False
            self.ProcLast = RanapProc.Code
            for pdu in pdus:
                ret.append( self._send_to_rnc(pdu) )
        return all(ret)
    
    def release(self, cause=('nAS', 83)):
        """release the Iu link with the given RANAP cause
        """
        if not self.connected.is_set():
            # nothing to release
            self._log('DBG', 'release: UE not connected')
            return True
        # prepare the RANAPRelease procedure
        RanapProc = self.init_ranap_proc(RANAPIuRelease, Cause=cause)
        if not RanapProc:
            return False
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    def send_error_ind(self, cause, **IEs):
        """start a RANAPErrorIndCN with the given RANAP cause
        
        IEs can contain any of the optional or extended IEs
        """
        if not self.connected.is_set():
            # RANAP link disconnected
            if self.RANAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the RANAP procedure
        IEs['Cause'] = cause
        RanapProc = self.init_ranap_proc(RANAPErrorIndCN, **IEs)
        if not RanapProc:
            return False
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    def send_common_id(self, **IEs):
        """start a RANAPCommonID with the UE's IMSI
        
        IEs can contain any of the extended IEs
        """
        if self.UE.IMSI is None:
            return False
        if not self.connected.is_set():
            # RANAP link disconnected
            if self.RANAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the RANAP procedure
        IEs['PermanentNAS_UE_ID'] = ('iMSI', NAS.encode_bcd(self.UE.IMSI))
        RanapProc = self.init_ranap_proc(RANAPCommonID, **IEs)
        if not RanapProc:
            return False
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    def invoke_trace(self, traceref, **IEs):
        """start a RANAPCNInvokeTrace with a given trace reference (2 or 3 bytes)
        
        IEs can contain any of the optional or extended IEs
        """
        if not self.connected.is_set():
            # RANAP link disconnected
            if self.RANAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the RANAP procedure
        IEs['TraceReference'] = traceref
        RanapProc = self.init_ranap_proc(RANAPCNInvokeTrace, **IEs)
        if not RanapProc:
            return False
        # required for the logging within the procedure
        RanapProc.TraceReference = traceref
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    def deactivate_trace(self, traceref, triggerid=None):
        """start a RANAPCNDeactivateTrace with a given trace reference (2 or 3 bytes)
        and optional trigger id (2 or 3 bytes)
        """
        if not self.connected.is_set():
            # RANAP link disconnected
            if self.RANAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the RANAP procedure
        IEs = {'TraceReference': traceref}
        if isinstance(triggerid, bytes_types):
            IEs['TriggerID'] = triggerid
        RanapProc = self.init_ranap_proc(RANAPCNDeactivateTrace, **IEs)
        if not RanapProc:
            return False
        # required for the logging within the procedure
        RanapProc.TraceReference = traceref
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    def report_loc_ctrl(self, reqtype={'event':'direct', 'reportArea':'service-area', 'accuracyCode':0},
                              **IEs):
        """start a RANAPLocationReportingControl with a given request type
        RequestType is a sequence of {event (enum), reportArea (enum), accuracyCode (int)}
        
        IEs can contain any of the extended IEs
        """
        if not self.connected.is_set():
            # RANAP link disconnected
            if self.RANAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the RANAP procedure
        IEs['RequestType'] = reqtype
        RanapProc = self.init_ranap_proc(RANAPLocationReportingControl, **IEs)
        if not RanapProc:
            return False
        # required for the logging within the procedure
        RanapProc.RequestType = reqtype
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    def request_loc_data(self, reqtype={'requestedLocationRelatedDataType': 'decipheringKeysUEBasedOTDOA'},
                               **IEs):
        """start a RANAPLocationRelatedData with a given request type
        RequestType is a sequence of {requestedLocationRelatedDataType (enum),
        requestedGPSAssistanceData (octets, optional)}
        
        IEs can contain any of the optional or extended IEs
        """
        if not self.connected.is_set():
            # RANAP link disconnected
            if self.RANAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the RANAP procedure
        IEs['LocationRelatedDataRequestType'] = reqtype
        RanapProc = self.init_ranap_proc(RANAPLocationRelatedData, **IEs)
        if not RanapProc:
            return False
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    def report_data_vol(self, rabidlist):
        """start a RANAPDataVolumeReport for the given list of RAB IDs (uint8)
        """
        if not self.connected.is_set():
            # RANAP link disconnected
            if self.RANAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # IE RAB-DataVolumeReportRequestList is a sequence of ProtocolIE-Container
        # which is a sequence of ProtocolIE-Field
        # with {id: 32, crit: reject, val: RAB-DataVolumeReportRequestItem}
        # IE RAB-DataVolumeReportRequestItem is a sequence {RAB-ID (BIT STRING of size 8), iE-Extensions}
        RIDList = []
        for rabid in rabidlist:
            RIDList.append({'id': 32, 'criticality': 'reject',
                            'value': ('RAB-DataVolumeReportRequestItem', {'rAB-ID': (rabid, 8)})})
        # prepare the RANAP procedure
        IEs = {'RAB_DataVolumeReportRequestList': [RIDList]}
        RanapProc = self.init_ranap_proc(RANAPDataVolumeReport, **IEs)
        if not RanapProc:
            return False
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    def request_srns_ctxt(self, rabidlist):
        """start a RANAPSRNSContextTransfer for the given list of RAB IDs (uint8)
        """
        if not self.connected.is_set():
            # RANAP link disconnected
            if self.RANAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # IE RAB-DataForwardingList-SRNS-CtxReq is a sequence of ProtocolIE-Container
        # which is a sequence of ProtocolIE-Field
        # with {id: 27, crit: reject, val: RAB-DataForwardingItem-SRNS-CtxReq}
        # IE RAB-DataForwardingItem-SRNS-CtxReq is a sequence {RAB-ID (BIT STRING of size 8), iE-Extensions}
        RIDList = []
        for rabid in rabidlist:
            RIDList.append({'id': 27, 'criticality': 'reject',
                            'value': ('RAB-DataForwardingItem-SRNS-CtxReq', {'rAB-ID': (rabid, 8)})})
        # prepare the RANAP procedure
        IEs = {'RAB_DataForwardingList_SRNS_CtxReq': [RIDList]}
        RanapProc = self.init_ranap_proc(RANAPSRNSContextTransfer, **IEs)
        if not RanapProc:
            return False
        # encode the RANAP PDU and send it over RUA
        return self._send_to_rnc_ranap([RanapProc])
    
    #--------------------------------------------------------------------------#
    # NAS-related methods
    #--------------------------------------------------------------------------#
    
    def ret_ranap_dt(self, NasTx, sapi=0):
        """returns a RANAPDirectTransfer procedure initialize with the NAS PDU to 
        be sent
        """
        if self.DOM == 'CS' and self.UE.TRACE_NAS_CS:
            self._log('TRACE_NAS_CS_DL', '\n' + NasTx.show())
        elif self.DOM == 'PS' and self.UE.TRACE_NAS_PS:
            self._log('TRACE_NAS_PS_DL', '\n' + NasTx.show())
        try:
            naspdu = NasTx.to_bytes()
        except Exception as err:
            self._log('ERR', 'unable to encode the NAS PDU: %r' % err)
            return []
        else:
            if sapi == 3:
                sapi = 'sapi-3'
            else:
                sapi = 'sapi-0'
            RanapProc = self.init_ranap_proc(RANAPDirectTransferCN,
                                             NAS_PDU=naspdu,
                                             SAPI=sapi)
            if RanapProc:
                return [RanapProc]
            else:
                return []
    
    def trigger_nas(self, RanapProc):
        # this is used by IuCS/PS RANAP procedures to recall an ongoing NAS procedure
        # e.g. SMC to recall a LUR or Attach
        if RanapProc._cb is None:
            # no callback set, this is actually useless
            return []
        NasProc = RanapProc._cb
        return NasProc.postprocess(RanapProc)
    
    #--------------------------------------------------------------------------#
    # to send arbitrary NAS buffers to the UE
    #--------------------------------------------------------------------------#
    
    def send_nas_raw(self, naspdu, sapi=0, rx_hook=lambda x:[], wait_t=1):
        """Sends whatever bytes, or list of bytes, to the UE as NAS PDU(s)
        """
        if not self._net_init_con():
            return False
        #
        self.RX_HOOK = rx_hook
        if sapi == 3:
            sapi = 'sapi-3'
        else:
            sapi = 'sapi-0'
        #
        if isinstance(naspdu, bytes_types):
            RanapProc = self.init_ranap_proc(RanapDirectTransferCN,
                                             NAS_PDU=naspdu,
                                             SAPI=sapi)
            if RanapProc:
                if not self._send_to_rnc_ranap([RanapProc]):
                    del self.RX_HOOK
                    return False
                else:
                    self._log('INF', 'send_nas_raw: 0x%s' % hexlify(naspdu).decode('ascii'))
                    sleep(wait_t)
            else:
                del self.RX_HOOK
                return False
        #
        elif isinstance(naspdu, (tuple, list)):
            for pdu in naspdu:
                ret = self.send_nas_raw(pdu, sapi, rx_hook, wait_t=1)
                if not ret:
                    return False
        #
        del self.RX_HOOK
        return True

