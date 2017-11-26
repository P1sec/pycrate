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
    # reference to the HNBd
    RNC = None
    
    # core network domain (CS or PS)
    DOM = None
    
    # for pure RANAP procedure (no NAS trafic, neither RAB-oriented stuff)
    # should we page the UE to run the procedure successfully when UE is idle
    RANAP_FORCE_PAGE = False
     
    
    def _log(self, logtype, msg):
        self.UE._log(logtype, '[%s: %3i] %s' % (self.__class__.__name__, self.CtxId, msg))
    
    def __init__(self, ued, hnbd, ctx_id):
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
        # RANAP callback for NAS stacks
        self.RanapTx  = None
        #
        # dict of available 2G / 3G security contexts, indexed by CKSN
        # and current CKSN in use
        self.SEC = {}
        self.reset_sec_ctx()
        #
        self.connected = Event()
        if hnbd is not None:
            self.set_ran(hnbd)
            self.set_ctx(ctx_id)
        else:
            self.unset_ctx()
    
    def set_ran(self, hnbd):
        self.SEC['CKSN'] = None
        self.RNC = hnbd
        self.connected.set()
    
    def unset_ran(self):
        del self.RNC
        self.SEC['CKSN'] = None
        self.connected.clear()
    
    def set_ran_unconnected(self, hnbd):
        # required for paging
        self.SEC['CKSN'] = None
        self.RNC = hnbd
    
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
    # RANAP-related methods
    #--------------------------------------------------------------------------#
    
    def process_ranap(self, buf):
        """process a RANAP PDU buffer sent by the RNC handling the UE connection
        and return a list with RANAP PDU(s) to be sent back to the RNC
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
            Proc = self.init_ranap_proc(RANAPErrorIndCN, Cause=('protocol', 97))
            if Proc is None:
                return []
            else:
                Proc.recv(buf)
                self.ProcLast = Proc.Code
                return Proc.send()
        #
        if self.DOM == 'CS' and self.UE.TRACE_ASN_RANAP_CS:
            self._log('TRACE_ASN_RANAP_CS_UL', '\n' + PDU_RANAP.to_asn1())
        elif self.DOM == 'PS' and self.UE.TRACE_ASN_RANAP_PS:
            self._log('TRACE_ASN_RANAP_PS_UL', '\n' + PDU_RANAP.to_asn1())
        pdu = PDU_RANAP()
        asn_ranap_release()
        errcause = None
        #
        if pdu[0] == 'initiatingMessage':
            # RNC-initiated procedure, create it through the dispatcher
            try:
                Proc = RANAPProcRncDispatcher[pdu[1]['procedureCode']](self)
            except:
                self._log('ERR', 'invalid RANAP PDU, initiatingMessage, code %i'\
                          % pdu[1]['procedureCode'])
                # returns a RANAP error ind: protocol, abstract-syntax-error-reject
                errcause = ('protocol', 100)
                Proc = self.init_ranap_proc(RANAPErrorIndCN, Cause=errcause)
                if Proc is None:
                    return []
            else:
                # store the procedure, if no error ind
                self.Proc[Proc.Code] = Proc
                if self.TRACK_PROC:
                    # keep track of the procedure
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu )
            #
            if Proc.Cont['suc'] is not None or errcause is not None:
                # procedure requires a response
                # set the last procedure code in the RNC handler
                self.ProcLast = Proc.Code
                # send back any potential response to the RNC
                # Proc.send() will take care to clean-up self.Proc
                return self._encode_pdu(Proc.send())
            else:
                # potentially create new RANAP procedures, 
                # as outcome of the one received
                snd = []
                for ProcRet in Proc.trigger():
                    # all those procedures must have been initiated with self.init_ranap_proc()
                    # hence, they are already set in self.Proc
                    # and tracked in self._proc
                    snd.extend( ProcRet.send() )
                    # set the last procedure code
                    self.ProcLast = ProcRet.Code
                return self._encode_pdu(snd)
        #
        else:
            # CN-initiated procedure, already existing in self.Proc
            # transfer the PDU to it
            try:
                Proc = self.Proc[pdu[1]['procedureCode']]
            except:
                self._log('ERR', 'invalid RANAP PDU, %s, code %i' % (pdu[0], pdu[1]['procedureCode']))
                # returns a RANAP error ind: protocol, message-not-compatible-with-receiver-state
                errcause = ('protocol', 99)
                Proc = self.init_ranap_proc(RANAPErrorIndCN, Cause=errcause)
                if Proc is None:
                    return []
            # process the PDU within the procedure
            Proc.recv( pdu )
            #
            if errcause is not None:
                # set the last procedure code
                self.ProcLast = Proc.Code
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
                    self.ProcLast = ProcRet.Code
                return self._encode_pdu(snd)
    
    def _encode_pdu(self, pdus):
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
    
    def init_ranap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RANAP procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        if not issubclass(ProcClass, RANAPSigProc):
            self._log('WNG', 'starting a connection-less RANAP procedure '\
                             'over a RUA connection-oriented transfer')
        if ProcClass.Code in self.Proc:
            self._log('ERR', 'a RANAP procedure %s is already ongoing, unable to start a new one'\
                      % ProcClass.__name__)
            return None
        try:
            Proc = ProcClass(self)
        except:
            # self has no active Iu link
            self._log('ERR', 'no active Iu link to start a RANAP procedure %s' % ProcClass.__name__)
            return None
        # store the procedure
        self.Proc[Proc.Code] = Proc
        if self.TRACK_PROC:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
    
    def clear(self):
        # clears all running RANAP CS/PS procedures
        for code in self.Proc.keys():
            self.Proc[code].abort()
    
    #--------------------------------------------------------------------------#
    # NAS-related methods
    #--------------------------------------------------------------------------#
    
    def ret_ranap_dt(self, NAS_PDU):
        # return a RANAPDirectTransfer with the NAS PDU to be sent
        try:
            naspdu = NAS_PDU.to_bytes()
        except Exception as err:
            self._log('ERR', 'unable to encode downlink NAS PDU: %r' % err)
        else:
            RanapProc = self.init_ranap_proc(RANAPDirectTransferCN,
                                             NAS_PDU=naspdu,
                                             SAPI='sapi-0')
            if RanapProc:
                return [RanapProc]
        return []
    
    def trigger_nas(self, RanapProc):
        # this is used by IuCS/PS RANAP procedures to recall an ongoing NAS procedure
        if RanapProc._cb is None:
            # no callback set, this is actually useless
            return []
        NasProc = RanapProc._cb
        NasTx = NasProc.postprocess(RanapProc)
        return self._ret_ranap_proc(NasTx)
    
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
        # prepare the kwargs for encoding the SMC encoding
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
        if self.SEC['CKSN'] is not None:
            try:
                return self.SEC[self.SEC['CKSN']]
            except:
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
        l = list(range(0, 7))
        if cur is not None:
            l.remove(cur)
        [self.SEC.__delitem__(i) for i in l]
        if cur == 0:
            return 1
        else:
            return 0
    
    def set_sec_ctx(self, cksn, ctx, vect):
        if ctx == 3:
            # 3G sec ctx
            ctx = {'VEC': vect,
                   'CTX': ctx,
                   'CK' : vect[3],
                   'IK' : vect[4],
                   'UEA': self.SMC_UEA,
                   'UIA': self.SMC_UIA}
        else:
            # ctx == 2, 2G sec ctx
            # convert 2G Kc to 3G Ck, Ik
            CK, IK = conv_C4(vect[2]), conv_C5(vect[2])
            ctx = {'VEC': vect,
                   'CTX': ctx,
                   'CK' : CK,
                   'IK' : IK,
                   'UEA': self.SMC_UEA,
                   'UIA': self.SMC_UIA}
        self.SEC[cksn]   = ctx
        self.SEC['CKSN'] = cksn
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    def _send_to_rnc(self, buf):
        if self.RNC is None:
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
    
    def _send_to_rnc_nasdt(self, naspdu, sapi=0):
        # prepare the RANAPDirectTransferCN procedure
        if sapi == 3:
            sapi = 'sapi-3'
        else:
            sapi = 'sapi-0'
        RanapProc = self.init_ranap_proc(RANAPDirectTransferCN,
                                         NAS_PDU=naspdu,
                                         SAPI=sapi)
        if not RanapProc:
            return False
        # encode the RANAP PDU and send it over RUA
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', '_send_to_rnc_nasdt: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the RNC handler
        self.ProcLast = RanapProc.Code
        # send to RNC in connected mode
        return self._send_to_rnc(pdu)
    
    def _send_to_ue(self, naspdu, sapi=0):
        if not self.page_block():
            self._log('ERR', 'unable to page')
            return False
        return self._send_to_rnc_nasdt(naspdu, sapi)
    
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
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', 'release: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the RNC handler
        self.ProcLast = RanapProc.Code
        # send to RNC in connected mode
        return self._send_to_rnc(pdu)
    
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
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', 'send_error_ind: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the Iu handler and remove from the 
        # procedure stack
        self.ProcLast = RanapProc.Code
        try:
            del self.Proc[RanapProc.Code]
        except:
            pass
        # send to the RNC in connection-oriented signaling
        return self._send_to_rnc(pdu)
    
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
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', 'send_common_id: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the RNC handler
        self.ProcLast = RanapProc.Code
        # send to the RNC in connection-oriented signaling
        return self._send_to_rnc(pdu)
    
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
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', 'invoke_trace: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the RNC handler
        self.ProcLast = RanapProc.Code
        # send to the RNC in connection-oriented signaling
        return self._send_to_rnc(pdu)
    
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
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', 'deactivate_trace: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the RNC handler
        self.ProcLast = RanapProc.Code
        # send to the RNC in connection-oriented signaling
        return self._send_to_rnc(pdu)
    
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
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', 'report_loc_ctrl: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the RNC handler
        self.ProcLast = RanapProc.Code
        # send to the RNC in connection-oriented signaling
        return self._send_to_rnc(pdu)
    
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
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', 'request_loc_data: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the RNC handler
        self.ProcLast = RanapProc.Code
        # send to the RNC in connection-oriented signaling
        return self._send_to_rnc(pdu)
    
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
        # IE RAB-DataVolumeReportRequestItem is a sequence {RAB-ID (BIT STRING of size 8)}
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
        pdu = self._encode_pdu(RanapProc.send())
        if not pdu:
            self._log('ERR', 'report_data_vol: invalid IEs')
            return False
        pdu = pdu[0]
        # set the last procedure code in the RNC handler
        self.ProcLast = RanapProc.Code
        # send to the RNC in connection-oriented signaling
        return self._send_to_rnc(pdu)
    
    #--------------------------------------------------------------------------#
    # to send arbitrary NAS buffers to the UE
    #--------------------------------------------------------------------------#
    
    def send_nas_raw(self, naspdu, sapi=0, rx_hook=lambda x:None, wait_t=1):
        """Sends whatever bytes, or list of bytes, to the UE as NAS PDU(s)
        """
        if not self._net_init_con():
            return False
        #
        self.RX_HOOK = rx_hook
        if isinstance(naspdu, bytes_types):
            if not self._send_to_rnc_nasdt(naspdu, sapi=sapi):
                del self.RX_HOOK
                return False
            else:
                self._log('INF', 'send_nas_raw: 0x%s' % hexlify(naspdu).decode('ascii'))
                sleep(wait_t)
        #
        elif isinstance(naspdu, (tuple, list)):
            for pdu in naspdu:
                if not isinstance(pdu, bytes_types):
                    pass
                elif not self.connected.is_set():
                    # poor UE got disconnected, just ask it to reconnect
                    if not self._net_init_con():
                        del self.RX_HOOK    
                        return False
                elif not self._send_to_rnc_nasdt(pdu, sapi=sapi):
                    del self.RX_HOOK
                    return False
                else:
                    self._log('INF', 'send_nas_raw: 0x%s' % hexlify(naspdu).decode('ascii'))
                    sleep(wait_t)
        #
        del self.RX_HOOK
        return True
