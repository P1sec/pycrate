# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1Sec.
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
# * File Name : pycrate_corenet/HdlrGNB.py
# * Created : 2020-04-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils                     import *
from .ProcCNNgap                import *

from pycrate_mobile.TS24501_IE  import (
    FGSIDTYPE_NO, # 0
    FGSIDTYPE_SUPI,
    FGSIDTYPE_GUTI,
    FGSIDTYPE_IMEI,
    FGSIDTYPE_STMSI,
    FGSIDTYPE_IMEISV,
    FGSIDTYPE_MAC,
    FGSIDTYPE_EUI64, # 7
    FGSIDFMT_IMSI, # 0
    FGSIDFMT_NSI,
    FGSIDFMT_GCI,
    FGSIDFMT_GLI, # 3
    )


class GNBd(object):
    """gNB handler within a CorenetServer instance
    responsible for NGAP signalling
    """
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level
    DEBUG           = ('ERR', 'WNG', 'INF', 'DBG')
    # to log NGAP PDU
    TRACE_ASN_NGAP  = False
    # to keep track of all NGAP procedures
    TRACK_PROC_NGAP = True
    
    # Radio Access Technology remainder
    # need to be updated at init, depending of the GlobalRANID
    RAT = RAT_NR
    
    # ID: (PLMN, ID-type, ID-bit-str-val)
    ID = (None, None, (0, 32))
    
    # SCTP socket
    SK    = None
    SKSid = 0
    Addr  = None
    
    # Server reference
    Server = None
    
    
    def _log(self, logtype, msg):
        """GNBd logging facility
        
        DEBUG logtype: 'ERR', 'WNG', 'INF', 'DBG'
        TRACE logtype: 'TRACE_ASN_NGAP_[UL|DL]'
        """
        if logtype[:3] == 'TRA':
            log('[TRA] [GNB: %s.%s.%.8x] [%s]\n%s%s%s'\
                % (self.ID[1], self.ID[0], self.ID[2][0], logtype[6:],
                   TRACE_COLOR_START, msg, TRACE_COLOR_END))
        elif logtype in self.DEBUG:
            log('[%s] [GNB: %s.%s.%.8x] %s' % (logtype, self.ID[1], self.ID[0], self.ID[2][0], msg))
    
    def __init__(self, server, sk, sid):
        self.connect(server, sk, sid)
        #
        # init GNB config dict
        self.Config = {}
        # dict to link context-id -> UEd instance
        self.UE = {}
        # dict of warning message id -> warning message IEs
        self.WARN = {}
        #
        # dict of ongoing NGAP procedures (indexed by their procedure code)
        self.Proc     = {}
        # procedure code of the last procedure emitting a pdu toward the RAN
        self.ProcLast = None
        # list of tracked procedures (requires TRACK_PROC_NGAP = True)
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
    # handling of non-UE-associated NGAP signalling procedures
    #--------------------------------------------------------------------------#
    
    def process_ngap_pdu(self, pdu_rx):
        """process an NGAP PDU sent by the gNB for non-UE-associated signalling
        and return a list of NGAP PDU(s) to be sent back to it
        """
        errcause = None
        if pdu_rx[0] == 'initiatingMessage':
            # gNB-initiated procedure, instantiate it
            try:
                Proc = NGAPNonUEProcRANDispatcher[pdu_rx[1]['procedureCode']](self)
            except Exception:
                self._log('ERR', 'invalid NGAP PDU, initiatingMessage, code %i'\
                          % pdu_rx[1]['procedureCode'])
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = self.init_ngap_proc(NGAPErrorIndNonUECN, Cause=errcause)
            else:
                if self.TRACK_PROC_NGAP:
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.Class == 2 and Proc.errcause:
                Err = self.init_ngap_proc(NGAPErrorIndNonUECN, Cause=Proc.errcause)
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
                self._log('ERR', 'invalid NGAP PDU, %s, code %i'\
                          % (pdu_rx[0], pdu_rx[1]['procedureCode']))
                errcause = ('protocol', 'message-not-compatible-with-receiver-state')
                Proc = self.init_ngap_proc(NGAPErrorIndNonUECN, Cause=errcause)
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.errcause:
                Err = self.init_ngap_proc(NGAPErrorIndNonUECN, Cause=Proc.errcause)
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
    
    def init_ngap_proc(self, ProcClass, **IEs):
        """initialize a CN-initiated NGAP procedure of class `ProcClass' for 
        non-UE-associated signalling, encode the initiatingMessage PDU with given 
        **IEs and return the procedure
        """
        if not issubclass(ProcClass, NGAPNonUESigProc):
            self._log('WNG', 'initializing an invalid NGAP procedure, %s' % ProcClass.__name__)
        if ProcClass.Code in self.Proc:
            self._log('ERR', 'an NGAP procedure %s is already ongoing, unable to start a new one'\
                      % ProcClass.__name__)
            return None
        Proc = ProcClass(self)
        if Proc.Code in NGAPNonUEProcCNDispatcher and Proc.Class == 1:
            # store the procedure, which requires a response from the gNB
            self.Proc[Proc.Code] = Proc
        if self.TRACK_PROC_NGAP:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **IEs)
        return Proc
    
    def start_ngap_proc(self, ProcClass, **IEs):
        """initialize a CN-initiated NGAP procedure of class `ProcClass' for 
        non-UE-associated signalling, encode the initiatingMessage PDU with given 
        **IEs and send the PDU generated by the procedure to the gNB
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_ngap_proc(ProcClass, **IEs)
        if Proc is None:
            return 0
        self.ProcLast, cnt = Proc.Code, 0
        for pdu_tx in Proc.send():
            if self.Server.send_ngap_pdu(self, pdu_tx, self.SKSid):
                cnt += 1
        return cnt
    
    def get_ngsetup_ies_from_cfg(self):
        """return the dict of IEs for the NGSetupResponse from the Config dict
        """
        ies = {
            'AMFName'            : self.Server.ConfigNG['AMFName'],
            'PLMNSupportList'    : plmnsupplist_to_asn(self.Server.AMF_PLMNSupp),
            'RelativeAMFCapacity': self.Server.ConfigNG['RelativeAMFCapacity'],
            'ServedGUAMIList'    : guamilist_to_asn(self.Server.AMF_GUAMI),
            }
        if 'UERetentionInformation' in self.Server.ConfigNG:
            ies['UERetentionInformation'] = self.Server.ConfigNG['UERetentionInformation']
        return ies
    
    #--------------------------------------------------------------------------#
    # handling of UE-associated NGAP signalling procedures
    #--------------------------------------------------------------------------#
    
    def process_ngap_ue_pdu(self, pdu_rx, sid):
        """process an NGAP PDU sent by the gNB for UE-associated signalling with
        a given SCTP stream id
        and return a list of NGAP PDU(s) to be sent back to it
        """
        if pdu_rx[0] == 'initiatingMessage' and pdu_rx[1]['procedureCode'] == 15:
            # initialUEMessage, retrieve / create the UE instance 
            ue, ctx_id = self.get_ued(pdu_rx)
            if ue is None:
                self._log('ERR', 'unknown UE trying to connect')
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = self.init_ngap_proc(NGAPErrorIndNonUECN, Cause=errcause)
                Proc.recv( pdu_rx )
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                self.set_ue_ng(ue, ctx_id)
                try:
                    ue.set_ran(self, ctx_id, sid)
                except Exception as err:
                    self._log('ERR', 'UE connected to several RAN, %r' % err)
                    return []
        else:
            ctx_id = self.get_gnb_ue_ctx_id(pdu_rx)
        if ctx_id is None:
            self._log('ERR', 'no gNB UE context id provided')
            errcause = ('protocol', 'abstract-syntax-error-reject')
            Proc = self.init_ngap_proc(NGAPErrorIndNonUECN, Cause=errcause)
            Proc.recv( pdu_rx )
            self.ProcLast = Proc.Code
            return Proc.send()
        else:
            try:
                ue = self.UE[ctx_id]
            except Exception:
                self._log('ERR', 'invalid gNB UE context id provided')
                errcause = ('radioNetwork', 'unknown-local-UE-NGAP-ID')
                Proc = self.init_ngap_proc(NGAPErrorIndNonUECN, Cause=errcause)
                Proc.recv( pdu_rx )
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                return ue.NG.process_ngap_pdu(pdu_rx)
        
        return []
    
    
    def set_ue_ng(self, ued, ctx_id):
        self.UE[ctx_id] = ued
    
    def unset_ue_ng(self, ctx_id):
        try:
            del self.UE[ctx_id]
        except Exception:
            self._log('WNG', 'no UE with NG context-id %i to unset' % ctx_id)
    
    def get_ued(self, pdu_rx):
        ran_ue_id, nas_pdu, tai, s_tmsi = None, None, None, None
        for ie in pdu_rx[1]['value'][1]['protocolIEs']:
            if ie['id'] == 26:
                # S-TMSI
                s_tmsi = ie['value'][1]
            elif ie['id'] == 38:
                # NAS-PDU
                nas_pdu = ie['value'][1]
            elif ie['id'] == 85:
                # RAN-UE-NGAP-ID
                ran_ue_id = ie['value'][1]
        if ran_ue_id is None or not nas_pdu:
            # missing mandatory IE
            self._log('WNG', 'Unable to get UE id from NAS message, missing mandatory IE')
            return None, ran_ue_id
        if s_tmsi:
            # use the NGAP S-TMSI
            return self.Server.get_ued(mtmsi=bytes_to_uint(s_tmsi['fiveG-TMSI'], 32)), ran_ue_id
        else:
            # use the FGSID within the NAS PDU
            TS24007.IE.DECODE_INNER = False
            NasRx, err = NAS.parse_NAS5G(nas_pdu, inner=False)
            TS24007.IE.DECODE_INNER = True
            if err:
                return None, ran_ue_id
            sh = NasRx[0]['SecHdr'].get_val()
            if sh != 0:
                # in 5G, initial NAS message have directly a reduced list of clear-text IEs
                # therefore a security header there is invalid
                self._log('WNG', 'Unable to get UE id from NAS message, invalid initial '\
                          'NAS message with security')
                return None, ran_ue_id
            else:
                # clear-text NAS PDU
                if '5GSID' in NasRx._by_name and not NasRx['5GSID'].get_trans():
                    fgsid = NasRx['5GSID'][-1].get_val()
                else:
                    self._log('WNG', 'Unable to get UE id from NAS message, missing 5GSID IE')
                    return None, ran_ue_id
                FgsId = NAS.FGSID()
                FgsId.from_bytes(fgsid)
                FgsIdType = FgsId['Type'].get_val()
                if FgsIdType == FGSIDTYPE_SUPI and FgsId['Fmt'].get_val() == FGSIDFMT_IMSI:
                    psid = FgsId['Value']['ProtSchemeID'].get_val()
                    if psid == 0:
                        # clear-text IMSI
                        imsi = FgsId['Value']['PLMN'].decode() + \
                               FgsId['Value']['Output'].get_alt().decode()
                        return self.Server.get_ued(imsi=imsi), ran_ue_id
                    elif psid in (1, 2):
                        # std ECIES protection, use the AuC-SIDF to decrypt it
                        hnpkid = FgsId['Value']['HNPKID'].get_val()
                        ephpubk, cipht, mac = FgsId['Value']['Output'].get_val() 
                        msin = self.Server.AUCd.sidf_unconceal(hnpkid, ephpubk, cipht, mac)
                        if msin is None:
                            # invalid SUCI
                            self._log('WNG', 'Unable to get UE id from NAS message, invalid SUCI')
                            return None, ran_ue_id
                        else:
                            imsi = FgsId['Value']['PLMN'].decode() + NAS.decode_bcd(msin)
                            return self.Server.get_ued(imsi=imsi), ran_ue_id
                    else:
                        return None, ran_ue_id
                elif FgsIdType == FGSIDTYPE_GUTI:
                    # TODO: should ensure PLMN and AMF identifiers correspond
                    return self.Server.get_ued(fgtmsi=FgsId['5GTMSI'].get_val()), ran_ue_id 
                else:
                    self._log('WNG', 'Unable to get UE id from NAS message, 5GSID of '\
                              'unexpected type %i' % FgsIdType)
                    return None, ran_ue_id
    
    def get_gnb_ue_ctx_id(self, pdu_rx):
        gnb_ue_id = None
        for ie in pdu_rx[1]['value'][1]['protocolIEs']:
            if ie['id'] == 85:
                # RAN-UE-NGAP-ID
                gnb_ue_id = ie['value'][1]
                break
        return gnb_ue_id
    
    #--------------------------------------------------------------------------#
    # CN-initiated non-UE-associated NGAP signalling procedures
    #--------------------------------------------------------------------------#
    
    def page(self, **IEs):
        """send a NGAP Paging message to the gNB
        """
        # TODO
        pass
    
    def send_err(self, **IEs):
        """send a NGAP Error Indication to the gNB
        """
        # TODO
        pass
    
