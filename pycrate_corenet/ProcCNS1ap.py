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
# * File Name : pycrate_corenet/ProcCNS1ap.py
# * Created : 2017-11-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'S1APSigProc',
    'S1APNonUESigProc',
    #
    'S1APERABSetup',
    'S1APERABModify',
    'S1APERABRelease',
    'S1APERABModificationInd',
    'S1APInitialContextSetup',
    'S1APUEContextReleaseRequest',
    'S1APUEContextRelease',
    'S1APUEContextModification',
    'S1APUERadioCapabilityMatch',
    'S1APUEContextModificationInd',
    'S1APUEContextSuspend',
    'S1APUEContextResume',
    'S1APConnectionEstablishmentInd',
    'S1APHandoverPreparation',
    'S1APHandoverResourceAllocation',
    'S1APHandoverNotification',
    'S1APPathSwitchRequest',
    'S1APHandoverCancel',
    'S1APENBStatusTransfer',
    'S1APMMEStatusTransfer',
    'S1APPaging',
    'S1APInitialUEMessage',
    'S1APDownlinkNASTransport',
    'S1APUplinkNASTransport',
    'S1APNASNonDeliveryInd',
    'S1APRerouteNASRequest',
    'S1APResetCN',
    'S1APResetENB',
    'S1APErrorIndNonUECN',
    'S1APErrorIndNonUEENB',
    'S1APErrorIndCN',
    'S1APErrorIndENB',
    'S1APS1Setup',
    'S1APENBConfigUpdate',
    'S1APMMEConfigUpdate',
    'S1APOverloadStart',
    'S1APOverloadStop',
    'S1APDownlinkS1CDMA2000Tunnelling',
    'S1APUplinkS1CDMA2000Tunnelling',
    'S1APUECapabilityInfoInd',
    'S1APTraceStart',
    'S1APTraceFailureInd',
    'S1APDeactivateTrace',
    'S1APCellTrafficTrace',
    'S1APLocationReportingControl',
    'S1APLocationReportFailure',
    'S1APLocationReport',
    'S1APWriteReplaceWarning',
    'S1APKill',
    'S1APPWSRestartInd',
    'S1APPWSFailureInd',
    'S1APENBDirectInfoTransfer',
    'S1APMMEDirectInfoTransfer',
    'S1APENBConfigTransfer',
    'S1APMMEConfigTransfer',
    'S1APDownlinkUELPPaTransport',
    'S1APUplinkUELPPaTransport',
    'S1APDownlinkNonUELPPaTransport',
    'S1APUplinkNonUELPPaTransport',
    #
    'S1APProcEnbDispatcher',
    'S1APProcCnDispatcher',
    'S1APNonUEProcEnbDispatcher',
    'S1APNonUEProcCnDispatcher'
    ]

from .utils     import *
from .ProcProto import *

#------------------------------------------------------------------------------#
# S1AP signalling procedure
# TS 36.413, version d30
# Core Network side
#------------------------------------------------------------------------------#

class S1APSigProc(LinkSigProc):
    """S1AP UE-associated signalling procedure handler
    
    instance attributes:
        - Name  : procedure name
        - S1    : reference to the S1d instance running this procedure
        - ENB   : reference to the ENBd instance connected by S1
        - Server: reference to the CorenetServer instance handling the eNB
        - UE    : reference to the UEd instance connected by S1
        - Desc  : ASN.1 procedure description
        - Code  : procedure code
        - Crit  : procedure criticality
        - Cont  : ASN.1 procedure PDU(s) content
        - Encod : custom PDU encoders with fixed values
        - Decod : custom PDU decoders with transform functions
    """
    
    TRACK_PDU = True
    
    # for UE-related signalling
    UE = None
    
    def __init__(self, s1d):
        #
        self.Name   = self.__class__.__name__
        self.S1     = s1d
        self.ENB    = s1d.ENB
        self.Server = s1d.ENB.Server
        if s1d.UE:
            self.UE = s1d.UE
        else:
            self._log('WNG', 'no UEd instance attached')
        #
        # to store PDU traces
        self._pdu = []
        # list of PDU to be sent to the eNB
        self._pdu_tx = []
        # enable NAS procedure to set callback to .postprocess() before self terminates
        self._cb = None
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.S1._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def _recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.errcause, self.UEInfo = None, {}
        try:
            self.decode_pdu(pdu, self.UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu (%s), sending error indication' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
    
    def recv(self, pdu):
        self._recv(pdu)
        self._log('ERR', 'recv() not implemented')
    
    def _send(self):
        if self.TRACK_PDU:
            for pdu in self._pdu_tx:
                self._pdu.append( (time(), 'DL', pdu) )
        return self._pdu_tx
    
    def send(self):
        self._log('ERR', 'send() not implemented')
        return self._send()
    
    def trigger(self):
        return []
    
    def abort(self):
        if self.Code in self.S1.Proc:
            del self.S1.Proc[self.Code]
        self._log('INF', 'aborting')


class S1APNonUESigProc(LinkSigProc):
    """S1AP non-UE-associated signalling procedure handler
    
    instance attributes:
        - Name  : procedure name
        - ENB   : reference to the ENBd instance connected by S1
        - Server: reference to the CorenetServer instance handling the eNB
        - Desc  : ASN.1 procedure description
        - Code  : procedure code
        - Crit  : procedure criticality
        - Cont  : ASN.1 procedure PDU(s) content
        - Encod : custom PDU encoders with fixed values
        - Decod : custom PDU decoders with transform functions
    """
    
    TRACK_PDU = True
    
    def __init__(self, enbd):
        #
        self.Name   = self.__class__.__name__
        self.ENB    = enbd
        self.Server = enbd.Server
        #
        # to store PDU traces
        self._pdu = []
        # list of PDU to be sent to the HNB
        self._pdu_tx = []
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.ENB._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def _recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.errcause, self.ENBInfo = None, {}
        try:
            self.decode_pdu(pdu, self.ENBInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu (%s), sending error indication' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
    
    def recv(self, pdu):
        self._recv(pdu)
        self._log('ERR', 'recv() not implemented')
    
    def _send(self):
        if self.TRACK_PDU:
            for pdu in self._pdu_tx:
                self._pdu.append( (time(), 'DL', pdu) )
        return self._pdu_tx
    
    def send(self):
        self._log('ERR', 'send() not implemented')
        return self._send()
    
    def trigger(self):
        return []
    
    def abort(self):
        if self.Code in self.ENB.Proc:
            del self.ENB.Proc[self.Code]
        self._log('INF', 'aborting')


#------------------------------------------------------------------------------#
# E-RAB Management procedures
# TS 36.413, section 8.2
#------------------------------------------------------------------------------#

class S1APERABSetup(S1APSigProc):
    """E-RAB Setup: TS 36.413, section 8.2.1
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 16: E_RABToBeSetupListBearerSUReq (M)
      - 66: UEAggregateMaximumBitrate (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 28: E_RABSetupListBearerSURes (O)
      - 29: E_RABList (O)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.e_RABSetup
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


class S1APERABModify(S1APSigProc):
    """E-RAB Modify: TS 36.413, section 8.2.2
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 30: E_RABToBeModifiedListBearerModReq (M)
      - 66: UEAggregateMaximumBitrate (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 31: E_RABModifyListBearerModRes (O)
      - 32: E_RABList (O)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.e_RABModify
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


class S1APERABRelease(S1APSigProc):
    """E-RAB Release: TS 36.413, section 8.2.3
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 26: NAS_PDU (O)
      - 33: E_RABList (M)
      - 66: UEAggregateMaximumBitrate (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 34: E_RABList (O)
      - 58: CriticalityDiagnostics (O)
      - 69: E_RABReleaseListBearerRelComp (O)
      - 189: UserLocationInformation (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.e_RABRelease
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


class S1APERABModificationInd(S1APSigProc):
    """E-RAB Modification Indication: TS 36.413, section 8.2.4
    
    eNB-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 176: TunnelInformation (O)
      - 199: E_RABToBeModifiedListBearerModInd (M)
      - 201: E_RABNotToBeModifiedListBearerModInd (O)
      - 226: CSGMembershipInfo (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
      - 146: CSGMembershipStatus (O)
      - 203: E_RABModifyListBearerModConf (O)
      - 205: E_RABList (O)
      - 210: E_RABList (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.e_RABModificationIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


#------------------------------------------------------------------------------#
# Context Management procedures
# TS 36.413, section 8.3
#------------------------------------------------------------------------------#

class S1APInitialContextSetup(S1APSigProc):
    """Initial Context Setup: TS 36.413, section 8.3.1
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 24: E_RABToBeSetupListCtxtSUReq (M)
      - 25: TraceActivation (O)
      - 41: HandoverRestrictionList (O)
      - 66: UEAggregateMaximumBitrate (M)
      - 73: SecurityKey (M)
      - 74: UERadioCapability (O)
      - 75: GUMMEI (O)
      - 106: SubscriberProfileIDforRFP (O)
      - 107: UESecurityCapabilities (M)
      - 108: CSFallbackIndicator (O)
      - 124: SRVCCOperationPossible (O)
      - 146: CSGMembershipStatus (O)
      - 158: MME_UE_S1AP_ID (O)
      - 159: LAI (O)
      - 165: ManagementBasedMDTAllowed (O)
      - 177: MDTPLMNList (O)
      - 187: AdditionalCSFallbackIndicator (C)
      - 192: Masked_IMEISV (O)
      - 195: ProSeAuthorized (O)
      - 196: ExpectedUEBehaviour (O)
      - 241: UEUserPlaneCIoTSupportIndicator (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 48: E_RABList (O)
      - 51: E_RABSetupListCtxtSURes (M)
      - 58: CriticalityDiagnostics (O)
    UnsuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.initialContextSetup
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    def send(self):
        self._enable_gtpu()
        return self._send()
    
    def _enable_gtpu(self):
        if hasattr(self, '_gtp_add_mobile_ebi'):
            for erab in self._gtp_add_mobile_ebi:
                pdncfg = self.S1.ESM.PDN[erab]
                rabcfg = pdncfg['RAB']
                pdncfg['state'] = 1
                self.UE.Server.GTPUd.add_mobile(
                    rabcfg['SGW-GTP-TEID'], # teid_ul
                    pdncfg['PDNAddr'], # mobile_addr
                    (rabcfg['SGW-TLA'], rabcfg['ENB-TLA']), # local gtpu addr, enb gtpu ip (maybe None)
                    rabcfg['ENB-GTP-TEID']) # teid_dl (maybe None)
        else:
            self._log('WNG', 'enable_gtpu: no GTP mobile info provided')
    
    def _disable_gtpu(self):
        if hasattr(self, '_gtp_rem_mobile_ebi'):
            for erab in self._gtp_rem_mobile_ebi:
                if erab in self.S1.ESM.PDN:
                    pdncfg = self.S1.ESM.PDN[erab]
                    self.Server.GTPUd.rem_mobile(pdncfg['RAB']['SGW-GTP-TEID'])
                    pdncfg['state'] = 0
        else:
            self._log('WNG', 'disable_gtpu: no GTP mobile info provided')
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.S1.Proc[self.Code]
        except Exception:
            pass
        #
        if self.errcause:
            self._log('WNG', 'error in the response decoding')
            self.success = False
            if hasattr(self, '_gtp_add_mobile_ebi'):
                self._gtp_rem_mobile_ebi = self._gtp_add_mobile_ebi
                self._disable_gtpu()
        #
        elif pdu[0] == 'unsuccessfulOutcome':
            try:
                self._log('WNG', 'failure, rejected with cause %r' % (self.UEInfo['Cause'], ))
            except Exception:
                self._log('WNG', 'failure, rejected without cause')
            self.success = False
            if hasattr(self, '_gtp_add_mobile_ebi'):
                self._gtp_rem_mobile_ebi = self._gtp_add_mobile_ebi
                self._disable_gtpu()
        #
        else:
            self.success = True
            # E-RAB successfully established, to be completed with eNB IP and TEID
            for erabsetupitem in self.UEInfo['E_RABSetupListCtxtSURes']:
                erabsetupitem = erabsetupitem['value'][1]
                erab = erabsetupitem['e-RAB-ID']
                if erab in self._gtp_add_mobile_ebi:
                    rabcfg = self.S1.ESM.PDN[erab]['RAB']
                    rabcfg['ENB-TLA'] = inet_ntoa(uint_to_bytes(*erabsetupitem['transportLayerAddress']))
                    rabcfg['ENB-GTP-TEID'] = bytes_to_uint(erabsetupitem['gTP-TEID'], 32)
                    # activate the DL parameters
                    self.Server.GTPUd.set_mobile_dl(
                        rabcfg['SGW-GTP-TEID'], # teid_ul
                        ran_ip=(rabcfg['SGW-TLA'], rabcfg['ENB-TLA']),
                        teid_dl=rabcfg['ENB-GTP-TEID'])
            # E-RAB failed to established
            if 'E_RABList' in self.UEInfo:
                self._gtp_rem_mobile_ebi = []
                for erabitem in self.UEInfo['E_RABList']:
                    erabitem = erabitem['value'][1]
                    erab = erabitem['e-RAB-ID']
                    if erab in self._gtp_add_mobile_ebi:
                        self._gtp_rem_mobile_ebi.append(erab)
                        self._log('INF', 'unable to establish E-RAB %i, cause %r'\
                                  % (erab, erabitem['cause']))
                self._disable_gtpu()
    
    def abort(self):
        S1APSigProc.abort(self)
        if hasattr(self, '_gtp_add_mobile_ebi'):
            self._gtp_rem_mobile_ebi = self._gtp_add_mobile_ebi
            self._disable_gtpu()


class S1APUEContextReleaseRequest(S1APSigProc):
    """UE Context Release Request (eNB initiated): TS 36.413, section 8.3.2
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 164: GWContextReleaseIndication (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uEContextReleaseRequest
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    recv = S1APSigProc._recv
    
    def trigger(self):
        # copy the cause signaled by the eNB
        Proc = self.S1.init_s1ap_proc(S1APUEContextRelease,
                                      Cause=self.UEInfo['Cause'],
                                      UE_S1AP_IDs=('uE-S1AP-ID-pair',
                                                   {'mME-UE-S1AP-ID': self.S1.CtxId,
                                                    'eNB-UE-S1AP-ID': self.S1.CtxId}))
        if Proc:
            return [Proc]
        else:
            return []


class S1APUEContextRelease(S1APSigProc):
    """UE Context Release (MME initiated): TS 36.413, section 8.3.3
    
    CN-initiated
    request
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 2: Cause (M)
      - 99: UE_S1AP_IDs (M)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
      - 189: UserLocationInformation (O)
      - 212: CellIdentifierAndCELevelForCECapableUEs (O)
      - 213: InformationOnRecommendedCellsAndENBsForPaging (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uEContextRelease
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    send = S1APSigProc._send
    
    def _release_s1(self):
        # suspend all RAB
        self.S1.ESM.pdn_suspend()
        # update mobility state
        if self.S1.EMM.state != 'INACTIVE':
            self.S1.EMM.state = 'IDLE'
        self._log('INF', 'UE disconnected, cause %r' % (self._NetInfo['Cause'], ))
        #
        # disconnect the S1 interface to the eNB for the UE
        self.S1.unset_ran()
        self.S1.unset_ctx()
    
    def recv(self, pdu):
        # recv the S1APUEContextRelease response
        self._recv(pdu)
        # remove from the S1AP procedure stack
        try:
            del self.S1.Proc[self.Code]
        except Exception:
            pass
        self._release_s1()
    
    def abort(self):
        # remove from the S1AP procedure stack
        try:
            del self.S1.Proc[self.Code]
        except Exception:
            pass
        self._log('INF', 'aborting')
        self._release_s1()


class S1APUEContextModification(S1APSigProc):
    """UE Context Modification: TS 36.413, section 8.3.4
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 66: UEAggregateMaximumBitrate (O)
      - 73: SecurityKey (O)
      - 106: SubscriberProfileIDforRFP (O)
      - 107: UESecurityCapabilities (O)
      - 108: CSFallbackIndicator (O)
      - 146: CSGMembershipStatus (O)
      - 159: LAI (O)
      - 187: AdditionalCSFallbackIndicator (C)
      - 195: ProSeAuthorized (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
    UnsuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uEContextModification
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class S1APUERadioCapabilityMatch(S1APSigProc):
    """UE Radio Capability Match: TS 36.413, section 8.3.5
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 74: UERadioCapability (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
      - 169: VoiceSupportMatchIndicator (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uERadioCapabilityMatch
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


class S1APUEContextModificationInd(S1APSigProc):
    """UE Context Modification Indication: TS 36.413, section 8.3.6
    
    eNB-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 226: CSGMembershipInfo (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
      - 146: CSGMembershipStatus (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uEContextModificationIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


class S1APUEContextSuspend(S1APNonUESigProc):
    """UE Context Suspend: TS 36.413, section 8.3.7
    
    eNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 212: CellIdentifierAndCELevelForCECapableUEs (O)
      - 213: InformationOnRecommendedCellsAndENBsForPaging (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uEContextSuspend
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


class S1APUEContextResume(S1APNonUESigProc):
    """UE Context Resume: TS 36.413, section 8.3.8
    
    eNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 235: E_RABFailedToResumeListResumeReq (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
      - 237: E_RABFailedToResumeListResumeRes (O)
    UnsuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uEContextResume
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class S1APConnectionEstablishmentInd(S1APSigProc):
    """Connection Establishment Indication: TS 36.413, section 8.3.9
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 74: UERadioCapability (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.connectionEstablishmentIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


#------------------------------------------------------------------------------#
# Handover Signalling
# TS 36.413, section 8.4
#------------------------------------------------------------------------------#

class S1APHandoverPreparation(S1APNonUESigProc):
    """Handover Preparation: TS 36.413, section 8.4.1
    
    eNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 1: HandoverType (M)
      - 2: Cause (M)
      - 4: TargetID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 79: Direct_Forwarding_Path_Availability (O)
      - 104: Source_ToTarget_TransparentContainer (M)
      - 125: SRVCCHOIndication (O)
      - 127: CSG_Id (O)
      - 132: MSClassmark2 (C)
      - 133: MSClassmark3 (C)
      - 138: Source_ToTarget_TransparentContainer (O)
      - 145: CellAccessMode (O)
      - 150: PS_ServiceNotAvailable (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 1: HandoverType (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 12: E_RABSubjecttoDataForwardingList (O)
      - 13: E_RABList (O)
      - 58: CriticalityDiagnostics (O)
      - 123: Target_ToSource_TransparentContainer (M)
      - 135: NASSecurityParametersfromE_UTRAN (C)
      - 139: Target_ToSource_TransparentContainer (O)
    UnsuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.handoverPreparation
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class S1APHandoverResourceAllocation(S1APNonUESigProc):
    """Handover Resource Allocation: TS 36.413, section 8.4.2
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 1: HandoverType (M)
      - 2: Cause (M)
      - 25: TraceActivation (O)
      - 40: SecurityContext (M)
      - 41: HandoverRestrictionList (O)
      - 53: E_RABToBeSetupListHOReq (M)
      - 66: UEAggregateMaximumBitrate (M)
      - 75: GUMMEI (O)
      - 98: RequestType (O)
      - 104: Source_ToTarget_TransparentContainer (M)
      - 107: UESecurityCapabilities (M)
      - 124: SRVCCOperationPossible (O)
      - 127: CSG_Id (O)
      - 136: NASSecurityParameterstoE_UTRAN (C)
      - 146: CSGMembershipStatus (O)
      - 158: MME_UE_S1AP_ID (O)
      - 165: ManagementBasedMDTAllowed (O)
      - 177: MDTPLMNList (O)
      - 192: Masked_IMEISV (O)
      - 195: ProSeAuthorized (O)
      - 196: ExpectedUEBehaviour (O)
      - 241: UEUserPlaneCIoTSupportIndicator (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 18: E_RABAdmittedList (M)
      - 19: E_RABFailedtoSetupListHOReqAck (O)
      - 58: CriticalityDiagnostics (O)
      - 123: Target_ToSource_TransparentContainer (M)
      - 127: CSG_Id (O)
      - 145: CellAccessMode (O)
    UnsuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.handoverResourceAllocation
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class S1APHandoverNotification(S1APNonUESigProc):
    """Handover Notification: TS 36.413, section 8.4.3
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 67: TAI (M)
      - 100: EUTRAN_CGI (M)
      - 176: TunnelInformation (O)
      - 186: LHN_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.handoverNotification
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APPathSwitchRequest(S1APNonUESigProc):
    """Path Switch Request: TS 36.413, section 8.4.4
    
    eNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 8: ENB_UE_S1AP_ID (M)
      - 22: E_RABToBeSwitchedDLList (M)
      - 67: TAI (M)
      - 88: MME_UE_S1AP_ID (M)
      - 100: EUTRAN_CGI (M)
      - 107: UESecurityCapabilities (M)
      - 127: CSG_Id (O)
      - 145: CellAccessMode (O)
      - 146: CSGMembershipStatus (O)
      - 157: GUMMEI (O)
      - 176: TunnelInformation (O)
      - 186: LHN_ID (O)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 33: E_RABList (O)
      - 40: SecurityContext (M)
      - 58: CriticalityDiagnostics (O)
      - 66: UEAggregateMaximumBitrate (O)
      - 95: E_RABToBeSwitchedULList (O)
      - 146: CSGMembershipStatus (O)
      - 158: MME_UE_S1AP_ID (O)
      - 195: ProSeAuthorized (O)
      - 241: UEUserPlaneCIoTSupportIndicator (O)
    UnsuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.pathSwitchRequest
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class S1APHandoverCancel(S1APSigProc):
    """Handover Cancellation: TS 36.413, section 8.4.5
    
    eNB-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
    SuccessfulOutcome:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.handoverCancel
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


class S1APENBStatusTransfer(S1APNonUESigProc):
    """eNB Status Transfer: TS 36.413, section 8.4.6
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 90: ENB_StatusTransfer_TransparentContainer (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.eNBStatusTransfer
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APMMEStatusTransfer(S1APNonUESigProc):
    """MME Status Transfer: TS 36.413, section 8.4.7
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 90: ENB_StatusTransfer_TransparentContainer (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.mMEStatusTransfer
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


#------------------------------------------------------------------------------#
# Paging
# TS 36.413, section 8.5
#------------------------------------------------------------------------------#

class S1APPaging(S1APNonUESigProc):
    """Paging: TS 36.413, section 8.5
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 43: UEPagingID (M)
      - 44: PagingDRX (O)
      - 46: TAIList (M)
      - 80: UEIdentityIndexValue (M)
      - 109: CNDomain (M)
      - 128: CSG_IdList (O)
      - 151: PagingPriority (O)
      - 198: UERadioCapabilityForPaging (O)
      - 211: AssistanceDataForPaging (O)
      - 227: Paging_eDRXInformation (O)
      - 231: Extended_UEIdentityIndexValue (O)
      - 239: NB_IoT_Paging_eDRXInformation (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.paging
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
   
    send = S1APNonUESigProc._send


#------------------------------------------------------------------------------#
# NAS transport
# TS 36.413, section 8.6
#------------------------------------------------------------------------------#

class S1APInitialUEMessage(S1APSigProc):
    """Initial UE Message: TS 36.413, section 8.6.2.1
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 8: ENB_UE_S1AP_ID (M)
      - 26: NAS_PDU (M)
      - 67: TAI (M)
      - 75: GUMMEI (O)
      - 96: S_TMSI (O)
      - 100: EUTRAN_CGI (M)
      - 127: CSG_Id (O)
      - 134: RRC_Establishment_Cause (M)
      - 145: CellAccessMode (O)
      - 155: TransportLayerAddress (O)
      - 160: RelayNode_Indicator (O)
      - 170: GUMMEIType (O)
      - 176: TunnelInformation (O)
      - 184: TransportLayerAddress (O)
      - 186: LHN_ID (O)
      - 223: MME_Group_ID (O)
      - 230: UE_Usage_Type (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.initialUEMessage
    
    # Custom decoders
    Decod = {
        'ini': ({
            'TAI'       : lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                                     bytes_to_uint(x['tAC'], 16)),
            'EUTRAN_CGI': lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                                     cellid_bstr_to_str(x['cell-ID']))
            }, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
        if not self.errcause:
            # verification against ENBd parameters and S1AP infos:
            err = False
            if self.UEInfo['EUTRAN_CGI'][0] != self.ENB.ID[0] or \
            self.UEInfo['EUTRAN_CGI'][1][:5] != self.ENB.ID[1][:5]:
                self._log('WNG', 'invalid EUTRAN-CGI %s.%s' % self.UEInfo['EUTRAN_CGI'])
                err = True
            if self.UEInfo['TAI'] not in self.ENB.Config['TAIs']:
                self._log('WNG', 'invalid TAI, %s.%.4x' % self.UEInfo['TAI'])
                err = True
            if err:
                self.errcause = ('protocol', 'message-not-compatible-with-receiver-state')
        #
        if not self.errcause:
            self.S1.EMM.state = 'ACTIVE'
            self._log('INF', 'RRC establishment cause: %s' % self.UEInfo['RRC_Establishment_Cause'])
            self.UE.set_tai(*self.UEInfo['TAI'])
            self._ret = self.S1.process_nas(self.UEInfo['NAS_PDU'])
    
    def trigger(self):
        return self._ret


class S1APDownlinkNASTransport(S1APSigProc):
    """Downlink NAS Transport: TS 36.413, section 8.6.2.2
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 26: NAS_PDU (M)
      - 41: HandoverRestrictionList (O)
      - 74: UERadioCapability (O)
      - 106: SubscriberProfileIDforRFP (O)
      - 124: SRVCCOperationPossible (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.downlinkNASTransport
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    send = S1APSigProc._send


class S1APUplinkNASTransport(S1APSigProc):
    """Uplink NAS Transport: TS 36.413, section 8.6.2.3
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 26: NAS_PDU (M)
      - 67: TAI (M)
      - 100: EUTRAN_CGI (M)
      - 155: TransportLayerAddress (O)
      - 184: TransportLayerAddress (O)
      - 186: LHN_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uplinkNASTransport
    
    # Custom decoders
    Decod = {
        'ini': ({
            'TAI'       : lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                                     bytes_to_uint(x['tAC'], 16)),
            'EUTRAN_CGI': lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                                     cellid_bstr_to_str(x['cell-ID']))
            }, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
        if not self.errcause:
            # verification against ENBd parameters and S1AP infos:
            err = False
            if self.UEInfo['EUTRAN_CGI'][0] != self.ENB.ID[0] or \
            self.UEInfo['EUTRAN_CGI'][1][:5] != self.ENB.ID[1][:5]:
                self._log('WNG', 'invalid EUTRAN-CGI %s.%s' % self.UEInfo['EUTRAN_CGI'])
                err = True
            if self.UEInfo['TAI'] not in self.ENB.Config['TAIs']:
                self._log('WNG', 'invalid TAI, %s.%.4x' % self.UEInfo['TAI'])
                err = True
            if err:
                self.errcause = ('protocol', 'message-not-compatible-with-receiver-state')
        #
        if not self.errcause:
            self._ret = self.S1.process_nas(self.UEInfo['NAS_PDU'])
    
    def trigger(self):
        return self._ret


class S1APNASNonDeliveryInd(S1APSigProc):
    """NAS Non Delivery Indication: TS 36.413, section 8.6.2.4
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 26: NAS_PDU (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.nASNonDeliveryIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APRerouteNASRequest(S1APSigProc):
    """Reroute NAS Request: TS 36.413, section 8.6.2.5
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (O)
      - 8: ENB_UE_S1AP_ID (M)
      - 223: MME_Group_ID (M)
      - 224: Additional_GUTI (O)
      - 225: [OCTET STRING] (M)
      - 230: UE_Usage_Type (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.rerouteNASRequest
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


#------------------------------------------------------------------------------#
# Management procedures
# TS 36.413, section 8.7
#------------------------------------------------------------------------------#

class S1APResetCN(S1APNonUESigProc):
    """Reset: TS 36.413, section 8.7.1 and 8.7.1.2.1
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 2: Cause (M)
      - 92: ResetType (M)
    SuccessfulOutcome:
      IEs:
      - 58: CriticalityDiagnostics (O)
      - 93: UE_associatedLogicalS1_ConnectionListResAck (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.reset
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    send = S1APNonUESigProc._send
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.ENB.Proc[self.Code]
        except Exception:
            pass
        if not self.errcause:
            self._log('INF', 'success')


class S1APResetENB(S1APNonUESigProc):
    """Reset: TS 36.413, section 8.7.1 and 8.7.1.2.2
    
    eNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 2: Cause (M)
      - 92: ResetType (M)
    SuccessfulOutcome:
      IEs:
      - 58: CriticalityDiagnostics (O)
      - 93: UE_associatedLogicalS1_ConnectionListResAck (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.reset
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            if self.ENBInfo['ResetType'][0] == 's1-Interface':
                # reset all resources
                self._log('INF', 'complete s1 interface, cause %r' % (self.ENBInfo['Cause'], ))
                for ue in self.ENB.UE.values():
                    ue.S1.unset_ran()
                    ue.S1.unset_ctx()
                # prepare the reset response
                self.encode_pdu('suc')
                
            else:
                # reset only listed resources
                self._log('INF', 'part of s1 interface, cause %r' % (self.ENBInfo['Cause'], ))
                # get the list of enb-ue-id to reset
                ue_res_list, ue_ack_list = self.ENBInfo['ResetType'][1], []
                for res in ue_res_list:
                    if res['id'] == 91 and res['Value'][0] == 'UE-associatedLogicalS1-ConnectionItem':
                        conitem = res['Value'][1]
                        if 'eNB-UE-S1AP-ID' in conitem:
                            uectx = conitem['eNB-UE-S1AP-ID']
                        elif 'mME-UE-S1AP-ID' in conitem:
                            uectx = conitem['mME-UE-S1AP-ID']
                        else:
                            uectx = None
                        if uectx is not None:
                            if uectx in self.ENB.UE:
                                ue = self.ENB.UE[enbid]
                                ue.S1.unset_ran()
                                ue.S1.unset_ctx()
                            ue_ack_list.append(res)
                # prepare the reset response
                self.encode_pdu('suc', E_associatedLogicalS1_ConnectionListResAck=ue_ack_list)
    
    send = S1APNonUESigProc._send


class S1APErrorIndNonUECN(S1APNonUESigProc):
    """Error Indication: TS 36.413, section 8.7.2
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (O)
      - 2: Cause (O)
      - 8: ENB_UE_S1AP_ID (O)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.errorIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    errcause = None
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
    
    send = S1APNonUESigProc._send


class S1APErrorIndNonUEENB(S1APNonUESigProc):
    """Error Indication: TS 36.413, section 8.7.2
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (O)
      - 2: Cause (O)
      - 8: ENB_UE_S1AP_ID (O)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.errorIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause and 'Cause' in self.ENBInfo:
            self._log('WNG', 'error ind received: %r' % (self.ENBInfo['Cause'], ))
            # if it corresponds to an said-unknown UE ID, disconnect the UE instance
            if self.ENBInfo['Cause'] == ('radioNetwork', 'unknown-enb-ue-s1ap-id') \
            and 'MME_UE_S1AP_ID' in self.ENBInfo \
            and self.ENBInfo['MME_UE_S1AP_ID'] in self.ENB.UE:
                ue = self.ENB.UE[self.ENBInfo['MME_UE_S1AP_ID']]
                if ue.S1.is_connected():
                    self._log('INF', 'UE %s to be disconnected' % ue.IMSI)
                    ue.S1.unset_ran()
            # if it corresponds to a previously CN-initiated class 1 procedure
            # abort it
            try:
                self.ENB.Proc[self.ENB.ProcLast].abort()
            except Exception:
                pass


class S1APErrorIndCN(S1APSigProc):
    """Error Indication: TS 36.413, section 8.7.2
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (O)
      - 2: Cause (O)
      - 8: ENB_UE_S1AP_ID (O)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.errorIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    errcause = None
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
    
    send = S1APSigProc._send


class S1APErrorIndENB(S1APSigProc):
    """Error Indication: TS 36.413, section 8.7.2
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (O)
      - 2: Cause (O)
      - 8: ENB_UE_S1AP_ID (O)
      - 58: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.errorIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            self._log('WNG', 'error ind received: %s.%i' % self.UEInfo['Cause'])
            # if it corresponds to a previously CN-initiated class 1 procedure
            # abort it
            try:
                self.S1.Proc[self.S1.ProcLast].abort()
            except Exception:
                pass


class S1APS1Setup(S1APNonUESigProc):
    """S1 Setup: TS 36.413, section 8.7.3
    
    eNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 59: Global_ENB_ID (M)
      - 60: ENBname (O)
      - 64: SupportedTAs (M)
      - 128: CSG_IdList (O)
      - 137: PagingDRX (M)
      - 228: UE_RetentionInformation (O)
      - 234: NB_IoT_DefaultPagingDRX (O)
    SuccessfulOutcome:
      IEs:
      - 58: CriticalityDiagnostics (O)
      - 61: MMEname (O)
      - 87: RelativeMMECapacity (M)
      - 105: ServedGUMMEIs (M)
      - 163: MMERelaySupportIndicator (O)
      - 228: UE_RetentionInformation (O)
    UnsuccessfulOutcome:
      IEs:
      - 2: Cause (M)
      - 58: CriticalityDiagnostics (O)
      - 65: TimeToWait (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.s1Setup
    
    # Custom decoders
    Decod = {
        'ini': ({
            'Global_ENB_ID': globenbid_to_hum,
            'SupportedTAs': supptas_to_hum,
            },
            {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    def recv(self, pdu):
        # recv the S1SetupRequest
        self._recv(pdu)
        if self.errcause:
            # procedure unsuccessful outcome
            self.encode_pdu('uns', Cause=self.errcause)
            self._log('INF', 'eNB S1 not setup successfully')
        else:
            self.ENB.Config = cpdict(self.ENBInfo)
            self.ENB.Config['TAIs'] = []
            for tas in self.ENBInfo['SupportedTAs']:
                for plmn in tas['broadcastPLMNs']:
                    if plmn == self.Server.PLMN or \
                    self.Server.EQUIV_PLMN and plmn in self.Server.EQUIV_PLMN:
                        # supported PLMN by Corenet
                        self.ENB.Config['TAIs'].append( (plmn, tas['tAC']) )
            self.ENB.ID = (self.ENBInfo['Global_ENB_ID']['pLMNidentity'],
                           self.ENBInfo['Global_ENB_ID']['eNB-ID'][1])
            # prepare the S1SetupResponse
            IEs = self.ENB.get_s1setup_ies_from_cfg()
            self.encode_pdu('suc', **IEs)
            self._log('INF', 'eNB S1 setup successfully')
    
    send = S1APNonUESigProc._send


class S1APENBConfigUpdate(S1APNonUESigProc):
    """eNB Configuration Update: TS 36.413, section 8.7.4
    
    eNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 60: ENBname (O)
      - 64: SupportedTAs (O)
      - 128: CSG_IdList (O)
      - 137: PagingDRX (O)
      - 234: NB_IoT_DefaultPagingDRX (O)
    SuccessfulOutcome:
      IEs:
      - 58: CriticalityDiagnostics (O)
    UnsuccessfulOutcome:
      IEs:
      - 2: Cause (M)
      - 58: CriticalityDiagnostics (O)
      - 65: TimeToWait (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.eNBConfigurationUpdate
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class S1APMMEConfigUpdate(S1APNonUESigProc):
    """MME Configuration Update: TS 36.413, section 8.7.5
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 61: MMEname (O)
      - 87: RelativeMMECapacity (O)
      - 105: ServedGUMMEIs (O)
    SuccessfulOutcome:
      IEs:
      - 58: CriticalityDiagnostics (O)
    UnsuccessfulOutcome:
      IEs:
      - 2: Cause (M)
      - 58: CriticalityDiagnostics (O)
      - 65: TimeToWait (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.mMEConfigurationUpdate
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class S1APOverloadStart(S1APNonUESigProc):
    """Overload Start: TS 36.413, section 8.7.6
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 101: OverloadResponse (M)
      - 154: GUMMEIList (O)
      - 161: TrafficLoadReductionIndication (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.overloadStart
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APOverloadStop(S1APNonUESigProc):
    """Overload Stop: TS 36.413, section 8.7.7
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 154: GUMMEIList (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.overloadStop
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


#------------------------------------------------------------------------------#
# S1 CDMA2000 Tunnelling Procedures
# TS 36.413, section 8.8
#------------------------------------------------------------------------------#

class S1APDownlinkS1CDMA2000Tunnelling(S1APSigProc):
    """Downlink S1 CDMA2000 Tunnelling: TS 36.413, section 8.8.2.1
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 12: E_RABSubjecttoDataForwardingList (O)
      - 70: Cdma2000PDU (M)
      - 71: Cdma2000RATType (M)
      - 83: Cdma2000HOStatus (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.downlinkS1cdma2000tunnelling
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APUplinkS1CDMA2000Tunnelling(S1APSigProc):
    """Uplink S1 CDMA2000 Tunnelling: TS 36.413, section 8.8.2.1
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 70: Cdma2000PDU (M)
      - 71: Cdma2000RATType (M)
      - 72: Cdma2000SectorID (M)
      - 84: Cdma2000HORequiredIndication (O)
      - 97: Cdma2000OneXRAND (O)
      - 102: Cdma2000OneXSRVCCInfo (O)
      - 140: EUTRANRoundTripDelayEstimationInfo (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uplinkS1cdma2000tunnelling
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


#------------------------------------------------------------------------------#
# UE Capability Info Indication
# TS 36.413, section 8.9
#------------------------------------------------------------------------------#

class S1APUECapabilityInfoInd(S1APSigProc):
    """UE Capability Info Indication: TS 36.413, section 8.9
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 74: UERadioCapability (M)
      - 198: UERadioCapabilityForPaging (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uECapabilityInfoIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            # set the UERadioCapability in UE.Cap
            ueradcap, uecapinfo = decode_ue_rad_cap(self.UEInfo['UERadioCapability'])
            self.UE.Cap['UERadioCap'] = (self.UEInfo['UERadioCapability'], ueradcap, uecapinfo)
            if 'UERadioCapabilityForPaging' in self.UEInfo:
                self.UE.Cap['UERadioCapPaging'] = self.UEInfo['UERadioCapabilityForPaging']
            #
            if 'UERadioCapabilityForPaging' in self.UEInfo:
                self.UE.Cap['UERadioCapPaging'] = (self.UEInfo['UERadioCapabilityForPaging'],
                                                   None, None)


#------------------------------------------------------------------------------#
# Trace Procedures
# TS 36.413, section 8.10
#------------------------------------------------------------------------------#

class S1APTraceStart(S1APSigProc):
    """Trace Start: TS 36.413, section 8.10.1
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 25: TraceActivation (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.traceStart
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    send = S1APSigProc._send


class S1APTraceFailureInd(S1APSigProc):
    """Trace Failure Indication: TS 36.413, section 8.10.2
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 86: E_UTRAN_Trace_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.traceFailureIndication
    
    # Custom decoders
    Decod = {
        'ini': ({
            'E_UTRAN_Trace_ID': lambda x: (plmn_buf_to_str(x[:3]),
                                           bytes_to_uint(x[3:6], 24), 
                                           bytes_to_uint(x[6:8], 16)),
            }, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            # just log the failure
            self._log('INF', 'trace id %s.%.6x.%.4x, cause %r'\
                      % (self.UEInfo['E_UTRAN_Trace_ID'][0],
                         self.UEInfo['E_UTRAN_Trace_ID'][1],
                         self.UEInfo['E_UTRAN_Trace_ID'][2],
                         self.UEInfo['Cause']))


class S1APDeactivateTrace(S1APSigProc):
    """Deactivate Start: TS 36.413, section 8.10.3
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 86: E_UTRAN_Trace_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.deactivateTrace
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    send = S1APSigProc._send


class S1APCellTrafficTrace(S1APSigProc):
    """Cell Traffic Trace: TS 36.413, section 8.10.4
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 86: E_UTRAN_Trace_ID (M)
      - 100: EUTRAN_CGI (M)
      - 131: TransportLayerAddress (M)
      - 166: PrivacyIndicator (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.cellTrafficTrace
    
    # Custom decoders
    Decod = {
        'ini': ({
            'E_UTRAN_Trace_ID': lambda x: (plmn_buf_to_str(x[:3]),
                                           bytes_to_uint(x[3:6], 24), 
                                           bytes_to_uint(x[6:8], 16)),
            'EUTRAN_CGI': lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                                     cellid_bstr_to_str(x['cell-ID'])),
            }, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            # convert the TLA
            if self.UEInfo['TransportLayerAddress'][1] == 32:
                # IPv4
                addr = inet_ntoa_cn(1, uint_to_bytes(self.UEInfo['TransportLayerAddress'][0], 32))
            elif self.UEInfo['TransportLayerAddress'][1] == 128:
                # IPv6
                addr = inet_ntoa_cn(2, uint_to_bytes(self.UEInfo['TransportLayerAddress'][0], 128))
            else:
                addr = uint_to_bytes(*self.UEInfo['TransportLayerAddress'])
            # just log the indications
            self._log('INF', 'trace id %s.%.6x.%.4x, EUTRAN CGI %s.%s, address %s'\
                      % (self.UEInfo['E_UTRAN_Trace_ID'][0],
                         self.UEInfo['E_UTRAN_Trace_ID'][1],
                         self.UEInfo['E_UTRAN_Trace_ID'][2],
                         self.UEInfo['EUTRAN_CGI'][0],
                         self.UEInfo['EUTRAN_CGI'][1],
                         addr))


#------------------------------------------------------------------------------#
# Location Reporting Procedures
# TS 36.413, section 8.11
#------------------------------------------------------------------------------#

class S1APLocationReportingControl(S1APSigProc):
    """Location Reporting Control: TS 36.413, section 8.11.1
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 98: RequestType (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.locationReportingControl
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    send = S1APSigProc._send


class S1APLocationReportFailure(S1APSigProc):
    """Location Report Failure Indication: TS 36.413, section 8.11.2
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 2: Cause (M)
      - 8: ENB_UE_S1AP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.locationReportingFailureIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            # just log the failure
            self._log('INF', 'cause %r' % (self.UEInfo['Cause'], ))


class S1APLocationReport(S1APSigProc):
    """Location Report: TS 36.413, section 8.11.3
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 67: TAI (M)
      - 98: RequestType (M)
      - 100: EUTRAN_CGI (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.locationReport
    
    # Custom decoders
    Decod = {
        'ini': ({
            'TAI'       : lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                                     bytes_to_uint(x['tAC'], 16)),
            'EUTRAN_CGI': lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                                     cellid_bstr_to_str(x['cell-ID']))
            }, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            # just log the failure
            self._log('INF', 'reqtype %s, TAI %s.%.4x, EUTRAN CGI %s.%s'\
                      % (self.UEInfo['RequestType'],
                         self.UEInfo['TAI'][0],
                         self.UEInfo['TAI'][1],
                         self.UEInfo['EUTRAN_CGI'][0],
                         self.UEInfo['EUTRAN_CGI'][1]
                         ))

#------------------------------------------------------------------------------#
# Warning Message Transmission Procedures
# TS 36.413, section 8.12
#------------------------------------------------------------------------------#

class S1APWriteReplaceWarning(S1APNonUESigProc):
    """Write Replace Warning: TS 36.413, section 8.12.1
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 111: MessageIdentifier (M)
      - 112: SerialNumber (M)
      - 113: WarningAreaList (O)
      - 114: RepetitionPeriod (M)
      - 115: NumberofBroadcastRequest (M)
      - 116: WarningType (O)
      - 117: WarningSecurityInfo (O)
      - 118: DataCodingScheme (O)
      - 119: WarningMessageContents (O)
      - 142: ConcurrentWarningMessageIndicator (O)
      - 144: ExtendedRepetitionPeriod (O)
    SuccessfulOutcome:
      IEs:
      - 58: CriticalityDiagnostics (O)
      - 111: MessageIdentifier (M)
      - 112: SerialNumber (M)
      - 120: BroadcastCompletedAreaList (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.writeReplaceWarning
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    send = S1APNonUESigProc._send
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.ENB.Proc[self.Code]
        except Exception:
            pass
        if not self.errcause:
            msgid, sernum = self.ENBInfo['MessageIdentifier'][0], self.ENBInfo['SerialNumber'][0]
            if msgid != self._NetInfo['MessageIdentifier'][0]:
                self._log('MessageIdentifier mismatch: 0x%.4x instead of 0x%.4x'\
                          % (msgid, self._NetInfo['MessageIdentifier'][0]))
            elif 'BroadcastCompletedAreaList' not in self.ENBInfo \
            or not self.ENBInfo['BroadcastCompletedAreaList']:
                self._log('broadcasting failed')
            else:
                self.ENB.WARN[(msgid, sernum)] = self._NetInfo
                self._log('INF', 'broadcasting warning message')


class S1APKill(S1APNonUESigProc):
    """Kill: TS 36.413, section 8.12.2
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 111: MessageIdentifier (M)
      - 112: SerialNumber (M)
      - 113: WarningAreaList (O)
      - 191: KillAllWarningMessages (O)
    SuccessfulOutcome:
      IEs:
      - 58: CriticalityDiagnostics (O)
      - 111: MessageIdentifier (M)
      - 112: SerialNumber (M)
      - 141: BroadcastCancelledAreaList (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.kill
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    send = S1APNonUESigProc._send
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.ENB.Proc[self.Code]
        except Exception:
            pass
        if not self.errcause:
            self._log('INF', 'stopped broadcasting warning message')


class S1APPWSRestartInd(S1APNonUESigProc):
    """PWS Restart Indication: TS 36.413, section 8.12.3
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 59: Global_ENB_ID (M)
      - 182: ECGIListForRestart (M)
      - 188: TAIListForRestart (M)
      - 190: EmergencyAreaIDListForRestart (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.pWSRestartIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            self._log('INF', 'restarting broascasting warning message')


class S1APPWSFailureInd(S1APNonUESigProc):
    """PWS Failure Indication: TS 36.413, section 8.12.4
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 59: Global_ENB_ID (M)
      - 222: PWSfailedECGIList (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.pWSFailureIndication
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            self._log('INF', 'failure broascasting warning message')


#------------------------------------------------------------------------------#
# eNB / MME Direct Information Transfer
# TS 36.413, section 8.13 and 8.14
#------------------------------------------------------------------------------#

class S1APENBDirectInfoTransfer(S1APNonUESigProc):
    """eNB Direct Information Transfer: TS 36.413, section 8.13
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 121: Inter_SystemInformationTransferType (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.eNBDirectInformationTransfer
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APMMEDirectInfoTransfer(S1APNonUESigProc):
    """MME Direct Information Transfer: TS 36.413, section 8.14
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 122: Inter_SystemInformationTransferType (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.mMEDirectInformationTransfer
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


#------------------------------------------------------------------------------#
# eNB / MME Configuration Transfer
# TS 36.413, section 8.15 and 8.16
#------------------------------------------------------------------------------#

class S1APENBConfigTransfer(S1APNonUESigProc):
    """eNB Configuration Transfer: TS 36.413, section 8.15
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 129: SONConfigurationTransfer (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.eNBConfigurationTransfer
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APMMEConfigTransfer(S1APNonUESigProc):
    """eNB Configuration Transfer: TS 36.413, section 8.16
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 130: SONConfigurationTransfer (O)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.mMEConfigurationTransfer
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


#------------------------------------------------------------------------------#
# LPPa transport
# TS 36.413, section 8.17
#------------------------------------------------------------------------------#

class S1APDownlinkUELPPaTransport(S1APSigProc):
    """Downlink UE Associated LPPa Transport: TS 36.413, section 8.17.2.1
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 147: LPPa_PDU (M)
      - 148: Routing_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.downlinkUEAssociatedLPPaTransport
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APUplinkUELPPaTransport(S1APSigProc):
    """Uplink UE Associated LPPa Transport: TS 36.413, section 8.17.2.2
    
    eNB-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: MME_UE_S1AP_ID (M)
      - 8: ENB_UE_S1AP_ID (M)
      - 147: LPPa_PDU (M)
      - 148: Routing_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uplinkUEAssociatedLPPaTransport
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APDownlinkNonUELPPaTransport(S1APNonUESigProc):
    """Downlink Non UE Associated LPPa Transport: TS 36.413, section 8.17.2.3
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 147: LPPa_PDU (M)
      - 148: Routing_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.downlinkNonUEAssociatedLPPaTransport
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


class S1APUplinkNonUELPPaTransport(S1APNonUESigProc):
    """Uplink Non UE Associated LPPa Transport: TS 36.413, section 8.17.2.4
    
    eNB-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 147: LPPa_PDU (M)
      - 148: Routing_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = S1AP.S1AP_PDU_Descriptions.uplinkNonUEAssociatedLPPaTransport
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': None,
        'uns': None
        }


# initializing all S1AP procedures classes
S1APERABSetup.init()
S1APERABModify.init()
S1APERABRelease.init()
S1APERABModificationInd.init()
S1APInitialContextSetup.init()
S1APUEContextReleaseRequest.init()
S1APUEContextRelease.init()
S1APUEContextModification.init()
S1APUERadioCapabilityMatch.init()
S1APUEContextModificationInd.init()
S1APUEContextSuspend.init()
S1APUEContextResume.init()
S1APConnectionEstablishmentInd.init()
S1APHandoverPreparation.init()
S1APHandoverResourceAllocation.init()
S1APHandoverNotification.init()
S1APPathSwitchRequest.init()
S1APHandoverCancel.init()
S1APENBStatusTransfer.init()
S1APMMEStatusTransfer.init()
S1APPaging.init()
S1APInitialUEMessage.init()
S1APDownlinkNASTransport.init()
S1APUplinkNASTransport.init()
S1APNASNonDeliveryInd.init()
S1APRerouteNASRequest.init()
S1APResetCN.init()
S1APResetENB.init()
S1APErrorIndNonUECN.init()
S1APErrorIndNonUEENB.init()
S1APErrorIndCN.init()
S1APErrorIndENB.init()
S1APS1Setup.init()
S1APENBConfigUpdate.init()
S1APMMEConfigUpdate.init()
S1APOverloadStart.init()
S1APOverloadStop.init()
S1APDownlinkS1CDMA2000Tunnelling.init()
S1APUplinkS1CDMA2000Tunnelling.init()
S1APUECapabilityInfoInd.init()
S1APTraceStart.init()
S1APTraceFailureInd.init()
S1APDeactivateTrace.init()
S1APCellTrafficTrace.init()
S1APLocationReportingControl.init()
S1APLocationReportFailure.init()
S1APLocationReport.init()
S1APWriteReplaceWarning.init()
S1APKill.init()
S1APPWSRestartInd.init()
S1APPWSFailureInd.init()
S1APENBDirectInfoTransfer.init()
S1APMMEDirectInfoTransfer.init()
S1APENBConfigTransfer.init()
S1APMMEConfigTransfer.init()
S1APDownlinkUELPPaTransport.init()
S1APUplinkUELPPaTransport.init()
S1APDownlinkNonUELPPaTransport.init()
S1APUplinkNonUELPPaTransport.init()

# S1AP eNB-initiated UE-associated signalling procedures dispatcher
S1APProcEnbDispatcher = {
    12 : S1APInitialUEMessage,
    13 : S1APUplinkNASTransport,
    15 : S1APErrorIndENB,
    16 : S1APNASNonDeliveryInd,
    18 : S1APUEContextReleaseRequest,
    20 : S1APUplinkS1CDMA2000Tunnelling,
    22 : S1APUECapabilityInfoInd,
    28 : S1APTraceFailureInd,
    32 : S1APLocationReportFailure,
    33 : S1APLocationReport,
    42 : S1APCellTrafficTrace,
    45 : S1APUplinkUELPPaTransport,
    50 : S1APERABModificationInd,
    53 : S1APUEContextModificationInd
    }

# S1AP CN-initiated UE-associated signalling procedures dispatcher
S1APProcCnDispatcher = {
    5 : S1APERABSetup,
    6 : S1APERABModify,
    7 : S1APERABRelease,
    9 : S1APInitialContextSetup,
    11 : S1APDownlinkNASTransport,
    15 : S1APErrorIndCN,
    19 : S1APDownlinkS1CDMA2000Tunnelling,
    21 : S1APUEContextModification,
    23 : S1APUEContextRelease,
    26 : S1APDeactivateTrace,
    27 : S1APTraceStart,
    31 : S1APLocationReportingControl,
    44 : S1APDownlinkUELPPaTransport,
    48 : S1APUERadioCapabilityMatch,
    52 : S1APRerouteNASRequest,
    54 : S1APConnectionEstablishmentInd
    }

# S1AP eNB-initiated non-UE-associated signalling procedures dispatcher
S1APNonUEProcEnbDispatcher = {
    0 : S1APHandoverPreparation,
    2 : S1APHandoverNotification,
    3 : S1APPathSwitchRequest,
    4 : S1APHandoverCancel,
    14 : S1APResetENB,
    15 : S1APErrorIndNonUEENB,
    17 : S1APS1Setup,
    24 : S1APENBStatusTransfer,
    29 : S1APENBConfigUpdate,
    37 : S1APENBDirectInfoTransfer,
    40 : S1APENBConfigTransfer,
    41 : S1APMMEConfigTransfer,
    47 : S1APUplinkNonUELPPaTransport,
    49 : S1APPWSRestartInd,
    51 : S1APPWSFailureInd,
    55 : S1APUEContextSuspend,
    56 : S1APUEContextResume,
    }

# S1AP CN-initiated non-UE-associated signalling procedures dispatcher
S1APNonUEProcCnDispatcher = {
    1 : S1APHandoverResourceAllocation,
    10 : S1APPaging,
    14 : S1APResetCN,
    15 : S1APErrorIndNonUECN,
    25 : S1APMMEStatusTransfer,
    30 : S1APMMEConfigUpdate,
    34 : S1APOverloadStart,
    35 : S1APOverloadStop,
    36 : S1APWriteReplaceWarning,
    38 : S1APMMEDirectInfoTransfer,
    43 : S1APKill,
    46 : S1APDownlinkNonUELPPaTransport
    }

