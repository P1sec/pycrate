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
# * File Name : pycrate_corenet/ProcCNNgap.py
# * Created : 2020-04-15
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    "NGAPSigProc",
    "NGAPNonUESigProc",
    #
    "NGAPPDUSessResSetup",
    "NGAPPDUSessResRelease",
    "NGAPPDUSessResModify",
    "NGAPPDUSessResNotify",
    "NGAPPDUSessResModifyInd",
    "NGAPInitialContextSetup",
    "NGAPUEContextReleaseRequest",
    "NGAPUEContextRelease",
    "NGAPUEContextModification",
    "NGAPRRCInactiveTransitionReport",
    "NGAPHandoverPreparation",
    "NGAPHandoverResourceAllocation",
    "NGAPHandoverNotification",
    "NGAPPathSwitchRequest",
    "NGAPHandoverCancel",
    "NGAPUplinkRANStatusTransfer",
    "NGAPDownlinkRANStatusTransfer",
    "NGAPPaging",
    "NGAPInitialUEMessage",
    "NGAPDownlinkNASTransport",
    "NGAPUplinkNASTransport",
    "NGAPNASNonDeliveryInd",
    "NGAPRerouteNASRequest",
    "NGAPNGSetup",
    "NGAPRANConfigUpdate",
    "NGAPAMFConfigUpdate",
    "NGAPNGResetCN",
    "NGAPNGResetRAN",
    "NGAPErrorIndNonUECN",
    "NGAPErrorIndNonUERAN",
    "NGAPErrorIndCN",
    "NGAPErrorIndRAN",
    "NGAPAMFStatusInd",
    "NGAPOverloadStart",
    "NGAPOverloadStop",
    "NGAPUplinkRANConfigTransfer",
    "NGAPDownlinkRANConfigTransfer",
    "NGAPWriteReplaceWarning",
    "NGAPPWSCancel",
    "NGAPPWSRestartInd",
    "NGAPPWSFailureInd",
    "NGAPDownlinkUENRPPaTransport",
    "NGAPUplinkUENRPPaTransport",
    "NGAPDownlinkNonUENRPPaTransport",
    "NGAPUplinkNonUENRPPaTransport",
    "NGAPTraceStart",
    "NGAPTraceFailureInd",
    "NGAPDeactivateTrace",
    "NGAPCellTrafficTrace",
    "NGAPLocationReportingControl",
    "NGAPLocationReportingFailureInd",
    "NGAPLocationReport",
    "NGAPUETNLABindingRelease",
    "NGAPUERadioCapabilityInfoInd",
    "NGAPUERadioCapabilityCheck",
    "NGAPSecondaryRATDataUsageReport",
    "NGAPUplinkRIMInfoTransfer",
    "NGAPDownlinkRIMInfoTransfer",
    #
    "NGAPProcRANDispatcher",
    "NGAPProcCNDispatcher",
    "NGAPNonUEProcRANDispatcher",
    "NGAPNonUEProcCNDispatcher",   
    ]

from .utils     import *
from .ProcProto import *


#------------------------------------------------------------------------------#
# NGAP signalling procedure
# TS 38.413, version g10
# Core Network side
#------------------------------------------------------------------------------#


class NGAPSigProc(LinkSigProc):
    """NGAP UE-associated signalling procedure handler
    
    instance attributes:
        - Name  : procedure name
        - NG    : reference to the UENGd instance running this procedure
        - GNB   : reference to the GNBd instance connected by NG
        - Server: reference to the CorenetServer instance handling the gNB
        - UE    : reference to the UEd instance connected by NG
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
    
    def __init__(self, ngd):
        #
        self.Name   = self.__class__.__name__
        self.NG     = ngd
        self.GNB    = ngd.GNB
        self.Server = ngd.GNB.Server
        if ngd.UE:
            self.UE = ngd.UE
        else:
            self._log('WNG', 'no UEd instance attached')
        #
        # to store PDU traces
        self._pdu = []
        # list of PDU to be sent to the gNB
        self._pdu_tx = []
        # enable NAS procedure to set callback to .postprocess() before self terminates
        self._cb = None
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.NG._log(logtype, '[%s] %s' % (self.Name, msg))
    
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
        if self.Code in self.NG.Proc:
            del self.NG.Proc[self.Code]
        self._log('INF', 'aborting')


class NGAPNonUESigProc(LinkSigProc):
    """NGAP non-UE-associated signalling procedure handler
    
    instance attributes:
        - Name  : procedure name
        - GNB   : reference to the GNBd instance connected by NG
        - Server: reference to the CorenetServer instance handling the gNB
        - Desc  : ASN.1 procedure description
        - Code  : procedure code
        - Crit  : procedure criticality
        - Cont  : ASN.1 procedure PDU(s) content
        - Encod : custom PDU encoders with fixed values
        - Decod : custom PDU decoders with transform functions
    """
    
    TRACK_PDU = True
    
    def __init__(self, gnbd):
        #
        self.Name   = self.__class__.__name__
        self.GNB    = gnbd
        self.Server = gnbd.Server
        #
        # to store PDU traces
        self._pdu = []
        # list of PDU to be sent to the HNB
        self._pdu_tx = []
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.GNB._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def _recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.errcause, self.GNBInfo = None, {}
        try:
            self.decode_pdu(pdu, self.GNBInfo)
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
        if self.Code in self.GNB.Proc:
            del self.GNB.Proc[self.Code]
        self._log('INF', 'aborting')


#------------------------------------------------------------------------------#
# PDU Session Management Procedures
# TS 38.413, section 8.2
#------------------------------------------------------------------------------#

class NGAPPDUSessResSetup(NGAPSigProc):
    """PDU Session Resource Setup: TS 38.413, section 8.2.1
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 38: NAS_PDU (O)
      - 74: PDUSessionResourceSetupListSUReq (M)
      - 83: RANPagingPriority (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 110: UEAggregateMaximumBitRate (O)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 58: PDUSessionResourceFailedToSetupListSURes (O)
      - 75: PDUSessionResourceSetupListSURes (O)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pDUSessionResourceSetup
    
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


class NGAPPDUSessResRelease(NGAPSigProc):
    """PDU Session Resource Release: TS 38.413, section 8.2.2
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 38: NAS_PDU (O)
      - 79: PDUSessionResourceToReleaseListRelCmd (M)
      - 83: RANPagingPriority (O)
      - 85: RAN_UE_NGAP_ID (M)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 70: PDUSessionResourceReleasedListRelRes (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 121: UserLocationInformation (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pDUSessionResourceRelease
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
            }, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }


class NGAPPDUSessResModify(NGAPSigProc):
    """PDU Session Resource Modify: TS 38.413, section 8.2.3
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 64: PDUSessionResourceModifyListModReq (M)
      - 83: RANPagingPriority (O)
      - 85: RAN_UE_NGAP_ID (M)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 54: PDUSessionResourceFailedToModifyListModRes (O)
      - 65: PDUSessionResourceModifyListModRes (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 121: UserLocationInformation (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pDUSessionResourceModify
    
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


class NGAPPDUSessResNotify(NGAPSigProc):
    """PDU Session Resource Notify: TS 38.413, section 8.2.4
    
    RAN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 66: PDUSessionResourceNotifyList (O)
      - 67: PDUSessionResourceReleasedListNot (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 121: UserLocationInformation (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pDUSessionResourceNotify
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
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


class NGAPPDUSessResModifyInd(NGAPSigProc):
    """PDU Session Resource Modify Indication: TS 38.413, section 8.2.5
    
    RAN-initiatied
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 63: PDUSessionResourceModifyListModInd (M)
      - 85: RAN_UE_NGAP_ID (M)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 62: PDUSessionResourceModifyListModCfm (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 131: PDUSessionResourceFailedToModifyListModCfm (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pDUSessionResourceModifyIndication
    
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
# UE Context Management Procedures
# TS 38.413, section 8.3
#------------------------------------------------------------------------------#

class NGAPInitialContextSetup(NGAPSigProc):
    """Initial Context Setup: TS 38.413, section 8.3.1
    
    CN-initiated
    request-reponse
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: AllowedNSSAI (M)
      - 10: AMF_UE_NGAP_ID (M)
      - 18: CoreNetworkAssistanceInformationForInactive (O)
      - 24: EmergencyFallbackIndicator (O)
      - 28: GUAMI (M)
      - 31: IndexToRFSP (O)
      - 33: LocationReportingRequestType (O)
      - 34: MaskedIMEISV (O)
      - 36: MobilityRestrictionList (O)
      - 38: NAS_PDU (O)
      - 48: AMFName (O)
      - 71: PDUSessionResourceSetupListCxtReq (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 91: RRCInactiveTransitionReportRequest (O)
      - 94: SecurityKey (M)
      - 108: TraceActivation (O)
      - 110: UEAggregateMaximumBitRate (C)
      - 117: UERadioCapability (O)
      - 118: UERadioCapabilityForPaging (O)
      - 119: UESecurityCapabilities (M)
      - 146: RedirectionVoiceFallback (O)
      - 165: CNAssistedRANTuning (O)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 55: PDUSessionResourceFailedToSetupListCxtRes (O)
      - 72: PDUSessionResourceSetupListCxtRes (O)
      - 85: RAN_UE_NGAP_ID (M)
    UnsuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 132: PDUSessionResourceFailedToSetupListCxtFail (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.initialContextSetup
    
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


class NGAPUEContextReleaseRequest(NGAPSigProc):
    """UE Context Release Request: TS 38.413, section 8.3.2
    
    RAN-initiatied
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 133: PDUSessionResourceListCxtRelReq (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uEContextReleaseRequest
    
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
    
    recv = NGAPSigProc._recv
    
    def trigger(self):
        # copy the cause signaled by the gNB
        Proc = self.NG.init_ngap_proc(NGAPUEContextRelease,
                                      Cause=self.UEInfo['Cause'],
                                      UE_NGAP_IDs=('uE-NGAP-ID-pair',
                                                   {'aMF-UE-NGAP-ID': self.NG.CtxId,
                                                    'rAN-UE-NGAP-ID': self.NG.CtxId}))
        if Proc:
            return [Proc]
        else:
            return []


class NGAPUEContextRelease(NGAPSigProc):
    """UE Context Release: TS 38.413, section 8.3.3
    
    CN-initiated
    request-reponse
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 15: Cause (M)
      - 114: UE_NGAP_IDs (M)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 32: InfoOnRecommendedCellsAndRANNodesForPaging (O)
      - 60: PDUSessionResourceListCxtRelCpl (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 121: UserLocationInformation (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uEContextRelease
    
    # Custom decoders
    Decod = {
        'ini': ({}, {}),
        'suc': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
            }, {}),
        'uns': None
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': None
        }
    
    send = NGAPSigProc._send
    
    def _release_ng(self):
        # TODO: suspend all PDU sessions
        #self.NG.FGSM.pdu_suspend()
        # update mobility state
        if self.NG.FGMM.state != 'INACTIVE':
            self.NG.FGMM.state = 'IDLE'
        self._log('INF', 'UE disconnected, cause %r' % (self._NetInfo['Cause'], ))
        #
        # disconnect the NG interface to the gNB for the UE
        self.NG.unset_ran()
        self.NG.unset_ctx()
    
    def recv(self, pdu):
        # recv the NGAPUEContextRelease response
        self._recv(pdu)
        # remove from the NGAP procedure stack
        try:
            del self.NG.Proc[self.Code]
        except Exception:
            pass
        self._release_ng()
    
    def abort(self):
        # remove from the NGAP procedure stack
        try:
            del self.NG.Proc[self.Code]
        except Exception:
            pass
        self._log('INF', 'aborting')
        self._release_ng()


class NGAPUEContextModification(NGAPSigProc):
    """UE Context Modification: TS 38.413, section 8.3.4
    
    CN-initiated
    request-reponse
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 18: CoreNetworkAssistanceInformationForInactive (O)
      - 24: EmergencyFallbackIndicator (O)
      - 31: IndexToRFSP (O)
      - 40: AMF_UE_NGAP_ID (O)
      - 83: RANPagingPriority (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 91: RRCInactiveTransitionReportRequest (O)
      - 94: SecurityKey (O)
      - 110: UEAggregateMaximumBitRate (O)
      - 119: UESecurityCapabilities (O)
      - 162: GUAMI (O)
      - 165: CNAssistedRANTuning (O)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 92: RRCState (O)
      - 121: UserLocationInformation (O)
    UnsuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uEContextModification
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
            }, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class NGAPRRCInactiveTransitionReport(NGAPSigProc):
    """RRC Inactive Transition Report: TS 38.413, section 8.3.5
    
    RAN-initiatied
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 92: RRCState (M)
      - 121: UserLocationInformation (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.rRCInactiveTransitionReport
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
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


#------------------------------------------------------------------------------#
# UE Mobility Management Procedures
# TS 38.413, section 8.4
#------------------------------------------------------------------------------#

class NGAPHandoverPreparation(NGAPNonUESigProc):
    """Handover Preparation: TS 38.413, section 8.4.1
    
    RAN-initiatied
    request-reponse
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 22: DirectForwardingPathAvailability (O)
      - 29: HandoverType (M)
      - 61: PDUSessionResourceListHORqd (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 101: SourceToTarget_TransparentContainer (M)
      - 105: TargetID (M)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 29: HandoverType (M)
      - 39: NASSecurityParametersFromNGRAN (C)
      - 59: PDUSessionResourceHandoverList (O)
      - 78: PDUSessionResourceToReleaseListHOCmd (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 106: TargetToSource_TransparentContainer (M)
    UnsuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.handoverPreparation
    
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


class NGAPHandoverResourceAllocation(NGAPNonUESigProc):
    """Handover Resource Allocation: TS 38.413, section 8.4.2
    
    CN-initiated
    request-reponse
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: AllowedNSSAI (M)
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 18: CoreNetworkAssistanceInformationForInactive (O)
      - 28: GUAMI (M)
      - 29: HandoverType (M)
      - 33: LocationReportingRequestType (O)
      - 34: MaskedIMEISV (O)
      - 36: MobilityRestrictionList (O)
      - 37: NAS_PDU (O)
      - 41: NewSecurityContextInd (O)
      - 73: PDUSessionResourceSetupListHOReq (M)
      - 91: RRCInactiveTransitionReportRequest (O)
      - 93: SecurityContext (M)
      - 101: SourceToTarget_TransparentContainer (M)
      - 108: TraceActivation (O)
      - 110: UEAggregateMaximumBitRate (M)
      - 119: UESecurityCapabilities (M)
      - 146: RedirectionVoiceFallback (O)
      - 165: CNAssistedRANTuning (O)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 53: PDUSessionResourceAdmittedList (M)
      - 56: PDUSessionResourceFailedToSetupListHOAck (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 106: TargetToSource_TransparentContainer (M)
    UnsuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.handoverResourceAllocation
    
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


class NGAPHandoverNotification(NGAPNonUESigProc):
    """Handover Notification: TS 38.413, section 8.4.3
    
    RAN-initiatied
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 121: UserLocationInformation (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.handoverNotification
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
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


class NGAPPathSwitchRequest(NGAPNonUESigProc):
    """Path Switch Request: TS 38.413, section 8.4.4
    
    RAN-initiatied
    request-reponse
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 57: PDUSessionResourceFailedToSetupListPSReq (O)
      - 76: PDUSessionResourceToBeSwitchedDLList (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 100: AMF_UE_NGAP_ID (M)
      - 119: UESecurityCapabilities (M)
      - 121: UserLocationInformation (M)
    SuccessfulOutcome:
      IEs:
      - 0: AllowedNSSAI (M)
      - 10: AMF_UE_NGAP_ID (M)
      - 18: CoreNetworkAssistanceInformationForInactive (O)
      - 19: CriticalityDiagnostics (O)
      - 41: NewSecurityContextInd (O)
      - 68: PDUSessionResourceReleasedListPSAck (O)
      - 77: PDUSessionResourceSwitchedList (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 91: RRCInactiveTransitionReportRequest (O)
      - 93: SecurityContext (M)
      - 119: UESecurityCapabilities (O)
      - 146: RedirectionVoiceFallback (O)
      - 165: CNAssistedRANTuning (O)
    UnsuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 69: PDUSessionResourceReleasedListPSFail (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pathSwitchRequest
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
            }, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }
    
    # Custom encoders
    Encod = {
        'ini': ({}, {}),
        'suc': ({}, {}),
        'uns': ({}, {})
        }


class NGAPHandoverCancel(NGAPSigProc):
    """Handover Cancellation: TS 38.413, section 8.4.5
    
    RAN-initiatied
    request-reponse
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 85: RAN_UE_NGAP_ID (M)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.handoverCancel
    
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


class NGAPUplinkRANStatusTransfer(NGAPSigProc):
    """Uplink RAN Status Transfer: TS 38.413, section 8.4.6
    
    RAN-initiatied
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 84: RANStatusTransfer_TransparentContainer (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uplinkRANStatusTransfer
    
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


class NGAPDownlinkRANStatusTransfer(NGAPSigProc):
    """Downlink RAN Status Transfer: TS 38.413, section 8.4.7
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 84: RANStatusTransfer_TransparentContainer (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.downlinkRANStatusTransfer
    
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
# Paging Procedures
# TS 38.413, section 8.5
#------------------------------------------------------------------------------#

class NGAPPaging(NGAPNonUESigProc):
    """Paging: TS 38.413, section 8.5.1
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 11: AssistanceDataForPaging (O)
      - 50: PagingDRX (O)
      - 51: PagingOrigin (O)
      - 52: PagingPriority (O)
      - 103: TAIListForPaging (M)
      - 115: UEPagingIdentity (M)
      - 118: UERadioCapabilityForPaging (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.paging
    
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
# Transport of NAS Messages Procedures
# TS 38.413, section 8.6
#------------------------------------------------------------------------------#

class NGAPInitialUEMessage(NGAPSigProc):
    """Initial UE Message: TS 38.413, section 8.6.1
    
    RAN-initiatied
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: AllowedNSSAI (O)
      - 3: AMFSetID (O)
      - 26: FiveG_S_TMSI (O)
      - 38: NAS_PDU (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 90: RRCEstablishmentCause (M)
      - 112: UEContextRequest (O)
      - 121: UserLocationInformation (M)
      - 171: SourceToTarget_AMFInformationReroute (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.initialUEMessage
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
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
            # verification of UserLocInfo against GNBd parameters:
            err = False
            userloc = self.UEInfo['UserLocationInformation']
            tai = userloc['TAI']
            if 'NR-CGI' in userloc:
                cgi = userloc['NR-CGI']
            else:
                cgi = userloc['EUTRA-CGI']
            if cgi[0] != self.GNB.ID[0] or cgi[1][0] != self.GNB.ID[2][0]:
                self._log('WNG', 'invalid Cell Global-ID, %s.%.9x' % (cgi[0], cgi[1][0]))
                err = True
            elif tai not in self.GNB.Config['TAIs']:
                self._log('WNG', 'invalid TAI, %s.%.6x' % tai)
                err = True
            if err:
                self.errcause = ('protocol', 'message-not-compatible-with-receiver-state')
        #
        if not self.errcause:
            self.NG.FGMM.state = 'ACTIVE'
            self._log('INF', 'RRC establishment cause: %s' % self.UEInfo['RRCEstablishmentCause'])
            self.UE.set_tai(*tai)
            self._ret = self.NG.process_nas(self.UEInfo['NAS_PDU'])
    
    def trigger(self):
        return self._ret


class NGAPDownlinkNASTransport(NGAPSigProc):
    """Downlink NAS Transport: TS 38.413, section 8.6.2
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: AllowedNSSAI (O)
      - 10: AMF_UE_NGAP_ID (M)
      - 31: IndexToRFSP (O)
      - 36: MobilityRestrictionList (O)
      - 38: NAS_PDU (M)
      - 48: AMFName (O)
      - 83: RANPagingPriority (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 110: UEAggregateMaximumBitRate (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.downlinkNASTransport
    
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
    
    send = NGAPSigProc._send


class NGAPUplinkNASTransport(NGAPSigProc):
    """Uplink NAS Transport: TS 38.413, section 8.6.3
    
    RAN-initiatied
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 38: NAS_PDU (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 121: UserLocationInformation (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uplinkNASTransport
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
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
            # verification of UserLocInfo against GNBd parameters:
            err = False
            userloc = self.UEInfo['UserLocationInformation']
            tai = userloc['TAI']
            if 'NR-CGI' in userloc:
                cgi = userloc['NR-CGI']
            else:
                cgi = userloc['EUTRA-CGI']
            if cgi[0] != self.GNB.ID[0] or cgi[1][0] != self.GNB.ID[2][0]:
                self._log('WNG', 'invalid Cell Global-ID, %s.%.9x' % (cgi[0], cgi[1][0]))
                err = True
            elif tai not in self.GNB.Config['TAIs']:
                self._log('WNG', 'invalid TAI, %s.%.6x' % tai)
                err = True
            if err:
                self.errcause = ('protocol', 'message-not-compatible-with-receiver-state')
        #
        if not self.errcause:
            self._ret = self.NG.process_nas(self.UEInfo['NAS_PDU'])
    
    def trigger(self):
        return self._ret


class NGAPNASNonDeliveryInd(NGAPSigProc):
    """NAS Non Delivery Indication: TS 38.413, section 8.6.4
    
    RAN-initiatied
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 38: NAS_PDU (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.nASNonDeliveryIndication
    
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


class NGAPRerouteNASRequest(NGAPSigProc):
    """Reroute NAS Request: TS 38.413, section 8.6.5
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: AllowedNSSAI (O)
      - 3: AMFSetID (M)
      - 10: AMF_UE_NGAP_ID (O)
      - 42: [OCTET STRING] (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 171: SourceToTarget_AMFInformationReroute (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.rerouteNASRequest
    
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
# Interface Management Procedures
# TS 38.413, section 8.7
#------------------------------------------------------------------------------#

class NGAPNGSetup(NGAPNonUESigProc):
    """NG Setup : TS 38.413, section 8.7.1
    
    gNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 21: PagingDRX (M)
      - 27: GlobalRANNodeID (M)
      - 82: RANNodeName (O)
      - 102: SupportedTAList (M)
      - 147: UERetentionInformation (O)
    SuccessfulOutcome:
      IEs:
      - 1: AMFName (M)
      - 19: CriticalityDiagnostics (O)
      - 80: PLMNSupportList (M)
      - 86: RelativeAMFCapacity (M)
      - 96: ServedGUAMIList (M)
      - 147: UERetentionInformation (O)
    UnsuccessfulOutcome:
      IEs:
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
      - 107: TimeToWait (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.nGSetup
    
    # Custom decoders
    Decod = {
        'ini': ({
            'GlobalRANNodeID': globranid_to_hum,
            'SupportedTAList': supptalist_to_hum,
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
        # recv the NGSetupRequest
        self._recv(pdu)
        if self.errcause:
            # procedure unsuccessful outcome
            self.encode_pdu('uns', Cause=self.errcause)
            self._log('INF', 'gNB NG Setup unsuccessful')
        else:
            self.GNB.Config = cpdict(self.GNBInfo)
            tais = set()
            for (tac, bcastplmnlist) in self.GNBInfo['SupportedTAList'].items():
                for (plmn, _) in bcastplmnlist:
                    tais.add( (plmn, tac) )
            self.GNB.Config['TAIs'] = tuple(tais)
            self.GNB.ID = self.GNBInfo['GlobalRANNodeID']
            # prepare the NGSetupResponse
            IEs = self.GNB.get_ngsetup_ies_from_cfg()
            self.encode_pdu('suc', **IEs)
            self._log('INF', 'gNB NG Setup successful')
    
    send = NGAPNonUESigProc._send


class NGAPRANConfigUpdate(NGAPNonUESigProc):
    """RAN Configuration Update: TS 38.413, section 8.7.2
    
    RAN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 21: PagingDRX (O)
      - 27: GlobalRANNodeID (O)
      - 82: RANNodeName (O)
      - 102: SupportedTAList (O)
      - 167: NGRAN_TNLAssociationToRemoveList (O)
    SuccessfulOutcome:
      IEs:
      - 19: CriticalityDiagnostics (O)
    UnsuccessfulOutcome:
      IEs:
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
      - 107: TimeToWait (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.rANConfigurationUpdate
    
    # Custom decoders
    Decod = {
        'ini': ({
            'GlobalRANNodeID': globranid_to_hum,
            'SupportedTAList': supptalist_to_hum,
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
        # recv the RANConfigUpdate, which provides similar configuration 
        # information as the NGSetup message
        self._recv(pdu)
        if self.errcause:
            # procedure unsuccessful outcome
            self.encode_pdu('uns', Cause=self.errcause)
            self._log('INF', 'gNB Config Update unsuccessful')
        else:
            gnbcfg = cpdict(self.GNBInfo)
            if 'NGRAN_TNLAssociationToRemoveList' in gnbcfg:
                del gnbcfg['NGRAN_TNLAssociationToRemoveList']
            self.GNB.Config.update(gnbcfg)
            if 'SupportedTAList' in gnbcfg:
                tais = set()
                for (tac, bcastplmnlist) in self.GNBInfo['SupportedTAList'].items():
                    for (plmn, _) in bcastplmnlist:
                        tais.add( (plmn, tac) )
                self.GNB.Config['TAIs'] = tuple(tais)
            if 'GlobalRANNodeID' in gnbcfg:
                self.GNB.ID = self.GNBInfo['GlobalRANNodeID']
            # TODO: process NGRAN_TNLAssociationToRemoveList
            # prepare the ConfigUpdateResponse
            self.encode_pdu('suc')
            self._log('INF', 'gNB Config Update successful')
    
    send = NGAPNonUESigProc._send


class NGAPAMFConfigUpdate(NGAPNonUESigProc):
    """AMF Configuration Update: TS 38.413, section 8.7.3
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 1: AMFName (O)
      - 6: AMF_TNLAssociationToAddList (O)
      - 7: AMF_TNLAssociationToRemoveList (O)
      - 8: AMF_TNLAssociationToUpdateList (O)
      - 80: PLMNSupportList (O)
      - 86: RelativeAMFCapacity (O)
      - 96: ServedGUAMIList (O)
    SuccessfulOutcome:
      IEs:
      - 4: TNLAssociationList (O)
      - 5: AMF_TNLAssociationSetupList (O)
      - 19: CriticalityDiagnostics (O)
    UnsuccessfulOutcome:
      IEs:
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
      - 107: TimeToWait (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.aMFConfigurationUpdate
    
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
    
    def recv(self, pdu):
        # receive the AMFConfigUpdate response
        self._recv(pdu)
        try:
            del self.GNB.Proc[self.Code]
        except Exception:
            pass
        if not self.errcause:
            self._log('INF', 'success')
    
    send = NGAPNonUESigProc._send


class NGAPNGResetCN(NGAPNonUESigProc):
    """NG Reset: TS 38.413, section 8.7.4.2.1
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 15: Cause (M)
      - 88: ResetType (M)
    SuccessfulOutcome:
      IEs:
      - 19: CriticalityDiagnostics (O)
      - 111: UE_associatedLogicalNG_connectionList (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.nGReset
    
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


class NGAPNGResetRAN(NGAPNonUESigProc):
    """NG Reset: TS 38.413, section 8.7.4.2.2
    
    RAN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 15: Cause (M)
      - 88: ResetType (M)
    SuccessfulOutcome:
      IEs:
      - 19: CriticalityDiagnostics (O)
      - 111: UE_associatedLogicalNG_connectionList (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.nGReset
    
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


class NGAPErrorIndNonUECN(NGAPNonUESigProc):
    """Error Indication: TS 38.413, section 8.7.5
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (O)
      - 15: Cause (O)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.errorIndication
    
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
    
    send = NGAPNonUESigProc._send


class NGAPErrorIndNonUERAN(NGAPNonUESigProc):
    """Error Indication: TS 38.413, section 8.7.5
    
    RAN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (O)
      - 15: Cause (O)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.errorIndication
    
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
        if not self.errcause and 'Cause' in self.GNBInfo:
            self._log('WNG', 'error ind received: %r' % (self.GNBInfo['Cause'], ))
            # if it corresponds to a said-unknown UE ID, disconnect the UE instance
            if self.GNBInfo['Cause'] == ('radioNetwork', 'unknown-local-UE-NGAP-ID') \
            and 'AMF_UE_NGAP_ID' in self.GNBInfo \
            and self.GNBInfo['AMF_UE_NGAP_ID'] in self.GNB.UE:
                ue = self.GNB.UE[self.GNBInfo['AMF_UE_NGAP_ID']]
                if ue.NG.is_connected():
                    self._log('INF', 'UE %s to be disconnected' % ue.IMSI)
                    ue.NG.unset_ran()
            # if it corresponds to a previously CN-initiated class 1 procedure
            # abort it
            try:
                self.GNB.Proc[self.GNB.ProcLast].abort()
            except Exception:
                pass


class NGAPErrorIndCN(NGAPSigProc):
    """Error Indication: TS 38.413, section 8.7.5
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (O)
      - 15: Cause (O)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.errorIndication
    
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
    
    send = NGAPSigProc._send


class NGAPErrorIndRAN(NGAPSigProc):
    """Error Indication: TS 38.413, section 8.7.5
    
    RAN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (O)
      - 15: Cause (O)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.errorIndication
    
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
                self.NG.Proc[self.NG.ProcLast].abort()
            except Exception:
                pass


class NGAPAMFStatusInd(NGAPNonUESigProc):
    """AMF Status Indication: TS 38.413, section 8.7.6
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 120: UnavailableGUAMIList (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.aMFStatusIndication
    
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


class NGAPOverloadStart(NGAPNonUESigProc):
    """Overload Start: TS 38.413, section 8.7.7
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 2: OverloadResponse (O)
      - 9: TrafficLoadReductionIndication (O)
      - 49: OverloadStartNSSAIList (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.overloadStart
    
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


class NGAPOverloadStop(NGAPNonUESigProc):
    """Overload Start: TS 38.413, section 8.7.8
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
        None
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.overloadStop
    
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
# Configuration Transfer Procedures
# TS 38.413, section 8.8
#------------------------------------------------------------------------------#

class NGAPUplinkRANConfigTransfer(NGAPNonUESigProc):
    """Uplink RAN Configuration Transfer: TS 38.413, section 8.8.1
    
    RAN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 99: SONConfigurationTransfer (O)
      - 158: EN_DCSONConfigurationTransfer (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uplinkRANConfigurationTransfer
    
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


class NGAPDownlinkRANConfigTransfer(NGAPNonUESigProc):
    """Downlink RAN Configuration Transfer: TS 38.413, section 8.8.2
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 98: SONConfigurationTransfer (O)
      - 157: EN_DCSONConfigurationTransfer (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.downlinkRANConfigurationTransfer
    
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
# Warning Message Transmission Procedures
# TS 38.413, section 8.9
#------------------------------------------------------------------------------#

class NGAPWriteReplaceWarning(NGAPNonUESigProc):
    """Write-Replace Warning: TS 38.413, section 8.9.1
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 17: ConcurrentWarningMessageInd (O)
      - 20: DataCodingScheme (O)
      - 35: MessageIdentifier (M)
      - 47: NumberOfBroadcastsRequested (M)
      - 87: RepetitionPeriod (M)
      - 95: SerialNumber (M)
      - 122: WarningAreaList (O)
      - 123: WarningMessageContents (O)
      - 124: WarningSecurityInfo (O)
      - 125: WarningType (O)
      - 141: WarningAreaCoordinates (O)
    SuccessfulOutcome:
      IEs:
      - 13: BroadcastCompletedAreaList (O)
      - 19: CriticalityDiagnostics (O)
      - 35: MessageIdentifier (M)
      - 95: SerialNumber (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.writeReplaceWarning
    
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


class NGAPPWSCancel(NGAPNonUESigProc):
    """PWS Cancel: TS 38.413, section 8.9.2
    
    CN-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 14: CancelAllWarningMessages (O)
      - 35: MessageIdentifier (M)
      - 95: SerialNumber (M)
      - 122: WarningAreaList (O)
    SuccessfulOutcome:
      IEs:
      - 12: BroadcastCancelledAreaList (O)
      - 19: CriticalityDiagnostics (O)
      - 35: MessageIdentifier (M)
      - 95: SerialNumber (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pWSCancel
    
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


class NGAPPWSRestartInd(NGAPNonUESigProc):
    """PWS Restart Indication: TS 38.413, section 8.9.3
    
    RAN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 16: CellIDListForRestart (M)
      - 23: EmergencyAreaIDListForRestart (O)
      - 27: GlobalRANNodeID (M)
      - 104: TAIListForRestart (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pWSRestartIndication
    
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


class NGAPPWSFailureInd(NGAPNonUESigProc):
    """PWS Failure Indication: TS 38.413, section 8.9.4
    
    RAN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 27: GlobalRANNodeID (M)
      - 81: PWSFailedCellIDList (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.pWSFailureIndication
    
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
# NRPPa Transport Procedures
# TS 38.413, section 8.10
#------------------------------------------------------------------------------#

class NGAPDownlinkUENRPPaTransport(NGAPSigProc):
    """DOWNLINK UE ASSOCIATED NRPPA TRANSPORT: TS 38.413, section 8.10.2.1
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 46: NRPPa_PDU (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 89: RoutingID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.downlinkUEAssociatedNRPPaTransport
    
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


class NGAPUplinkUENRPPaTransport(NGAPSigProc):
    """UPLINK UE ASSOCIATED NRPPA TRANSPORT: TS 38.413, section 8.10.2.2
    
    RAN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 46: NRPPa_PDU (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 89: RoutingID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uplinkUEAssociatedNRPPaTransport
    
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


class NGAPDownlinkNonUENRPPaTransport(NGAPNonUESigProc):
    """DOWNLINK NON UE ASSOCIATED NRPPA TRANSPORT: TS 38.413, section 8.10.3.1
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 46: NRPPa_PDU (M)
      - 89: RoutingID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.downlinkNonUEAssociatedNRPPaTransport
    
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


class NGAPUplinkNonUENRPPaTransport(NGAPNonUESigProc):
    """UPLINK NON UE ASSOCIATED NRPPA TRANSPORT: TS 38.413, section 8.10.3.2
    
    RAN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 46: NRPPa_PDU (M)
      - 89: RoutingID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uplinkNonUEAssociatedNRPPaTransport
    
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
# Trace Procedures
# TS 38.413, section 8.11
#------------------------------------------------------------------------------#

class NGAPTraceStart(NGAPSigProc):
    """Trace Start: TS 38.413, section 8.11.1
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 108: TraceActivation (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.traceStart
    
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


class NGAPTraceFailureInd(NGAPSigProc):
    """Trace Failure Indication: TS 38.413, section 8.11.2
    
    RAN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 44: NGRANTraceID (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.traceFailureIndication
    
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


class NGAPDeactivateTrace(NGAPSigProc):
    """Deactivate Trace: TS 38.413, section 8.11.3
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 44: NGRANTraceID (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.deactivateTrace
    
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


class NGAPCellTrafficTrace(NGAPSigProc):
    """Cell Traffic Trace: TS 38.413, section 8.11.4
    
    RAN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 43: NGRAN_CGI (M)
      - 44: NGRANTraceID (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 109: TransportLayerAddress (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.cellTrafficTrace
    
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
# Location Reporting Procedures
# TS 38.413, section 8.12
#------------------------------------------------------------------------------#

class NGAPLocationReportingControl(NGAPSigProc):
    """Location Reporting Control: TS 38.413, section 8.12.1
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 33: LocationReportingRequestType (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.locationReportingControl
    
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


class NGAPLocationReportingFailureInd(NGAPSigProc):
    """Location Reporting Failure Indication: TS 38.413, section 8.12.2
    
    RAN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.locationReportingFailureIndication
    
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


class NGAPLocationReport(NGAPSigProc):
    """Location Report: TS 38.413, section 8.12.3
    
    RAN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 33: LocationReportingRequestType (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 116: UEPresenceInAreaOfInterestList (O)
      - 121: UserLocationInformation (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.locationReport
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
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


#------------------------------------------------------------------------------#
# UE TNLA Binding Procedures
# TS 38.413, section 8.13
#------------------------------------------------------------------------------#

class NGAPUETNLABindingRelease(NGAPSigProc):
    """UE TNLA Binding Release: TS 38.413, section 8.13.1
    
    CN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uETNLABindingRelease
    
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
# UE Radio Capability Management Procedures
# TS 38.413, section 8.14
#------------------------------------------------------------------------------#

class NGAPUERadioCapabilityInfoInd(NGAPSigProc):
    """UE Radio Capability Info Indication: TS 38.413, section 8.14.1
    
    RAN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 117: UERadioCapability (M)
      - 118: UERadioCapabilityForPaging (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uERadioCapabilityInfoIndication
    
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


class NGAPUERadioCapabilityCheck(NGAPSigProc):
    """UE Radio Capability Info Check: TS 38.413, section 8.14.2
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 117: UERadioCapability (O)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 30: IMSVoiceSupportIndicator (M)
      - 85: RAN_UE_NGAP_ID (M)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uERadioCapabilityCheck
    
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
# Data Usage Reporting Procedures
# TS 38.413, section 8.15
#------------------------------------------------------------------------------#

class NGAPSecondaryRATDataUsageReport(NGAPSigProc):
    """Secondary RAT Data Usage Report: TS 38.413, section 8.15.1
    
    RAN-initiated
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 121: UserLocationInformation (O)
      - 142: PDUSessionResourceSecondaryRATUsageList (M)
      - 143: HandoverFlag (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.secondaryRATDataUsageReport
    
    # Custom decoders
    Decod = {
        'ini': ({
            'UserLocationInformation': lambda x: ngap_userloc_to_hum(x)
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


#------------------------------------------------------------------------------#
# RIM Information Transfer Procedures
# TS 38.413, section 8.16
#------------------------------------------------------------------------------#

class NGAPUplinkRIMInfoTransfer(NGAPNonUESigProc):
    """Uplink RIM Information Transfer: TS 38.413, section 8.16.1
    
    RAN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 175: RIMInformationTransfer (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.uplinkRIMInformationTransfer
    
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


class NGAPDownlinkRIMInfoTransfer(NGAPNonUESigProc):
    """Downlink RIM Information Transfer: TS 38.413, section 8.16.2
    
    CN-initiated
    request only
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 175: RIMInformationTransfer (O)
    """
    
    # ASN.1 procedure description
    Desc = NGAP.NGAP_PDU_Descriptions.downlinkRIMInformationTransfer
    
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


# initializing all NGAP procedures classes
NGAPPDUSessResSetup.init()
NGAPPDUSessResRelease.init()
NGAPPDUSessResModify.init()
NGAPPDUSessResNotify.init()
NGAPPDUSessResModifyInd.init()
NGAPInitialContextSetup.init()
NGAPUEContextReleaseRequest.init()
NGAPUEContextRelease.init()
NGAPUEContextModification.init()
NGAPRRCInactiveTransitionReport.init()
NGAPHandoverPreparation.init()
NGAPHandoverResourceAllocation.init()
NGAPHandoverNotification.init()
NGAPPathSwitchRequest.init()
NGAPHandoverCancel.init()
NGAPUplinkRANStatusTransfer.init()
NGAPDownlinkRANStatusTransfer.init()
NGAPPaging.init()
NGAPInitialUEMessage.init()
NGAPDownlinkNASTransport.init()
NGAPUplinkNASTransport.init()
NGAPNASNonDeliveryInd.init()
NGAPRerouteNASRequest.init()
NGAPNGSetup.init()
NGAPRANConfigUpdate.init()
NGAPAMFConfigUpdate.init()
NGAPNGResetCN.init()
NGAPNGResetRAN.init()
NGAPErrorIndNonUECN.init()
NGAPErrorIndNonUERAN.init()
NGAPErrorIndCN.init()
NGAPErrorIndRAN.init()
NGAPAMFStatusInd.init()
NGAPOverloadStart.init()
NGAPOverloadStop.init()
NGAPUplinkRANConfigTransfer.init()
NGAPDownlinkRANConfigTransfer.init()
NGAPWriteReplaceWarning.init()
NGAPPWSCancel.init()
NGAPPWSRestartInd.init()
NGAPPWSFailureInd.init()
NGAPDownlinkUENRPPaTransport.init()
NGAPUplinkUENRPPaTransport.init()
NGAPDownlinkNonUENRPPaTransport.init()
NGAPUplinkNonUENRPPaTransport.init()
NGAPTraceStart.init()
NGAPTraceFailureInd.init()
NGAPDeactivateTrace.init()
NGAPCellTrafficTrace.init()
NGAPLocationReportingControl.init()
NGAPLocationReportingFailureInd.init()
NGAPLocationReport.init()
NGAPUETNLABindingRelease.init()
NGAPUERadioCapabilityInfoInd.init()
NGAPUERadioCapabilityCheck.init()
NGAPSecondaryRATDataUsageReport.init()
NGAPUplinkRIMInfoTransfer.init()
NGAPDownlinkRIMInfoTransfer.init()

# NGAP RAN-initiated UE-associated signalling procedures dispatcher
NGAPProcRANDispatcher = {
    2  : NGAPCellTrafficTrace,
    9  : NGAPErrorIndRAN,
    10 : NGAPHandoverCancel,
    15 : NGAPInitialUEMessage,
    17 : NGAPLocationReportingFailureInd,
    18 : NGAPLocationReport,
    19 : NGAPNASNonDeliveryInd,
    27 : NGAPPDUSessResModifyInd,
    30 : NGAPPDUSessResNotify,
    37 : NGAPRRCInactiveTransitionReport,
    38 : NGAPTraceFailureInd,
    42 : NGAPUEContextReleaseRequest,
    44 : NGAPUERadioCapabilityInfoInd,
    46 : NGAPUplinkNASTransport,
    49 : NGAPUplinkRANStatusTransfer,
    50 : NGAPUplinkUENRPPaTransport,
    52 : NGAPSecondaryRATDataUsageReport
    }

# NGAP CN-initiated UE-associated signalling procedures dispatcher
NGAPProcCNDispatcher = {
    3  : NGAPDeactivateTrace,
    4  : NGAPDownlinkNASTransport,
    7  : NGAPDownlinkRANStatusTransfer,
    8  : NGAPDownlinkUENRPPaTransport,
    9  : NGAPErrorIndCN,
    14 : NGAPInitialContextSetup,
    16 : NGAPLocationReportingControl,
    26 : NGAPPDUSessResModify,
    28 : NGAPPDUSessResRelease,
    29 : NGAPPDUSessResSetup,
    36 : NGAPRerouteNASRequest,
    39 : NGAPTraceStart,
    40 : NGAPUEContextModification,
    41 : NGAPUEContextRelease,
    43 : NGAPUERadioCapabilityCheck,
    45 : NGAPUETNLABindingRelease
    }

# NGAP RAN-initiated non-UE-associated signalling procedures dispatcher
NGAPNonUEProcRANDispatcher = {
    9  : NGAPErrorIndNonUERAN,
    11 : NGAPHandoverNotification,
    12 : NGAPHandoverPreparation,
    20 : NGAPNGResetRAN,
    21 : NGAPNGSetup,
    25 : NGAPPathSwitchRequest,
    33 : NGAPPWSFailureInd,
    34 : NGAPPWSRestartInd,
    35 : NGAPRANConfigUpdate,
    47 : NGAPUplinkNonUENRPPaTransport,
    48 : NGAPUplinkRANConfigTransfer,
    53 : NGAPUplinkRIMInfoTransfer
    }

# NGAP CN-initiated non-UE-associated signalling procedures dispatcher
NGAPNonUEProcCNDispatcher = {
    0  : NGAPAMFConfigUpdate,
    1  : NGAPAMFStatusInd,
    5  : NGAPDownlinkNonUENRPPaTransport,
    6  : NGAPDownlinkRANConfigTransfer,
    9  : NGAPErrorIndNonUECN,
    13 : NGAPHandoverResourceAllocation,
    20 : NGAPNGResetCN,
    22 : NGAPOverloadStart,
    23 : NGAPOverloadStop,
    24 : NGAPPaging,
    32 : NGAPPWSCancel,
    51 : NGAPWriteReplaceWarning,
    54 : NGAPDownlinkRIMInfoTransfer
    }

