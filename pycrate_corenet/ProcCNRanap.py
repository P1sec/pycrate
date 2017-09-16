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
# * File Name : pycrate_corenet/ProcCNRanap.py
# * Created : 2017-07-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils     import *
from .ProcProto import *

#------------------------------------------------------------------------------#
# RANAP signaling procedure
# TS 25.413, version d20
# Core Network side
#------------------------------------------------------------------------------#

class RANAPSigProc(LinkSigProc):
    """RANAP signaling procedure handler
    
    instance attributes:
        - Name  : procedure name
        - Iu    : reference to the Iu[C|P]Sd instance running this procedure
        - RNC   : reference to the HNBd instance connected by Iu
        - Server: reference to the CorenetServer instance handling the RNC
        - UE    : reference to the UEd instance connected by Iu (only for 
                  Iu-related RANAP procedure)
        - Desc  : ASN.1 procedure description
        - Code  : procedure code
        - Crit  : procedure criticality
        - Cont  : ASN.1 procedure PDU(s) content
        - Encod : custom PDU encoders with fixed values
        - Decod : custom PDU decoders with tranform functions
    """
    
    TRACK_PDU = True
    
    # for UE-related signaling
    UE = None
    
    def __init__(self, iud):
        #
        self.Name   = self.__class__.__name__
        self.Iu     = iud
        self.RNC    = iud.RNC
        self.Server = iud.RNC.Server
        if iud.UE:
            self.UE = iud.UE
        #
        # to store PDU traces
        self._pdu = []
        # list of PDU to be sent to the HNB
        self._snd = []
        # enable NAS procedure to set callback to .postprocess() before self terminates
        self._cb = None
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.Iu._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self._log('ERR', 'recv() not implemented')
    
    def send(self):
        self._log('ERR', 'send() not implemented')
        return self._snd
    
    def trigger(self):
        return []
    
    def abort(self):
        if self.Code in self.Iu.Proc:
            del self.Iu.Proc[self.Code]
        self._log('INF', 'aborting')
    

class RANAPRABAssignment(RANAPSigProc):
    """RAB Assignment: TS 25.413, section 8.2
    
    CN-initiated
    request-response(s)
    
    InitiatingMessage:
      IEs:
      - 41: RAB_ReleaseList (O)
      - 54: RAB_SetupOrModifyList (O)
      Extensions:
      - 233: UE_AggregateMaximumBitRate (O)
      - 239: MSISDN (O)
    Outcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 35: RAB_FailedList (O)
      - 38: RAB_QueuedList (O)
      - 39: RAB_ReleaseFailedList (O)
      - 43: RAB_ReleasedList (O)
      - 52: RAB_SetupOrModifiedList (O)
      Extensions:
      - 110: GERAN_Iumode_RAB_FailedList_RABAssgntResponse (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.rAB_Assignment
    
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


class RANAPRABReleaseRequest(RANAPSigProc):
    """RAB Release Request: TS 25.413, section 8.3
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 41: RAB_ReleaseList (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.rAB_ReleaseRequest
    
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


class RANAPIuReleaseRequest(RANAPSigProc):
    """Iu Release Request: TS 25.413, section 8.4
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 4: Cause (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.iu_ReleaseRequest
    
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
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        self.errcause, self.UEInfo = None, {}
        try:
            self.decode_pdu(pdu, self.UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
        #
        # this will trigger an IuRelease procedure
        # remove from the Iu RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except:
            pass
    
    def trigger(self):
        if self.errcause:
            Err = self.Iu.init_ranap_proc(RANAPErrorIndCN, Cause=self.errcause)
            if Err:
                return [Err]
            else:
                return []
        else:
            # copy the cause signaled by the RNC
            IuRel = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=self.UEInfo['Cause'])
            if IuRel:
                return [IuRel]
            else:
                return []


class RANAPIuRelease(RANAPSigProc):
    """Iu Release: TS 25.413, section 8.5
    
    CN-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 4: Cause (M)
      Extensions:
      - 252: End_Of_CSFB (O)
      - 254: Out_Of_UTRAN (O)
      - 277: PLMNidentity (O)
    SuccessfulOutcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 31: RAB_DataVolumeReportList (O)
      - 44: RAB_ReleasedList_IuRelComp (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.iu_Release
    
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
        # recv the IuRelease response
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        self.errcause, self.UEInfo = None, {}
        try:
            self.decode_pdu(pdu, self.UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
        #
        # update mobility state
        if self.Iu.DOM == 'CS':
            if self.Iu.MM.state != 'INACTIVE':
                self.Iu.MM.state = 'IDLE'
        else:
            if self.Iu.GMM.state != 'INACTIVE':
                self.Iu.GMM.state = 'IDLE'
        #
        # disconnect the Iu interface to the RNC for the UE
        self.Iu.unset_ran()
        self.Iu.unset_ctx()
        self.Iu.SEC['CKSN'] = None
        #
        # remove from the Iu RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except:
            pass
    
    def send(self):
        # send the IuRelease request
        if self.TRACK_PDU:
            for pdu in self._snd:
                self._pdu.append( (time(), 'DL', pdu) )
        # send back the list of PDU to be returned to the HNB
        return self._snd
    

class RANAPRelocationPreparation(RANAPSigProc):
    """Relocation Preparation: TS 25.413, section 8.6
    
    RNC-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 4: Cause (M)
      - 7: ClassmarkInformation2 (C)
      - 8: ClassmarkInformation3 (C)
      - 20: OldBSS_ToNewBSS_Information (O)
      - 56: RelocationType (M)
      - 60: SourceID (M)
      - 61: Source_ToTarget_TransparentContainer (C)
      - 62: TargetID (M)
      Extensions:
      - 108: GERAN_Classmark (O)
      - 161: SourceBSS_ToTargetBSS_TransparentContainer (O)
      - 203: CSG_Id (O)
      - 226: SRVCC_HO_Indication (O)
      - 235: Cell_Access_Mode (O)
      - 259: RSRVCC_HO_Indication (O)
    SuccessfulOutcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 14: L3_Information (O)
      - 28: RAB_DataForwardingList (O)
      - 46: RAB_RelocationReleaseList (O)
      - 63: Target_ToSource_TransparentContainer (O)
      Extensions:
      - 99: InterSystemInformation_TransparentContainer (O)
      - 162: TargetBSS_ToSourceBSS_TransparentContainer (O)
      - 227: SRVCC_Information (O)
      - 260: RSRVCC_Information (O)
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      Extensions:
      - 99: InterSystemInformation_TransparentContainer (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.relocationPreparation
    
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


class RANAPRelocationResourceAllocation(RANAPSigProc):
    """Relocation Resource Allocation: TS 25.413, section 8.7
    
    CN-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 4: Cause (M)
      - 11: EncryptionInformation (O)
      - 12: IntegrityProtectionInformation (O)
      - 23: PermanentNAS_UE_ID (O)
      - 49: RAB_SetupList_RelocReq (O)
      - 61: SourceRNC_ToTargetRNC_TransparentContainer (M)
      - 79: IuSignallingConnectionIdentifier (M)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 105: SNA_Access_Information (O)
      - 118: UESBI_Iu (O)
      - 127: PLMNidentity (O)
      - 133: CNMBMSLinkingInformation (O)
      - 203: CSG_Id (O)
      - 233: UE_AggregateMaximumBitRate (O)
      - 234: CSG_Membership_Status (O)
      - 239: MSISDN (O)
      - 261: PLMNidentity (O)
      - 289: PowerSavingIndicator (O)
    SuccessfulOutcome:
      IEs:
      - 5: ChosenEncryptionAlgorithm (O)
      - 6: ChosenIntegrityProtectionAlgorithm (O)
      - 9: CriticalityDiagnostics (O)
      - 35: RAB_FailedList (O)
      - 50: RAB_SetupList_RelocReqAck (O)
      - 63: TargetRNC_ToSourceRNC_TransparentContainer (O)
      Extensions:
      - 100: NewBSS_To_OldBSS_Information (O)
      - 203: CSG_Id (O)
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      Extensions:
      - 100: NewBSS_To_OldBSS_Information (O)
      - 108: GERAN_Classmark (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.relocationResourceAllocation
    
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
    

class RANAPRelocationDetect(RANAPSigProc):
    """Relocation Detect: TS 25.413, section 8.8
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
        None
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.relocationDetect
    
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


class RANAPRelocationComplete(RANAPSigProc):
    """Relocation Complete: TS 25.413, section 8.9
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
        None
      Extensions:
      - 250: HigherBitratesThan16MbpsFlag (O)
      - 262: TunnelInformation (O)
      - 275: LHN_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.relocationComplete
    
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


class RANAPRelocationCancel(RANAPSigProc):
    """Relocation Cancel: TS 25.413, section 8.10
    
    RNC-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 4: Cause (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.relocationCancel
    
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


class RANAPSRNSContextTransfer(RANAPSigProc):
    """SRNS Context Transfer: TS 25.413, section 8.11
    
    CN-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 29: RAB_DataForwardingList_SRNS_CtxReq (M)
      Extensions:
      - 167: RAT_Type (O)
    SuccessfulOutcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 25: RAB_ContextList (O)
      - 85: RAB_ContextFailedtoTransferList (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.sRNS_ContextTransfer
    
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


class RANAPSRNSDataForwarding(RANAPSigProc):
    """SRNS Data Forwarding: TS 25.413, section 8.12
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 28: RAB_DataForwardingList (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.sRNS_DataForward
    
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


class RANAPSRNSContextForwardToCN(RANAPSigProc):
    """SRNS Context Forwarding from Source RNC to CN: TS 25.413, section 8.13
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 25: RAB_ContextList (M)
      Extensions:
      - 103: RRC_Container (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.forwardSRNS_Context
    
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


class RANAPSRNSContextForwardToRNC(RANAPSigProc):
    """SRNS Context Forwarding from CN to target RNC: TS 25.413, section 8.14
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 25: RAB_ContextList (M)
      Extensions:
      - 103: RRC_Container (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.forwardSRNS_Context
    
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


class RANAPPaging(RANAPSigProc):
    """Paging: TS 25.413, section 8.15
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 17: NonSearchingIndication (O)
      - 21: PagingAreaID (O)
      - 22: PagingCause (O)
      - 23: PermanentNAS_UE_ID (M)
      - 64: TemporaryUE_ID (O)
      - 76: DRX_CycleLengthCoefficient (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 229: CSG_Id_List (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.paging
    
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


class RANAPCommonID(RANAPSigProc):
    """Common ID: TS 25.413, section 8.16
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 23: PermanentNAS_UE_ID (M)
      Extensions:
      - 105: SNA_Access_Information (O)
      - 118: UESBI_Iu (O)
      - 127: PLMNidentity (O)
      - 202: SubscriberProfileIDforRFP (O)
      - 228: SRVCC_Operation_Possible (O)
      - 234: CSG_Membership_Status (O)
      - 249: Management_Based_MDT_Allowed (O)
      - 263: MDT_PLMN_List (O)
      - 272: RSRVCC_Operation_Possible (O)
      - 277: PLMNidentity (O)
      - 289: PowerSavingIndicator (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.commonID
    
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


class RANAPCNInvokeTrace(RANAPSigProc):
    """CN Invoke Trace: TS 25.413, section 8.17
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 19: OMC_ID (O)
      - 65: TraceReference (M)
      - 66: TraceType (O)
      - 68: TriggerID (O)
      - 69: UE_ID (O)
      Extensions:
      - 125: TracePropagationParameters (O)
      - 244: MDT_Configuration (O)
      - 251: TransportLayerAddress (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.cN_InvokeTrace
    
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


class RANAPSecurityModeControl(RANAPSigProc):
    """Security Mode Control: TS 25.413, section 8.18
    
    CN-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 11: EncryptionInformation (O)
      - 12: IntegrityProtectionInformation (M)
      - 75: KeyStatus (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 5: ChosenEncryptionAlgorithm (O)
      - 6: ChosenIntegrityProtectionAlgorithm (M)
      - 9: CriticalityDiagnostics (O)
      Extensions:
        None
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.securityModeControl
    
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
        # recv the SMC response
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        self.errcause, self.UEInfo = None, {}
        try:
            self.decode_pdu(pdu, self.UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
        #
        if self.errcause:
            self._log('WNG', 'error in the response decoding')
            self.success = False
            self.Iu.SEC['CKSN'] = None
        elif pdu[0] == 'unsuccessfulOutcome':
            if 'Cause' not in self.UEInfo:
                self._log('WNG', 'rejected without cause')
            else:
                self._log('WNG', 'rejected with cause %r' % self.UEInfo['Cause'])
            self.success = False
            self.Iu.reset_sec_ctx()
        else:
            self.success = True
            # update the Iu security context with selected algorithms
            secctx = self.Iu.SEC[self.Iu.SEC['CKSN']]
            try:
                secctx['UEA'] = self.UEInfo['ChosenEncryptionAlgorithm']
            except:
                secctx['UEA'] = None
            try:
                secctx['UIA'] = self.UEInfo['ChosenIntegrityProtectionAlgorithm']
            except:
                secctx['UIA'] = None
            self._log('INF', 'accepted with UEA %r / UIA %i' % (secctx['UEA'], secctx['UIA']))
        #
        # remove from the Iu RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except:
            pass
        #
        # signal the result back to the NAS stack if required
        if self._cb:
            self.ret = self.Iu.trigger_nas(self)
            self._cb = None
    
    def send(self):
        # send the SecurityModeCommand
        if self.TRACK_PDU:
            for pdu in self._snd:
                self._pdu.append( (time(), 'DL', pdu) )
        # send back the list of PDU to be returned to the HNB
        return self._snd
    
    def trigger(self):
        if self.errcause:
            Err = self.Iu.init_ranap_proc(RANAPErrorIndCN, Cause=self.errcause)
            if Err:
                return [Err]
            else:
                return []
        elif not self.success:
            # copy the cause signaled by the RNC
            IuRel = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=self.UEInfo['Cause'])
            if IuRel:
                return [IuRel]
            else:
                return []
        else:
            # new RANAP procedures may have been prepared by the NAS layer
            return self.ret


class RANAPLocationReportingControl(RANAPSigProc):
    """Location Reporting Control: TS 25.413, section 8.19
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 57: RequestType (M)
      Extensions:
      - 111: VerticalAccuracyCode (O)
      - 112: ResponseTime (O)
      - 113: PositioningPriority (O)
      - 114: ClientType (O)
      - 164: IncludeVelocity (O)
      - 168: PeriodicLocationInfo (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.locationReportingControl
    
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


class RANAPLocationReport(RANAPSigProc):
    """Location Report: TS 25.413, section 8.20
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 0: AreaIdentity (O)
      - 4: Cause (O)
      - 57: RequestType (O)
      Extensions:
      - 97: LastKnownServiceArea (O)
      - 119: PositionData (O)
      - 120: PositionDataSpecificToGERANIuMode (O)
      - 122: AccuracyFulfilmentIndicator (O)
      - 165: VelocityEstimate (O)
      - 283: BarometricPressure (O)
      - 285: CivicAddress (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.locationReport
    
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


class RANAPDataVolumeReport(RANAPSigProc):
    """Data Volume Report: TS 25.413, section 8.21
    
    CN-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 33: RAB_DataVolumeReportRequestList (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 31: RAB_DataVolumeReportList (O)
      - 72: RAB_FailedtoReportList (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.dataVolumeReport
    
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


class RANAPInitialUEMessage(RANAPSigProc):
    """Initial UE Message: TS 25.413, section 8.22
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 15: LAI (M)
      - 16: NAS_PDU (M)
      - 55: RAC (C)
      - 58: SAI (M)
      - 79: IuSignallingConnectionIdentifier (M)
      - 86: GlobalRNC_ID (M)
      Extensions:
      - 23: PermanentNAS_UE_ID (O)
      - 108: GERAN_Classmark (O)
      - 127: PLMNidentity (O)
      - 130: NAS_SequenceNumber (O)
      - 166: RedirectAttemptFlag (O)
      - 171: ExtendedRNC_ID (O)
      - 203: CSG_Id (O)
      - 235: Cell_Access_Mode (O)
      - 241: TransportLayerAddress (O)
      - 250: HigherBitratesThan16MbpsFlag (O)
      - 262: TunnelInformation (O)
      - 273: TransportLayerAddress (O)
      - 275: LHN_ID (O)
      - 286: SGSN_Group_Identity (O)
      - 290: UE_Usage_Type (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.initialUE_Message
    
    # Custom decoders
    Decod = {
        'ini': ({
            'LAI' : lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                               bytes_to_uint(x['lAC'], 16)),
            'RAC' : lambda x: bytes_to_uint(x, 8),
            'SAI' : lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                               bytes_to_uint(x['lAC'], 16),
                               bytes_to_uint(x['sAC'], 16)),
            'IuSignallingConnectionIdentifier': lambda x: x[0],
            'GlobalRNC_ID': lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                                       x['rNC-ID'])},
            {}),
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
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        self.errcause, self.retnas, self.UEInfo = None, None, {}
        try:
            self.decode_pdu(pdu, self.UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
        #
        if self.errcause is None:
            # verification against HNBd parameters and HNBAP / RUA infos:
            err, plmn = False, self.RNC.Config['PLMNidentity']
            if self.UEInfo['CN_DomainIndicator'][:2].upper() != self.Iu.DOM:
                self._log('WNG', 'invalid CN_DomainIndicator, %s' % self.UEInfo['CN_DomainIndicator'][:2])
                err = True
            if self.UEInfo['LAI'] != (plmn, self.RNC.Config['LAC']):
                self._log('WNG', 'invalid LAI, %s.%.4x' % self.UEInfo['LAC'])
                err = True
            if 'RAC' in self.UEInfo and self.UEInfo['RAC'] != self.RNC.Config['RAC']:
                self._log('WNG', 'invalid RAC, %.2x' % self.UEInfo['RAC'])
                err = True
            if self.UEInfo['SAI'][2] != self.RNC.Config['SAC']:
                self._log('WNG', 'invalid SAC, %.2x' % self.UEInfo['SAI'][2])
                err = True
            if self.UEInfo['GlobalRNC_ID'] != (plmn, self.RNC.RNC_ID):
                self._log('WNG', 'invalid GlobalRNC-ID, %s' % self.UEInfo['GlobalRNC_ID'])
                err = True
            if err:
                self.errcause = ('protocol', 'message-not-compatible-with-receiver-state')
        #
        # remove from the Iu RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except:
            pass
        #
        if self.errcause is None:
            # update mobility state
            if self.Iu.DOM == 'CS':
                self.Iu.MM.state = 'ACTIVE'
            else:
                self.Iu.GMM.state = 'ACTIVE'
            # update UE location
            self.UE.set_lai(*self.UEInfo['LAI'])
            if 'RAC' in self.UEInfo:
                self.UE.set_rac(self.UEInfo['RAC'])
            # process the NAS PDU, and get a list (potentially empty) of new
            # RANAP procedures to be run 
            self.ret = self.Iu.process_nas(self.UEInfo['NAS_PDU'])
    
    def trigger(self):
        if self.errcause:
            Err = self.Iu.init_ranap_proc(RANAPErrorIndCN, Cause=self.errcause)
            if Err:
                return [Err]
            else:
                return []
        else:
            # a new RANAP procedure may have been prepared by the NAS layer
            return self.ret


class RANAPDirectTransferCN(RANAPSigProc):
    """Direct Transfer: TS 25.413, section 8.23
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 15: LAI (O)
      - 16: NAS_PDU (M)
      - 55: RAC (O)
      - 58: SAI (O)
      - 59: SAPI (O)
      Extensions:
      - 128: RedirectionCompleted (O)
      - 129: RedirectionIndication (O)
      - 202: SubscriberProfileIDforRFP (O)
      - 241: TransportLayerAddress (O)
      - 273: TransportLayerAddress (O)
      - 275: LHN_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.directTransfer
    
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
    
    def send(self):
        if self.TRACK_PDU:
            for pdu in self._snd:
                self._pdu.append( (time(), 'DL', pdu) )
        # remove from the Iu RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except:
            pass
        # send back the list of PDU to be returned to the HNB
        return self._snd


class RANAPDirectTransferRNC(RANAPSigProc):
    """Direct Transfer: TS 25.413, section 8.23
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 15: LAI (O)
      - 16: NAS_PDU (M)
      - 55: RAC (O)
      - 58: SAI (O)
      - 59: SAPI (O)
      Extensions:
      - 128: RedirectionCompleted (O)
      - 129: RedirectionIndication (O)
      - 202: SubscriberProfileIDforRFP (O)
      - 241: TransportLayerAddress (O)
      - 273: TransportLayerAddress (O)
      - 275: LHN_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.directTransfer
    
    # Custom decoders
    Decod = {
        'ini': ({
            'LAI' : lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                               bytes_to_uint(x['lAC'], 16)),
            'RAC' : lambda x: bytes_to_uint(x, 8),
            'SAI' : lambda x: (plmn_buf_to_str(x['pLMNidentity']),
                               bytes_to_uint(x['lAC'], 16),
                               bytes_to_uint(x['sAC'], 16))},
            {}),
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
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        self.errcause, self.retnas, self.UEInfo = None, None, {}
        try:
            self.decode_pdu(pdu, self.UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
        #
        if self.errcause is None:
            # verification against HNBd parameters and HNBAP / RUA infos:
            err = False
            if 'LAI' in self.UEInfo:
                if self.UEInfo['LAI'] != (self.RNC.Config['PLMNidentity'], 
                                          self.RNC.Config['LAC']):
                    self._log('WNG', 'invalid LAI, %s.%.4x' % self.UEInfo['LAC'])
                    err = True
                else:
                    # update UE location
                    self.UE.set_lai(*self.UEInfo['LAI'])
            if 'RAC' in self.UEInfo:
                if self.UEInfo['RAC'] != self.RNC.Config['RAC']:
                    self._log('WNG', 'invalid RAC, %.2x' % self.UEInfo['RAC'])
                    err = True
                else:
                    # update UE RAC
                    self.UE.set_rac(self.UEInfo['RAC'])
            if 'SAI' in self.UEInfo and \
            self.UEInfo['SAI'][2] != self.RNC.Config['SAC']:
                self._log('WNG', 'invalid SAC, %.2x' % self.UEInfo['SAI'][2])
                err = True
            #if err:
            #    self.errcause = ('protocol', 'message-not-compatible-with-receiver-state')
        #
        # remove from the Iu RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except:
            pass
        #
        if self.errcause is None:
            # process the NAS PDU, and get a list (potentially empty) of new
            # RANAP procedures to be triggered
            self.ret = self.Iu.process_nas(self.UEInfo['NAS_PDU'])
    
    def trigger(self):
        if self.errcause:
            Err = self.Iu.init_ranap_proc(RANAPErrorIndCN, Cause=self.errcause)
            if Err:
                return [Err]
            else:
                return []
        else:
            # new RANAP procedures may have been prepared by the NAS layer
            return self.ret


class RANAPOverloadControlCN(RANAPSigProc):
    """Overload Control: TS 25.413, section 8.25
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 18: NumberOfSteps (O)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 3: CN_DomainIndicator (O)
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
      - 245: Priority_Class_Indicator (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.overloadControl
    
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


class RANAPOverloadControlRNC(RANAPSigProc):
    """Overload Control: TS 25.413, section 8.25
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 18: NumberOfSteps (O)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 3: CN_DomainIndicator (O)
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
      - 245: Priority_Class_Indicator (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.overloadControl
    
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


class RANAPResetCN(RANAPSigProc):
    """Reset: TS 25.413, section 8.26
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 4: Cause (M)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    SuccessfulOutcome:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 9: CriticalityDiagnostics (O)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.reset
    
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


class RANAPResetRNC(RANAPSigProc):
    """Reset: TS 25.413, section 8.26
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 4: Cause (M)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    SuccessfulOutcome:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 9: CriticalityDiagnostics (O)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.reset
    
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


class RANAPErrorIndCN(RANAPSigProc):
    """Error Indication: TS 25.413, section 8.27
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (O)
      - 4: Cause (O)
      - 9: CriticalityDiagnostics (O)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.errorIndication
    
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
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        # this means we are not able to process a request received from the RNC
        # this is handled directly within the IuHdlr instance
    
    def send(self):
        if self.TRACK_PDU:
            for pdu in self._snd:
                self._pdu.append( (time(), 'DL', pdu) )
        # send back the list of PDU to be returned to the HNB
        return self._snd


class RANAPErrorIndRNC(RANAPSigProc):
    """Error Indication: TS 25.413, section 8.27
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (O)
      - 4: Cause (O)
      - 9: CriticalityDiagnostics (O)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.errorIndication
    
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
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        self.ErrInfo = {}
        try:
            self.decode_pdu(pdu, self.ErrInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            # do not respond to an error ind, with another error ind...
        else:
            self._log('WNG', 'error indication received: %s.%s' % self.ErrInfo['Cause'])
            # this means the RNC failed to process the previous msg sent to it
            code = self.Iu.ProcLast
            try:
                Proc = self.Iu.Proc[code]
            except:
                pass
            else:
                # abort the corresponding running procedure
                Proc.abort()
        #
        # remove from the RNC RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except:
            pass
    

class RANAPCNDeacivateTrace(RANAPSigProc):
    """CN Deactivate Trace: TS 25.413, section 8.28
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 65: TraceReference (M)
      - 68: TriggerID (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.cN_DeactivateTrace
    
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


class RANAPResetResourceCN(RANAPSigProc):
    """Reset Resource: TS 25.413, section 8.29
    
    CN-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 4: Cause (M)
      - 77: ResetResourceList (M)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    SuccessfulOutcome:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 9: CriticalityDiagnostics (O)
      - 77: ResetResourceAckList (M)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.resetResource
    
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


class RANAPResetResourceRNC(RANAPSigProc):
    """Reset Resource: TS 25.413, section 8.29
    
    RNC-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 4: Cause (M)
      - 77: ResetResourceList (M)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    SuccessfulOutcome:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 9: CriticalityDiagnostics (O)
      - 77: ResetResourceAckList (M)
      - 86: GlobalRNC_ID (O)
      Extensions:
      - 96: GlobalCN_ID (O)
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.resetResource
    
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


class RANAPRABModificationRequest(RANAPSigProc):
    """RAB Modification Request: TS 25.413, section 8.30
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 91: RAB_ModifyList (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.rAB_ModifyRequest
    
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


class RANAPLocationRelatedData(RANAPSigProc):
    """Location Related Data: TS 25.413, section 8.31
    
    CN-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 95: LocationRelatedDataRequestType (O)
      Extensions:
      - 115: LocationRelatedDataRequestTypeSpecificToGERANIuMode (O)
      - 185: RequestedGANSSAssistanceData (C)
    SuccessfulOutcome:
      IEs:
      - 94: BroadcastAssistanceDataDecipheringKeys (O)
      Extensions:
      - 9: CriticalityDiagnostics (O)
      - 186: BroadcastAssistanceDataDecipheringKeys (O)
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      Extensions:
      - 9: CriticalityDiagnostics (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.locationRelatedData
    
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


class RANAPInformationTransfer(RANAPSigProc):
    """Information Transfer: TS 25.413, section 8.32
    
    CN-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 96: GlobalCN_ID (O)
      - 104: InformationTransferID (M)
      - 106: ProvidedData (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 9: CriticalityDiagnostics (O)
      - 86: GlobalRNC_ID (M)
      - 104: InformationTransferID (M)
      Extensions:
      - 171: ExtendedRNC_ID (O)
    UnsuccessfulOutcome:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      - 86: GlobalRNC_ID (M)
      - 104: InformationTransferID (M)
      Extensions:
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.informationTransfer
    
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


class RANAPUESpecificInformation(RANAPSigProc):
    """UE Specific Information: TS 25.413, section 8.33
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 118: UESBI_Iu (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.uESpecificInformation
    
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


class RANAPDirectInformationTransferCN(RANAPSigProc):
    """Direct Information Transfer: TS 25.413, section 8.34
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 86: GlobalRNC_ID (O)
      - 96: GlobalCN_ID (O)
      - 126: InterSystemInformationTransferType (O)
      Extensions:
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.directInformationTransfer
    
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


class RANAPDirectInformationTransferRNC(RANAPSigProc):
    """Direct Information Transfer: TS 25.413, section 8.34
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 86: GlobalRNC_ID (O)
      - 96: GlobalCN_ID (O)
      - 126: InterSystemInformationTransferType (O)
      Extensions:
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.directInformationTransfer
    
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


class RANAPUplinkInformationTransfer(RANAPSigProc):
    """Uplink Information Transfer: TS 25.413, section 8.35
    
    RNC-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 86: GlobalRNC_ID (M)
      - 123: InformationTransferType (C)
      - 136: InformationExchangeID (M)
      - 137: InformationExchangeType (M)
      - 139: InformationRequestType (C)
      Extensions:
      - 171: ExtendedRNC_ID (O)
    SuccessfulOutcome:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 9: CriticalityDiagnostics (O)
      - 96: GlobalCN_ID (O)
      - 136: InformationExchangeID (M)
      - 138: InformationRequested (O)
      Extensions:
        None
    UnsuccessfulOutcome:
      IEs:
      - 3: CN_DomainIndicator (M)
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      - 96: GlobalCN_ID (O)
      - 136: InformationExchangeID (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.uplinkInformationExchange
    
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


class RANAPMBSMSessionStart(RANAPSigProc):
    """MBMS Session Start: TS 25.413, section 8.36
    
    CN-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 79: IuSignallingConnectionIdentifier (M)
      - 96: GlobalCN_ID (O)
      - 135: FrequenceLayerConvergenceFlag (O)
      - 143: MBMSBearerServiceType (M)
      - 145: MBMSServiceArea (M)
      - 146: MBMSSessionDuration (M)
      - 147: MBMSSessionIdentity (O)
      - 148: PDP_TypeInformation (O)
      - 149: RAB_Parameters (M)
      - 150: RAListofIdleModeUEs (O)
      - 153: TMGI (M)
      - 157: MBMSSessionRepetitionNumber (O)
      - 163: TimeToMBMSDataTransfer (M)
      Extensions:
      - 169: MBMSCountingInformation (O)
      - 201: MBMSSynchronisationInformation (O)
      - 238: PDP_TypeInformation_extension (O)
      - 276: Session_Re_establishment_Indicator (O)
    SuccessfulOutcome:
      IEs:
      - 4: Cause (O)
      - 9: CriticalityDiagnostics (O)
      - 154: TransportLayerInformation (O)
      Extensions:
        None
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.mBMSSessionStart
    
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


class RANAPMBMSSessionUpdate(RANAPSigProc):
    """MBMS Session Update: TS 25.413, section 8.37
    
    CN-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 134: DeltaRAListofIdleModeUEs (M)
      - 152: SessionUpdateID (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 4: Cause (O)
      - 9: CriticalityDiagnostics (O)
      - 152: SessionUpdateID (M)
      - 154: TransportLayerInformation (O)
      Extensions:
        None
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      - 152: SessionUpdateID (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.mBMSSessionUpdate
    
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


class RANAPMBMSSessionStop(RANAPSigProc):
    """MBMS Session Stop: TS 25.413, section 8.38
    
    CN-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 144: MBMSCNDe_Registration (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 4: Cause (O)
      - 9: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.mBMSSessionStop
    
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


class RANAPMBMSUELinking(RANAPSigProc):
    """MBMS UE Linking: TS 25.413, section 8.39
    
    CN-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 141: JoinedMBMSBearerService_IEs (O)
      - 142: LeftMBMSBearerService_IEs (O)
      Extensions:
        None
    Outcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 155: UnsuccessfulLinking_IEs (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.mBMSUELinking
    
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


class RANAPMBMSRegistration(RANAPSigProc):
    """MBMS Registration: TS 25.413, section 8.40
    
    RNC-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 86: GlobalRNC_ID (O)
      - 132: APN (C)
      - 140: IPMulticastAddress (C)
      - 151: MBMSRegistrationRequestType (M)
      - 153: TMGI (M)
      Extensions:
      - 171: ExtendedRNC_ID (O)
    SuccessfulOutcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 96: GlobalCN_ID (O)
      - 153: TMGI (O)
      Extensions:
        None
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      - 96: GlobalCN_ID (O)
      - 153: TMGI (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.mBMSRegistration
    
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


class RANAPMBMSCNDeregistration(RANAPSigProc):
    """MBMS CN Deregistration: TS 25.413, section 8.41
    
    CN-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 96: GlobalCN_ID (O)
      - 153: TMGI (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 4: Cause (O)
      - 9: CriticalityDiagnostics (O)
      - 86: GlobalRNC_ID (M)
      - 153: TMGI (M)
      Extensions:
      - 171: ExtendedRNC_ID (O)
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.mBMSCNDe_Registration
    
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


class RANAPMBMSRABEstablishmentInd(RANAPSigProc):
    """MBMS RAB Establishement Indication: TS 25.413, section 8.42
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 154: TransportLayerInformation (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.mBMSRABEstablishmentIndication
    
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


class RANAPMBMSRABRelease(RANAPSigProc):
    """MBMS RAB Release: TS 25.413, section 8.43
    
    RNC-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 4: Cause (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      Extensions:
        None
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.mBMSRABRelease
    
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


class RANAPEnhancedRelocationComplete(RANAPSigProc):
    """Enhanced Relocation Complete: TS 25.413, section 8.44
    
    RNC-initiated
    request-accept, request
    
    InitiatingMessage:
      IEs:
      - 79: IuSignallingConnectionIdentifier (M)
      - 188: RAB_SetupList_EnhancedRelocCompleteReq (O)
      - 196: IuSignallingConnectionIdentifier (M)
      - 212: GlobalRNC_ID (M)
      - 213: ExtendedRNC_ID (O)
      - 222: GlobalRNC_ID (M)
      - 223: ExtendedRNC_ID (O)
      Extensions:
      - 5: ChosenEncryptionAlgorithm (O)
      - 6: ChosenIntegrityProtectionAlgorithm (O)
      - 203: CSG_Id (O)
      - 235: Cell_Access_Mode (O)
      - 250: HigherBitratesThan16MbpsFlag (O)
      - 262: TunnelInformation (O)
      - 275: LHN_ID (O)
    SuccessfulOutcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 190: RAB_SetupList_EnhancedRelocCompleteRes (O)
      - 210: RAB_ToBeReleasedList_EnhancedRelocCompleteRes (O)
      Extensions:
      - 233: UE_AggregateMaximumBitRate (O)
      - 234: CSG_Membership_Status (O)
      - 239: MSISDN (O)
    UnsuccessfulOutcome:
      IEs:
      - 4: Cause (M)
      - 9: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.enhancedRelocationComplete
    
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


class RANAPEnhancedRelocationCompleteConfirm(RANAPSigProc):
    """Enhanced Relocation Complete Confirm: TS 25.413, section 8.45
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 35: RAB_FailedList (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.enhancedRelocationCompleteConfirm
    
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


class RANAPSRVCCPreparation(RANAPSigProc):
    """SRVCC Preparation: TS 25.413, section 8.46
    
    RNC-initiated
    request-response
    
    InitiatingMessage:
      IEs:
        None
      Extensions:
        None
    Outcome:
      IEs:
      - 9: CriticalityDiagnostics (O)
      - 224: EncryptionKey (M)
      - 225: IntegrityProtectionKey (M)
      - 227: SRVCC_Information (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.sRVCCPreparation
    
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


class RANAPUERadioCapabilityMatch(RANAPSigProc):
    """UE Radio Capability Match: TS 25.413, section 8.47
    
    CN-initiated
    request-response
    
    InitiatingMessage:
      IEs:
        None
      Extensions:
        None
    Outcome:
      IEs:
      - 258: VoiceSupportMatchIndicator (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.ueRadioCapabilityMatch
    
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


class RANAPUERegistrationQuery(RANAPSigProc):
    """UE Registration Query: TS 25.413, section 8.48
    
    RNC-initiated
    request
    
    InitiatingMessage:
      IEs:
      - 23: PermanentNAS_UE_ID (M)
      - 79: IuSignallingConnectionIdentifier (M)
      Extensions:
        None
    Outcome:
      IEs:
      - 281: UERegistrationQueryResult (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.ueRegistrationQuery
    
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


class RANAPRerouteNASRequest(RANAPSigProc):
    """Reroute NAS Request: TS 25.413, section 8.49
    
    CN-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 286: SGSN_Group_Identity (M)
      - 287: P_TMSI (O)
      - 288: [OCTET STRING] (M)
      - 290: UE_Usage_Type (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.rerouteNASRequest
    
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


class RANAPPrivateMessageRNC(RANAPSigProc):
    """Private Message: TS 25.413
    
    RNC-initiated
    request only
    
    InitiatingMessage:
      None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.privateMessage
    
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


class RANAPPrivateMessageCN(RANAPSigProc):
    """Private Message: TS 25.413
    
    CN-initiated
    request only
    
    InitiatingMessage:
      None
    """
    
    # ASN.1 procedure description
    Desc = RANAP.RANAP_PDU_Descriptions.privateMessage
    
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


RANAPRABAssignment.init()
RANAPRABReleaseRequest.init()
RANAPIuReleaseRequest.init()
RANAPIuRelease.init()
RANAPRelocationPreparation.init()
RANAPRelocationResourceAllocation.init()
RANAPRelocationDetect.init()
RANAPRelocationComplete.init()
RANAPRelocationCancel.init()
RANAPSRNSContextTransfer.init()
RANAPSRNSDataForwarding.init()
RANAPSRNSContextForwardToCN.init()
RANAPSRNSContextForwardToRNC.init()
RANAPPaging.init()
RANAPCommonID.init()
RANAPCNInvokeTrace.init()
RANAPSecurityModeControl.init()
RANAPLocationReportingControl.init()
RANAPLocationReport.init()
RANAPDataVolumeReport.init()
RANAPInitialUEMessage.init()
RANAPDirectTransferCN.init()
RANAPDirectTransferRNC.init()
RANAPOverloadControlCN.init()
RANAPOverloadControlRNC.init()
RANAPResetCN.init()
RANAPResetRNC.init()
RANAPErrorIndCN.init()
RANAPErrorIndRNC.init()
RANAPCNDeacivateTrace.init()
RANAPResetResourceCN.init()
RANAPResetResourceRNC.init()
RANAPRABModificationRequest.init()
RANAPLocationRelatedData.init()
RANAPInformationTransfer.init()
RANAPUESpecificInformation.init()
RANAPDirectInformationTransferCN.init()
RANAPDirectInformationTransferRNC.init()
RANAPUplinkInformationTransfer.init()
RANAPMBSMSessionStart.init()
RANAPMBMSSessionUpdate.init()
RANAPMBMSSessionStop.init()
RANAPMBMSUELinking.init()
RANAPMBMSRegistration.init()
RANAPMBMSCNDeregistration.init()
RANAPMBMSRABEstablishmentInd.init()
RANAPMBMSRABRelease.init()
RANAPEnhancedRelocationComplete.init()
RANAPEnhancedRelocationCompleteConfirm.init()
RANAPSRVCCPreparation.init()
RANAPUERadioCapabilityMatch.init()
RANAPUERegistrationQuery.init()
RANAPRerouteNASRequest.init()
RANAPPrivateMessageRNC.init()
RANAPPrivateMessageCN.init()

# RANAP RNC-initiated procedures dispatcher
RANAPProcRncDispatcher = {
    1 : RANAPIuRelease,
    2 : RANAPRelocationPreparation,
    4 : RANAPRelocationCancel,
    9 : RANAPResetRNC,
    10 : RANAPRABReleaseRequest,
    11 : RANAPIuReleaseRequest,
    12 : RANAPRelocationDetect,
    13 : RANAPRelocationComplete,
    18 : RANAPLocationReport,
    19 : RANAPInitialUEMessage,
    20 : RANAPDirectTransferRNC,
    21 : RANAPOverloadControlRNC,
    22 : RANAPErrorIndRNC,
    24 : RANAPSRNSContextForwardToCN,
    25 : RANAPPrivateMessageRNC,
    27 : RANAPResetResourceRNC,
    29 : RANAPRABModificationRequest,
    33 : RANAPUplinkInformationTransfer,
    34 : RANAPDirectInformationTransferRNC,
    39 : RANAPMBMSRegistration,
    41 : RANAPMBMSRABEstablishmentInd,
    42 : RANAPMBMSRABRelease,
    43 : RANAPEnhancedRelocationComplete,
    44 : RANAPEnhancedRelocationCompleteConfirm,
    46 : RANAPSRVCCPreparation,
    48 : RANAPUERegistrationQuery
    }

# RANAP CN-initiated procedures dispatcher
RANAPProcCnDispatcher = {
    0 : RANAPRABAssignment,
    3 : RANAPRelocationResourceAllocation,
    5 : RANAPSRNSContextTransfer,
    6 : RANAPSecurityModeControl,
    7 : RANAPDataVolumeReport,
    9 : RANAPResetCN,
    14 : RANAPPaging,
    15 : RANAPCommonID,
    16 : RANAPCNInvokeTrace,
    17 : RANAPLocationReportingControl,
    20 : RANAPDirectTransferCN,
    21 : RANAPOverloadControlCN,
    22 : RANAPErrorIndCN,
    23 : RANAPSRNSDataForwarding,
    24 : RANAPSRNSContextForwardToRNC,
    25 : RANAPPrivateMessageCN,
    26 : RANAPCNDeacivateTrace,
    27 : RANAPResetResourceCN,
    30 : RANAPLocationRelatedData,
    31 : RANAPInformationTransfer,
    32 : RANAPUESpecificInformation,
    34 : RANAPDirectInformationTransferCN,
    35 : RANAPMBSMSessionStart,
    36 : RANAPMBMSSessionUpdate,
    37 : RANAPMBMSSessionStop,
    38 : RANAPMBMSUELinking,
    40 : RANAPMBMSCNDeregistration,
    47 : RANAPUERadioCapabilityMatch,
    49 : RANAPRerouteNASRequest,
    }

