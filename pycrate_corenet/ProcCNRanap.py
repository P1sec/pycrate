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
# * File Name : pycrate_corenet/ProcCNRanap.py
# * Created : 2017-07-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'RANAPSigProc',
    'RANAPConlessSigProc',
    #
    'RANAPRelocationPreparation',
    'RANAPRelocationCancel',
    'RANAPRABReleaseRequest',
    'RANAPIuReleaseRequest',
    'RANAPRelocationDetect',
    'RANAPRelocationComplete',
    'RANAPLocationReport',
    'RANAPInitialUEMessage',
    'RANAPDirectTransferRNC',
    'RANAPErrorIndRNC',
    'RANAPSRNSContextForwardToCN',
    'RANAPPrivateMessageRNC',
    'RANAPRABModificationRequest',
    'RANAPMBMSRegistration',
    'RANAPMBMSRABEstablishmentInd',
    'RANAPMBMSRABRelease',
    'RANAPEnhancedRelocationComplete',
    'RANAPEnhancedRelocationCompleteConfirm',
    'RANAPSRVCCPreparation',
    'RANAPUERegistrationQuery',
    'RANAPRABAssignment',
    'RANAPIuRelease',
    'RANAPRelocationResourceAllocation',
    'RANAPSRNSContextTransfer',
    'RANAPSecurityModeControl',
    'RANAPDataVolumeReport',
    'RANAPCommonID',
    'RANAPCNInvokeTrace',
    'RANAPLocationReportingControl',
    'RANAPDirectTransferCN',
    'RANAPErrorIndCN',
    'RANAPSRNSDataForwarding',
    'RANAPSRNSContextForwardToRNC',
    'RANAPPrivateMessageCN',
    'RANAPCNDeactivateTrace',
    'RANAPLocationRelatedData',
    'RANAPUESpecificInformation',
    'RANAPMBSMSessionStart',
    'RANAPMBMSSessionUpdate',
    'RANAPMBMSSessionStop',
    'RANAPMBMSUELinking',
    'RANAPMBMSCNDeregistration',
    'RANAPUERadioCapabilityMatch',
    'RANAPRerouteNASRequest',
    #
    'RANAPResetRNC',
    'RANAPResetCN',
    'RANAPPaging',
    'RANAPOverloadControlRNC',
    'RANAPOverloadControlCN',
    'RANAPErrorIndConlessRNC',
    'RANAPErrorIndConlessCN',
    'RANAPResetResourceRNC',
    'RANAPResetResourceCN',
    'RANAPUplinkInformationTransfer',
    'RANAPInformationTransfer',
    'RANAPDirectInformationTransferRNC',
    'RANAPDirectInformationTransferCN',
    #
    'RANAPProcRncDispatcher',
    'RANAPProcCnDispatcher',
    'RANAPConlessProcRncDispatcher',
    'RANAPConlessProcCnDispacther'
    ]

from .utils     import *
from .ProcProto import *

#------------------------------------------------------------------------------#
# RANAP signalling procedure
# TS 25.413, version d20
# Core Network side
#------------------------------------------------------------------------------#

class RANAPSigProc(LinkSigProc):
    """RANAP connection-oriented signalling procedure handler
    
    instance attributes:
        - Name  : procedure name
        - Iu    : reference to the Iu[C|P]Sd instance running this procedure
        - RNC   : reference to the HNBd instance connected by Iu
        - Server: reference to the CorenetServer instance handling the RNC
        - UE    : reference to the UEd instance connected by Iu
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
    
    def __init__(self, iud):
        #
        self.Name   = self.__class__.__name__
        self.Iu     = iud
        self.RNC    = iud.RNC
        self.Server = iud.RNC.Server
        if iud.UE:
            self.UE = iud.UE
        else:
            self._log('WNG', 'no UEd instance attached')
        #
        # to store PDU traces
        self._pdu = []
        # list of PDU to be sent to the HNB
        self._pdu_tx = []
        # enable NAS procedure to set callback to .postprocess() before self terminates
        self._cb = None
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.Iu._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def _recv(self, pdu_rx):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu_rx) )
        self.errcause, self.UEInfo = None, {}
        try:
            self.decode_pdu(pdu_rx, self.UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu (%s), sending error indication' % err)
            # error cause: protocol, abstract-syntax-error-reject
            self.errcause = ('protocol', 100)
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
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
        if self.Code in self.Iu.Proc:
            del self.Iu.Proc[self.Code]
        self._log('INF', 'aborting')


class RANAPConlessSigProc(LinkSigProc):
    """RANAP connection-less signalling procedure handler
    
    instance attributes:
        - Name  : procedure name
        - RNC   : reference to the HNBd instance connected by Iu
        - Server: reference to the CorenetServer instance handling the RNC
        - Desc  : ASN.1 procedure description
        - Code  : procedure code
        - Crit  : procedure criticality
        - Cont  : ASN.1 procedure PDU(s) content
        - Encod : custom PDU encoders with fixed values
        - Decod : custom PDU decoders with transform functions
    """
    
    TRACK_PDU = True
    
    def __init__(self, rncd):
        #
        self.Name   = self.__class__.__name__
        self.RNC    = rncd
        self.Server = rncd.Server
        #
        # to store PDU traces
        self._pdu = []
        # list of PDU to be sent to the HNB
        self._pdu_tx = []
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.RNC._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def _recv(self, pdu_rx):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu_rx) )
        self.errcause, self.RNCInfo = None, {}
        try:
            self.decode_pdu(pdu_rx, self.RNCInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu (%s), sending error indication' % err)
            # error cause: protocol, abstract-syntax-error-reject
            self.errcause = ('protocol', 100)
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
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
        if self.Code in self.RNC.ProcRanap:
            del self.RNC.ProcRanap[self.Code]
        self._log('INF', 'aborting')


class RANAPRABAssignment(RANAPSigProc):
    """RAB Assignment: TS 25.413, section 8.2
    
    CN-initiated
    request-response(s)
    connection-oriented signalling procedure
    
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
    
    # TODO: currently, only the creation of RAB is handled here
    # the deletion of RAB should also be implemented at least, to support
    # the NAS SM procedure DeactivatePDPCtxtReq
    
    def send(self):
        if hasattr(self, '_gtp_add_mobile_nsapi'):
            self._enable_gtpu()
        # in case of RAB teardown, we wait for the outcome to disable the GTP tunnels
        return self._send()
    
    def _enable_gtpu(self):
        if hasattr(self, '_gtp_add_mobile_nsapi'):
            for nsapi in self._gtp_add_mobile_nsapi:
                pdpcfg = self.Iu.SM.PDP[nsapi]
                rabcfg = pdpcfg['RAB']
                pdpcfg['state'] = 1
                self.UE.Server.GTPUd.add_mobile(
                    rabcfg['SGW-GTP-TEID'], # teid_ul
                    pdpcfg['PDPAddr'], # mobile_addr
                    (rabcfg['SGW-TLA'], rabcfg['HNB-TLA']), # local gtpu addr, hnb gtpu ip (maybe None)
                    rabcfg['HNB-GTP-TEID']) # teid_dl (maybe None)
        else:
            self._log('WNG', 'enable_gtpu: no GTP mobile info provided')
    
    def _disable_gtpu(self):
        if hasattr(self, '_gtp_rem_mobile_nsapi'):
            for nsapi in self._gtp_rem_mobile_nsapi:
                if nsapi in self.Iu.SM.PDP:
                    pdpcfg = self.Iu.SM.PDP[nsapi]
                    self.Server.GTPUd.rem_mobile(pdpcfg['RAB']['SGW-GTP-TEID'])
                    pdpcfg['state'] = 0
        else:
            self._log('WNG', 'disable_gtpu: no GTP mobile info provided')
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.Iu.Proc[self.Code]
        except Exception:
            pass
        #
        if self.errcause:
            self.success = False
            self._log('WNG', 'error in the response decoding')
            if hasattr(self, '_gtp_add_mobile_nsapi'):
                self._gtp_rem_mobile_nsapi = self._gtp_add_mobile_nsapi
            if hasattr(self, '_gtp_rem_mobile_nsapi'):
                self._disable_gtpu()
        else:
            self.success = True
            if hasattr(self, '_gtp_add_mobile_nsapi'):
                self._gtp_rem_mobile_nsapi = []
            # TODO: rablists are sequence of sequence of rabitem...
            # here we go over all 1st level item
            # and take the 1st item of the previous selection to call it "rabitem"
            # in case rabitem are sequenced at the 2nd level, we won't see them...
            #
            if 'RAB_SetupOrModifiedList' in self.UEInfo:
                # RAB successfully established, to be completed with eNB IP and TEID
                for rabitem in self.UEInfo['RAB_SetupOrModifiedList']:
                    rabitem = rabitem[0]['value'][1]
                    nsapi   = rabitem['rAB-ID'][0]
                    if nsapi in self._gtp_add_mobile_nsapi:
                        rabcfg = self.Iu.SM.PDP[nsapi]['RAB']
                        tla = rabitem['transportLayerAddress']
                        if tla[1] == 32:
                            # raw IPv4 address
                            rabcfg['HNB-TLA'] = inet_ntoa(uint_to_bytes(*rabitem['transportLayerAddress']))
                        elif tla[1] == 160:
                            # X.213 addr
                            x213pref = tla[0]>>136
                            if x213pref>>16 == 0x35 and x213pref & 0xffff == 1:
                                # IPv4 address
                                rabcfg['HNB-TLA'] = inet_ntoa(uint_to_bytes((tla[0]>>104)&0xffffffff, 32))
                        if rabcfg['HNB-TLA'] is None:
                            self._log('WNG', 'no IPv4 TLA provided')
                            self._gtp_rem_mobile_nsapi.append(nsapi)
                        else:
                            if rabitem['iuTransportAssociation'][0] == 'gTP-TEI':
                                rabcfg['HNB-GTP-TEID'] = bytes_to_uint(rabitem['iuTransportAssociation'][1], 32)
                                # activate the GTP DL parameters
                                self.Server.GTPUd.set_mobile_dl(
                                    rabcfg['SGW-GTP-TEID'], # teid_ul
                                    ran_ip=(rabcfg['SGW-TLA'], rabcfg['HNB-TLA']),
                                    teid_dl=rabcfg['HNB-GTP-TEID'])
                            else:
                                self._log('WNG', 'no GTP TEID provided')
                                self._gtp_rem_mobile_nsapi.append(nsapi)
            #
            if 'RAB_FailedList' in self.UEInfo:
                # RAB failed to establish, to be disabled
                for rabitem in self.UEInfo['RAB_FailedList']:
                    rabitem = rabitem[0]['value'][1]
                    nsapi   = rabitem['rAB-ID'][0]
                    if nsapi in self._gtp_add_mobile_nsapi:
                        self._gtp_rem_mobile_nsapi.append(nsapi)
                        self._log('INF', 'unable to establish RAB %i, cause %r'\
                                  % (nsapi, rabitem['cause']))
            #
            if 'RAB_QueueList' in self.UEInfo:
                self._log('WNG', 'handling of RAB-QueueList not implemented')
                # TODO
            #
            if 'RAB_ReleaseFailedList' in self.UEInfo:
                # RAB failed to be toredown
                for rabitem in self.UEInfo['RAB_ReleaseFailedList']:
                    rabitem = rabitem[0]['value'][1]
                    nsapi   = rabitem['rAB-ID'][0]
                    if nsapi in self._gtp_rem_mobile_nsapi:
                        self._log('INF', 'unable to release RAB %i, cause %r'\
                                  % (nsapi, rabitem['cause']))
            #
            if 'RAB_ReleasedList' in self.UEInfo:
                # RAB successfully tore down
                for rabitem in self.UEInfo['RAB_ReleasedList']:
                    rabitem = rabitem[0]['value'][1]
                    nsapi   = rabitem['rAB-ID'][0]
                    if nsapi in self._gtp_rem_mobile_nsapi:
                        # nothing to do actually
                        pass
            #
            if self._gtp_rem_mobile_nsapi:
                self._disable_gtpu()
        #
        if self._cb:
            self._ret = self.Iu.trigger_nas(self)
            self._cb = None
        else:
            self._ret = []
    
    def trigger(self):
        if self._ret:
            # new RANAP procedure prepared by the NAS layer
            return self._ret
        else:
            return []
    
    def abort(self):
        RANAPSigProc.abort(self)
        if hasattr(self, '_gtp_add_mobile_nsapi'):
            self._gtp_rem_mobile_nsapi = self._gtp_add_mobile_nsapi
            self._disable_gtpu()


class RANAPRABReleaseRequest(RANAPSigProc):
    """RAB Release Request: TS 25.413, section 8.3
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPIuReleaseRequest(RANAPSigProc):
    """Iu Release Request: TS 25.413, section 8.4
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
        self._recv(pdu)
    
    def trigger(self):
        # copy the cause signaled by the RNC
        Proc = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=self.UEInfo['Cause'])
        if Proc:
            return [Proc]
        else:
            return []


class RANAPIuRelease(RANAPSigProc):
    """Iu Release: TS 25.413, section 8.5
    
    CN-initiated
    request-response
    connection-oriented signalling procedure
    
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
    
    send = RANAPSigProc._send
    
    def _release_iu(self):
        # update mobility state
        if self.Iu.DOM == 'CS':
            if self.Iu.MM.state != 'INACTIVE':
                self.Iu.MM.state = 'IDLE'
        else:
            # suspend all RAB
            self.Iu.SM.pdp_suspend()
            if self.Iu.GMM.state != 'INACTIVE':
                self.Iu.GMM.state = 'IDLE'
        self._log('INF', 'UE disconnected, cause %r' % (self._NetInfo['Cause'], ))
        #
        # disconnect the Iu interface to the RNC for the UE
        self.Iu.unset_ran()
        self.Iu.unset_ctx()
    
    def recv(self, pdu):
        # recv the IuRelease response
        self._recv(pdu)
        # remove from the Iu RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except Exception:
            pass
        self._release_iu()
    
    def abort(self):
        # remove from the Iu RANAP procedure stack
        try:
            del self.Iu.Proc[self.Code]
        except Exception:
            pass
        self._log('INF', 'aborting')
        self._release_iu()


class RANAPRelocationPreparation(RANAPSigProc):
    """Relocation Preparation: TS 25.413, section 8.6
    
    RNC-initiated
    request-accept, request-reject
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPRelocationResourceAllocation(RANAPSigProc):
    """Relocation Resource Allocation: TS 25.413, section 8.7
    
    CN-initiated
    request-accept, request-reject
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPRelocationDetect(RANAPSigProc):
    """Relocation Detect: TS 25.413, section 8.8
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPRelocationComplete(RANAPSigProc):
    """Relocation Complete: TS 25.413, section 8.9
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPRelocationCancel(RANAPSigProc):
    """Relocation Cancel: TS 25.413, section 8.10
    
    RNC-initiated
    request-response
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPSRNSContextTransfer(RANAPSigProc):
    """SRNS Context Transfer: TS 25.413, section 8.11
    
    CN-initiated
    request-response
    connection-oriented signalling procedure
    
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
    
    # not implemented
    send = RANAPSigProc._send
    
    def recv(self, pdu):
        # recv the SRNSContextTransfer response
        self._recv(pdu)
        try:
            del self.Iu.Proc[self.Code]
        except Exception:
            pass
        if not self.errcause:
            # TODO: do something with the list of RAB contexts
            self._log('INF', 'success')


class RANAPSRNSDataForwarding(RANAPSigProc):
    """SRNS Data Forwarding: TS 25.413, section 8.12
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPSRNSContextForwardToCN(RANAPSigProc):
    """SRNS Context Forwarding from Source RNC to CN: TS 25.413, section 8.13
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPSRNSContextForwardToRNC(RANAPSigProc):
    """SRNS Context Forwarding from CN to target RNC: TS 25.413, section 8.14
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPPaging(RANAPConlessSigProc):
    """Paging: TS 25.413, section 8.15
    
    CN-initiated
    request only
    connection-less signalling procedure
    
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
    
    send = RANAPConlessSigProc._send


class RANAPCommonID(RANAPSigProc):
    """Common ID: TS 25.413, section 8.16
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    def send(self):
        self._log('INF', 'sent')
        return self._send()


class RANAPCNInvokeTrace(RANAPSigProc):
    """CN Invoke Trace: TS 25.413, section 8.17
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    def send(self):
        try:
            tracerefl = '0x%s' % hexlify(self.TraceReference).decode('ascii')
        except Exception:
            tracerefl = repr(self.TraceReference)
        self._log('INF', 'sent with trace reference %s' % tracerefl)
        return self._send()


class RANAPSecurityModeControl(RANAPSigProc):
    """Security Mode Control: TS 25.413, section 8.18
    
    CN-initiated
    request-accept, request-reject
    connection-oriented signalling procedure
    
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
    
    send = RANAPSigProc._send
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.Iu.Proc[self.Code]
        except Exception:
            pass
        #
        if self.errcause:
            self._log('WNG', 'error in the response decoding')
            self.success = False
            self.Iu.SEC['CKSN'] = None
        elif pdu[0] == 'unsuccessfulOutcome':
            try:
                self._log('WNG', 'failure, rejected with cause %r' % (self.UEInfo['Cause'], ))
            except Exception:
                self._log('WNG', 'failure, rejected without cause')
            self.success = False
            self.Iu.reset_sec_ctx()
        else:
            self.success, self._ret = True, []
            # update the Iu security context with selected algorithms
            secctx = self.Iu.SEC[self.Iu.SEC['CKSN']]
            try:
                secctx['UEA'] = self.UEInfo['ChosenEncryptionAlgorithm']
                uea = secctx['UEA']
            except Exception:
                secctx['UEA'] = None
                uea = 0
            try:
                secctx['UIA'] = self.UEInfo['ChosenIntegrityProtectionAlgorithm']
                uia = 1 + secctx['UIA'] # UIA1 -> uia = 1, UIA2 -> uia = 2
            except Exception:
                secctx['UIA'] = None
                uia = 0
            self._log('INF', 'accepted with UEA%i / UIA%i' % (uea, uia))
        #
        # signal the result back to the NAS stack if required
        if self._cb:
            self._ret = self.Iu.trigger_nas(self)
            self._cb = None
    
    def trigger(self):
        if not self.success:
            # copy the cause signaled by the RNC
            Proc = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=self.UEInfo['Cause'])
            if Proc:
                return [Proc]
            else:
                return []
        else:
            # new RANAP procedures may have been prepared by the NAS layer
            return self._ret


class RANAPLocationReportingControl(RANAPSigProc):
    """Location Reporting Control: TS 25.413, section 8.19
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    def send(self):
        self._log('INF', 'sent with request type %r' % self.RequestType)
        return self._send()


class RANAPLocationReport(RANAPSigProc):
    """Location Report: TS 25.413, section 8.20
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    _PosDataDiscLUT = {
        0 : 'Positioning Data Set present (non-GANSS methods used)',
        1 : 'GANSS Positioning Data Set present (GANSS methods used)',
        2 : 'Additional Positioning Data Set'
        }
    _PosMethLUT = {
        5 : 'Mobile Assisted GPS',
        6 : 'Mobile Based GPS',
        7 : 'Conventional GPS',
        8 : 'U-TDOA',
        9 : 'OTDOA',
        10 : 'IPDL',
        11 : 'RTT',
        12 : 'Cell ID'
        }
    _UsageLUT = {
        0 : 'Attempted unsuccessfully due to failure or interruption - not used',
        1 : 'Attempted successfully: results not used to generate location - not used',
        2 : 'Attempted successfully: results used to verify but not generate location - not used',
        3 : 'Attempted successfully: results used to generate location',
        4 : 'Attempted successfully: case where MS supports multiple mobile based positioning methods '\
            'and the actual method or methods used by the MS cannot be determined'
        }
    _GANSSPosMethLUT = {
        0 : 'MS-Based',
        1 : 'MS-Assisted',
        2 : 'Conventional'
        }
    _GANSSID = {
        0 : 'Galileo',
        1 : 'SBAS',
        2 : 'Modernized GPS',
        3 : 'QZSS',
        4 : 'GLONASS',
        5 : 'BDS '
        }
    _AddPosMethLUT = {
        1 : 'MS-Assisted',
        2 : 'Standalone'
        }
    _AddID = {
        0 : 'Barometric Pressure',
        1 : 'WLAN',
        3 : 'Bluetooth',
        4 : 'MBS'
        }
    
    def recv(self, pdu):
        # recv the data volume report response
        self._recv(pdu)
        if not self.errcause:
            desc, ueinfo = [], dict(self.UEInfo)
            if 'RequestType' in ueinfo:
                del ueinfo['RequestType']
            if 'AreaIdentity' in ueinfo and ueinfo['AreaIdentity'][0] == 'sAI':
                desc.append('SAI PLMN %s, LAC 0x%.4x, SAC 0x%.4x'\
                            % (plmn_buf_to_str(ueinfo['AreaIdentity'][1]['pLMNidentity']),
                               unpack('>H', ueinfo['AreaIdentity'][1]['lAC'])[0],
                               unpack('>H', ueinfo['AreaIdentity'][1]['sAC'])[0]))
                del ueinfo['AreaIdentity']
            if 'PositionData' in ueinfo:
                try:
                    desc.extend( self._get_position_data(ueinfo['PositionData']) )
                except Exception:
                    pass
                else:
                    del ueinfo['PositionData']
            if ueinfo:
                # some more unprocessed values
                desc.extend(['%s, %r' % (k, v) for (k, v) in ueinfo.items()])
            self._log('INF', ' | '.join(desc))
    
    @classmethod
    def _get_position_data(cls, data):
        disc, ds, desc = data['positioningDataDiscriminator'][0], data['positioningDataSet'], []
        if disc == 0:
            pmu = ord(ds[0])
            pm, pu = pmu>>3, pmu&0x7
            desc.append('positioning method %i (%s) and usage %i (%s)'\
                        % (pm, cls._PosMethLUT[pm], pu, cls._UsageLUT[pu]))
            if len(ds) > 1:
                pmu = ord(ds[1])
                pm, pid, pu = pmu>>6, (pmu>>3)&0x7, pmu&0x7
                desc.append('GANSS positioning method %i (%s), id %i (%s), usage %i (%s)'\
                            % (pm, cls._GANSSPosMethLUT[pm], pid, cls._GANSSID[pid], pu, cls._UsageLUT[pu]))
                if len(ds) > 2:
                    pmu = ord(ds[2])
                    pm, pid, pu = pmu>>6, (pmu>>3)&0x7, pmu&0x7
                    desc.append('additional positioning method %i (%s), id %i (%s), usage %i (%s)'\
                                % (pm, cls._AddPosMethLUT[pm], pid, cls._AddID[pid], pu, cls._UsageLUT[pu]))
        #
        elif disc == 1:
            pmu = ord(ds[1])
            pm, pid, pu = pmu>>6, (pmu>>3)&0x7, pmu&0x7
            desc.append('GANSS positioning method %i (%s), id %i (%s), usage %i (%s)'\
                        % (pm, cls._GANSSPosMethLUT[pm], pid, cls._GANSSID[pid], pu, cls._UsageLUT[pu]))
            if len(ds) > 2:
                pmu = ord(ds[2])
                pm, pid, pu = pmu>>6, (pmu>>3)&0x7, pmu&0x7
                desc.append('additional positioning method %i (%s), id %i (%s), usage %i (%s)'\
                            % (pm, cls._AddPosMethLUT[pm], pid, cls._AddID[pid], pu, cls._UsageLUT[pu]))
        #
        elif disc == 2:
            pmu = ord(ds[2])
            pm, pid, pu = pmu>>6, (pmu>>3)&0x7, pmu&0x7
            desc.append('additional positioning method %i (%s), id %i (%s), usage %i (%s)'\
                        % (pm, cls._AddPosMethLUT[pm], pid, cls._AddID[pid], pu, cls._UsageLUT[pu]))
        #
        return desc


class RANAPDataVolumeReport(RANAPSigProc):
    """Data Volume Report: TS 25.413, section 8.21
    
    CN-initiated
    request-response
    connection-oriented signalling procedure
    
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
    
    send = RANAPSigProc._send
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.Iu.Proc[self.Code]
        except Exception:
            pass
        if not self.errcause:
            # TODO: do something with the data volume report
            self._log('INF', 'success')


class RANAPInitialUEMessage(RANAPSigProc):
    """Initial UE Message: TS 25.413, section 8.22
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
        self._recv(pdu)
        if not self.errcause:
            # verification against HNBd parameters and HNBAP / RUA infos:
            err, plmn = False, self.RNC.Config['PLMNidentity']
            if self.UEInfo['CN_DomainIndicator'][:2].upper() != self.Iu.DOM:
                self._log('WNG', 'invalid CN Domain Indicator, %s' % self.UEInfo['CN_DomainIndicator'][:2])
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
                # error cause: protocol, message-not-compatible-with-receiver-state
                self.errcause = ('Protocol', 99)
        #
        if not self.errcause:
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
            self._ret = self.Iu.process_nas(self.UEInfo['NAS_PDU'])
    
    def trigger(self):
        return self._ret


class RANAPDirectTransferCN(RANAPSigProc):
    """Direct Transfer: TS 25.413, section 8.23
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    send = RANAPSigProc._send


class RANAPDirectTransferRNC(RANAPSigProc):
    """Direct Transfer: TS 25.413, section 8.23
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
        self._recv(pdu)
        if not self.errcause:
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
            if err:
                # this means the RNC changed its loc config without prior informing the CN
                # error cause: protocol, message-not-compatible-with-receiver-state
                self.errcause = ('Protocol', 99)
        #
        if not self.errcause:
            # process the NAS PDU, and get a list (potentially empty) of new
            # RANAP procedures to be triggered
            self._ret = self.Iu.process_nas(self.UEInfo['NAS_PDU'])
    
    def trigger(self):
        return self._ret


class RANAPOverloadControlCN(RANAPConlessSigProc):
    """Overload Control: TS 25.413, section 8.25
    
    CN-initiated
    request only
    connection-less signalling procedure
    
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
    
    # not implemented


class RANAPOverloadControlRNC(RANAPConlessSigProc):
    """Overload Control: TS 25.413, section 8.25
    
    RNC-initiated
    request only
    connection-less signalling procedure
    
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
    
    # not implemented


class RANAPResetCN(RANAPConlessSigProc):
    """Reset: TS 25.413, section 8.26
    
    CN-initiated
    request only
    connection-less signalling procedure
    
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
    
    send = RANAPConlessSigProc._send
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.RNC.ProcRanap[self.Code]
        except Exception:
            pass
        if not self.errcause:
            self._log('INF', 'success')


class RANAPResetRNC(RANAPConlessSigProc):
    """Reset: TS 25.413, section 8.26
    
    RNC-initiated
    request only
    connection-less signalling procedure
    
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
    
    def recv(self, pdu):
        # recv the reset indication
        self._recv(pdu)
        if not self.errcause:
            self._log('INF', 'cause %r' % (self.RNCInfo['Cause'], ))
            # reset all UE connections handled by the RNC handler in the core network 
            # domain indicated
            if self.RNCInfo['CN_DomainIndicator'] == 'ps-domain':
                for ue in self.RNC.UE_IuPS.values():
                    ue.IuPS.unset_ran()
                    ue.IuPS.unset_ctx()
                self.RNC.UE_IuPS.clear()
            else:
                for ue in self.UE_IuCS.values():
                    ue.IuCS.unset_ran()
                    ue.IuCS.unset_ctx()
                self.UE_IuCS.clear()
    
    def send(self):
        # copy requested IEs in response
        IEs['CN_DomainIndicator'] = self.RNCInfo['CN_DomainIndicator']
        if 'GlobalRNC_ID' in self.RNCInfo:
            IEs['GlobalRNC_ID'] = self.RNCInfo['GlobalRNC_ID']
        if 'GlobalCN_ID' in self.RNCInfo:
            IEs['GlobalCN_ID'] = self.RNCInfo['GlobalCN_ID']
        if 'ExtendedRNC_ID' in self.RNCInfo:
            IEs['ExtendedRNC_ID'] = self.RNCInfo['ExtendedRNC_ID']
        self.encode_pdu('suc', **IEs)
        return self._send()


class RANAPErrorIndConlessCN(RANAPConlessSigProc):
    """Error Indication: TS 25.413, section 8.27
    
    CN-initiated
    request only
    connection-less signalling procedure
    
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
    
    errcause = None
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
    
    send = RANAPConlessSigProc._send


class RANAPErrorIndConlessRNC(RANAPConlessSigProc):
    """Error Indication: TS 25.413, section 8.27
    
    RNC-initiated
    request only
    connection-less signalling procedure
    
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
        self._recv(pdu)
        if not self.errcause:
            self._log('WNG', 'error ind received: %s.%i' % (self.RNCInfo['Cause'], ))
            # if it corresponds to a previously CN-initiated class 1 procedure
            # abort it
            try:
                self.RNC.ProcRanap[self.RNC.ProcRanapLast].abort()
            except Exception:
                pass


class RANAPErrorIndCN(RANAPSigProc):
    """Error Indication: TS 25.413, section 8.27
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    errcause = None
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
    
    send = RANAPSigProc._send


class RANAPErrorIndRNC(RANAPSigProc):
    """Error Indication: TS 25.413, section 8.27
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
        self._recv(pdu)
        if not self.errcause is None and 'Cause' in self.UEInfo:
            self._log('WNG', 'error ind received: %s.%i' % self.UEInfo['Cause'])
            # if it corresponds to a previously CN-initiated class 1 procedure
            # abort it
            try:
                self.Iu.Proc[self.Iu.ProcLast].abort()
            except Exception:
                pass


class RANAPCNDeactivateTrace(RANAPSigProc):
    """CN Deactivate Trace: TS 25.413, section 8.28
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    def send(self):
        try:
            tracerefl = '0x%s' % hexlify(self.TraceReference)
        except Exception:
            tracerefl = repr(self.TraceReference)
        self._log('INF', 'sent with trace reference %s' % tracerefl)
        return self._send()


class RANAPResetResourceCN(RANAPConlessSigProc):
    """Reset Resource: TS 25.413, section 8.29
    
    CN-initiated
    request-response
    connection-less signalling procedure
    
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
    
    send = RANAPConlessSigProc._send
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.RNC.ProcRanap[self.Code]
        except Exception:
            pass
        if not self.errcause:
            self._log('INF', 'success')


class RANAPResetResourceRNC(RANAPConlessSigProc):
    """Reset Resource: TS 25.413, section 8.29
    
    RNC-initiated
    request-response
    connection-less signalling procedure
    
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
    
    def recv(self, pdu):
        self._recv(pdu)
        if not self.errcause:
            self._log('INF', 'cause %r' % (self.RNCInfo['Cause'], ))
            RResList, RResIds = self.RNCInfo['ResetResourceList'], []
            try:
                # we expect a single prot container (TODO: to be confirmed)
                assert(len(RResList) == 1)
                RResList = RReslist[0]
                for RRes in RResList:
                    RResIds.append(RRes['value'][1]['iuSigConId'][0])
            except Exception:
                self._log('WNG', 'unexpected formatting of ResetResourceList')
            #
            # reset all UE connections handled by the RNC handler self.RNC in the
            # core network domain indicated
            if self.RNCInfo['CN_DomainIndicator'] == 'ps-domain':
                for rres in RResIds:
                    try:
                        ue = self.RNC.UE_IuPS[rres]
                    except Exception:
                        pass
                    else:
                        ue.IuPS.SM.pdp_suspend()
                        if ue.IuPS.GMM.state != 'INACTIVE':
                            ue.IuPS.GMM.state = 'IDLE'
                        ue.IuPS.unset_ran()
                        ue.IuPS.unset_ctx()
                        del self.RNC.UE_IuPS[rres]
            else:
                for rres in RResIds:
                    try:
                        ue = self.RNC.UE_IuCS[rres]
                    except Exception:
                        pass
                    else:
                        if ue.IuCS.MM.state != 'INACTIVE':
                            ue.IuCS.MM.state = 'IDLE'
                        ue.IuCS.unset_ran()
                        ue.IuCS.unset_ctx()
                        del self.RNC.UE_IuCS[rres]
            self.RResIds = RResIds
      
    def send(self):
        if self.errcause:
            # no unsuccesful outcome possible, send an error ind
            Proc = self.RNC.init_ranap_proc(RANAPErrorIndConlessCN, Cause=self.errcause)
            if Proc:
                return Proc.send()
            else:
                return []
        else:
            # prepare response IEs
            IEs = {'CN_DomainIndicator': self.RNCInfo['CN_DomainIndicator']}
            if 'GlobalRNC_ID' in self.RNCInfo:
                IEs['GlobalRNC_ID'] = self.RNCInfo['GlobalRNC_ID']
            if 'GlobalCN_ID' in self.RNCInfo:
                IEs['GlobalCN_ID'] = self.RNCInfo['GlobalCN_ID']
            if 'ExtendedRNC_ID' in self.RNCInfo:
                IEs['ExtendedRNC_ID'] = self.RNCInfo['ExtendedRNC_ID']
            RResAck = []
            IEs['ResetResourceAckList'] = [RResAck]
            for rres in self.RResIds:
                RResAck.append({'id': 78, 'criticality': 'reject',
                                'value': ('ResetResourceItem', {'iuSigConId': (rres, 24)})})
            self.encode_pdu('suc', **IEs)
            return self._send()


class RANAPRABModificationRequest(RANAPSigProc):
    """RAB Modification Request: TS 25.413, section 8.30
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPLocationRelatedData(RANAPSigProc):
    """Location Related Data: TS 25.413, section 8.31
    
    CN-initiated
    request-accept, request-reject
    connection-oriented signalling procedure
    
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
    
    send = RANAPSigProc._send
    
    def recv(self, pdu):
        self._recv(pdu)
        try:
            del self.Iu.Proc[self.Code]
        except Exception:
            pass
        #
        if self.errcause:
            self.success = False
        elif pdu[0] == 'unsuccessfulOutcome':
            self.success = False
            try:
                self._log('WNG', 'failure, rejected with cause %r' % (self.UEInfo['Cause'], ))
            except Exception:
                self._log('WNG', 'failure, rejected without cause')
        else:
            self.success = True
            self._log('INF', 'success')
            # TODO: do something with the returned info


class RANAPInformationTransfer(RANAPConlessSigProc):
    """Information Transfer: TS 25.413, section 8.32
    
    CN-initiated
    request-accept, request-reject
    connection-less signalling procedure
    
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
    
    # not implemented


class RANAPUESpecificInformation(RANAPSigProc):
    """UE Specific Information: TS 25.413, section 8.33
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPDirectInformationTransferCN(RANAPConlessSigProc):
    """Direct Information Transfer: TS 25.413, section 8.34
    
    CN-initiated
    request only
    connection-less signalling procedure
    
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
    
    # not implemented


class RANAPDirectInformationTransferRNC(RANAPConlessSigProc):
    """Direct Information Transfer: TS 25.413, section 8.34
    
    RNC-initiated
    request only
    connection-less signalling procedure
    
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
    
    # not implemented


class RANAPUplinkInformationTransfer(RANAPConlessSigProc):
    """Uplink Information Transfer: TS 25.413, section 8.35
    
    RNC-initiated
    request-accept, request-reject
    connection-less signalling procedure
    
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
    
    # not implemented


class RANAPMBSMSessionStart(RANAPSigProc):
    """MBMS Session Start: TS 25.413, section 8.36
    
    CN-initiated
    request-accept, request-reject
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPMBMSSessionUpdate(RANAPSigProc):
    """MBMS Session Update: TS 25.413, section 8.37
    
    CN-initiated
    request-accept, request-reject
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPMBMSSessionStop(RANAPSigProc):
    """MBMS Session Stop: TS 25.413, section 8.38
    
    CN-initiated
    request-response
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPMBMSUELinking(RANAPSigProc):
    """MBMS UE Linking: TS 25.413, section 8.39
    
    CN-initiated
    request-response
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPMBMSRegistration(RANAPSigProc):
    """MBMS Registration: TS 25.413, section 8.40
    
    RNC-initiated
    request-accept, request-reject
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPMBMSCNDeregistration(RANAPSigProc):
    """MBMS CN Deregistration: TS 25.413, section 8.41
    
    CN-initiated
    request-response
    connection-less signalling procedure
    
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
    
    # not implemented


class RANAPMBMSRABEstablishmentInd(RANAPSigProc):
    """MBMS RAB Establishement Indication: TS 25.413, section 8.42
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPMBMSRABRelease(RANAPSigProc):
    """MBMS RAB Release: TS 25.413, section 8.43
    
    RNC-initiated
    request-accept, request-reject
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPEnhancedRelocationComplete(RANAPSigProc):
    """Enhanced Relocation Complete: TS 25.413, section 8.44
    
    RNC-initiated
    request-accept, request
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPEnhancedRelocationCompleteConfirm(RANAPSigProc):
    """Enhanced Relocation Complete Confirm: TS 25.413, section 8.45
    
    RNC-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPSRVCCPreparation(RANAPSigProc):
    """SRVCC Preparation: TS 25.413, section 8.46
    
    RNC-initiated
    request-response
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPUERadioCapabilityMatch(RANAPSigProc):
    """UE Radio Capability Match: TS 25.413, section 8.47
    
    CN-initiated
    request-response
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPUERegistrationQuery(RANAPSigProc):
    """UE Registration Query: TS 25.413, section 8.48
    
    RNC-initiated
    request
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPRerouteNASRequest(RANAPSigProc):
    """Reroute NAS Request: TS 25.413, section 8.49
    
    CN-initiated
    request only
    connection-oriented signalling procedure
    
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
    
    # not implemented


class RANAPPrivateMessageRNC(RANAPSigProc):
    """Private Message: TS 25.413
    
    RNC-initiated
    request only
    connection-less signalling procedure
    
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
    
    # not implemented


class RANAPPrivateMessageCN(RANAPSigProc):
    """Private Message: TS 25.413
    
    CN-initiated
    request only
    connection-less signalling procedure
    
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
    
    # not implemented


# initializing all RANAP procedures classes
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
RANAPErrorIndConlessCN.init()
RANAPErrorIndConlessRNC.init()
RANAPErrorIndCN.init()
RANAPErrorIndRNC.init()
RANAPCNDeactivateTrace.init()
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

# RANAP RNC-initiated connection-oriented signalling procedures dispatcher
RANAPProcRncDispatcher = {
    2 : RANAPRelocationPreparation,
    4 : RANAPRelocationCancel,
    10 : RANAPRABReleaseRequest,
    11 : RANAPIuReleaseRequest,
    12 : RANAPRelocationDetect,
    13 : RANAPRelocationComplete,
    18 : RANAPLocationReport,
    19 : RANAPInitialUEMessage,
    20 : RANAPDirectTransferRNC,
    22 : RANAPErrorIndRNC,
    24 : RANAPSRNSContextForwardToCN,
    25 : RANAPPrivateMessageRNC,
    29 : RANAPRABModificationRequest,
    39 : RANAPMBMSRegistration,
    41 : RANAPMBMSRABEstablishmentInd,
    42 : RANAPMBMSRABRelease,
    43 : RANAPEnhancedRelocationComplete,
    44 : RANAPEnhancedRelocationCompleteConfirm,
    46 : RANAPSRVCCPreparation,
    48 : RANAPUERegistrationQuery
    }

# RANAP CN-initiated connection-oriented signalling procedures dispatcher
RANAPProcCnDispatcher = {
    0 : RANAPRABAssignment,
    1 : RANAPIuRelease,
    3 : RANAPRelocationResourceAllocation,
    5 : RANAPSRNSContextTransfer,
    6 : RANAPSecurityModeControl,
    7 : RANAPDataVolumeReport,
    15 : RANAPCommonID,
    16 : RANAPCNInvokeTrace,
    17 : RANAPLocationReportingControl,
    20 : RANAPDirectTransferCN,
    22 : RANAPErrorIndCN,
    23 : RANAPSRNSDataForwarding,
    24 : RANAPSRNSContextForwardToRNC,
    25 : RANAPPrivateMessageCN,
    26 : RANAPCNDeactivateTrace,
    30 : RANAPLocationRelatedData,
    32 : RANAPUESpecificInformation,
    35 : RANAPMBSMSessionStart,
    36 : RANAPMBMSSessionUpdate,
    37 : RANAPMBMSSessionStop,
    38 : RANAPMBMSUELinking,
    40 : RANAPMBMSCNDeregistration,
    47 : RANAPUERadioCapabilityMatch,
    49 : RANAPRerouteNASRequest,
    }

# RANAP RNC-initiated connection-less signalling procedures dispatcher
RANAPConlessProcRncDispatcher = {
    9 : RANAPResetRNC,
    21 : RANAPOverloadControlRNC,
    22 : RANAPErrorIndConlessRNC,
    27 : RANAPResetResourceRNC,
    33 : RANAPUplinkInformationTransfer,
    34 : RANAPDirectInformationTransferRNC,
    }

# RANAP CN-initiated connection-less signalling procedures dispatcher
RANAPConlessProcCnDispacther = {
    9 : RANAPResetCN,
    14 : RANAPPaging,
    21 : RANAPOverloadControlCN,
    22 : RANAPErrorIndConlessCN,
    27 : RANAPResetResourceCN,
    31 : RANAPInformationTransfer,
    34 : RANAPDirectInformationTransferCN,
    }

