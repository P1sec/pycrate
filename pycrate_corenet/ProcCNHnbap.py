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
# * File Name : pycrate_corenet/ProcCNHnbap.py
# * Created : 2017-07-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'HNBAPSigProc',
    'HNBAPHNBRegistration',
    'HNBAPHNBDeregistrationHNB',
    'HNBAPUERegistration',
    'HNBAPUEDeregistrationHNB',
    'HNBAPErrorIndHNB',
    'HNBAPPrivateMessageHNB',
    'HNBAPTNLUpdate',
    'HNBAPHNBConfigTransfer',
    'HNBAPURNTIQuery',
    'HNBAPHNBDeregistrationGW',
    'HNBAPUEDeregistrationGW',
    'HNBAPErrorIndGW',
    'HNBAPPrivateMessageGW',
    'HNBAPCSGMembershipUpdate',
    'HNBAPRelocationComplete',
    #
    'HNBAPProcHnbDispatcher',
    'HNBAPProcGwDispatcher'
    ]

from .utils     import *
from .ProcProto import *

#------------------------------------------------------------------------------#
# HNBAP signalling procedure
# TS 25.469, version d10
# HNB-GW side
#------------------------------------------------------------------------------#

class HNBAPSigProc(LinkSigProc):
    """HNBAP signalling procedure handler
    
    instance attributes:
        - Name  : procedure name
        - HNB   : reference to the HNBd instance running this procedure
        - Server: reference to the CorenetServer instance handling the HNB
        - Desc  : ASN.1 procedure description
        - Code  : procedure code
        - Crit  : procedure criticality
        - Cont  : ASN.1 procedure PDU(s) content
        - Encod : custom PDU encoders with fixed values
        - Decod : custom PDU decoders with tranform functions
    """
    
    TRACK_PDU = True
    
    def __init__(self, hnbd):
        #
        self.Name   = self.__class__.__name__
        self.HNB    = hnbd
        self.Server = hnbd.Server
        #
        # to store PDU traces
        self._pdu = []
        # list of PDU to be sent to the HNB
        self._pdu_tx = []
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.HNB._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def _recv(self, pdu_rx):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu_rx) )
        self.errcause, self.HNBInfo = None, {}
        try:
            self.decode_pdu(pdu_rx, self.HNBInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu (%s), sending error indication' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
    
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
        self._log('ERR', 'trigger() not implemented')
        return []
    
    def abort(self):
        if self.Code in self.HNB.ProcHnbap:
            del self.HNB.ProcHnbap[self.Code]
        self._log('INF', 'aborting')


class HNBAPHNBRegistration(HNBAPSigProc):
    """HNB Registration: TS 25.469, section 8.2
    
    HNB-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 3: HNB_Identity (M)
      - 6: LAC (M)
      - 7: RAC (M)
      - 8: HNB_Location_Information (M)
      - 9: PLMNidentity (M)
      - 10: SAC (M)
      - 11: CellIdentity (M)
      - 15: CSG_ID (O)
      Extensions:
      - 18: HNB_Cell_Access_Mode (O)
      - 20: SAC (O)
      - 29: IP_Address (O)
      - 30: PSC (O)
      - 41: Tunnel_Information (O)
      - 42: CELL_FACHMobilitySupport (O)
      - 46: HNBCapacity (O)
      - 47: NeighbourCellIdentityList (O)
      - 52: URAIdentityList (O)
    SuccessfulOutcome:
      IEs:
      - 14: RNC_ID (M)
      Extensions:
      - 19: MuxPortNumber (O)
      - 29: IP_Address (O)
      - 43: S_RNTIPrefix (O)
    UnsuccessfulOutcome:
      IEs:
      - 1: Cause (M)
      - 2: CriticalityDiagnostics (O)
      - 16: BackoffTimer (C)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.hNBRegister
    
    # Custom decoders
    Decod = {
        'ini': ({
            'LAC' : lambda x: bytes_to_uint(x, 16),
            'RAC' : lambda x: bytes_to_uint(x, 8),
            'PLMNidentity' : plmn_buf_to_str,
            'SAC' : lambda x: bytes_to_uint(x, 16),
            'CellIdentity' : cellid_bstr_to_str}, # CellID
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
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
        if self.errcause:
            # procedure unsuccessful outcome
            self.encode_pdu('uns', Cause=self.errcause)
            self._log('INF', 'HNB not registered successfully')
        else:
            self.HNB.Config = cpdict(self.HNBInfo)
            self.HNB.ID = (self.HNBInfo['PLMNidentity'], self.HNBInfo['CellIdentity'])
            self.encode_pdu('suc', RNC_ID=self.HNB.RNC_ID)
            self._log('INF', 'HNB registered successfully')
    
    send = HNBAPSigProc._send


class HNBAPHNBDeregistrationHNB(HNBAPSigProc):
    """HNB Deregistration, hnb-initiated: TS 25.469, section 8.3.1
    
    HNB-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 1: Cause (M)
      - 16: BackoffTimer (C)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.hNBDe_Register
    
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
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
        if not self.errcause:
            # remove the HNB from the Server.LAC / RAC dict
            self.Server._unset_hnb_loc(self)
            self._log('INF', 'HNB deregistered')


class HNBAPHNBDeregistrationGW(HNBAPSigProc):
    """HNB Deregistration, gateway-initiated: TS 25.469, section 8.3.2
    
    GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 1: Cause (M)
      - 16: BackoffTimer (C)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.hNBDe_Register
    
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


class HNBAPUERegistration(HNBAPSigProc):
    """UE Registration: TS 25.469, section 8.4
    
    HNB-initiated
    request-accept, request-reject
    
    InitiatingMessage:
      IEs:
      - 5: UE_Identity (M)
      - 12: Registration_Cause (M)
      - 13: UE_Capabilities (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 4: Context_ID (M)
      - 5: UE_Identity (M)
      Extensions:
      - 21: CSGMembershipStatus (O)
    UnsuccessfulOutcome:
      IEs:
      - 1: Cause (M)
      - 2: CriticalityDiagnostics (O)
      - 5: UE_Identity (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.uERegister
    
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
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
        if not self.errcause:
            # get the UE identity (IMSI or TMSI)
            ue, UEId = None, self.HNBInfo['UE_Identity']
            if UEId[0] == 'iMSI':
                imsi = TS24008_IE.decode_bcd(UEId[1])
                ue = self.Server.get_ued(imsi=imsi)
            elif UEId[0] == 'tMSILAI':
                tmsi = UEId[1]['tMSI'][0]
                ue = self.Server.get_ued(tmsi=tmsi)
            elif UEId[0] == 'pTMSIRAI':
                ptmsi = UEId[1]['pTMSI'][0]
                ue = self.Server.get_ued(ptmsi=ptmsi)
            else:
                self._log('WNG', 'unsupported UE identity, %r' % UEId)
                # unsupported UE identity
                self.errcause = ('radioNetwork', 'invalid-UE-identity')
            #
            if ue is None:
                # UE not allowed / configured in the CorenetServer
                self.errcause = self.HNB.UEREG_NOTALLOWED
            else:
                ctx_id = self.HNB.set_ue_hnbap(ue)
                if 'UE_Capabilities' in self.HNBInfo:
                    ue.Cap['HNBAP'] = (None, self.HNBInfo['UE_Capabilities'])
        #
        if self.errcause:
            # procedure unsuccessful outcome
            self.encode_pdu('uns', Cause=self.errcause,
                                   UE_Identity=self.HNBInfo['UE_Identity'])
            self._log('INF', 'UE not registered successfully')
        else:
            self.encode_pdu('suc', Context_ID=(ctx_id, 24),
                                   UE_Identity=self.HNBInfo['UE_Identity'])
            self._log('INF', 'UE registered successfully, ctx %i' % ue.IuCS.CtxId)
    
    send = HNBAPSigProc._send


class HNBAPUEDeregistrationHNB(HNBAPSigProc):
    """UE Deregistration, hnb-initiated: TS 25.469, section 8.5.2
    
    HNB-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 1: Cause (M)
      - 4: Context_ID (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.uEDe_Register
    
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
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
        if not self.errcause:
            self.HNB.unset_ue_hnbap(self.HNBInfo['Context_ID'][0])
            # UE IuCS / IuPS handlers should have been unset through RANAP procedures


class HNBAPUEDeregistrationGW(HNBAPSigProc):
    """UE Deregistration, gw-initiated: TS 25.469, section 8.5.3
    
    GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 1: Cause (M)
      - 4: Context_ID (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.uEDe_Register
    
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


class HNBAPErrorIndHNB(HNBAPSigProc):
    """Error Indication, hnb-initiated: TS 25.469, section 8.6
    
    HNB-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 1: Cause (M)
      - 2: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.errorIndication
    
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
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
        if not self.errcause and 'Cause' in self.HNBInfo:
            self._log('WNG', 'error ind received: %s.%s' % self.HNBInfo['Cause'])
            # if it corresponds to a previously CN-initiated class 1 procedure
            # abort it
            try:
                self.ProcHnbap[self.HNB.ProcHnbapLast].abort()
            except Exception:
                pass


class HNBAPErrorIndGW(HNBAPSigProc):
    """Error Indication, gw-initiated: TS 25.469, section 8.6
    
    GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 1: Cause (M)
      - 2: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.errorIndication
    
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
    
    def recv(self, pdu_rx):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu_rx) )
    
    send = HNBAPSigProc._send


class HNBAPCSGMembershipUpdate(HNBAPSigProc):
    """CSG Membership Update: TS 25.469, section 8.7
    
    GW-initiated
    request-only
    
    InitiatingMessage:
      IEs:
      - 4: Context_ID (M)
      - 21: CSGMembershipStatus (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.csg_membership_update
    
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


class HNBAPTNLUpdate(HNBAPSigProc):
    """TNL Update: TS 25.469, section 8.9
    
    HNB-initiated
    request-response, request-reject
    
    InitiatingMessage:
      IEs:
      - 4: Context_ID (M)
      - 22: RABList (M)
      - 26: Update_cause (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 4: Context_ID (M)
      Extensions:
        None
    UnsuccessfulOutcome:
      IEs:
      - 1: Cause (M)
      - 2: CriticalityDiagnostics (O)
      - 4: Context_ID (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.tnlUpdate
    
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


class HNBAPHNBConfigTransfer(HNBAPSigProc):
    """HNB Configuration Transfer: TS 25.469, section 8.10
    
    HNB-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 28: NeighbourInfoRequestList (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 27: NeighbourInfoList (M)
      Extensions:
      - 48: AdditionalNeighbourInfoList (O)
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.hNBConfigTransfer
    
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


class HNBAPRelocationComplete(HNBAPSigProc):
    """Relocation Complete: TS 25.469, section 8.11
    
    GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 4: Context_ID (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.relocationComplete
    
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


class HNBAPURNTIQuery(HNBAPSigProc):
    """U-RNTI Query: TS 25.469, section 8.12
    
    HNB-initiated
    request-response
    
    InitiatingMessage:
      IEs:
      - 49: U_RNTI (M)
      Extensions:
        None
    SuccessfulOutcome:
      IEs:
      - 51: HNB_GWResponse (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.u_RNTIQuery
    
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


class HNBAPPrivateMessageHNB(HNBAPSigProc):
    """Private Message: TS 25.469
    
    HNB-initiated
    request only
    
    InitiatingMessage:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.privateMessage
    
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


class HNBAPPrivateMessageGW(HNBAPSigProc):
    """Private Message: TS 25.469
    
    GW-initiated
    request only
    
    InitiatingMessage:
        None
    """
    
    # ASN.1 procedure description
    Desc = HNBAP.HNBAP_PDU_Descriptions.privateMessage
    
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


# initializing all HNBAP procedures classes
HNBAPHNBRegistration.init()
HNBAPHNBDeregistrationHNB.init()
HNBAPUERegistration.init()
HNBAPUEDeregistrationHNB.init()
HNBAPErrorIndHNB.init()
HNBAPPrivateMessageHNB.init()
HNBAPTNLUpdate.init()
HNBAPHNBConfigTransfer.init()
HNBAPURNTIQuery.init()
HNBAPHNBDeregistrationGW.init()
HNBAPUEDeregistrationGW.init()
HNBAPErrorIndGW.init()
HNBAPPrivateMessageGW.init()
HNBAPCSGMembershipUpdate.init()
HNBAPRelocationComplete.init()

# HNBAP HNB-initiated procedures dispatcher
HNBAPProcHnbDispatcher = {
    1 : HNBAPHNBRegistration,
    2 : HNBAPHNBDeregistrationHNB,
    3 : HNBAPUERegistration,
    4 : HNBAPUEDeregistrationHNB,
    5 : HNBAPErrorIndHNB,
    6 : HNBAPPrivateMessageHNB,
    9 : HNBAPTNLUpdate,
    10 : HNBAPHNBConfigTransfer,
    14 : HNBAPURNTIQuery
    }

# HNBAP GW-initiated procedures dispatcher
HNBAPProcGwDispatcher = {
    2 : HNBAPHNBDeregistrationGW,
    4 : HNBAPUEDeregistrationGW,
    5 : HNBAPErrorIndGW,
    6 : HNBAPPrivateMessageGW,
    7 : HNBAPCSGMembershipUpdate,
    11 : HNBAPRelocationComplete
    }

