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
# * File Name : pycrate_corenet/ProcCNHnbap.py
# * Created : 2017-07-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils     import *
from .ProcProto import *

#------------------------------------------------------------------------------#
# HNBAP signaling procedure
# TS 25.469, version d10
# HNB-GW side
#------------------------------------------------------------------------------#

class HNBAPSigProc(LinkSigProc):
    """HNBAP signaling procedure handler
    
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
        self._snd = []
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype, msg):
        self.HNB._log(logtype, '[%s] %s' % (self.Name, msg))
    
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self._log('ERR', 'recv() not implemented')
    
    def send(self):
        self._log('ERR', 'send() not implemented')
        return self._snd
    
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
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        errcause = None
        self.HNB.Config.clear()
        # use the PDU to populate the Config of the HNBd
        try:
            self.decode_pdu(pdu, self.HNB.Config)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            self.HNB.Config.clear()
            errcause = ('protocol', 'abstract-syntax-error-reject')
        #
        if errcause is None:
            # procedure successful outcome
            self.HNB.ID = (self.HNB.Config['PLMNidentity'], self.HNB.Config['CellIdentity'])
            self.encode_pdu('suc', RNC_ID=self.HNB.RNC_ID)
            self._log('INF', 'HNB registered successfully')
        else:
            # procedure unsuccessful outcome
            self.encode_pdu('uns', Cause=errcause)
            self._log('INF', 'HNB not registered successfully')
    
    def send(self):
        if self.TRACK_PDU:
            for pdu in self._snd:
                self._pdu.append( (time(), 'DL', pdu) )
        # remove from the HNB HNBAP procedure stack
        try:
            del self.HNB.ProcHnbap[self.Code]
        except:
            pass
        # send back the list of PDU to be returned to the HNB
        return self._snd


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
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        errcause, UEInfo = None, {} 
        try:
            self.decode_pdu(pdu, UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            errcause = ('protocol', 'abstract-syntax-error-reject')
        #
        if errcause is None:
            # get the UE identity (IMSI or TMSI)
            ue, UEId = None, UEInfo['UE_Identity']
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
                errcause = ('radioNetwork', 'invalid-UE-identity')
            if ue is None:
                # UE not allowed / configured in the CorenetServer
                errcause = ('radioNetwork', 'uE-unauthorised')
            else:
                self.HNB.set_ue_hnbap(ue)
                if 'UE_Capabilities' in UEInfo:
                    ue.Cap['HNBAP'] = UEInfo['UE_Capabilities']
        #
        if errcause is None:
            # procedure successful outcome
            # both IuCS / IuPS are initialized with the same CtxId established here,
            # at the HNBAP layer, so we can take the IuCS one safely
            self.encode_pdu('suc', Context_ID=(ue.IuCS.CtxId, 24),
                                               UE_Identity=UEInfo['UE_Identity'])
            self._log('INF', 'UE registered successfully, ctx %i' % ue.IuCS.CtxId)
        else:
            # procedure unsuccessful outcome
            self.encode_pdu('uns', Cause=errcause)
            self._log('INF', 'UE not registered successfully')
    
    def send(self):
        if self.TRACK_PDU:
            for pdu in self._snd:
                self._pdu.append( (time(), 'DL', pdu) )
        # remove from the HNB HNBAP procedure stack
        try:
            del self.HNB.ProcHnbap[self.Code]
        except:
            pass
        # send back the list of PDU to be returned to the HNB
        return self._snd


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
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        errcause, UEInfo = None, {} 
        try:
            self.decode_pdu(pdu, UEInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu: %s' % err)
            errcause = ('protocol', 'abstract-syntax-error-reject')
        #
        if errcause is None:
            # UE RAN should have been unset through RUA / RANAP procedures
            self.HNB.unset_ue_hnbap(UEInfo['Context_ID'][0])
        #
        # remove from the HNB HNBAP procedure stack
        try:
            del self.HNB.ProcHnbap[self.Code]
        except:
            pass


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
            # this means the HNB failed to process the previous msg sent to it
            code = self.HNB.ProcHnbapLast
            try:
                Proc = self.HNB.ProcHnbap[code]
            except:
                pass
            else:
                # abort the corresponding running procedure
                Proc.abort()
        #
        # remove from the HNB HNBAP procedure stack
        try:
            del self.HNB.ProcHnbap[self.Code]
        except:
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
    
    def recv(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        # this means we are not able to process a request received from the HNB
        # this is handled directly within the HNBHdlr instance
    
    def send(self):
        if self.TRACK_PDU:
            for pdu in self._snd:
                self._pdu.append( (time(), 'DL', pdu) )
        # send back the list of PDU to be returned to the HNB
        return self._snd


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

