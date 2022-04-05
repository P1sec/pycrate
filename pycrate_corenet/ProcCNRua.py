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
# * File Name : pycrate_corenet/ProcCNRuapy
# * Created : 2017-07-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'RUASigProc',
    'RUAConnect',
    'RUADirectTransfer',
    'RUADisconnect',
    'RUAConnectlessTransfer',
    'RUAErrorInd',
    'RUAPrivateMessage',
    #
    'RUAProcDispatcher'
    ]

from .utils     import *
from .ProcProto import *

#------------------------------------------------------------------------------#
# RUA signalling procedure
# TS 25.468, version d10
# HNB-GW side
#------------------------------------------------------------------------------#

class RUASigProc(LinkSigProc):
    """RUA signalling procedure handler
    
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
        self.errcause, self.ConInfo = None, {}
        try:
            self.decode_pdu(pdu_rx, self.ConInfo)
        except Exception as err:
            self._err = err
            self._log('ERR', 'decode_pdu (%s), sending error indication' % err)
            self.errcause = ('protocol', 'abstract-syntax-error-reject')
    
    def recv(self, pdu_rx):
        self._recv(pdu_rx)
        self._log('ERR', 'recv() not implemented')
    
    def send(self):
        if self.TRACK_PDU:
            for pdu in self._pdu_tx:
                self._pdu.append( (time(), 'DL', pdu) )
        return self._pdu_tx
    
    def trigger(self):
        self._log('ERR', 'trigger() not implemented')
        return []
    
    def abort(self):
        self._log('INF', 'aborting')


# All following RUA procedures have recv() and trigger() methods defined
# corresponding to HNB-initiated procedures

class RUAConnect(RUASigProc):
    """Connect: TS 25.468, section 8.2
    
    HNB-initiated or GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: Context_ID (M)
      - 4: RANAP_Message (M)
      - 5: IntraDomainNasNodeSelector (O)
      - 6: Establishment_Cause (M)
      - 7: CN_DomainIndicator (M)
      Extensions:
      - 9: CSGMembershipStatus (O)
    """
    
    # ASN.1 procedure description
    Desc = RUA.RUA_PDU_Descriptions.connectionRequest
    
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
            # log EC request
            if self.ConInfo['Establishment_Cause'] == 'emergency-call':
                self._log('WNG', 'emergency call requested') 
            # get the UE corresponding to the RUA ctx_id
            ctx_id = self.ConInfo['Context_ID'][0]
            try:
                ued = self.HNB.UE_HNBAP[ctx_id]
            except Exception:
                self._log('ERR', 'no UE associated to context-id %i'\
                          % self.ConInfo['Context_ID'][0])
                self.errcause = ('radioNetwork', 'connect-failed')
            else:
                #
                # set the Iu context-id and dispatch the RANAP PDU
                if self.ConInfo['CN_DomainIndicator'] == 'cs-domain':
                    self.HNB.set_ue_iucs(ued, ctx_id)
                    try:
                        ued.set_ran(self.HNB, ctx_id, dom='CS')
                    except Exception as err:
                        self._log('ERR', 'UE connected to several RAN, %r' % err)
                        return []
                    self.retpdu = ued.IuCS.process_ranap(self.ConInfo['RANAP_Message'])
                else:
                    #self.ConInfo['CN_DomainIndicator'] == 'ps-domain'
                    self.HNB.set_ue_iups(ued, ctx_id)
                    try:
                        ued.set_ran(self.HNB, ctx_id, dom='PS')
                    except Exception as err:
                        self._log('ERR', 'UE connected to several RAN, %r' % err)
                        return []
                    self.retpdu = ued.IuPS.process_ranap(self.ConInfo['RANAP_Message'])
    
    def trigger(self):
        if self.errcause:
            Err = self.HNB.init_rua_proc(RUAErrorInd, Cause=self.errcause)
            return [Err]
        else:
            Trans = []
            for pdu in self.retpdu:
                # wrap each RANAP PDU into a RUA direct transfer PDU
                Trans.append( self.HNB.init_rua_proc(RUADirectTransfer,
                                                     Context_ID=self.ConInfo['Context_ID'],
                                                     RANAP_Message=pdu,
                                                     CN_DomainIndicator=self.ConInfo['CN_DomainIndicator']) )
            return Trans


class RUADirectTransfer(RUASigProc):
    """Direct Transfer: TS 25.468, section 8.3
    
    HNB-initiated or GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 3: Context_ID (M)
      - 4: RANAP_Message (M)
      - 7: CN_DomainIndicator (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RUA.RUA_PDU_Descriptions.directTransfer
    
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
            # get the UE corresponding to the ctx_id and dispatch the RANAP PDU
            if self.ConInfo['CN_DomainIndicator'] == 'cs-domain':
                try:
                    ued = self.HNB.UE_IuCS[self.ConInfo['Context_ID'][0]]
                except Exception:
                    self._log('ERR', 'no UE associated to context-id %i'\
                              % self.ConInfo['Context_ID'][0])
                    self.errcause = ('protocol', 'abstract-syntax-error-reject')
                else:
                    self.retpdu = ued.IuCS.process_ranap(self.ConInfo['RANAP_Message'])
            else:
                try:
                    ued = self.HNB.UE_IuPS[self.ConInfo['Context_ID'][0]]
                except Exception:
                    self._log('ERR', 'no UE associated to context-id %i'\
                              % self.ConInfo['Context_ID'][0])
                    self.errcause = ('protocol', 'abstract-syntax-error-reject')
                else:
                    self.retpdu = ued.IuPS.process_ranap(self.ConInfo['RANAP_Message'])
    
    def trigger(self):
        if self.errcause:
            Err = self.HNB.init_rua_proc(RUAErrorInd, Cause=self.errcause)
            return [Err]
        else:
            Trans = []
            for pdu in self.retpdu:
                # wrap each RANAP PDU into a RUA direct transfer PDU
                Trans.append( self.HNB.init_rua_proc(RUADirectTransfer,
                                                     Context_ID=self.ConInfo['Context_ID'],
                                                     RANAP_Message=pdu,
                                                     CN_DomainIndicator=self.ConInfo['CN_DomainIndicator']) )
            return Trans


class RUADisconnect(RUASigProc):
    """Disconnect: TS 25.468, section 8.4
    
    HNB-initiated or GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 1: Cause (M)
      - 3: Context_ID (M)
      - 4: RANAP_Message (C)
      - 7: CN_DomainIndicator (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RUA.RUA_PDU_Descriptions.disconnectRequest
    
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
            # get the UE corresponding to the ctx_id and dispatch the RANAP PDU
            if self.ConInfo['CN_DomainIndicator'] == 'cs-domain':
                try:
                    ued = self.HNB.UE_IuCS[self.ConInfo['Context_ID'][0]]
                except Exception:
                    self._log('ERR', 'no UE associated to context-id %i'\
                              % self.ConInfo['Context_ID'][0])
                    self.errcause = ('protocol', 'abstract-syntax-error-reject')
                else:
                    self.retpdu = ued.IuCS.process_ranap(self.ConInfo['RANAP_Message'])
                    # RANAP_Message should be an IuRelease response
                    # hence, there should be no RANAP answer from the CN
                    # after receiving an RUA disconnect
                    assert( self.retpdu == [] )
                    self.HNB.unset_ue_iucs(self.ConInfo['Context_ID'][0])
            else:
                try:
                    ued = self.HNB.UE_IuPS[self.ConInfo['Context_ID'][0]]
                except Exception:
                    self._log('ERR', 'no UE associated to context-id %i'\
                              % self.ConInfo['Context_ID'][0])
                    self.errcause = ('protocol', 'abstract-syntax-error-reject')
                else:
                    self.retpdu = ued.IuPS.process_ranap(self.ConInfo['RANAP_Message'])
                    assert( self.retpdu == [] )
                    self.HNB.unset_ue_iups(self.ConInfo['Context_ID'][0])
    
    def trigger(self):
        if self.errcause is not None:
            Err = self.HNB.init_rua_proc(RUAErrorInd, Cause=self.errcause)
            return [Err]
        else:
            # nothing to trigger after an RUA disconnect
            return []


class RUAConnectlessTransfer(RUASigProc):
    """Connectionless Transfer : TS 25.468, section 8.5
    
    HNB-initiated or GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 4: RANAP_Message (M)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RUA.RUA_PDU_Descriptions.connectionlessTransfer
    
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
            # connection-less transfer, process the RANAP PDU directly in the RNC handler
            self.retpdu = self.HNB.process_ranap(self.ConInfo['RANAP_Message'])
    
    def trigger(self):
        if self.errcause is not None:
            Err = self.HNB.init_rua_proc(RUAErrorInd, Cause=self.errcause)
            return [Err]
        else:
            Trans = []
            for pdu in self.retpdu:
                # wrap each RANAP PDU into a RUA connect less transfer PDU
                Trans.append( self.HNB.init_rua_proc(RUAConnectlessTransfer,
                                                     RANAP_Message=pdu) )
            return Trans


class RUAErrorInd(RUASigProc):
    """Error Indication: TS 25.468, section 8.6
    
    HNB-initiated or GW-initiated
    request only
    
    InitiatingMessage:
      IEs:
      - 1: Cause (M)
      - 2: CriticalityDiagnostics (O)
      Extensions:
        None
    """
    
    # ASN.1 procedure description
    Desc = RUA.RUA_PDU_Descriptions.errorIndication
    
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
    
    # we don't respond to a malformed error ind with another error ind
    errcause = None
    
    def recv(self, pdu_rx):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu_rx) )
        #
        # WNG: this is the same error ind procedure used for
        # HNB-initiated and GW-initiated procedure
        #
        if pdu_rx[0] == 'initiatingMessage' and pdu_rx[1]['procedureCode'] == 1:
            # HNB-initiated
            self.ErrInfo = {}
            try:
                self.decode_pdu(pdu_rx, self.ErrInfo)
            except Exception as err:
                self._err = err
                self._log('ERR', 'decode_pdu: %s' % err)
                # don't respond with another error ind
            else:
                self._log('WNG', 'error ind received: %s.%s' % self.ErrInfo['Cause'])
        #
        # otherwise: GW-initiated, nothing to do
    
    def trigger(self):
        # nothing to trigger after an error ind
        return []


class RUAPrivateMessage(RUASigProc):
    """Error Indication: TS 25.468
    
    HNB-initiated or GW-initiated
    request only
    
    InitiatingMessage:
      None
    """
    
    # ASN.1 procedure description
    Desc = RUA.RUA_PDU_Descriptions.errorIndication
    
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


# initializing all RUA procedures classes
RUAConnect.init()
RUADirectTransfer.init()
RUADisconnect.init()
RUAConnectlessTransfer.init()
RUAErrorInd.init()
RUAPrivateMessage.init()

# RUA procedures dispatcher
RUAProcDispatcher = {
    1 : RUAConnect,
    2 : RUADirectTransfer,
    3 : RUADisconnect,
    4 : RUAConnectlessTransfer,
    5 : RUAErrorInd,
    6 : RUAPrivateMessage
    }

