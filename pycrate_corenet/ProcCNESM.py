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
# * File Name : pycrate_corenet/ProcCNESM.py
# * Created : 2017-12-15
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils      import *
from .ProcProto  import *
from .ProcCNS1ap import *


TESTING = False

#------------------------------------------------------------------------------#
# NAS EPS Session Management signalling procedure
# TS 24.301, version da0
# Core Network side
#------------------------------------------------------------------------------#

class ESMSigProc(NASSigProc):
    """EPS Session Management signalling procedure handler
    
    instance attributes:
        - Name : procedure name
        - ESM  : reference to the UEESMd instance running this procedure
        - S1   : reference to the UES1d instance connecting the UE
        - Cont : 2-tuple of CN-initiated NAS message(s) and UE-initiated NAS 
                 message(s)
        - Timer: timer in sec. for this procedure
        - Encod: custom NAS message encoders with fixed values
        - Decod: custom NAS message decoders with transform functions
    """
    
    # tacking all exchanged NAS message within the procedure
    TRACK_PDU = True
    
    # potential timer
    Timer        = None
    TimerDefault = 4
    
    if TESTING:
        def __init__(self, encod=None):
            self._prepare(encod)
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            log('[TESTING] [%s] [EMMSigProc] [%s] %s' % (logtype, self.Name, msg))
    
    else:
        def __init__(self, esmd, encod=None, sec=True, ebi=0, EMMProc=None):
            self._prepare(encod)
            self.ESM  = esmd
            self.S1   = esmd.S1
            self.UE   = esmd.UE
            self._sec = sec
            self._ebi = ebi
            self._EMMProc = EMMProc
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            self.ESM._log(logtype, '[%s [%i]] %s' % (self.Name, self._ebi, msg))
    
    def decode_msg(self, msg, ret):
        NASSigProc.decode_msg(self, msg, ret)
        # add EPSBearerId and PTI into ret
        ret['EPSBearerId'] = msg[0].get_val()
        ret['PTI'] = msg[2].get_val()
    
    def output(self):
        self._log('ERR', 'output() not implemented')
        return None
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        self._log('ERR', 'process() not implemented')
        return None
    
    def postprocess(self, Proc=None):
        self._log('ERR', 'postprocess() not implemented')
        self.rm_from_esm_stack()
        return None
    
    def abort(self):
        # abort this procedure, and all procedures started within this one
        ProcStack = self.ESM.Proc[self._ebi]
        ind = ProcStack.index(self)
        if ind >= 0:
            for p in ProcStack[ind+1:]:
                p.abort()
            del ProcStack[ind:]
        self._log('INF', 'aborting')
    
    def rm_from_esm_stack(self):
        # remove the procedure from the EMM stack of procedures
        ProcStack = self.ESM.Proc[self._ebi]
        if ProcStack[-1] == self:
            del ProcStack[-1]
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.ESM, self.Timer, self.TimerDefault)
            self.TimerStart = time()
            self.TimerStop  = self.TimerStart + self.TimerValue
    
    def get_timer(self):
        if self.Timer is None:
            return None
        else:
            return getattr(self.ESM, self.Timer)
    
    #--------------------------------------------------------------------------#
    # common helpers
    #--------------------------------------------------------------------------#
    
    def _collect_cap(self):
        if not hasattr(self, 'Cap') or not hasattr(self, 'UEInfo'):
            return
        for Cap in self.Cap:
            if Cap in self.UEInfo:
                self.UE.Cap[Cap] = self.UEInfo[Cap]
    
    def _init_trans(self, UEInfo, Type):
        trans = {'Type'       : Type,
                 'EPSBearerId': UEInfo['EPSBearerId']}
        if Type == 'Default':
            trans.update({
                 'PDNType'    : UEInfo['PDNType'],
                 'RequestType': UEInfo['RequestType'],
                 'APN'        : UEInfo.get('APN', None),
                 'ProtConfig' : UEInfo.get('ProtConfig', None),
                 #'DeviceProp'     : None,
                 #'NBIFOMContainer': None,
                 #'HdrCompConfig'  : None,
                 #'ExtProtConfig'  : None,
                 })
        elif Type == 'Dedicated':
            pass
        elif Type == 'Modif':
            pass
        elif Type == 'Deact':
            pass
        self.ESM.Trans[UEInfo['PTI']] = trans


#------------------------------------------------------------------------------#
# Network-initiated ESM procedures: TS 24.301, section 6.4
#------------------------------------------------------------------------------#

class ESMDefaultEPSBearerCtxtAct(ESMSigProc):
    """Default EPS bearer context activation procedure: TS 24.301, section 6.4.1
    
    CN-initiated
    
    CN message:
        ESMActDefaultEPSBearerCtxtRequest (PD 2, Type 193), IEs:
        - Type4LV   : EPSQoS
        - Type4LV   : APN
        - Type4LV   : PDNAddr
        - Type4TLV  : TransId
        - Type4TLV  : QoS
        - Type3TV   : LLC_SAPI
        - Type1TV   : RadioPriority
        - Type4TLV  : PacketFlowId
        - Type4TLV  : APN_AMBR
        - Type3TV   : ESMCause
        - Type4TLV  : ProtConfig
        - Type1TV   : ConType
        - Type1TV   : WLANOffloadInd
        - Type4TLV  : NBIFOMContainer
        - Type4TLV  : HdrCompConfig
        - Type1TV   : CPOnlyInd
        - Type6TLVE : ExtProtConfig
        - Type4TLV  : ServingPLMNRateCtrl
    
    UE messages:
        ESMActDefaultEPSBearerCtxtAccept (PD 2, Type 194), IEs:
        - Type4TLV  : ProtConfig
        - Type6TLVE : ExtProtConfig

        ESMActDefaultEPSBearerCtxtReject (PD 2, Type 195), IEs:
        - Type2     : ESMCause
        - Type4TLV  : ProtConfig
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMActDefaultEPSBearerCtxtRequest, ),
        (TS24301_ESM.ESMActDefaultEPSBearerCtxtAccept, TS24301_ESM.ESMActDefaultEPSBearerCtxtReject)
        )
    
    Timer = 'T3485'


class ESMDedicatedEPSBearerCtxtAct(ESMSigProc):
    """Dedicated EPS bearer context activation procedure: TS 24.301, section 6.4.2
    
    CN-initiated
    
    CN message:
        ESMActDediEPSBearerCtxtRequest (PD 2, Type 197), IEs:
        - Type1V    : spare
        - Type1V    : LinkedEPSBearerId
        - Type4LV   : EPSQoS
        - Type4LV   : TFT
        - Type4TLV  : TransId
        - Type4TLV  : QoS
        - Type3TV   : LLC_SAPI
        - Type1TV   : RadioPriority
        - Type4TLV  : PacketFlowId
        - Type4TLV  : ProtConfig
        - Type1TV   : WLANOffloadInd
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig

    UE messages:
        ESMActDediEPSBearerCtxtAccept (PD 2, Type 198), IEs:
        - Type4TLV  : ProtConfig
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig

        ESMActDediEPSBearerCtxtReject (PD 2, Type 199), IEs:
        - Type2     : ESMCause
        - Type4TLV  : ProtConfig
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMActDediEPSBearerCtxtRequest, ),
        (TS24301_ESM.ESMActDediEPSBearerCtxtAccept, TS24301_ESM.ESMActDediEPSBearerCtxtReject)
        )
    
    Timer = 'T3485'


class ESMEPSBearerCtxtModif(ESMSigProc):
    """EPS bearer context modification procedure: TS 24.301, section 6.4.3
    
    CN-initiated
    
    CN message:
        ESMModifyEPSBearerCtxtRequest (PD 2, Type 201), IEs:
        - Type4TLV  : EPSQoS
        - Type4TLV  : TFT
        - Type4TLV  : QoS
        - Type3TV   : LLC_SAPI
        - Type1TV   : RadioPriority
        - Type4TLV  : PacketFlowId
        - Type4TLV  : APN_AMBR
        - Type4TLV  : ProtConfig
        - Type1TV   : WLANOffloadInd
        - Type4TLV  : NBIFOMContainer
        - Type4TLV  : HdrCompConfig
        - Type6TLVE : ExtProtConfig

    UE messages:
        ESMModifyEPSBearerCtxtAccept (PD 2, Type 202), IEs:
        - Type4TLV  : ProtConfig
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig

        ESMModifyEPSBearerCtxtReject (PD 2, Type 203), IEs:
        - Type2     : ESMCause
        - Type4TLV  : ProtConfig
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMModifyEPSBearerCtxtRequest, ),
        (TS24301_ESM.ESMModifyEPSBearerCtxtAccept, TS24301_ESM.ESMModifyEPSBearerCtxtReject)
        )
    
    Timer = 'T3486'


class ESMEPSBearerCtxtDeact(ESMSigProc):
    """EPS bearer context deactivation procedure: TS 24.301, section 6.4.4
    
    CN-initiated
    
    CN message:
        ESMDeactEPSBearerCtxtRequest (PD 2, Type 205), IEs:
        - Type2     : ESMCause
        - Type4TLV  : ProtConfig
        - Type4TLV  : BackOffTimer
        - Type1TV   : WLANOffloadInd
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig
         
    UE message:
        ESMDeactEPSBearerCtxtAccept (PD 2, Type 206), IEs:
        - Type4TLV  : ProtConfig
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMDeactEPSBearerCtxtRequest, ),
        (TS24301_ESM.ESMDeactEPSBearerCtxtAccept, )
        )
    
    Timer = 'T3495'


#------------------------------------------------------------------------------#
# UE requested ESM procedures: TS 24.301, section 6.5
#------------------------------------------------------------------------------#

class ESMPDNConnectivityRequest(ESMSigProc):
    """UE requested PDN connectivity procedure: TS 24.301, section 6.5.1

    UE-initiated
    triggers ESMDefaultEPSBearerCtxtAct

    CN message:
        ESMPDNConnectivityReject (PD 2, Type 209), IEs:
        - Type2     : ESMCause
        - Type4TLV  : ProtConfig
        - Type4TLV  : BackOffTimer
        - Type4TLV  : ReattemptInd
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig

    UE message:
        ESMPDNConnectivityRequest (PD 2, Type 208), IEs:
        - Type1V    : PDNType
        - Type1V    : RequestType
        - Type1TV   : ESMInfoTransferFlag
        - Type4TLV  : APN
        - Type4TLV  : ProtConfig
        - Type1TV   : DeviceProp
        - Type4TLV  : NBIFOMContainer
        - Type4TLV  : HdrCompConfig
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMPDNConnectivityReject, ),
        (TS24301_ESM.ESMPDNConnectivityRequest, )
        )
    
    Decod = {
        (2, 208): {
            'ESMInfoTransferFlag' : lambda x: x[1]['Value'].get_val(),
            },
        }
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        # insert the info into the ESM transaction dict
        self._init_trans(self.UEInfo, Type='Default')
        #
        if 'ESMInfoTransferFlag' in self.UEInfo and self.UEInfo['ESMInfoTransferFlag']:
            # initiate an info transfer proc to get complementary info
            NasProc = self.ESM.init_proc(ESMInfoRequest, ebi=self.UEInfo['EPSBearerId'])
            NasProc.set_msg(2, 217, EPSBearerId=self.UEInfo['EPSBearerId'],
                                    PTI=self.UEInfo['PTI'])
            return NasProc.output()
        #
        else:
            
            self.postprocess()
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, ESMInfoRequest):
            if not Proc.success:
                self.abort()
                return []
        #
        elif Proc != self and Proc is not None:
            self._err = Proc
            assert()
        #
        return self.output()
    
    def output(self):
        # process the whole transaction request
        ret, self.errcause = self.ESM.process_trans(self.UEInfo['PTI'])
        # deny request or start an ESNDefaultEPSBearerCtxtAct
        if self.errcause:
            self.set_msg(2, 209, ESMCause=self.errcause)
            self.encode_msg(2, 209)
        else:
            # TODO
            pass


class ESMPDNDisconnectRequest(ESMSigProc):
    """UE requested PDN disconnect procedure: TS 24.301, section 6.5.2
    
    UE-initiated
    triggers ESMEPSBearerCtxtDeact
    
    CN message:
        ESMPDNDisconnectReject (PD 2, Type 211), IEs:
        - Type2     : ESMCause
        - Type4TLV  : ProtConfig
        - Type6TLVE : ExtProtConfig
    
    UE message:
        ESMPDNDisconnectRequest (PD 2, Type 210), IEs:
        - Type1V    : spare
        - Type1V    : LinkedEPSBearerId
        - Type4TLV  : ProtConfig
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMPDNDisconnectReject, ),
        (TS24301_ESM.ESMPDNDisconnectRequest, )
        )


class ESMBearerResourceAllocRequest(ESMSigProc):
    """UE requested bearer resource allocation procedure: TS 24.301, section 6.5.3
    
    UE-initiated
    triggers ESMDedicatedEPSBearerCtxtAct or ESMEPSBearerCtxtModif
    
    CN message:
        ESMBearerResourceAllocReject (PD 2, Type 213), IEs:
        - Type2     : ESMCause
        - Type4TLV  : ProtConfig
        - Type4TLV  : BackOffTimer
        - Type4TLV  : ReattemptInd
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig
    
    UE message:
        ESMBearerResourceAllocRequest (PD 2, Type 212), IEs:
        - Type1V    : spare
        - Type1V    : LinkedEPSBearerId
        - Type4LV   : TFAggregate
        - Type4LV   : EPSQoS
        - Type4TLV  : ProtConfig
        - Type1TV   : DeviceProp
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMBearerResourceAllocReject, ),
        (TS24301_ESM.ESMBearerResourceAllocRequest, )
        )


class ESMBearerResourceModifRequest(ESMSigProc):
    """UE requested bearer resource modification procedure: TS 24.301, section 6.5.4
    
    UE-initiated
    triggers ESMDedicatedEPSBearerCtxtAct or ESMEPSBearerCtxtModif or ESMEPSBearerCtxtDeact
    
    CN message:
        ESMBearerResourceModifReject (PD 2, Type 215), IEs:
        - Type2     : ESMCause
        - Type4TLV  : ProtConfig
        - Type4TLV  : BackOffTimer
        - Type4TLV  : ReattemptInd
        - Type4TLV  : NBIFOMContainer
        - Type6TLVE : ExtProtConfig
    
    UE message:
        ESMBearerResourceModifRequest (PD 2, Type 214), IEs:
        - Type1V    : spare
        - Type1V    : LinkedEPSBearerId
        - Type4LV   : TFAggregate
        - Type4TLV  : EPSQoS
        - Type3TV   : ESMCause
        - Type4TLV  : ProtConfig
        - Type1TV   : DeviceProp
        - Type4TLV  : NBIFOMContainer
        - Type4TLV  : HdrCompConfig
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMBearerResourceModifReject, ),
        (TS24301_ESM.ESMBearerResourceModifRequest, )
        )


#------------------------------------------------------------------------------#
# Miscellaneous procedures: TS 24.301, section 6.6
#------------------------------------------------------------------------------#

class ESMInfoRequest(ESMSigProc):
    """ESM information request procedure: TS 24.301, section 6.6.1.2
    
    CN-initiated
    
    CN message:
        ESMInformationRequest (PD 2, Type 217), IEs:
          None

    UE message:
        ESMInformationResponse (PD 2, Type 218), IEs:
        - Type4TLV  : APN
        - Type4TLV  : ProtConfig
        - Type6TLVE : ExtProtConfig
    """
    
    Cont = (
        (TS24301_ESM.ESMInformationRequest, ),
        (TS24301_ESM.ESMInformationResponse, )
        )
    
    Timer = 'T3489'
    
    def output(self):
        self.encode_msg(2, 217)
        if not self._sec:
            self._nas_tx._sec = False
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        nas_tx = self.ESM.output_nas_esm(self._nas_tx, self._EMMProc)
        self.init_timer()
        return self.S1.ret_s1ap_dnt(nas_tx)
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        if self.UEInfo['PTI'] not in self.ESM.Trans:
            self.success = False
        else:
            trans = self.ESM.Trans[self.UEInfo['PTI']]
            if 'APN' in self.UEInfo:
                if trans['APN']:
                    self._log('WNG', 'overwriting APN %r with %r'\
                              % (trans['APN'], self.UEInfo['APN']))
                trans['APN'] = self.UEInfo['APN']
            if 'ProtConfig' in self.UEInfo:
                if trans['ProtConfig']:
                    self._log('WNG', 'overwriting ProtConfig %r with %r'\
                              % (trans['ProtConfig'], self.UEInfo['ProtConfig']))
                trans['ProtConfig'] = self.UEInfo['ProtConfig']
            self.success = True
        #
        self.rm_from_esm_stack()
        return []


class ESMNotification(ESMSigProc):
    """Notification procedure: TS 24.301, section 6.6.2
    
    CN-initiated
    
    CN message:    
        ESMNotification (PD 2, Type 219), IEs:
        - Type4LV   : NotificationInd
    
    UE message:
        None
    """
    
    Cont = (
        (TS24301_ESM.ESMNotification, ),
        None
        )


class ESMRemoteUEReport(ESMSigProc):
    """Remote UE Report procedure: TS 24.301, section 6.6.3
    
    UE-initiated
    
    CN message:
        ESMRemoteUEResponse (PD 2, Type 234), IEs:
          None

    UE message:
        ESMRemoteUEReport (PD 2, Type 233), IEs:
        - Type6TLVE : RemoteUEConnected
        - Type6TLVE : RemoteUEDisconnected
        - Type4TLV  : PKMFAddr
    """
    
    Cont = (
        (TS24301_ESM.ESMRemoteUEResponse, ),
        (TS24301_ESM.ESMRemoteUEReport, )
        )


class ESMDataTransportUE(ESMSigProc):
    """UE initiated transport of user data via the control plane: TS 24.301, section 6.6.4.2
    
    UE-initiated
    
    CN message:
        None
    
    UE message:
        ESMDataTransport (PD 2, Type 235), IEs:
        - Type6LVE  : UserData
        - Type1TV   : ReleaseAssistInd
    """
    
    Cont = (
        None,
        (TS24301_ESM.ESMDataTransport, )
        )


class ESMDataTransportCN(ESMSigProc):
    """Network initiated transport of user data via the control plane: TS 24.301, section 6.6.4.3
    
    CN-initiated
    
    CN message:
        ESMDataTransport (PD 2, Type 235), IEs:
        - Type6LVE  : UserData
        - Type1TV   : ReleaseAssistInd
    
    UE message:
        None
    """
    
    Cont = (
        (TS24301_ESM.ESMDataTransport, ),
        None
        )


ESMDefaultEPSBearerCtxtAct.init(filter_init=1)
ESMDedicatedEPSBearerCtxtAct.init(filter_init=1)
ESMEPSBearerCtxtModif.init(filter_init=1)
ESMEPSBearerCtxtDeact.init(filter_init=1)
ESMPDNConnectivityRequest.init(filter_init=1)
ESMPDNDisconnectRequest.init(filter_init=1)
ESMBearerResourceAllocRequest.init(filter_init=1)
ESMBearerResourceModifRequest.init(filter_init=1)
ESMInfoRequest.init(filter_init=1)
ESMNotification.init(filter_init=1)
ESMDataTransportUE.init(filter_init=1)
ESMDataTransportCN.init(filter_init=1)

# ESM UE-initiated procedures dispatcher
ESMProcUeDispatcher = {
    208 : ESMPDNConnectivityRequest,
    210 : ESMPDNDisconnectRequest,
    212 : ESMBearerResourceAllocRequest,
    214 : ESMBearerResourceModifRequest,
    235 : ESMDataTransportUE,
    }
ESMProcUeDispatcherStr = {ProcClass.Cont[1][0]()._name: ProcClass \
                          for ProcClass in ESMProcUeDispatcher.values()}

# ESM CN-initiated procedures dispatcher
ESMProcCnDispatcher = {
    193 : ESMDefaultEPSBearerCtxtAct,
    197 : ESMDedicatedEPSBearerCtxtAct,
    201 : ESMEPSBearerCtxtModif,
    205 : ESMEPSBearerCtxtDeact,
    217 : ESMInfoRequest,
    219 : ESMNotification,
    235 : ESMDataTransportCN,
    }
ESMProcCnDispatcherStr = {ProcClass.Cont[0][0]()._name: ProcClass \
                          for ProcClass in ESMProcCnDispatcher.values()}

