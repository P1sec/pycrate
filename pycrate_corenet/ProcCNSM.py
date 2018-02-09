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
# * File Name : pycrate_corenet/ProcCNSM.py
# * Created : 2018-01-25
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'SMSigProc',
    'SMPDPCtxtAct',
    'SMPDPCtxtDeactUE',
    'SMPDPCtxtModifUE',
    'SMSecondPDPCtxtAct',
    'SMPDPCtxtAct',
    'SMPDPCtxtActRequest',
    'SMPDPCtxtDeactCN',
    'SMPDPCtxtModifCN',
    'SMMBMSCtxtActRequest',
    'SMSecondPDPCtxtActRequest',
    'SMNotification',
    'SMMBMSCtxtDeact',
    #
    'SMProcUeDispatcher',
    'SMProcUeDispatcherStr',
    'SMProcCnDispatcher',
    'SMProcCnDispatcherStr'
    ]

from .utils      import *
from .ProcProto  import *
from .ProcCNRanap import *


TESTING = False

#------------------------------------------------------------------------------#
# NAS GPRS Session Management signalling procedures
# TS 24.008, version d90
# Core Network side
#------------------------------------------------------------------------------#

class SMSigProc(NASSigProc):
    """GPRS Session Management signalling procedure handler
    
    instance attributes:
        - Name : procedure name
        - SM   : reference to the UESMd instance running this procedure
        - Iu   : reference to the UEIuPSd instance connecting the UE
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
    TimerDefault = 2
    
    if TESTING:
        def __init__(self, tid, encod=None):
            self._prepare(encod)
            self._log('DBG', 'instantiating procedure')
            self._tid   = tid
            self._tif   = tid >> 7
            self._ti    = tid & 0x7f
        
        def _log(self, logtype, msg):
            log('[TESTING] [%s] [EMMSigProc] [%s] %s' % (logtype, self.Name, msg))
    
    else:
        def __init__(self, smd, tid, encod=None):
            self._prepare(encod)
            self.SM     = smd
            self.Iu     = smd.Iu
            self.UE     = smd.UE
            self._tid   = tid
            self._tif   = tid >> 7
            self._ti    = tid & 0x7f
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            self.SM._log(logtype, '[%s] %s' % (self.Name, msg))
    
    def output(self):
        self._log('ERR', 'output() not implemented')
        return []
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        self._log('ERR', 'process() not implemented')
        return []
    
    def postprocess(self, Proc=None):
        self._log('ERR', 'postprocess() not implemented')
        self.rm_from_sm_stack()
        return []
    
    def abort(self):
        # abort this procedure, and all procedures started within this one
        if self._tid in self.SM.Proc:
            ProcStack = self.SM.Proc[self._tid]
            ind = ProcStack.index(self)
            if ind >= 0:
                for p in ProcStack[ind+1:]:
                    p.abort()
                del ProcStack[ind:]
        self._log('INF', 'aborting')
    
    def rm_from_sm_stack(self):
        # remove the procedure from the SM stack of procedures
        if self._tid in self.SM.Proc:
            ProcStack = self.SM.Proc[self._tid]
            if ProcStack[-1] == self:
                del ProcStack[-1]
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.SM, self.Timer, self.TimerDefault)
            self.TimerStart = time()
            self.TimerStop  = self.TimerStart + self.TimerValue
    
    def get_timer(self):
        if self.Timer is None:
            return None
        else:
            return getattr(self.SM, self.Timer)
    
    #--------------------------------------------------------------------------#
    # common helpers
    #--------------------------------------------------------------------------#
    
    def _collect_cap(self):
        if not hasattr(self, 'Cap') or not hasattr(self, 'UEInfo'):
            return
        for Cap in self.Cap:
            if Cap in self.UEInfo:
                self.UE.Cap[Cap] = self.UEInfo[Cap]


#------------------------------------------------------------------------------#
# PDP context activation: TS 24.008, section 6.1.3.1
#------------------------------------------------------------------------------#

class SMPDPCtxtAct(SMSigProc):
    """PDP context activation procedure: TS 24.008, section 6.1.3.1
    
    UE-initiated
    
    CN messages:
        SMActivatePDPContextAccept (PD 10, Type 66), IEs:
        - Type3V    : LLC_SAPI
        - Type4LV   : QoS
        - Uint      : spare
        - Type1V    : RadioPriority
        - Type4TLV  : PDPAddr (T: 43)
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : PacketFlowId (T: 52)
        - Type4TLV  : SMCause (T: 57)
        - Type1TV   : ConType (T: 11)
        - Type1TV   : WLANOffloadInd (T: 12)
        - Type4TLV  : NBIFOMContainer (T: 51)
        
        SMActivatePDPContextReject (PD 10, Type 67), IEs:
        - Type3V    : SMCause
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : BackOffTimer (T: 55)
        - Type4TLV  : ReattemptInd (T: 107)
        - Type4TLV  : NBIFOMContainer (T: 51)
    
    UE message:
        SMActivatePDPContextRequest (PD 10, Type 65), IEs:
        - Type3V    : NSAPI
        - Type3V    : LLC_SAPI
        - Type4LV   : QoS
        - Type4LV   : PDPAddr
        - Type4TLV  : APN (T: 40)
        - Type4TLV  : ProtConfig (T: 39)
        - Type1TV   : ReqType (T: 10)
        - Type1TV   : DeviceProp (T: 12)
        - Type4TLV  : NBIFOMContainer (T: 51)
    """
    
    Cont = (
        (TS24008_SM.SMActivatePDPContextAccept, TS24008_SM.SMActivatePDPContextReject),
        (TS24008_SM.SMActivatePDPContextRequest, )
        )
    
    Decod = {
        (10, 65) : {
            'NSAPI'   : lambda x: x[0][1].get_val(),
            'LLC_SAPI': lambda x: x[0][1].get_val(),
            'APN'     : lambda x: [v[1] for v in x[2].get_val()],
            'PDPAddr' : lambda x: (x[1][1].get_val(), x[1][2].get_val())
            }
        }
    
    Cap = ('DeviceProp', )
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo, self.errcause = {}, None
        self.decode_msg(pdu, self.UEInfo)
        #
        # 1) check NSAPI
        if not 5 <= self.UEInfo['NSAPI'] <= 15:
            # invalid mandatory info
            self.errcause = 96
            return self.output()
        else:
            self.nsapi = self.UEInfo['NSAPI']
        #
        # 2) get APN and corresponding config
        if 'APN' not in self.UEInfo or not self.UEInfo['APN']:
            # missing APN
            self.errcause = 27
            return self.output()
        else:
            # only check the 1st apn component
            apn = self.UEInfo['APN'][0]
            if apn in self.SM.PDPConfig:
                pdpcfg = self.SM.PDPConfig[apn]
            elif '*' in self.SM.PDPConfig:
                pdpcfg = self.SM.PDPConfig['*']
            else:
                # unknown APN
                self.errcause = 27
                return self.output()
        #
        self.RespIEs, pdpaddr = {}, None
        # 3) check the ue request against pdpcfg
        if self.UEInfo['PDPAddr'] == (0, 1) and pdpcfg['Addr'][0] == 0:
            # PPP addr requested
            pdpaddr = (0, pdpcfg['Addr'][1])
            self.RespIEs['PDPAddr'] = (0, 0, 1, pdpcfg['Addr'][1])
        elif self.UEInfo['PDPAddr'][0] == 1:
            # IP addr requested
            if self.UEInfo['PDPAddr'][1] == 33:
                # IPv4
                if pdpcfg['Addr'][0] in (1, 3):
                    pdpaddr = (1, pdpcfg['Addr'][1])
                    self.RespIEs['PDPAddr'] = (0, 1, 33, inet_aton_cn(*pdpaddr, dom='PS'))
                else:
                    # PDP type IPv6 only allowed
                    self.errcause = 51
            elif self.UEInfo['PDPAddr'][1] == 87:
                # IPv6
                if pdpcfg['Addr'][0] in (2, 3):
                    pdpaddr = (2, pdpcfg['Addr'][-1])
                    self.RespIEs['PDPAddr'] = (0, 1, 87, inet_aton_cn(*pdpaddr, dom='PS'))
                else:
                    # PDP type IPv4 only allowed
                    self.errcause = 50
            elif self.UEInfo['PDPAddr'][1] == 141:
                # IPv4v6
                pdpaddr = pdpcfg['Addr']
                self.RespIEs['PDPAddr'] = (0, 1, (None, 33, 87, 141)[pdpaddr[0]],
                                           inet_aton_cn(*pdpaddr, dom='PS'))
                if pdpaddr[0] in (1, 2):
                    # single address only bearer
                    self.RespIEs['SMCause'] = 52
        if not pdpaddr and not self.errcause:
            # Unknown PDP address or PDP type
            self.errcause = 28
        #
        if self.errcause:
            return self.output()
        #
        # 3) check the protocol config options
        if 'ProtConfig' in self.UEInfo:
            self.RespIEs['ProtConfig'], pdpaddrreq = self.SM.process_protconfig(
                                                        pdpcfg, self.UEInfo['ProtConfig'])
            if not pdpaddrreq:
                del self.RespIEs['PDPAddr']
        #
        # set the PDP config properly
        self.SM.rab_set_default(self.nsapi, self._tid, apn, pdpaddr, pdpcfg)
        # just copy LLC_SAPI
        self.RespIEs['LLC_SAPI'] = (0, self.UEInfo['LLC_SAPI'])
        # NAS.QoS, reusing some RAB parameters
        rabcfg = pdpcfg['RAB']
        self.RespIEs['QoS'] = {
            'DelayClass': 4, # best effort
            'ReliabilityClass': 4, # unack GTP, LLC and RLC, protected data
            'PeakThroughput': 9, # 256 kO/s (-> 2Mb/s)
            'PrecedenceClass': 2, # normal priority
            'MeanThroughput': 31, # best effort
            'TrafficClass': RANAP.RANAP_IEs.TrafficClass._cont[rabcfg['TrafficClass']],
            'DeliveryOrder': 1 if rabcfg['DeliveryOrder'] == 'delivery-order-requested' else 2,
            'ErroneousSDU': 2 if rabcfg['SDU-Parameters'][0]['deliveryOfErroneousSDU'] == 'yes' else 3,
            'MaxSDUSize': 0b10011001, # 1520 octets, see TS 24.008, 10.5.6.5
            'MaxULBitrate': 0x80 + 55,  # 576 + 55*64  = 4096kb/s
            'MaxDLBitrate': 0x80 + 119, # 576 + 119*64 = 8192kb/s
            'ResidualBER': 2+rabcfg['SDU-Parameters'][0]['residualBitErrorRatio']['exponent'],
            'SDUErrorRatio': rabcfg['SDU-Parameters'][0]['sDU-ErrorRatio']['exponent'],
            'TransferDelay': 10, # 100 ms
            #'TrafficHandlingPriority': 0,
            'GuaranteedULBitrate': 255, # no guarantee
            'GuaranteedDLBitrate': 255, # no guarantee
            #'SignallingInd': 0,
            #'SourceStatsDesc': 0,
            #'MaxDLBitrateExt': 75, # 16Mb/s, extended value (MaxDLBitrate = 254)
            #'MaxULBitrateExt': 75, # 16Mb/s, extended value (MaxULBitrate = 254)
            }
        #
        if 'ReqType' in self.UEInfo:
            self._log('WNG', 'ReqType IE unsupported')
        if 'NBIFOMContainer' in self.UEInfo:
            self._log('WNG', 'NBIFOMContainer IE unsupported')
        #
        self.SM.Trans[self._tid] = self.nsapi
        return self.postprocess()
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, RANAPRABAssignment):
            if not Proc.success:
                # network failure
                self.errcause = 38
            # return SMActivatePDPContextAccept / Reject
            return self.output()
        #
        elif Proc == self:
            self._log('WNG', 'something bad happened with a previous procedure')
            # network failure
            self.errcause = 38
            # return SMActivatePDPContextReject
            return self.output()
        #
        elif Proc is not None:
            self._err = Proc
            assert()
        #
        else:
            # get the RAB config
            rabcfg = self.SM.PDP[self.nsapi]['RAB']
            # prepare IEs for a single RAB setup
            rablist = [{
                'id': 53, # id-RAB-SetupOrModifyItem
                'firstCriticality': 'reject',
                'firstValue': ('RAB-SetupOrModifyItemFirst', rabcfg['First']),
                'secondCriticality': 'ignore',
                'secondValue': ('RAB-SetupOrModifyItemSecond', rabcfg['Second'])
                }]
            IEs = {'RAB_SetupOrModifyList': [rablist]}
            # initiate a RANAPRABAssignment
            RanapProc = self.Iu.init_ranap_proc(RANAPRABAssignment, **IEs)
            if RanapProc:
                # pass the info required for setting the GTPU tunnel
                RanapProc._gtp_add_mobile_nsapi = [self.nsapi]
                # set a callback to here
                RanapProc._cb = self
                return [RanapProc]
            else:
                return []
    
    def output(self):
        if self.errcause:
            # prepare SMActivatePDPContextReject
            self.set_msg(10, 67, SMHeader={'TIPD': {'TIFlag': self._tif,
                                                    'TI': self._ti}},
                                 SMCause=self.errcause)
            self.encode_msg(10, 67)
            self._log('INF', 'reject, %r' % self._nas_tx['SMCause'][0])
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            self.rm_from_sm_stack()
            return self.Iu.ret_ranap_dt(self._nas_tx)
        #
        else:
            # prepare SMActivatePDPContextAccept
            self.RespIEs['SMHeader'] = {'TIPD': {'TIFlag': self._tif,
                                                 'TI': self._ti}}
            self.set_msg(10, 66, **self.RespIEs)
            self.encode_msg(10, 66)
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            self.rm_from_sm_stack()
            return self.Iu.ret_ranap_dt(self._nas_tx)


class SMPDPCtxtActRequest(SMSigProc):
    """PDP context activation procedure: TS 24.008, section 6.1.3.1
    
    CN-initiated
    triggers SMPDPCtxtAct
    
    CN message:
        SMRequestPDPContextActivation (PD 10, Type 68), IEs:
        - Type4LV   : PDPAddr
        - Type4TLV  : APN (T: 40)
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : NBIFOMContainer (T: 51)
    
    UE message:
        SMRequestPDPContextActivationReject (PD 10, Type 69), IEs:
        - Type3V    : SMCause
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : NBIFOMContainer (T: 51)
    """
    
    Cont = (
        (TS24008_SM.SMRequestPDPContextActivation, ),
        (TS24008_SM.SMRequestPDPContextActivationReject, )
        )
    
    Init  = (10, 68)
    Timer = 'T3385'


#------------------------------------------------------------------------------#
# Secondary PDP context activation: TS 24.008, section 6.1.3.2
#------------------------------------------------------------------------------#

class SMSecondPDPCtxtAct(SMSigProc):
    """Secondary PDP context activation procedure: TS 24.008, section 6.1.3.2
    
    UE-initiated
    
    CN messages:
        SMActivateSecondaryPDPContextAccept (PD 10, Type 78), IEs:
        - Type3V    : LLC_SAPI
        - Type4LV   : QoS
        - Type1V    : spare
        - Type1V    : RadioPriority
        - Type4TLV  : PacketFlowId (T: 52)
        - Type4TLV  : ProtConfig (T: 39)
        - Type1TV   : WLANOffloadInd (T: 12)
        - Type4TLV  : NBIFOMContainer (T: 51)
        
        SMActivateSecondaryPDPContextReject (PD 10, Type 79), IEs:
        - Type3V    : SMCause
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : BackOffTimer (T: 55)
        - Type4TLV  : ReattemptInd (T: 107)
        - Type4TLV  : NBIFOMContainer (T: 51)
    
    UE message:
        SMActivateSecondaryPDPContextRequest (PD 10, Type 77), IEs:
        - Type3V    : NSAPI
        - Type3V    : LLC_SAPI
        - Type4LV   : QoS
        - Type4LV   : LinkedTI
        - Type4TLV  : TFT (T: 54)
        - Type4TLV  : ProtConfig (T: 39)
        - Type1TV   : DeviceProp (T: 12)
        - Type4TLV  : NBIFOMContainer (T: 51)
    """
    
    Cont = (
        (TS24008_SM.SMActivateSecondaryPDPContextAccept, TS24008_SM.SMActivateSecondaryPDPContextReject),
        (TS24008_SM.SMActivateSecondaryPDPContextRequest, )
        )


class SMSecondPDPCtxtActRequest(SMSigProc):
    """Secondary PDP context activation procedure: TS 24.008, section 6.1.3.2
    
    CN-initiated
    triggers SMSecondPDPCtxtAct
    
    CN message:
        SMRequestSecondaryPDPContextActivation (PD 10, Type 91), IEs:
        - Type4LV   : QoS
        - Type4LV   : LinkedTI
        - Type4TLV  : TFT (T: 54)
        - Type4TLV  : ProtConfig (T: 39)
        - Type1TV   : WLANOffloadInd (T: 12)
        - Type4TLV  : NBIFOMContainer (T: 51)
    
    UE message:
        SMRequestSecondaryPDPContextActivationReject (PD 10, Type 92), IEs:
        - Type3V    : SMCause
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : NBIFOMContainer (T: 51)
    """
    
    Cont = (
        (TS24008_SM.SMRequestSecondaryPDPContextActivation, ),
        (TS24008_SM.SMRequestSecondaryPDPContextActivationReject, )
        )
    
    Init  = (10, 91)
    Timer = 'T3385'


#------------------------------------------------------------------------------#
# PDP context modification: TS 24.008, section 6.1.3.3
#------------------------------------------------------------------------------#

class SMPDPCtxtModifUE(SMSigProc):
    """PDP context modification procedure: TS 24.008, section 6.1.3.3
    
    UE-initiated
    
    CN messages:
        SMModifyPDPContextAcceptMT (PD 10, Type 75), IEs:
        - Type4TLV  : QoS (T: 48)
        - Type3TV   : LLC_SAPI (T: 50)
        - Type1TV   : RadioPriority (T: 8)
        - Type4TLV  : PacketFlowId (T: 52)
        - Type4TLV  : ProtConfig (T: 39)
        - Type1TV   : WLANOffloadInd (T: 12)
        - Type4TLV  : NBIFOMContainer (T: 51)
        
        SMModifyPDPContextReject (PD 10, Type 76), IEs:
        - Type3V    : SMCause
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : BackOffTimer (T: 55)
        - Type4TLV  : ReattemptInd (T: 107)
        - Type4TLV  : NBIFOMContainer (T: 51)
    
    UE message:
        SMModifyPDPContextRequestMO (PD 10, Type 74), IEs:
        - Type3TV   : LLC_SAPI (T: 50)
        - Type4TLV  : QoS (T: 48)
        - Type4TLV  : TFT (T: 49)
        - Type4TLV  : ProtConfig (T: 39)
        - Type1TV   : DeviceProp (T: 12)
        - Type4TLV  : NBIFOMContainer (T: 51)
    """
    
    Cont = (
        (TS24008_SM.SMModifyPDPContextAcceptMT, TS24008_SM.SMModifyPDPContextReject),
        (TS24008_SM.SMModifyPDPContextRequestMO, )
        )


class SMPDPCtxtModifCN(SMSigProc):
    """PDP context modification procedure: TS 24.008, section 6.1.3.3
    
    CN-initiated
    
    CN message:
        SMModifyPDPContextRequestMT (PD 10, Type 72), IEs:
        - Type1V    : spare
        - Type1V    : RadioPriority
        - Type3V    : LLC_SAPI
        - Type4LV   : QoS
        - Type4TLV  : PDPAddr (T: 43)
        - Type4TLV  : PacketFlowId (T: 52)
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : TFT (T: 54)
        - Type1TV   : WLANOffloadInd (T: 12)
        - Type4TLV  : NBIFOMContainer (T: 51)
    
    UE message:
        SMModifyPDPContextAcceptMO (PD 10, Type 73), IEs:
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : NBIFOMContainer (T: 51)
    """
    
    Cont = (
        (TS24008_SM.SMModifyPDPContextRequestMT, ),
        (TS24008_SM.SMModifyPDPContextAcceptMO, )
        )
    
    Init  = (10, 72)
    Timer = 'T3386'


#------------------------------------------------------------------------------#
# PDP context deactivation: TS 24.008, section 6.1.3.4
#------------------------------------------------------------------------------#

class SMPDPCtxtDeactUE(SMSigProc):
    """PDP context deactivation procedure: TS 24.008, section 6.1.3.4
    
    UE-initiated
    
    CN message:
        SMDeactivatePDPContextAccept (PD 10, Type 71), IEs:
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : MBMSProtConfig (T: 53)
    
    UE message:
        SMDeactivatePDPContextRequest (PD 10, Type 70), IEs:
        - Type3V    : SMCause
        - Type1TV   : TearDownInd (T: 9)
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : MBMSProtConfig (T: 53)
        - Type4TLV  : T3396 (T: 55)
        - Type1TV   : WLANOffloadInd (T: 12)
    """
    
    Cont = (
        (TS24008_SM.SMDeactivatePDPContextAccept, ),
        (TS24008_SM.SMDeactivatePDPContextRequest, )
        )
    
    Decod = {
        (10, 70): {
            'SMCause': lambda x: x[0].to_uint()
            }
        }
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo, self.errcause = {}, None
        self.decode_msg(pdu, self.UEInfo)
        #
        if self.UEInfo['SMCause'] != 36:
            self._log('INF', 'PDP context deactivation, %r' % self.UEInfo['SMCause'])
        #
        if self._tid in self.SM.Trans:
            # get the corresponding NSAPI
            nsapi = self.SM.Trans[self._tid]
        else:
            # no identified NSAPI, nothing to teardown
            self._log('INF', 'no NSAPI corresponding to the transaction identifier %i' % self._tid)
            return self.output()
        #
        self.rem_mobile_nsapi = [nsapi]
        if 'TearDownInd' in self.UEInfo and self.UEInfo['TearDownInd']:
            # the PDP ctx for the given NSAPI should be toredown,
            # and associated PDP ctx with same PDP addr and APN too
            self.rem_mobile_nsapi.extend( self.SM.PDP[nsapi]['linked'] )
        #
        if 'ProtConfig' in self.UEInfo:
            self._log('WNG', 'ProtConfig IE unsupported')
        if 'MBMSProtConfig' in self.UEInfo:
            self._log('WNG', 'MBMSProtConfig IE unsupported')
        if 'T3396' in self.UEInfo:
            self._log('WNG', 'T3396 IE unsupported')
        if 'WLANOffloadInd' in self.UEInfo:
            self._log('WNG', 'WLANOffloadInd IE unsupported')
        #
        return self.postprocess()
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, RANAPRABAssignment):
            return self.output()
        #
        elif Proc == self:
            self._log('WNG', 'something bad happened with a previous procedure')
            return self.output()
        #
        elif Proc is not None:
            self._err = Proc
            assert()
        #
        else:
            # initiate a RANAPRABAssignment with the RAB_ReleaseList
            rablist = []
            for nsapi in self.rem_mobile_nsapi:
                rablist.append({
                    'id': 40, # id-RAB-ReleaseItem
                    'criticality': 'ignore',
                    'value': ('RAB-ReleaseItem', {
                              'rAB-ID': (nsapi, 8),
                              'cause' : ('nAS', 83)}) # normal-release
                    })
            IEs = {'RAB_ReleaseList': [rablist]}
            # initiate a RANAPRABAssignment
            RanapProc = self.Iu.init_ranap_proc(RANAPRABAssignment, **IEs)
            if RanapProc:
                # pass the info required for deleting the GTPU tunnels
                RanapProc._gtp_rem_mobile_nsapi = self.rem_mobile_nsapi
                # set a callback to here
                RanapProc._cb = self
                return [RanapProc]
            else:
                return []
    
    def output(self):
        for nsapi in self.rem_mobile_nsapi:
            tid = self.SM.PDP[nsapi]['TID']
            del self.SM.PDP[nsapi]
            del self.SM.Trans[tid]
        self.set_msg(10, 71, SMHeader={'TIPD': {'TIFlag': self._tif,
                                                'TI': self._ti}})
        self.encode_msg(10, 71)
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.rm_from_sm_stack()
        return self.Iu.ret_ranap_dt(self._nas_tx)


class SMPDPCtxtDeactCN(SMSigProc):
    """PDP context deactivation procedure: TS 24.008, section 6.1.3.4
    
    CN-initiated
    
    CN message:
        SMDeactivatePDPContextRequest (PD 10, Type 70), IEs:
        - Type3V    : SMCause
        - Type1TV   : TearDownInd (T: 9)
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : MBMSProtConfig (T: 53)
        - Type4TLV  : T3396 (T: 55)
        - Type1TV   : WLANOffloadInd (T: 12)
    
    UE message:
        SMDeactivatePDPContextAccept (PD 10, Type 71), IEs:
        - Type4TLV  : ProtConfig (T: 39)
        - Type4TLV  : MBMSProtConfig (T: 53)
    """
    
    Cont = (
        (TS24008_SM.SMDeactivatePDPContextRequest, ),
        (TS24008_SM.SMDeactivatePDPContextAccept, )
        )
    
    Init  = (10, 70)
    Timer = 'T3395'


#------------------------------------------------------------------------------#
# Notification: TS 24.008, section 6.1.3.5a
#------------------------------------------------------------------------------#

class SMNotification(SMSigProc):
    """Notification procedure: TS 24.008, section 6.1.3.5a
    
    CM-initiated
    
    CN message:
        SMNotification (PD 10, Type 93), IEs:
        - Type4LV   : NotificationInd
    
    UE message:
        None
    """
    
    Cont = (
        (TS24008_SM.SMNotification, ),
        None
        )
    
    Init = (10, 93)


#------------------------------------------------------------------------------#
# MBMS context activation: TS 24.008, section 6.1.3.8
#------------------------------------------------------------------------------#
   
class SMMBMSCtxtAct(SMSigProc):
    """MBMS context activation procedure: TS 24.008, section 6.1.3.8
    
    UE-initiated
    
    CN message:
        SMActivateMBMSContextAccept (PD 10, Type 87), IEs:
        - Type4LV   : TMGI
        - Type3V    : LLC_SAPI
        - Type4TLV  : MBMSProtConfig (T: 53)
        
        SMActivateMBMSContextReject (PD 10, Type 88), IEs:
        - Type3V    : SMCause
        - Type4TLV  : MBMSProtConfig (T: 53)
        - Type4TLV  : BackOffTimer (T: 55)
        - Type4TLV  : ReattemptInd (T: 107)
    
    UE message:
        SMActivateMBMSContextRequest (PD 10, Type 86), IEs:
        - Type3V    : MBMS_NSAPI
        - Type3V    : LLC_SAPI
        - Type4LV   : MBMSBearerCap
        - Type4LV   : MCastAddr
        - Type4LV   : APN
        - Type4TLV  : MBMSProtConfig (T: 53)
        - Type1TV   : DeviceProp (T: 12)
    """
    
    Cont = (
        (TS24008_SM.SMActivateMBMSContextAccept, TS24008_SM.SMActivateMBMSContextReject),
        (TS24008_SM.SMActivateMBMSContextRequest, )
        )


class SMMBMSCtxtActRequest(SMSigProc):
    """MBMS context activation procedure: TS 24.008, section 6.1.3.8
    
    CN-initiated
    triggers SMMBMSCtxtAct
    
    CN message:
        SMRequestMBMSContextActivation (PD 10, Type 89), IEs:
        - Type3V    : LinkedNSAPI
        - Type4LV   : MCastAddr
        - Type4LV   : APN
        - Type4TLV  : MBMSProtConfig (T: 53)
    
    UE message:
        SMRequestMBMSContextActivationReject (PD 10, Type 90), IEs:
        - Type3V    : SMCause
        - Type4TLV  : MBMSProtConfig (T: 53)
    """
    
    Cont = (
        (TS24008_SM.SMRequestMBMSContextActivation, ),
        (TS24008_SM.SMRequestMBMSContextActivationReject, )
        )
    
    Init  = (10, 89)
    Timer = 'T3385'


#------------------------------------------------------------------------------#
# MBMS context deactivation: TS 24.008, section 6.1.3.9
#------------------------------------------------------------------------------#
# this is actually identical to deactivating a standard unicast PDP ctxt

SMMBMSCtxtDeact = SMPDPCtxtDeactCN


SMPDPCtxtAct.init(filter_init=1)
SMPDPCtxtDeactUE.init(filter_init=1)
SMPDPCtxtModifUE.init(filter_init=1)
SMSecondPDPCtxtAct.init(filter_init=1)
SMPDPCtxtAct.init(filter_init=1)
SMPDPCtxtActRequest.init(filter_init=1)
SMPDPCtxtDeactCN.init(filter_init=1)
SMPDPCtxtModifCN.init(filter_init=1)
SMMBMSCtxtActRequest.init(filter_init=1)
SMSecondPDPCtxtActRequest.init(filter_init=1)
SMNotification.init(filter_init=1)

# SM UE-initiated procedures dispatcher
SMProcUeDispatcher = {
    65: SMPDPCtxtAct,
    70: SMPDPCtxtDeactUE,
    74: SMPDPCtxtModifUE,
    77: SMSecondPDPCtxtAct,
    86: SMPDPCtxtAct,
    }
SMProcUeDispatcherStr = {ProcClass.Cont[1][0]()._name: ProcClass \
                         for ProcClass in SMProcUeDispatcher.values()}

# SM CN-initiated procedures dispatcher
SMProcCnDispatcher = {
    68: SMPDPCtxtActRequest,
    70: SMPDPCtxtDeactCN,
    72: SMPDPCtxtModifCN,
    89: SMMBMSCtxtActRequest,
    91: SMSecondPDPCtxtActRequest,
    93: SMNotification, 
    }
SMProcCnDispatcherStr = {ProcClass.Cont[0][0]()._name: ProcClass \
                         for ProcClass in SMProcCnDispatcher.values()}

