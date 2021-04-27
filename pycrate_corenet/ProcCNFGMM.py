# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2021. Benoit Michau. P1Sec.
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
# * File Name : pycrate_corenet/ProcCNFGMM.py
# * Created : 2021-04-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'FGMMSigProc',
    #
    'FGMMPrimAKA',
    'FGMMSecurityModeControl',
    'FGMMIdentification',
    'FGMMGenericUEConfigUpdate',
    'FGMMMONASTransport',
    'FGMMMTNASTransport',
    'FGMMNSSAA',
    #
    'FGMMRegistration',
    'FGMMMODeregistration',
    'FGMMMTDeregistration',
    'FGMMServiceRequest',
    'FGMMCtrlPlaneServiceRequest',
    #
    'FGMMProcUeDispatcher',
    'FGMMProcUeDispatcherStr',
    'FGMMProcCnDispatcher',
    'FGMMProcCnDispatcherStr'
    ]


from .utils      import *
from .ProcProto  import *
from .ProcCNNgap import *


TESTING = False

#------------------------------------------------------------------------------#
# NAS 5GS Mobility Management signalling procedure
# TS 24.501, version h21
# Core Network side
#------------------------------------------------------------------------------#

class FGMMSigProc(NASSigProc):
    """5GS Mobility Management signalling procedure handler
    
    instance attributes:
        - Name : procedure name
        - FGMM : reference to the UEFGMMd instance running this procedure
        - NG   : reference to the UENGd instance connecting the UE
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
    
    # network initiator message id
    Init = None
    
    if TESTING:
        def __init__(self, encod=None):
            self._prepare(encod)
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            log('[TESTING] [%s] [FGMMSigProc] [%s] %s' % (logtype, self.Name, msg))
    
    else:
        def __init__(self, fgmmd, encod=None, fgmm_preempt=False, sec=True):
            self._prepare(encod)
            self.FGMM = fgmmd
            self.NG   = fgmmd.NG
            self.UE   = fgmmd.UE
            self._fgmm_preempt = fgmm_preempt
            if fgmm_preempt:
                self.FGMM.ready.clear()
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            self.FGMM._log(logtype, '[%s] %s' % (self.Name, msg))
    
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
        self.rm_from_fgmm_stack()
        return []
    
    def abort(self):
        # abort this procedure, and all procedures started within this one
        ind = self.FGMM.Proc.index(self)
        if ind >= 0:
            for p in self.FGMM.Proc[ind+1:]:
                p.abort()
            del self.FGMM.Proc[ind:]
        if self._fgmm_preempt:
            # release the FGMM stack
            self.FGMM.ready.set()
        self._log('INF', 'aborting')
    
    def rm_from_fgmm_stack(self):
        # remove the procedure from the FGMM stack of procedures
        try:
            if self.FGMM.Proc[-1] == self:
                del self.FGMM.Proc[-1]
        except Exception:
            self._log('WNG', 'FGMM stack corrupted')
        else:
            if self._fgmm_preempt:
                # release the FGMM stack
                self.FGMM.ready.set()
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.FGMM, self.Timer, self.TimerDefault)
            self.TimerStart = time()
            self.TimerStop  = self.TimerStart + self.TimerValue
    
    def get_timer(self):
        if self.Timer is None:
            return None
        else:
            return getattr(self.FGMM, self.Timer)
    
    def fgmm_preempt(self):
        self._fgmm_preempt = True
        self.FGMM.ready.clear()
    
    #--------------------------------------------------------------------------#
    # common helpers
    #--------------------------------------------------------------------------#
    # None yet


#------------------------------------------------------------------------------#
# 5GMM common procedures: TS 24.501, section 5.4
#------------------------------------------------------------------------------#

class FGMMPrimAKA(FGMMSigProc):
    """Primary authentication and key agreement procedure: TS 24.501, section 5.4.1
    
    CN-initiated
    
    CN message:
        5GMMAuthenticationRequest (PD 126, Type 86), IEs:
        - Type1V    : spare
        - Type1V    : NAS_KSI
        - Type4LV   : ABBA
        - Type3TV   : RAND (T: 33)
        - Type4TLV  : AUTN (T: 32)
        - Type6TLVE : EAPMsg (T: 120)
        
        5GMMAuthenticationReject (PD 126, Type 88), IEs:
        - Type6TLVE : EAPMsg (T: 120)
        
        5GMMAuthenticationResult (PD 126, Type 90), IEs:
        - Type1V    : spare
        - Type1V    : NAS_KSI
        - Type6LVE  : EAPMsg
        - Type4TLV  : ABBA (T: 56)
    
    UE message:
        5GMMAuthenticationResponse (PD 126, Type 87), IEs:
        - Type4TLV  : RES (T: 45)
        - Type6TLVE : EAPMsg (T: 120)
        
        5GMMAuthenticationFailure (PD 126, Type 89), IEs:
        - Type3V    : 5GMMCause
        - Type4TLV  : AUTS (T: 48)
    """
    
    Cont  = (
        (TS24501_FGMM.FGMMAuthenticationRequest, TS24501_FGMM.FGMMAuthenticationReject),
        (TS24501_FGMM.FGMMAuthenticationResponse, TS24501_FGMM.FGMMAuthenticationFailure)
        )
    
    Init  = (126, 86)
    Timer = 'T3560'
    
    '''TODO
    def output(self):
        return []
    
    def process(self, pdu):
        return []
    '''


class FGMMSecurityModeControl(FGMMSigProc):
    """Security mode control procedure: TS 24.501, section 5.4.2
    
    CN-initiated
    
    CM message:
        5GMMSecurityModeCommand (PD 126, Type 93), IEs:
        - Type3V    : NASSecAlgo
        - Type1V    : spare
        - Type1V    : NAS_KSI
        - Type4LV   : UESecCap
        - Type1TV   : IMEISVReq (T: 14)
        - Type3TV   : EPSNASSecAlgo (T: 87)
        - Type4TLV  : Add5GSecInfo (T: 54)
        - Type6TLVE : EAPMsg (T: 120)
        - Type4TLV  : ABBA (T: 56)
        - Type4TLV  : S1UESecCap (T: 25)
    
    UE message:
        5GMMSecurityModeComplete (PD 126, Type 94), IEs:
        - Type6TLVE : IMEISV (T: 119)
        - Type6TLVE : NASContainer (T: 113)
        - Type6TLVE : PEI (T: 120)
        
        5GMMSecurityModeReject (PD 126, Type 95), IEs:
        - Type3V    : 5GMMCause
    """
    
    Cont  = (
        (TS24501_FGMM.FGMMSecurityModeCommand, ),
        (TS24501_FGMM.FGMMSecurityModeComplete, TS24501_FGMM.FGMMSecurityModeReject)
        )
    
    Init  = (126, 93)
    Timer = 'T3560'
    
    '''TODO
    def output(self):
        return []
    
    def process(self, pdu):
        return []
    '''


class FGMMIdentification(FGMMSigProc):
    """Identification procedure: TS 24.501, section 5.4.3
    
    CN-initiated
    
    CN message:
        5GMMIdentityRequest (PD 126, Type 91), IEs:
        - Type1V    : spare
        - Type1V    : 5GSIDType
    
    UE message:
        5GMMIdentityResponse (PD 126, Type 92), IEs:
        - Type6LVE  : 5GSID
    """
    
    Cont  = (
        (NAS.FGMMIdentityRequest, ),
        (NAS.FGMMIdentityResponse, )
        )
    
    Init  = (126, 91)
    Timer = 'T3570'
    
    '''TODO
    def output(self):
        return []
    
    def process(self, pdu):
        return []
    '''


class FGMMGenericUEConfigUpdate(FGMMSigProc):
    """Generic UE configuration update procedure: TS 24.501, section 5.4.4
    
    CN-initiated
    
    CN message:
        5GMMConfigurationUpdateCommand (PD 126, Type 84), IEs:
        - Type1TV   : ConfigUpdateInd (T: 13)
        - Type6TLVE : GUTI (T: 119)
        - Type4TLV  : 5GSTAIList (T: 84)
        - Type4TLV  : AllowedNSSAI (T: 21)
        - Type4TLV  : SAList (T: 39)
        - Type4TLV  : NetFullName (T: 67)
        - Type4TLV  : NetShortName (T: 69)
        - Type3TV   : LocalTimeZone (T: 70)
        - Type3TV   : UnivTimeAndTimeZone (T: 71)
        - Type4TLV  : DLSavingTime (T: 73)
        - Type6TLVE : LADNInfo (T: 121)
        - Type1TV   : MICOInd (T: 11)
        - Type1TV   : NetSlicingInd (T: 9)
        - Type4TLV  : ConfiguredNSSAI (T: 49)
        - Type4TLV  : RejectedNSSAI (T: 17)
        - Type6TLVE : OperatorAccessCatDefs (T: 118)
        - Type1TV   : SMSInd (T: 15)
        - Type4TLV  : T3447 (T: 108)
        - Type6TLVE : CAGInfoList (T: 117)
        - Type4TLV  : UERadioCapID (T: 103)
        - Type1TV   : UERadioCapIDDelInd (T: 10)
        - Type4TLV  : 5GSRegResult (T: 68)
        - Type4TLV  : Trunc5GSTMSIConfig (T: 27)
        - Type1TV   : AddConfigInd (T: 12)
    
    UE message:
        5GMMConfigurationUpdateComplete (PD 126, Type 85), IEs:
          None
    """
    
    Cont  = (
        (NAS.FGMMConfigurationUpdateCommand, ),
        (NAS.FGMMConfigurationUpdateComplete, )
        )
    
    Init  = (126, 84)
    Timer = 'T3555'
    
    '''TODO
    def output(self):
        return []
    
    def process(self, pdu):
        return []
    '''


class FGMMMONASTransport(FGMMSigProc):
    """UE-initiated NAS transport procedure: TS 24.501, section 5.4.5.2
    
    UE-initiated
    
    CN message:
        None
    
    UE message:
        5GMMULNASTransport (PD 126, Type 103), IEs:
        - Type1V    : spare
        - Type1V    : PayloadContainerType
        - Type6LVE  : PayloadContainer
        - Type3TV   : PDUSessID (T: 18)
        - Type3TV   : OldPDUSessID (T: 89)
        - Type1TV   : RequestType (T: 8)
        - Type4TLV  : SNSSAI (T: 34)
        - Type4TLV  : DNN (T: 37)
        - Type4TLV  : AddInfo (T: 36)
        - Type1TV   : MAPDUSessInfo (T: 10)
        - Type1TV   : ReleaseAssistInd (T: 15)
    """
    
    Cont  = (
        None,
        (NAS.FGMMULNASTransport,)
        )
    
    Init  = (126, 103)
    
    '''TODO
    def process(self, pdu):
        return []
    '''


class FGMMMTNASTransport(FGMMSigProc):
    """Network-initiated NAS transport procedure: TS 24.501, section 5.4.5.3
    
    CN-initiated
    
    CN message:
        5GMMDLNASTransport (PD 126, Type 104), IEs:
        - Type1V    : spare
        - Type1V    : PayloadContainerType
        - Type6LVE  : PayloadContainer
        - Type3TV   : PDUSessID (T: 18)
        - Type4TLV  : AddInfo (T: 36)
        - Type3TV   : 5GMMCause (T: 88)
        - Type4TLV  : BackOffTimer (T: 55)
    
    UE message:
        None
    """
    
    Cont  = (
        (NAS.FGMMDLNASTransport, ),
        None
        )
    
    Init  = (126, 104)
    
    '''TODO
    def output(self):
        return []
    '''


class FGMMNSSAA(FGMMSigProc):
    """Network slice-specific authentication and authorization procedure: TS 24.501, section 5.4.7
    
    CN-initiated
    
    CN message:
        5GMMNetworkSliceSpecAuthCommand (PD 126, Type 80), IEs:
        - Type4LV   : SNSSAI
        - Type6LVE  : EAPMsg
                                                                                                  
        5GMMNetworkSliceSpecAuthResult (PD 126, Type 82), IEs:
        - Type4LV   : SNSSAI
        - Type6LVE  : EAPMsg
    
    UE message:
        5GMMNetworkSliceSpecAuthComplete (PD 126, Type 81), IEs:
        - Type4LV   : SNSSAI
        - Type6LVE  : EAPMsg
    """
    
    Cont  = (
        (NAS.FGMMNetworkSliceSpecAuthCommand, NAS.FGMMNetworkSliceSpecAuthResult),
        (NAS.FGMMNetworkSliceSpecAuthComplete, )
        )
    
    Init  = (126, 80)
    Timer = 'T3575'
    
    '''TODO
    def output(self):
        return []
    
    def process(self, pdu):
        return []
    '''


#------------------------------------------------------------------------------#
# 5GMM specific procedures: TS 24.501, section 5.5
#------------------------------------------------------------------------------#

class FGMMRegistration(FGMMSigProc):
    """Registration procedure: TS 24.501, section 5.5.1
    
    UE-initiated
    
    CN message:
        5GMMRegistrationAccept (PD 126, Type 66), IEs:
        - Type4LV   : 5GSRegResult
        - Type6TLVE : GUTI (T: 119)
        - Type4TLV  : EquivPLMNList (T: 74)
        - Type4TLV  : 5GSTAIList (T: 84)
        - Type4TLV  : AllowedNSSAI (T: 21)
        - Type4TLV  : RejectedNSSAI (T: 17)
        - Type4TLV  : ConfiguredNSSAI (T: 49)
        - Type4TLV  : 5GSNetFeat (T: 33)
        - Type4TLV  : PDUSessStat (T: 80)
        - Type4TLV  : PDUSessReactResult (T: 38)
        - Type6TLVE : PDUSessReactResultErr (T: 114)
        - Type6TLVE : LADNInfo (T: 121)
        - Type1TV   : MICOInd (T: 11)
        - Type1TV   : NetSlicingInd (T: 9)
        - Type4TLV  : SAList (T: 39)
        - Type4TLV  : T3512 (T: 94)
        - Type4TLV  : Non3GPPDeregTimer (T: 93)
        - Type4TLV  : T3502 (T: 22)
        - Type4TLV  : EmergNumList (T: 52)
        - Type6TLVE : ExtEmergNumList (T: 122)
        - Type6TLVE : SORTransContainer (T: 115)
        - Type6TLVE : EAPMsg (T: 120)
        - Type1TV   : NSSAIInclMode (T: 10)
        - Type6TLVE : OperatorAccessCatDefs (T: 118)
        - Type4TLV  : 5GSDRXParam (T: 81)
        - Type1TV   : Non3GPPNWProvPol (T: 13)
        - Type4TLV  : EPSBearerCtxtStat (T: 96)
        - Type4TLV  : ExtDRXParam (T: 110)
        - Type4TLV  : T3447 (T: 108)
        - Type4TLV  : T3448 (T: 107)
        - Type4TLV  : T3324 (T: 106)
        - Type4TLV  : UERadioCapID (T: 103)
        - Type4TLV  : PendingNSSAI (T: 57)
        - Type6TLVE : CipheringKeyData (T: 116)
        - Type6TLVE : CAGInfoList (T: 117)
        - Type4TLV  : Trunc5GSTMSIConfig (T: 27)
        - Type4TLV  : WUSAssistInfo (T: 26)
        - Type4TLV  : NBN1ModeDRXParam (T: 41)
        
        5GMMRegistrationReject (PD 126, Type 68), IEs:
        - Type3V    : 5GMMCause
        - Type4TLV  : T3346 (T: 95)
        - Type4TLV  : T3502 (T: 22)
        - Type6TLVE : EAPMsg (T: 120)
        - Type4TLV  : RejectedNSSAI (T: 105)
        - Type6TLVE : CAGInfoList (T: 117)
        
    UE message:
        5GMMRegistrationRequest (PD 126, Type 65), IEs:
        - Type1V    : NAS_KSI
        - Type1V    : 5GSRegType
        - Type6LVE  : 5GSID
        - Type1TV   : NonCurrentNativeNAS_KSI (T: 12)
        - Type4TLV  : 5GMMCap (T: 16)
        - Type4TLV  : UESecCap (T: 46)
        - Type4TLV  : NSSAI (T: 47)
        - Type3TV   : TAI (T: 82)
        - Type4TLV  : EPSUENetCap (T: 23)
        - Type4TLV  : ULDataStat (T: 64)
        - Type4TLV  : PDUSessStat (T: 80)
        - Type1TV   : MICOInd (T: 11)
        - Type4TLV  : UEStatus (T: 43)
        - Type6TLVE : AddGUTI (T: 119)
        - Type4TLV  : AllowedPDUSessStat (T: 37)
        - Type4TLV  : UEUsage (T: 24)
        - Type4TLV  : 5GSDRXParam (T: 81)
        - Type6TLVE : EPSNASContainer (T: 112)
        - Type6TLVE : LADNInd (T: 116)
        - Type1TV   : PayloadContainerType (T: 8)
        - Type6TLVE : PayloadContainer (T: 123)
        - Type1TV   : NetSlicingInd (T: 9)
        - Type4TLV  : 5GSUpdateType (T: 83)
        - Type4TLV  : MSCm2 (T: 65)
        - Type4TLV  : SuppCodecs (T: 66)
        - Type6TLVE : NASContainer (T: 113)
        - Type4TLV  : EPSBearerCtxtStat (T: 96)
        - Type4TLV  : ExtDRXParam (T: 110)
        - Type4TLV  : T3324 (T: 106)
        - Type4TLV  : UERadioCapID (T: 103)
        - Type4TLV  : MappedNSSAI (T: 53)
        - Type4TLV  : AddInfoReq (T: 72)
        - Type4TLV  : WUSAssistInfo (T: 26)
        - Type2     : N5GCInd (T: 10)
        - Type4TLV  : NBN1ModeDRXParam (T: 48)
        
        5GMMRegistrationComplete (PD 126, Type 67), IEs:
        - Type6TLVE : SORTransContainer (T: 115)
    """
    
    Cont  = (
        (NAS.FGMMRegistrationAccept, NAS.FGMMRegistrationReject),
        (NAS.FGMMRegistrationRequest, NAS.FGMMRegistrationComplete)
        )
    
    Init  = (126, 65)
    Timer = 'T3550'
    
    '''TODO
    def process(self, pdu):
        return []
    
    def output(self):
        return []
    '''


class FGMMMODeregistration(FGMMSigProc):
    """UE-initiated de-registration procedure: TS 24.501, section 5.5.2.2
    
    UE-initiated
    
    CN message:
        5GMMMODeregistrationAccept (PD 126, Type 70), IEs:
          None
        
    UE message:
        5GMMMODeregistrationRequest (PD 126, Type 69), IEs:
        - Type1V    : NAS_KSI
        - Type1V    : DeregistrationType
        - Type6LVE  : 5GSID
    """
    
    Cont  = (
        (NAS.FGMMMODeregistrationAccept, ),
        (NAS.FGMMMODeregistrationRequest, )
        )
    
    Init  = (126, 69)
    
    '''TODO
    def process(self, pdu):
        return []
    
    def output(self):
        return []
    '''


class FGMMMTDeregistration(FGMMSigProc):
    """Network-initiated de-registration procedure: TS 24.501, section 5.5.2.3
    
    CN-initiated
    
    CN message:
        5GMMMTDeregistrationRequest (PD 126, Type 71), IEs:
        - Type1V    : spare
        - Type1V    : DeregistrationType
        - Type3TV   : 5GMMCause (T: 88)
        - Type4TLV  : T3346 (T: 95)
        - Type4TLV  : RejectedNSSAI (T: 109)
        
    UE message:
        5GMMMTDeregistrationAccept (PD 126, Type 71), IEs:
          None
    """
    
    Cont  = (
        (NAS.FGMMMTDeregistrationRequest, ),
        (NAS.FGMMMTDeregistrationAccept, )
        )
    
    Init  = (126, 71)
    Timer = 'T3522'

    '''TODO
    def output(self):
        return []
    
    def process(self, pdu):
        return []
    '''


#------------------------------------------------------------------------------#
# 5GMM connection management procedures: TS 24.501, section 5.6
#------------------------------------------------------------------------------#

class FGMMServiceRequest(FGMMSigProc):
    """Service request procedure: TS 24.501, section 5.6.1
    
    UE-initiated
    
    CN message:
        5GMMServiceAccept (PD 126, Type 78), IEs:
        - Type4TLV  : PDUSessStat (T: 80)
        - Type4TLV  : PDUSessReactResult (T: 38)
        - Type6TLVE : PDUSessReactResultErr (T: 114)
        - Type6TLVE : EAPMsg (T: 120)
        - Type4TLV  : T3448 (T: 107)
        
        5GMMServiceAccept (PD 126, Type 77), IEs:
        - Type3V    : 5GMMCause
        - Type4TLV  : PDUSessStat (T: 80)
        - Type4TLV  : T3346 (T: 95)
        - Type6TLVE : EAPMsg (T: 120)
        - Type4TLV  : T3448 (T: 107)
        - Type6TLVE : CAGInfoList (T: 117)
        
    UE message:
        5GMMServiceRequest (PD 126, Type 76), IEs:
        - Type1V    : ServiceType
        - Type1V    : NAS_KSI
        - Type6LVE  : 5GSID
        - Type4TLV  : ULDataStat (T: 64)
        - Type4TLV  : PDUSessStat (T: 80)
        - Type4TLV  : AllowedPDUSessStat (T: 37)
        - Type6TLVE : NASContainer (T: 113)
    """
    
    Cont  = (
        (NAS.FGMMServiceAccept, NAS.FGMMServiceReject),
        (NAS.FGMMServiceRequest, )
        )
    
    Init  = (126, 76)
    
    '''TODO
    def process(self, pdu):
        return []
    
    def output(self):
        return []
    '''


class FGMMCtrlPlaneServiceRequest(FGMMSigProc):
    """Service request procedure: TS 24.501, section 5.6.1
    
    UE-initiated
    
    CN message:
        5GMMServiceAccept (PD 126, Type 78), IEs:
        - Type4TLV  : PDUSessStat (T: 80)
        - Type4TLV  : PDUSessReactResult (T: 38)
        - Type6TLVE : PDUSessReactResultErr (T: 114)
        - Type6TLVE : EAPMsg (T: 120)
        - Type4TLV  : T3448 (T: 107)
        
        5GMMServiceAccept (PD 126, Type 77), IEs:
        - Type3V    : 5GMMCause
        - Type4TLV  : PDUSessStat (T: 80)
        - Type4TLV  : T3346 (T: 95)
        - Type6TLVE : EAPMsg (T: 120)
        - Type4TLV  : T3448 (T: 107)
        - Type6TLVE : CAGInfoList (T: 117)
        
    UE message:
        5GMMControlPlaneServiceRequest (PD 126, Type 79), IEs:
        - Type1V    : NAS_KSI
        - Type1V    : CtrlPlaneServiceType
        - Type4TLV  : CIoTSmallDataContainer (T: 111)
        - Type1TV   : PayloadContainerType (T: 8)
        - Type6TLVE : PayloadContainer (T: 123)
        - Type3TV   : PDUSessID (T: 18)
        - Type4TLV  : PDUSessStat (T: 80)
        - Type1TV   : ReleaseAssistInd (T: 15)
        - Type4TLV  : ULDataStat (T: 64)
        - Type6TLVE : NASContainer (T: 113)
        - Type4TLV  : AddInfo (T: 36)
    """
    
    Cont  = (
        (NAS.FGMMServiceAccept, NAS.FGMMServiceReject),
        (NAS.FGMMControlPlaneServiceRequest, )
        )
    
    Init  = (126, 79)
    
    '''TODO
    def process(self, pdu):
        return []
    
    def output(self):
        return []
    '''



FGMMPrimAKA.init(filter_init=1)
FGMMSecurityModeControl.init(filter_init=1)
FGMMIdentification.init(filter_init=1)
FGMMGenericUEConfigUpdate.init(filter_init=1)
FGMMMONASTransport.init(filter_init=1)
FGMMMTNASTransport.init(filter_init=1)
FGMMNSSAA.init(filter_init=1)
FGMMRegistration.init(filter_init=1)
FGMMMODeregistration.init(filter_init=1)
FGMMMTDeregistration.init(filter_init=1)
FGMMServiceRequest.init(filter_init=1)
FGMMCtrlPlaneServiceRequest.init(filter_init=1)

# 5G MM UE-initiated procedures dispatcher
FGMMProcUeDispatcher = {
    103 : FGMMMONASTransport,
    65 : FGMMRegistration,
    69 : FGMMMODeregistration,
    76 : FGMMServiceRequest,
    79 : FGMMCtrlPlaneServiceRequest,
    }

FGMMProcUeDispatcherStr = {ProcClass.Cont[1][0]()._name: ProcClass \
                           for ProcClass in FGMMProcUeDispatcher.values()}

# 5G MM CN-initiated procedures dispatcher
FGMMProcCnDispatcher = {
    86 : FGMMPrimAKA,
    93 : FGMMSecurityModeControl,
    91 : FGMMIdentification,
    84 : FGMMGenericUEConfigUpdate,
    104 : FGMMMTNASTransport,
    80 : FGMMNSSAA,
    71 : FGMMMTDeregistration,
    }

FGMMProcCnDispatcherStr = {ProcClass.Cont[0][0]()._name: ProcClass \
                           for ProcClass in FGMMProcCnDispatcher.values()}

