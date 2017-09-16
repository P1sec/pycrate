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
# * File Name : pycrate_corenet/ProcCNGMM.py
# * Created : 2017-07-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcProto   import *
from .ProcCNRanap import *


TESTING = False

#------------------------------------------------------------------------------#
# NAS GPRS Mobility Management signaling procedure
# TS 24.008, version d90
# Core Network side
#------------------------------------------------------------------------------#

class GMMSigProc(NASSigProc):
    """GPRS Mobility Management signaling procedure handler
    
    instance attributes:
        - Name : procedure name
        - GMM  : reference to the UEGMMd instance running this procedure
        - Iu   : reference to the IuPSd instance connecting the UE
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
            log('[TESTING] [%s] [GMMSigProc] [%s] %s' % (logtype, self.Name, msg))
    
    else:
        def __init__(self, gmmd, encod=None):
            self._prepare(encod)
            self.GMM  = gmmd
            self.Iu   = gmmd.Iu
            self.UE   = gmmd.UE
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            self.GMM._log(logtype, '[%s] %s' % (self.Name, msg))
    
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
    
    def postprocess(self, proc=None):
        self._log('ERR', 'postprocess() not implemented')
        return None
    
    def _collect_cap(self):
        if not hasattr(self, 'Cap') or not hasattr(self, 'UEInfo'):
            return
        for Cap in self.Cap:
            if Cap in self.UEInfo:
                self.UE.Cap[Cap] = self.UEInfo[Cap]
    
    def abort(self):
        # abort this procedure, and all procedures started within this one
        ind = self.GMM.Proc.index(self)
        if ind >= 0:
            for p in self.GMM.Proc[ind+1:]:
                p.abort()
            del self.GMM.Proc[ind:]
        self._log('INF', 'aborting')
    
    def rm_from_gmm_stack(self):
        # remove the procedure from the MM stack of procedures
        if self.GMM.Proc[-1] == self:
            del self.GMM.Proc[-1]
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.GMM, self.Timer, self.TimerDefault)
            self.TimerStart = time()
            self.TimerStop  = self.TimerStart + self.TimerValue
    
    def get_timer(self):
        if self.Timer is None:
            return None
        else:
            return getattr(self.GMM, self.Timer)


#------------------------------------------------------------------------------#
# GMM procedures: TS 24.008, section 4.7
#------------------------------------------------------------------------------#

class GMMAttach(GMMSigProc):
    """GPRS attach: TS 24.008, section 4.7.3
    
    UE-initiated
    
    CN messages:
        GMMAttachAccept (PD 8, Type 2), IEs:
        - Type1V    : ForceStdby
        - Type1V    : AttachResult
        - Type2     : PeriodicRAUpdateTimer
        - Type1V    : RadioPrioForTOM8
        - Type1V    : RadioPrioForSMS
        - Type3V    : RAI
        - Type3TV   : PTMSISign (T: 25)
        - Type3TV   : NegoREADYTimer (T: 23)
        - Type4TLV  : AllocPTMSI (T: 24)
        - Type4TLV  : MSIdent (T: 35)
        - Type3TV   : GMMCause (T: 37)
        - Type4TLV  : T3302 (T: 42)
        - Type2     : CellNotif (T: 140)
        - Type4TLV  : EquivPLMNList (T: 74)
        - Type1TV   : NetFeatSupp (T: 10)
        - Type4TLV  : T3319 (T: 55)
        - Type4TLV  : T3323 (T: 56)
        - Type4TLV  : T3312Ext (T: 57)
        - Type4TLV  : AddNetFeatSupp (T: 102)
        - Type4TLV  : T3324 (T: 106)
        - Type4TLV  : ExtDRXParam (T: 110)
        - Type1TV   : UPIntegrityInd (T: 12)
        - Type4TLV  : ReplayedMSNetCap (T: 49)
        - Type4TLV  : ReplayedMSRACap (T: 51)
        
        GMMAttachReject (PD 8, Type 4), IEs:
        - Type2     : GMMCause
        - Type4TLV  : T3302 (T: 42)
        - Type4TLV  : T3346 (T: 58)
    
    UE messages:
        GMMAttachRequest (PD 8, Type 1), IEs:
        - Type4LV   : MSNetCap
        - Type1V    : CKSN
        - Type1V    : AttachType
        - Type3V    : DRXParam
        - Type4LV   : ID
        - Type3V    : OldRAI
        - Type4LV   : MSRACap
        - Type3TV   : OldPTMSISign (T: 25)
        - Type3TV   : ReqREADYTimer (T: 23)
        - Type1TV   : TMSIStatus (T: 9)
        - Type4TLV  : PSLCSCap (T: 51)
        - Type4TLV  : MSCm2 (T: 17)
        - Type4TLV  : MSCm3 (T: 32)
        - Type4TLV  : SuppCodecs (T: 64)
        - Type4TLV  : UENetCap (T: 88)
        - Type4TLV  : AddID (T: 26)
        - Type4TLV  : AddRAI (T: 27)
        - Type4TLV  : VoiceDomPref (T: 93)
        - Type1TV   : DeviceProp (T: 13)
        - Type1TV   : PTMSIType (T: 14)
        - Type1TV   : MSNetFeatSupp (T: 12)
        - Type4TLV  : OldLAI (T: 20)
        - Type1TV   : AddUpdateType (T: 15)
        - Type4TLV  : TMSIBasedNRICont (T: 16)
        - Type4TLV  : T3324 (T: 106)
        - Type4TLV  : T3312Ext (T: 57)
        - Type4TLV  : ExtDRXParam (T: 110)
        
        GMMAttachComplete (PD 8, Type 3), IEs:
        - Type4TLV  : InterRATHOInfo (T: 39)
        - Type4TLV  : EUTRANInterRATHOInfo (T: 43)
    """
    
    Cont = (
        (TS24008_GMM.GMMAttachAccept, TS24008_GMM.GMMAttachReject),
        (TS24008_GMM.GMMAttachRequest, TS24008_GMM.GMMAttachComplete)
        )
    
    Decod = {
        (8, 1) : {
            'CKSN'          : lambda x: x(),
            'ID'            : lambda x: x[1].decode(),
            'OldRAI'        : lambda x: (x['PLMN'].decode(), x['LAC'](), x['RAC']()),
            'ReqREADYTimer' : lambda x: {'Unit': x[1]['Unit'](), 'Value': x[1]['Value']()},
            }
        }
    
    Cap = ('MSNetCap', 'DRXParam', 'MSRACap', 'PSLCSCap', 'MSCm2', 'MSCm3', 
           'SuppCodecs', 'UENetCap', 'VoiceDomPref', 'DeviceProp', 'MSNetFeatSupp',
           'ExtDRXParam')
    
    def process(self, pdu):
        # got a GMMAttachRequest
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        if pdu['Type']() == 1:
            # AttachRequest
            self.errcause, self.UEInfo = None, {}
            self.decode_msg(pdu, self.UEInfo)
            return self._process_req()
        else:
            # AttachComplete
            self.errcause, self.CompInfo = None, {}
            self.decode_msg(pdu, self.CompInfo)
            self.UE.set_ptmsi(self.ptmsi_realloc)
            self._log('INF', 'new P-TMSI set, %.8x' % self.ptmsi_realloc)
            self._end(nas_tx=False)
            return None
    
    def _process_req(self):
        att_type = self.UEInfo['AttachType']['Type']
        # collect capabilities
        self._collect_cap()
        #
        self._log('INF', 'request type %i (%s) from, old RAI %s.%.4x%.2x'\
                  % (att_type(), att_type._dic[att_type()],
                     self.UEInfo['OldRAI'][0], self.UEInfo['OldRAI'][1], self.UEInfo['OldRAI'][2]))
        #
        # check local ID
        if self.UE.IMSI is None:
            # UEd was created based on a PTMSI provided at the RRC layer
            # -> we need to get its IMSI before continuing
            # we remove it from the Server's provisory dict of UE
            try:
                del self.UE.Server._UEpre[self.UE.TMSI]
            except:
                pass
            #
            if self.UEInfo['ID'][0] == 1:
                # IMSI is provided at the NAS layer
                if not self._set_imsi(self.UEInfo['ID'][1]):
                    # IMSI not allowed
                    return self.output()
            else:
                # need to request the IMSI, prepare an id request procedure
                NasProc = self.GMM.init_proc(GMMIdentification)
                NasProc.set_msg(8, 21, IDType=NAS.IDTYPE_IMSI)
                return NasProc.output()
        #
        if self.Iu.require_auth(self, cksn=self.UEInfo['CKSN']):
            return self._ret_auth()
        #
        if self.Iu.require_smc(self):
            # if we are here, there was no auth procedure,
            # hence the cksn submitted by the UE is valid
            return self._ret_smc(self.UEInfo['CKSN'], False)
        #
        # otherwise, go directly to postprocess
        return self.postprocess()  
    
    def _set_imsi(self, imsi):
        # arriving here means the UE's IMSI was unknown at first
        # set the IMSI indicated by the UE
        self.UE.set_ident_from_ue(NAS.IDTYPE_IMSI, imsi)
        Server = self.UE.Server
        if not Server.is_imsi_allowed(imsi):
            self.errcause = self.GMM.IDENT_IMSI_NOT_ALLOWED
            return False
        else:
            if imsi in Server.UE:
                # a profile already exists for this IMSI
                self._log('WNG', 'profile for IMSI %s already exists, need to reject for reconnection'\
                          % imsi)
                # update the PTMSI table and reject self, so that it will reconnect
                # and get the already existing profile
                Server.PTMSI[self.UE.PTMSI] = imsi
                self.errcause = self.GMM.ATT_IMSI_PROV_REJECT
                return False
            else:
                Server.UE[imsi] = self.UE
                Server.PTMSI[self.UE.PTMSI] = imsi
                # update the Server UE's tables
                if imsi in Server.ConfigUE:
                    # update UE's config with it's dedicated config
                    self.UE.set_config( Server.ConfigUE[imsi] )
                return True
    
    def _ret_auth(self):
        NasProc = self.GMM.init_proc(GMMAuthenticationCiphering)
        return NasProc.output()
    
    def _ret_smc(self, cksn=None, newkey=False):
        # set a RANAP callback in the Iu stack for triggering an SMC
        RanapProc = self.Iu.init_ranap_proc(RANAPSecurityModeControl,
                                            **self.Iu.get_smc_ies(cksn, newkey))
        RanapProc._cb = self
        if RanapProc:
            self.Iu.RanapTx = [RanapProc]
        return None
    
    def postprocess(self, Proc):
        if isinstance(Proc, GMMIdentification):
            # got the UE's IMSI, check if it's allowed
            if self.UE.IMSI is None or not self._set_imsi(self.UE.IMSI):
                return self.output()
            elif self.Iu.require_auth(self):
                return self._ret_auth()
            elif self.Iu.require_smc(self):
                # if we are here, there was no auth procedure,
                # hence the cksn submitted by the UE is valid
                return self._ret_smc(self.UEInfo['CKSN'], False)
        elif isinstance(Proc, GMMAuthenticationCiphering):
            if self.Iu.require_smc(self):
                # if we are here, the valid cksn is the one established during
                # the auth procedure
                return self._ret_smc(Proc.cksn, True)
        elif isinstance(Proc, RANAPSecurityModeControl):
            if not Proc.success:
                self.abort()
                return None
            # self.Iu.SEC['CKSN'] has been taken into action as the RRC layer
        elif Proc is not None:
            assert()
        #
        return self.output()
    
    def output(self):
        if self.errcause:
            # prepare AttachReject IE
            if self.errcause == self.GMM.ATT_IMSI_PROV_REJECT:
                self.set_msg(8, 4, GMMCause=self.errcause, T3346=self.GMM.ATT_T3346)
            else:
                self.set_msg(8, 4, GMMCause=self.errcause)
            self.encode_msg(8, 4)
            self.ptmsi_realloc = -1
        else:
            # prepare AttachAccept IEs
            IEs = {'ForceStdby'            : {'Value': self.GMM.ATT_FSTDBY},
                   'AttachResult'          : {'FollowOnProc': self.UEInfo['AttachType']['FollowOnReq'](),
                                              'Result': self.UEInfo['AttachType']['Type']()},
                   'PeriodicRAUpdateTimer' : self.GMM.ATT_RAU_TIMER,
                   'RadioPrioForTOM8'      : {'Value': self.GMM.ATT_PRIO_TOM8},
                   'RadioPrioForSMS'       : {'Value': self.GMM.ATT_PRIO_SMS},
                   'RAI'                   : {'plmn': self.UE.PLMN, 'lac': self.UE.LAC, 'rac': self.UE.RAC}
                   }
            #
            # READY timer negotiation
            if 'ReqREADYTimer' in self.UEInfo:
                if self.GMM.ATT_READY_TIMER is None:
                    IEs['NegoREADYTimer'] = self.UEInfo['ReqREADYTimer']
                else:
                    IEs['NegoREADYTimer'] = self.GMM.ATT_READY_TIMER
            # in case we want to realloc a PTMSI, we start a PTMSIRealloc,
            # but don't forward its output
            if self.GMM.ATT_PTMSI_REALLOC:
                NasProc = self.GMM.init_proc(GMMPTMSIReallocation)
                void = NasProc.output(embedded=True)
                IEs['AllocPTMSI'] = {'type': NAS.IDTYPE_TMSI, 'ident': NasProc.ptmsi}
                self.ptmsi_realloc = NasProc.ptmsi
            else:
                self.ptmsi_realloc = -1
            #
            if self.GMM.ATT_T3302 is not None:
                IEs['T3302'] = self.GMM.ATT_T3302
            if self.Iu.Config['EquivPLMNList'] is not None:
                IEs['EquivPLMNList'] = self.Iu.Config['EquivPLMNList']
            if self.GMM.ATT_NETFEAT_SUPP is not None:
                IEs['NetFeatSupp'] = self.GMM.ATT_NETFEAT_SUPP
            #
            if isinstance(self.Iu.Config['EmergNumList'], bytes_types):
                IEs['EmergNumList'] = self.Iu.Config['EmergNumList']
            elif self.Iu.Config['EmergNumList'] is not None:
                IEs['EmergNumList'] = [{'ServiceCat': uint_to_bitlist(cat), 'Num': num} for \
                                       (cat, num) in self.Iu.Config['EmergNumList']]
            #
            if self.GMM.ATT_MSINF_REQ is not None:
                IE['ReqMSInfo'] = self.GMM.ATT_MSINF_REQ
            if self.GMM.ATT_T3312_EXT is not None:
                IEs['T3312Ext'] = self.GMM.ATT_T3312_EXT
            if self.GMM.ATT_ADDNETFEAT_SUPP is not None:
                IEs['AddNetFeatSupp'] = self.GMM.ATT_ADDNETFEAT_SUPP
            #
            if 'ExtDRXParam' in self.UEInfo:
                if self.GMM.ATT_EXTDRX is None:
                    IEs['ExtDRXParam'] = self.UEInfo['ExtDRXParam']
                else:
                    IEs['ExtDRXParam'] = self.GMM.ATT_EXTDRX
            #
            # encode the msg with all its IEs
            self.set_msg(8, 2, **IEs)
            self.encode_msg(8, 2)
        #
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        if self.ptmsi_realloc < 0:
            self._end(nas_tx=True)
        else:
            # use the timer of the GMMPTMSIRealloc
            # and wait for a GMMAttachComplete to end the procedure
            self.Timer = NasProc.Timer
            self.init_timer()
        # send Attach reject / accept
        return self._nas_tx
    
    def _end(self, nas_tx=True):
        if self.GMM.ATT_IUREL and \
        (self.errcause or not self.UEInfo['AttachType']['FollowOnReq']()):
            # trigger an IuRelease after the direct transfer
            RanapTx = []
            if nas_tx:
                RanapProcDT = self.Iu.init_ranap_proc(RANAPDirectTransferCN,
                                                      NAS_PDU=self._nas_tx.to_bytes(),
                                                      SAPI='sapi-0')
                if RanapProcDT:
                    RanapTx.append( RanapProcDT )
            # IuRelease with Cause NAS normal-release (83)
            RanapProcRel = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=('nAS', 83))
            if RanapProcRel:
                RanapTx.append( RanapProcRel )
            if RanapTx:
                self.Iu.RanapTx = RanapTx
        self.rm_from_gmm_stack()


class GMMDetachUE(GMMSigProc):
    """MS-initiated GPRS detach: TS 24.008, section 4.7.4.1
    
    UE-initiated
    
    CN message:
        GMMDetachAcceptMO (PD 8, Type 6), IEs:
        - Type1V    : spare
        - Type1V    : ForceStdby
    
    UE message:
        GMMDetachRequestMO (PD 8, Type 5), IEs:
        - Type1V    : spare
        - Type1V    : DetachTypeMO
        - Type4TLV  : AllocPTMSI (T: 24)
        - Type4TLV  : PTMSISign (T: 25)
    """
    
    Cont = (
        (TS24008_GMM.GMMDetachAcceptMO, ),
        (TS24008_GMM.GMMDetachRequestMO, )
        )
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        if self.UEInfo['DetachTypeMO']['PowerOff']():
            # if UE is to power-off, procedure ends here
            ret = self.output(poff=True)
        else:
            ret = self.output()
        self._detach()
        return ret
    
    def _detach(self):
        # we only consider GPRS detach here
        self.rm_from_gmm_stack()
        # abort all ongoing CS procedures
        self.Iu.clear_nas_proc()
        # set MM state
        self.GMM.state = 'INACTIVE'
        #
        self._log('INF', 'detaching')
    
    def output(self, poff=False):
        # prepare a stack of RANAP procedure(s)
        RanapTx = []
        if not poff:
            # set a RANAP direct transfer to transport the DetachAccept
            self.set_msg(8, 6, ForceStdby={'Value': self.GMM.DET_FSTDBY})
            self.encode_msg(8, 6)
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            RanapProcDT = self.Iu.init_ranap_proc(RANAPDirectTransferCN,
                                                  NAS_PDU=self._nas_tx.to_bytes(),
                                                  SAPI='sapi-0')
            if RanapProcDT:
                RanapTx.append( RanapProcDT )
        # set an Iu release with Cause NAS normal-release (83)
        RanapProcRel = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=('nAS', 83))
        if RanapProcRel:
            RanapTx.append( RanapProcRel )
        #
        if RanapTx:
            self.Iu.RanapTx = RanapTx
        return self._nas_tx


class GMMDetachCN(GMMSigProc):
    """Network-initiated GPRS detach: TS 24.008, section 4.7.4.2
    
    CN-initiated
    
    CN message:
        GMMDetachRequestMT (PD 8, Type 5), IEs:
        - Type1V    : ForceStdby
        - Type1V    : DetachTypeMT
        - Type3TV   : GMMCause (T: 37)
    
    UE message:
        GMMDetachAcceptMT (PD 8, Type 6), IEs:
          None
    """
    
    Cont = (
        (TS24008_GMM.GMMDetachRequestMT, ),
        (TS24008_GMM.GMMDetachAcceptMT, )
        )


class GMMRoutingAreaUpdating(GMMSigProc):
    """Routing area updating: TS 24.008, section 4.7.5
    
    UE-initiated
    
    CN-messages:
        GMMRoutingAreaUpdateAccept (PD 8, Type 9), IEs:
        - Type1V    : ForceStdby
        - Type1V    : UpdateResult
        - Type2     : PeriodicRAUpdateTimer
        - Type3V    : RAI
        - Type3TV   : PTMSISign (T: 25)
        - Type4TLV  : AllocPTMSI (T: 24)
        - Type4TLV  : MSIdent (T: 35)
        - Type4TLV  : RcvNPDUNumList (T: 38)
        - Type3TV   : NegoREADYTimer (T: 23)
        - Type3TV   : GMMCause (T: 37)
        - Type4TLV  : T3302 (T: 42)
        - Type2     : CellNotif (T: 140)
        - Type4TLV  : EquivPLMNList (T: 74)
        - Type4TLV  : PDPCtxtStat (T: 50)
        - Type1TV   : NetFeatSupp (T: 10)
        - Type4TLV  : EmergNumList (T: 52)
        - Type4TLV  : MBMSCtxtStat (T: 53)
        - Type1TV   : ReqMSInfo (T: 10)
        - Type4TLV  : T3319 (T: 55)
        - Type4TLV  : T3323 (T: 56)
        - Type4TLV  : T3312Ext (T: 57)
        - Type4TLV  : AddNetFeatSupp (T: 102)
        - Type4TLV  : T3324 (T: 106)
        - Type4TLV  : ExtDRXParam (T: 110)
        - Type1TV   : UPIntegrityInd (T: 12)
        - Type4TLV  : ReplayedMSNetCap (T: 49)
        - Type4TLV  : ReplayedMSRACap (T: 51)
        
        GMMRoutingAreaUpdateReject (PD 8, Type 11), IEs:
        - Type2     : GMMCause
        - Type1V    : spare
        - Type1V    : ForceStdby
        - Type4TLV  : T3302 (T: 42)
        - Type4TLV  : T3346 (T: 58)
    
    UE messages:
        GMMRoutingAreaUpdateRequest (PD 8, Type 8), IEs:
        - Type1V    : CKSN
        - Type1V    : UpdateType
        - Type3V    : OldRAI
        - Type4LV   : MSRACap
        - Type3TV   : OldPTMSISign (T: 25)
        - Type3TV   : ReqREADYTimer (T: 23)
        - Type3TV   : DRXParam (T: 39)
        - Type1TV   : TMSIStatus (T: 9)
        - Type4TLV  : PTMSI (T: 24)
        - Type4TLV  : MSNetCap (T: 49)
        - Type4TLV  : PDPCtxtStat (T: 50)
        - Type4TLV  : PSLCSCap (T: 51)
        - Type4TLV  : MBMSCtxtStat (T: 53)
        - Type4TLV  : UENetCap (T: 88)
        - Type4TLV  : AddID (T: 26)
        - Type4TLV  : AddRAI (T: 27)
        - Type4TLV  : MSCm2 (T: 17)
        - Type4TLV  : MSCm3 (T: 32)
        - Type4TLV  : SuppCodecs (T: 64)
        - Type4TLV  : VoiceDomPref (T: 93)
        - Type1TV   : PTMSIType (T: 14)
        - Type1TV   : DeviceProp (T: 13)
        - Type1TV   : MSNetFeatSupp (T: 12)
        - Type4TLV  : OldLAI (T: 20)
        - Type1TV   : AddUpdateType (T: 15)
        - Type4TLV  : TMSIBasedNRICont (T: 16)
        - Type4TLV  : T3324 (T: 106)
        - Type4TLV  : T3312Ext (T: 57)
        - Type4TLV  : ExtDRXParam (T: 110)
        
        GMMRoutingAreaUpdateComplete (PD 8, Type 10), IEs:
        - Type4TLV  : RcvNPDUNumList (T: 38)
        - Type4TLV  : InterRATHOInfo (T: 39)
        - Type4TLV  : EUTRANInterRATHOInfo (T: 43)
    """
    
    Cont = (
        (TS24008_GMM.GMMRoutingAreaUpdateAccept, TS24008_GMM.GMMRoutingAreaUpdateReject),
        (TS24008_GMM.GMMRoutingAreaUpdateRequest, TS24008_GMM.GMMRoutingAreaUpdateComplete)
        )
    
    Decod = {
        (8, 8) : {
            'CKSN'          : lambda x: x(),
            'OldRAI'        : lambda x: (x['PLMN'].decode(), x['LAC'](), x['RAC']()),
            'ReqREADYTimer' : lambda x: {'Unit': x[1]['Unit'](), 'Value': x[1]['Value']()},
            }
        }
    
    Cap = ('MSRACap', 'DRXParam', 'MSNetCap', 'PSLCSCap', 'UENetCap', 'MSCm2', 
           'MSCm3', 'SuppCodecs', 'VoiceDomPref', 'DeviceProp', 'MSNetFeatSupp',
           'ExtDRXParam') 
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        if pdu['Type']() == 8:
            # RoutingAreaUpdateRequest
            self.errcause, self.UEInfo = None, {}
            self.decode_msg(pdu, self.UEInfo)
            return self._process_req()
        else:
            # RoutingAreaUpdateComplete
            self.errcause, self.CompInfo = None, {}
            self.decode_msg(pdu, self.CompInfo)
            self.UE.set_ptmsi(self.ptmsi_realloc)
            self._log('INF', 'new P-TMSI set, %.8x' % self.ptmsi_realloc)
            self._end(nas_tx=False)
            return None
    
    def _process_req(self):
        rau_type = self.UEInfo['UpdateType']['Type']
        # collect capabilities
        self._collect_cap()
        #
        self._log('INF', 'request type %i (%s) from, old RAI %s.%.4x%.2x'\
                  % (rau_type(), rau_type._dic[rau_type()],
                     self.UEInfo['OldRAI'][0], self.UEInfo['OldRAI'][1], self.UEInfo['OldRAI'][2]))
        #
        if self.Iu.require_auth(self, cksn=self.UEInfo['CKSN']):
            return self._ret_auth()
        #
        if self.Iu.require_smc(self):
            # if we are here, there was no auth procedure,
            # hence the cksn submitted by the UE is valid
            return self._ret_smc(self.UEInfo['CKSN'], False)
        #
        # otherwise, go directly to postprocess
        return self.postprocess()  
    
    def _ret_auth(self):
        NasProc = self.GMM.init_proc(GMMAuthenticationCiphering)
        return NasProc.output()
    
    def _ret_smc(self, cksn=None, newkey=False):
        # set a RANAP callback in the Iu stack for triggering an SMC
        RanapProc = self.Iu.init_ranap_proc(RANAPSecurityModeControl,
                                            **self.Iu.get_smc_ies(cksn, newkey))
        RanapProc._cb = self
        if RanapProc:
            self.Iu.RanapTx = [RanapProc]
        return None
    
    def postprocess(self, Proc):
        if isinstance(Proc, GMMAuthenticationCiphering):
            if self.Iu.require_smc(self):
                # if we are here, the valid cksn is the one established during
                # the auth procedure
                return self._ret_smc(Proc.cksn, True)
        elif isinstance(Proc, RANAPSecurityModeControl):
            if not Proc.success:
                self.abort()
                return None
            # self.Iu.SEC['CKSN'] has been taken into action as the RRC layer
        elif Proc is not None:
            assert()
        #
        return self.output()
    
    def output(self):
        if self.errcause:
            # prepare RAUReject IE
            self.set_msg(8, 11, GMMCause=self.errcause)
            self.encode_msg(8, 11)
            self.ptmsi_realloc = -1
        else:
            # prepare RAUAccept IEs
            IEs = {'ForceStdby'            : {'Value': self.GMM.RAU_FSTDBY},
                   'UpdateResult'          : {'FollowOnProc': self.UEInfo['UpdateType']['FollowOnReq'](),
                                              'Result': self.UEInfo['UpdateType']['Type']()},
                   'PeriodicRAUpdateTimer' : self.GMM.RAU_RAU_TIMER,
                   'RAI'                   : {'plmn': self.UE.PLMN, 'lac': self.UE.LAC, 'rac': self.UE.RAC}
                   }
            #
            # in case we want to realloc a PTMSI, we start a PTMSIRealloc,
            # but don't forward its output
            if self.GMM.RAU_PTMSI_REALLOC:
                NasProc = self.GMM.init_proc(GMMPTMSIReallocation)
                void = NasProc.output(embedded=True)
                IEs['AllocPTMSI'] = {'type': NAS.IDTYPE_TMSI, 'ident': NasProc.ptmsi}
                self.ptmsi_realloc = NasProc.ptmsi
            else:
                self.ptmsi_realloc = -1
            # READY timer negotiation
            if 'ReqREADYTimer' in self.UEInfo:
                if self.GMM.RAU_READY_TIMER is None:
                    IEs['NegoREADYTimer'] = self.UEInfo['ReqREADYTimer']
                else:
                    IEs['NegoREADYTimer'] = self.GMM.RAU_READY_TIMER
            #
            if self.GMM.RAU_T3302 is not None:
                IEs['T3302'] = self.GMM.RAU_T3302
            if self.Iu.Config['EquivPLMNList'] is not None:
                IEs['EquivPLMNList'] = self.Iu.Config['EquivPLMNList']
            if self.GMM.RAU_NETFEAT_SUPP is not None:
                IEs['NetFeatSupp'] = self.GMM.RAU_NETFEAT_SUPP
            #
            if isinstance(self.Iu.Config['EmergNumList'], bytes_types):
                IEs['EmergNumList'] = self.Iu.Config['EmergNumList']
            elif self.Iu.Config['EmergNumList'] is not None:
                IEs['EmergNumList'] = [{'ServiceCat': uint_to_bitlist(cat), 'Num': num} for \
                                       (cat, num) in self.Iu.Config['EmergNumList']]
            #
            if self.GMM.RAU_MSINF_REQ is not None:
                IE['ReqMSInfo'] = self.GMM.RAU_MSINF_REQ
            if self.GMM.RAU_T3312_EXT is not None:
                IEs['T3312Ext'] = self.GMM.RAU_T3312_EXT
            if self.GMM.RAU_ADDNETFEAT_SUPP is not None:
                IEs['AddNetFeatSupp'] = self.GMM.RAU_ADDNETFEAT_SUPP
            #
            if 'ExtDRXParam' in self.UEInfo:
                if self.GMM.RAU_EXTDRX is None:
                    IEs['ExtDRXParam'] = self.UEInfo['ExtDRXParam']
                else:
                    IEs['ExtDRXParam'] = self.GMM.RAU_EXTDRX
            #
            # encode the msg with all its IEs
            self.set_msg(8, 9, **IEs)
            self.encode_msg(8, 9)
        #
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        if self.ptmsi_realloc < 0:
            self._end(nas_tx=True)
        else:
            # use the timer of the GMMPTMSIRealloc
            # and wait for a GMMRAUComplete to end the procedure
            self.Timer = NasProc.Timer
            self.init_timer()
        # send RAU reject / accept
        return self._nas_tx
    
    def _end(self, nas_tx=True):
        if self.GMM.RAU_IUREL and \
        (self.errcause or not self.UEInfo['UpdateType']['FollowOnReq']()):
            # trigger an IuRelease after the direct transfer
            RanapTx = []
            if nas_tx:
                RanapProcDT = self.Iu.init_ranap_proc(RANAPDirectTransferCN,
                                                      NAS_PDU=self._nas_tx.to_bytes(),
                                                      SAPI='sapi-0')
                if RanapProcDT:
                    RanapTx.append( RanapProcDT )
            # IuRelease with Cause NAS normal-release (83)
            RanapProcRel = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=('nAS', 83))
            if RanapProcRel:
                RanapTx.append( RanapProcRel )
            if RanapTx:
                self.Iu.RanapTx = RanapTx
        self.rm_from_gmm_stack()


class GMMPTMSIReallocation(GMMSigProc):
    """P-TMSI reallocation: TS 24.008, section 4.7.6
    
    CN-initiated
    
    CN message:
        GMMPTMSIReallocationCommand (PD 8, Type 16), IEs:
        - Type4LV   : AllocPTMSI
        - Type3V    : RAI
        - Type1V    : spare
        - Type1V    : ForceStdby
        - Type3TV   : PTMSISign (T: 25)
    
    UE message:
        GMMPTMSIReallocationComplete (PD 8, Type 17), IEs:
          None
    """
    
    Cont = (
        (TS24008_GMM.GMMPTMSIReallocationCommand, ),
        (TS24008_GMM.GMMPTMSIReallocationComplete, )
        )
    
    Timer = 'T3350'
    
    def output(self, embedded=False):
        # embedded=True is used to embed this procedure within an Attach or RAU
        # hence the output message is not built, only the .ptmsi is available
        # but the procedure still runs and waits for the UE response 
        # after all
        self.ptmsi = self.UE.get_new_tmsi()
        if not embedded:
            # prepare IEs
            self.set_msg(8, 16, AllocPTMSI={'type': NAS.IDTYPE_TMSI, 'ident': self.ptmsi},
                                RAI       ={'plmn': self.UE.PLMN, 'lac': self.UE.LAC, 'rac': self.UE.RAC},
                                ForceStdby={'Value': self.GMM.REA_FSTDBY})
            self.encode_msg(8, 16)
            # log the NAS msg
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            #
            self.init_timer()
            # send it over RANAP
            return self._nas_tx
        else:
            # when the P-TMSI realloc is embedded, there is no realloc complete
            # to expect...
            self.rm_from_gmm_stack()
            return None
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        # just take the new ptmsi in use
        self.UE.set_ptmsi(self.ptmsi)
        self._log('INF', 'new P-TMSI set, %.8x' % self.ptmsi)
        self.rm_from_gmm_stack()
        return None


class GMMAuthenticationCiphering(GMMSigProc):
    """Authentication and ciphering: TS 24.008, section 4.7.7
    
    CN-initiated
    
    CN messages:
        GMMAuthenticationCipheringRequest (PD 8, Type 18), IEs:
        - Type1V    : IMEISVReq
        - Type1V    : CiphAlgo
        - Type1V    : ACRef
        - Type1V    : ForceStdby
        - Type3TV   : RAND (T: 33)
        - Type1TV   : CKSN (T: 8)
        - Type4TLV  : AUTN (T: 40)
        - Type4TLV  : ReplayedMSNetCap (T: 49)
        - Type1TV   : IntegAlgo (T: 9)
        - Type4TLV  : MAC (T: 67)
        - Type4TLV  : ReplayedMSRACap (T: 51)
    
        GMMAuthenticationCipheringReject (PD 8, Type 20), IEs:
          None
    
    UE messages:
        GMMAuthenticationCipheringResponse (PD 8, Type 19), IEs:
        - Type1V    : spare
        - Type1V    : ACRef
        - Type3TV   : RES (T: 34)
        - Type4TLV  : IMEISV (T: 35)
        - Type4TLV  : RESExt (T: 41)
        - Type4TLV  : MAC (T: 67)
        
        GMMAuthenticationCipheringFailure (PD 8, Type 28), IEs:
        - Type2     : GMMCause
        - Type4TLV  : AUTS (T: 48)
    """
    
    Cont = (
        (TS24008_GMM.GMMAuthenticationCipheringRequest, TS24008_GMM.GMMAuthenticationCipheringReject),
        (TS24008_GMM.GMMAuthenticationCipheringResponse, TS24008_GMM.GMMAuthenticationCipheringFailure)
        )
    
    Timer = 'T3360'
    
    Decod = {
        (8, 19): {
            'RES'    : lambda x: x['V'](),
            'IMEISV' : lambda x: x[2].decode(),
            'RESExt' : lambda x: x['V']()
            },
        (8, 28): {
            'AUTS'   : lambda x: x['V']()
            }
        }
    
    def output(self):
        # get a new CKSN
        self.cksn = self.Iu.get_new_cksn()
        # in case a RAND is configured as a class encoder, we use it for 
        # generating the auth vector
        if 'RAND' in self.__class__.Encod[(8, 18)]:
            RAND = self.__class__.Encod[(5, 18)]['RAND']
        else:
            RAND = None
        #
        if not self.UE.USIM or self.GMM.AUTH_2G:
            # 2G authentication
            self.ctx = 2
            self.vect = self.UE.Server.AUCd.make_2g_vector(self.UE.IMSI, RAND)
        else:
            # 3G authentication
            self.ctx = 3
            self.vect = self.UE.Server.AUCd.make_3g_vector(self.UE.IMSI, self.GMM.AUTH_AMF, RAND)
        #
        if self.vect is None:
            # IMSI is not in the AuC db
            self._log('ERR', 'unable to get an authentication vector from AuC')
            self.rm_from_gmm_stack()
            return None
        #
        # prepare IEs
        IEs = {'IMEISVReq'  : self.GMM.AUTH_IMEI_REQ,
               'CiphAlgo'   : 0,
               'ACRef'      : 0,
               'ForceStdby' : {'Value': self.GMM.AUTH_FSTDBY},
               'RAND'       : self.vect[0],
               'CKSN'       : self.cksn}
        if self.ctx == 3:
            # msg with AUTN
            autn = self.vect[2]
            if self.GMM.AUTH_AUTN_EXT:
                autn += self.GMM.AUTH_AUTN_EXT
            IEs['AUTN'] = autn
        #
        self.set_msg(8, 18, **IEs)
        self.encode_msg(8, 18)
        # log the NAS msg
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        #
        self.init_timer()
        # send it over RANAP
        return self._nas_tx
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        if pdu['Type']() == 19:
            return self._process_resp()
        else:
            return self._process_fail()
    
    def _process_resp(self):
        # check if the whole UE response is corresponding to the expected one
        if self.ctx == 3:
            # 3G auth context
            res = self.UEInfo['RES']
            if 'RESExt' in self.UEInfo:
                res += self.UEInfo['RESExt']
            if res != self.vect[1]:
                # incorrect response from the UE: auth reject
                self._log('WNG', '3G authentication reject, XRES %s, RES %s'\
                          % (hexlify(self.vect[1]).decode('ascii'),
                             hexlify(res).decode('ascii'))) 
                self.encode_msg(8, 20)
                rej = True
            else:
                self._log('DBG', '3G authentication accepted')
                rej = False
                # set a 3G security context
                self.Iu.set_sec_ctx(self.cksn, 3, self.vect)
        else:
            # 2G auth context
            if self.UEInfo['RES'] != self.vect[1]:
                # incorrect response from the UE: auth reject
                self._log('WNG', '2G authentication reject, XRES %s, RES %s'\
                          % (hexlify(self.vect[1]).decode('ascii'),
                             hexlify(self.UEInfo['RES']).decode('ascii')))
                self.encode_msg(8, 20)
                rej = True
            else:
                self._log('DBG', '2G authentication accepted')
                rej = False
                # set a 2G security context
                self.Iu.set_sec_ctx(self.cksn, 2, self.vect)
        #
        self.rm_from_gmm_stack()
        if rej:
            return self._nas_tx
        else:
            if 'IMEISV' in self.UEInfo:
                self.UE.set_ident_from_ue(NAS.IDTYPE_IMEISV, self.UEInfo['IMEISV'])
            return None
     
    def _process_fail(self):
        if self.UEInfo['GMMCause']() == 21 and 'AUTS' in self.UEInfo:
            # synch failure
            # resynchronize the SQN and if done successfully, restart an auth procedure
            ret = self.UE.Server.AUCd.synch_sqn(self.UE.IMSI, self.vect[0], self.UEInfo['AUTS'])
            if ret is None:
                # something did not work
                self._log('ERR', 'unable to resynchronize SQN in AuC')
                self.encode_msg(8, 20)
                self.rm_from_gmm_stack()
                return self._nas_tx
            #
            elif ret:
                # USIM did not authenticate correctly
                self._log('WNG', 'USIM authentication failed for resynch')
                self.encode_msg(8, 20)
                self.rm_from_gmm_stack()
                return self._nas_tx
            #
            else:
                # resynch OK
                self._log('INF', 'USIM SQN resynchronization done')
                self.rm_from_gmm_stack()
                # restart a new auth procedure
                NasProc = self.GMM.init_proc(GMMAuthenticationCiphering)
                return NasProc.output()
        #
        else:
            # UE refused our auth request...
            self._log('ERR', 'UE rejected AUTN, %s' % self.UEInfo['Cause'])
            self.rm_from_gmm_stack()
            return None


class GMMIdentification(GMMSigProc):
    """Identification: TS 24.008, section 4.7.8
    
    CN-initiated
    
    CN message:
        GMMIdentityRequest (PD 8, Type 21), IEs:
        - Type1V    : ForceStdby
        - Type1V    : IDType

    UE message:
        GMMIdentityResponse (PD 8, Type 22), IEs:
        - Type4LV   : ID
    """
    
    Cont = (
        (TS24008_GMM.GMMIdentityRequest, ),
        (TS24008_GMM.GMMIdentityResponse, )
        )
    
    Timer = 'T3370'
    
    Decod = {
        (8, 22): {
            'ID': lambda x: x[1].decode(),
            }
        }
    
    def output(self):
        # build the Id Request msg, Id type has to be set by the caller
        self.set_msg(8, 21, ForceStdby={'Value': self.GMM.AUTH_FSTDBY})
        self.encode_msg(8, 21)
        # log the NAS msg
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        #
        self.init_timer()
        # send it
        return self._nas_tx
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # get the identity IE value
        idtreq = self._nas_tx['IDType']()
        #
        if self.UEInfo['ID'][0] != idtreq:
            self._log('WNG', 'identity responded not corresponding to type requested '\
                      '(%i instead of %i)' % (self.UEInfo['ID'][0], idtreq))
        self._log('INF', 'identity responded, %r' % self._nas_rx['ID'][1])
        self.UE.set_ident_from_ue(*self.UEInfo['ID'])
        #
        self.rm_from_gmm_stack()
        return None


class GMMInformation(GMMSigProc):
    """GMM information: TS 24.008, section 4.7.12
    
    CN-initiated
    
    CN message:
        GMMInformation (PD 8, Type 33), IEs:
        - Type4TLV  : NetFullName (T: 67)
        - Type4TLV  : NetShortName (T: 69)
        - Type3TV   : LocalTimeZone (T: 70)
        - Type3TV   : UnivTimeAndTimeZone (T: 71)
        - Type4TLV  : LSAIdentity (T: 72)
        - Type4TLV  : NetDLSavingTime (T: 73)

    UE message:
        None
    """
    
    Cont = (
        (TS24008_GMM.GMMInformation, ),
        None
        )


class GMMServiceRequest(GMMSigProc):
    """Service request: TS 24.008, section 4.7.13
    
    UE-initiated
    
    CN messages:
        GMMServiceAccept (PD 8, Type 13), IEs:
        - Type4TLV  : PDPCtxtStat (T: 50)
        - Type4TLV  : MBMSCtxtStat (T: 53)
    
        GMMServiceReject (PD 8, Type 14), IEs:
        - Type2     : GMMCause
        - Type4TLV  : T3346 (T: 58)
    
    UE message:
        GMMServiceRequest (PD 8, Type 12), IEs:
        - Type1V    : ServiceType
        - Type1V    : CKSN
        - Type4LV   : PTMSI
        - Type4TLV  : PDPCtxtStat (T: 50)
        - Type4TLV  : MBMSCtxtStat (T: 53)
        - Type4TLV  : ULDataStat (T: 54)
        - Type1TV   : DeviceProp (T: 13)
    """
    
    Cont = (
        (TS24008_GMM.GMMServiceAccept, TS24008_GMM.GMMServiceReject),
        (TS24008_GMM.GMMServiceRequest, )
        )


# filter_init=1, indicates we are the core network side
GMMAttach.init(filter_init=1)
GMMDetachUE.init(filter_init=1)
GMMDetachCN.init(filter_init=1)
GMMRoutingAreaUpdating.init(filter_init=1)
GMMPTMSIReallocation.init(filter_init=1)
GMMAuthenticationCiphering.init(filter_init=1)
GMMIdentification.init(filter_init=1)
GMMInformation.init(filter_init=1)
GMMServiceRequest.init(filter_init=1)

# GMM UE-initiated procedures dispatcher
GMMProcUeDispatcher = {
    1 : GMMAttach,
    5 : GMMDetachUE,
    8 : GMMRoutingAreaUpdating,
    12: GMMServiceRequest
    }

# GMM CN-initiated procedures dispatcher
GMMProcCnDispatcher = {
    5 : GMMDetachCN,
    16: GMMPTMSIReallocation,
    18: GMMAuthenticationCiphering,
    21: GMMIdentification,
    33: GMMInformation,
    }

