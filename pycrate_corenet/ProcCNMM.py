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
# * File Name : pycrate_corenet/ProcCNMM.py
# * Created : 2017-07-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'MMSigProc',
    'MMIMSIDetach',
    'MMLocationUpdating',
    'MMCMForcedRelease',
    'MMConnectionEstablishment',
    'MMCMCallReestablishment',
    'RRPagingResponse',
    'MMAuthentication',
    'MMIdentification',
    'MMTMSIReallocation',
    'MMMOCMActivity',
    'MMAbort',
    'MMInformation',
    #
    'MMProcUeDispatcher',
    'MMProcUeDispatcherStr',
    'MMProcCnDispatcher',
    'MMProcCnDispatcherStr'
    ]

from .utils       import *
from .ProcProto   import *
from .ProcCNRanap import *


TESTING = False

#------------------------------------------------------------------------------#
# NAS Mobility Management signalling procedures
# TS 24.008, version d90
# Core Network side
#------------------------------------------------------------------------------#

class MMSigProc(NASSigProc):
    """Mobility Management signalling procedure handler
    
    instance attributes:
        - Name : procedure name
        - MM   : reference to the UEMMd instance running this procedure
        - Iu   : reference to the IuCSd instance connecting the UE
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
            log('[TESTING] [%s] [MMSigProc] [%s] %s' % (logtype, self.Name, msg))
    
    else:
        def __init__(self, mmd, encod=None, mm_preempt=False):
            self._prepare(encod)
            self.MM = mmd
            self.Iu = mmd.Iu
            self.UE = mmd.UE
            self._mm_preempt = mm_preempt
            if mm_preempt:
                # preempt the MM stack
                self.MM.ready.clear()
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            self.MM._log(logtype, '[%s] %s' % (self.Name, msg))
    
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
        return []
    
    def abort(self):
        # abort this procedure, and all procedures started within this one
        ind = self.MM.Proc.index(self)
        if ind >= 0:
            for p in self.MM.Proc[ind+1:]:
                p.abort()
            del self.MM.Proc[ind:]
        if self._mm_preempt:
            # release the MM stack
            self.MM.ready.set()
        self._log('INF', 'aborting')
    
    def rm_from_mm_stack(self):
        # remove the procedure from the MM stack of procedures
        try:
            if self.MM.Proc[-1] == self:
                del self.MM.Proc[-1]
        except Exception:
            self._log('WNG', 'MM stack corrupted')
        else:
            if self._mm_preempt:
                # release the MM stack
                self.MM.ready.set()
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.MM, self.Timer, self.TimerDefault)
            self.TimerStart = time()
            self.TimerStop  = self.TimerStart + self.TimerValue
    
    def get_timer(self):
        if self.Timer is None:
            return None
        else:
            return getattr(self.MM, self.Timer)
    
    def mm_preempt(self):
        self._mm_preempt = True
        self.MM.ready.clear()
    
    #--------------------------------------------------------------------------#
    # common helpers
    #--------------------------------------------------------------------------#
    
    def _collect_cap(self):
        if not hasattr(self, 'Cap') or not hasattr(self, 'UEInfo'):
            return
        for Cap in self.Cap:
            if Cap in self.UEInfo:
                self.UE.Cap[Cap] = self.UEInfo[Cap]
    
    def _chk_imsi(self):
        # arriving here means the UE's IMSI was unknown at first
        Server, imsi = self.UE.Server, self.UE.IMSI
        if not Server.is_imsi_allowed(imsi):
            self.errcause = self.MM.IDENT_IMSI_NOT_ALLOWED
            return False
        else:
            # update the TMSI table
            Server.TMSI[self.UE.TMSI] = imsi
            #
            if imsi in Server.UE:
                # in the meantime, IMSI was obtained from the PS domain connection
                if self.UE != Server.UE[imsi]:
                    # there is 2 distincts Iu contexts, that need to be merged
                    ue = Server.UE[imsi]
                    if not ue.merge_cs_handler(self.Iu):
                        # unable to merge to the existing profile
                        self._log('WNG', 'profile for IMSI %s already exists, '\
                                  'need to reject for reconnection' % imsi)
                        # reject so that it will reconnect
                        # and get the already existing profile
                        self.errcause = self.MM.LU_IMSI_PROV_REJECT
                        return False
                    else:
                        return True
                else:
                    return True
            else:
                # update the Server UE's tables
                Server.UE[imsi] = self.UE
                if imsi in Server.ConfigUE:
                    # update UE's config with it's dedicated config
                    self.UE.set_config( Server.ConfigUE[imsi] )
                else:
                    self.UE.set_config( Server.ConfigUE['*'] )
                return True
    
    def _ret_req_imsi(self):
        NasProc = self.MM.init_proc(MMIdentification)
        NasProc.set_msg(5, 24, IDType=NAS.IDTYPE_IMSI)
        return NasProc.output()
    
    def _ret_req_imei(self):
        NasProc = self.MM.init_proc(MMIdentification)
        NasProc.set_msg(5, 24, IDType=NAS.IDTYPE_IMEI)
        return NasProc.output()
    
    def _ret_auth(self):
        NasProc = self.MM.init_proc(MMAuthentication)
        return NasProc.output()
    
    def _ret_smc(self, cksn=None, newkey=False):
        # initialize a RANAP SMC procedure
        RanapProc = self.Iu.init_ranap_proc(RANAPSecurityModeControl,
                                            **self.Iu.get_smc_ies(cksn, newkey))
        if RanapProc:
            # and set a callback to self in it
            RanapProc._cb = self
            return [RanapProc]
        else:
            return []


#------------------------------------------------------------------------------#
# MM common procedures: TS 24.008, section 4.3
#------------------------------------------------------------------------------#

class MMTMSIReallocation(MMSigProc):
    """TMSI reallocation: TS 24.008, section 4.3.1
    
    MM common procedure
    CN-initiated
    
    CN message:
        MMTMSIReallocationCommand (PD 5, Type 26), IEs:
        - Type3V    : LAI
        - Type4LV   : ID
    
    UE message:
        MMTMSIReallocationComplete (PD 5, Type 27), IEs:
          None
    """
    
    Cont = (
        (TS24008_MM.MMTMSIReallocationCommand, ),
        (TS24008_MM.MMTMSIReallocationComplete, )
        )
    
    Init  = (5, 26)
    Timer = 'T3250'
    
    def output(self, embedded=False):
        # embedded=True is used to embed this procedure within a LUR
        # hence the output message is not built, only the .tmsi is available
        # but the procedure still runs and waits for the UE response 
        # after all
        # Warning, when the TMSI IE is set by hand, it is not taken into account
        # by MM procedures
        if 'ID' not in self.Encod[self.Init]:
            self.tmsi = self.UE.get_new_tmsi()
            self.set_msg(5, 26, LAI={'PLMN': self.UE.PLMN, 'LAC': self.UE.LAC},
                                ID={'type': NAS.IDTYPE_TMSI, 'ident': self.tmsi})
        else:
            self.tmsi = None
            self.set_msg(5, 26, LAI={'PLMN': self.UE.PLMN, 'LAC': self.UE.LAC})
        #
        if not embedded:
            self.encode_msg(5, 26)
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            self.init_timer()
            return self.Iu.ret_ranap_dt(self._nas_tx)
        else:
            self.init_timer()
            return []
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # just take the new tmsi in use
        if self.tmsi is not None:
            self.UE.set_tmsi(self.tmsi)
            self._log('INF', 'new TMSI set, 0x%.8x' % self.tmsi)
        else:
            self._log('WNG', 'handcrafted TMSI sent, not updating the local TMSI')
        self.rm_from_mm_stack()
        return []


class MMAuthentication(MMSigProc):
    """Authentication: TS 24.008, section 4.3.2
    
    MM common procedure
    CN-initiated
    
    CN message:
        MMAuthenticationRequest (PD 5, Type 18), IEs:
        - Type1V    : spare
        - Type1V    : CKSN
        - Type3V    : RAND
        - Type4TLV  : AUTN (T: 32)
        
        MMAuthenticationReject (PD 5, Type 17), IEs:
          None
    
    UE message:
        MMAuthenticationResponse (PD 5, Type 20), IEs:
        - Type3V    : RES
        - Type4TLV  : RESExt (T: 33)

        MMAuthenticationFailure (PD 5, Type 28), IEs:
        - Type3V    : RejectCause
        - Type4TLV  : AUTS (T: 34)
    """
    
    Cont = (
        (TS24008_MM.MMAuthenticationRequest,
         TS24008_MM.MMAuthenticationReject),
        (TS24008_MM.MMAuthenticationResponse,
         TS24008_MM.MMAuthenticationFailure)
        )
    
    Decod = {
        (5, 20): {
            'RES'    : lambda x: x[0].get_val(),
            'RESExt' : lambda x: x[2].get_val()
            },
        (5, 28): {
            'AUTS'   : lambda x: x[2].get_val()
            }
        }
    
    Init  = (5, 18)
    Timer = 'T3260'
    
    def output(self):
        # get a new CKSN
        self.cksn = self.Iu.get_new_cksn()
        #
        EncodReq = self.Encod[self.Init]
        # in case CKSN is handcrafted, just warn (will certainly fail)
        if 'CKSN' in EncodReq:
            self._log('WNG', 'handcrafted CKSN (%r), generated CKSN (%i)'\
                      % (EncodReq['CKSN'], self.cksn))
        # in case RAND is handcrafted, we use it for generating the auth vector
        if 'RAND' in EncodReq:
            RAND = EncodReq['RAND']
        else:
            RAND = None
        #
        if not self.UE.USIM or self.MM.AUTH_2G:
            # 2G authentication
            self.ctx = 2
            self.vect = self.UE.Server.AUCd.make_2g_vector(self.UE.IMSI, RAND)
        else:
            # 3G authentication
            self.ctx = 3
            self.vect = self.UE.Server.AUCd.make_3g_vector(self.UE.IMSI, self.MM.AUTH_AMF, RAND)
        #
        if self.vect is None:
            # IMSI is not in the AuC db
            self._log('ERR', 'unable to get an authentication vector from AuC')
            self.rm_from_mm_stack()
            return []
        #
        if self.ctx == 2:
            # msg without AUTN
            self.set_msg(5, 18, CKSN=self.cksn, RAND=self.vect[0])
        else:
            # msg with AUTN
            autn = self.vect[2]
            if self.MM.AUTH_AUTN_EXT:
                autn += self.MM.AUTH_AUTN_EXT
            self.set_msg(5, 18, CKSN=self.cksn, RAND=self.vect[0], AUTN=autn)
        #
        self.encode_msg(5, 18)
        # log the NAS msg
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        #
        self.init_timer()
        # send it over RANAP
        return self.Iu.ret_ranap_dt(self._nas_tx)
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        # in case a SQN resynch just happened, remove the indicator
        if hasattr(self.MM, '_auth_resynch'):
            del self.MM._auth_resynch
        #
        if pdu[0]['Type'].get_val() == 20:
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
                self.encode_msg(5, 17)
                self.success = False
            else:
                self._log('DBG', '3G authentication accepted')
                self.success = True
                # set a 3G security context
                self.Iu.set_sec_ctx(self.cksn, 3, self.vect)
        else:
            # 2G auth context
            if self.UEInfo['RES'] != self.vect[1]:
                # incorrect response from the UE: auth reject
                self._log('WNG', '2G authentication reject, XRES %s, RES %s'\
                          % (hexlify(self.vect[1]).decode('ascii'),
                             hexlify(self.UEInfo['RES']).decode('ascii')))
                self.encode_msg(5, 17)
                self.success = False
            else:
                self._log('DBG', '2G authentication accepted')
                self.success = True
                # set a 2G security context
                self.Iu.set_sec_ctx(self.cksn, 2, self.vect)
        #
        self.rm_from_mm_stack()
        if not self.success:
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            return self.Iu.ret_ranap_dt(self._nas_tx)
        else:
            return []
     
    def _process_fail(self):
        self.success = False
        if self.UEInfo['RejectCause'].get_val() == 21 and 'AUTS' in self.UEInfo:
            # synch failure: resynchronize the SQN
            # set an indicator to avoid the PS stack to do another resynch 
            self.MM._auth_resynch = True
            ret = self.UE.Server.AUCd.synch_sqn(self.UE.IMSI, self.vect[0], self.UEInfo['AUTS'])
            if ret is None:
                # something did not work
                self._log('ERR', 'unable to resynchronize SQN in AuC')
                self.encode_msg(5, 17)
                self.rm_from_mm_stack()
                if self.TRACK_PDU:
                    self._pdu.append( (time(), 'DL', self._nas_tx) )
                return self.Iu.ret_ranap_dt(self._nas_tx)
            #
            elif ret:
                # USIM did not authenticate correctly
                self._log('WNG', 'USIM authentication failed for resynch')
                self.encode_msg(5, 17)
                self.rm_from_mm_stack()
                if self.TRACK_PDU:
                    self._pdu.append( (time(), 'DL', self._nas_tx) )
                return self.Iu.ret_ranap_dt(self._nas_tx)
            #
            else:
                # resynch OK: restart an auth procedure
                self._log('INF', 'USIM SQN resynchronization done')
                self.rm_from_mm_stack()
                # restart a new auth procedure
                NasProc = self.MM.init_proc(MMAuthentication)
                return NasProc.output()
        #
        else:
            # UE refused our auth request...
            self._log('ERR', 'UE rejected AUTN, %s' % self.UEInfo['RejectCause'])
            self.rm_from_mm_stack()
            return []


class MMIdentification(MMSigProc):
    """Identification: TS 24.008, section 4.3.3
    
    MM common procedure
    CN-initiated
    
    CN message:
        MMIdentityRequest (PD 5, Type 24), IEs:
        - Type1V    : spare
        - Type1V    : IDType
    
    UE message:
        MMIdentityResponse (PD 5, Type 25), IEs:
        - Type4LV   : ID
        - Type1TV   : PTMSIType (T: 14)
        - Type4TLV  : RAI (T: 27)
        - Type4TLV  : PTMSISign (T: 25)
    """
    
    Cont = (
        (TS24008_MM.MMIdentityRequest, ),
        (TS24008_MM.MMIdentityResponse, )
        )
    
    Decod = {
        (5, 25): {
            'ID'        : lambda x: x[1].decode(),
            'PTMSIType' : lambda x: x[1].get_val(),
            'RAI'       : lambda x: x[2].decode()
            }
        }
    
    Init  = (5, 24)
    Timer = 'T3270'
    
    def output(self):
        # build the Id Request msg, Id type has to be set by the caller
        self.encode_msg(5, 24)
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.init_timer()
        return self.Iu.ret_ranap_dt(self._nas_tx)
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # get the identity IE value
        self.IDType = self._nas_tx['IDType'][0].get_val()
        #
        if self.UEInfo['ID'][0] != self.IDType:
            self._log('WNG', 'identity responded not corresponding to type requested '\
                      '(%i instead of %i)' % (self.UEInfo['ID'][0], self.IDType))
        self._log('INF', 'identity responded, %r' % self._nas_rx['ID'][1])
        self.UE.set_ident_from_ue(*self.UEInfo['ID'], dom='CS')
        #
        self.rm_from_mm_stack()
        return []


class MMIMSIDetach(MMSigProc):
    """IMSI detach: TS 24.008, section 4.3.4
    
    MM common procedure
    UE-initiated
    
    CN message:
        None
    
    UE message:
        MMIMSIDetachIndication (PD 5, Type 1), IEs:
        - Type3V    : MSCm1
        - Type4LV   : ID
    """
    
    Cont = (
        None,
        (TS24008_MM.MMIMSIDetachIndication, )
        )
    
    Decod = {
        (5, 1): {
            'ID' : lambda x: x[1].decode(),
            }
        }
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        # in case of PS connectivity established, need to clear it too
        if self.UE.IuPS is not None:
            self.UE.IuPS.clear_nas_proc()
            self.UE.IuPS.GMM.state = 'INACTIVE'
        #
        # abort all ongoing CS procedures
        self.rm_from_mm_stack()
        self.Iu.clear_nas_proc()
        # set MM state
        self.MM.state = 'INACTIVE'
        #
        self._log('INF', 'detaching')
        # set a RANAP callback to trigger an Iu release
        # with Cause NAS normal-release (83)
        RanapProc = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=('nAS', 83))
        if RanapProc:
            return [RanapProc]
        else:
            return []


class MMAbort(MMSigProc):
    """Abort: TS 24.008, section 4.3.5
    
    MM common procedure
    CN-initiated
    
    CN message:
        MMAbort (PD 5, Type 41), IEs:
        - Type3V    : RejectCause
    
    UE message:
        None
    """
    
    Cont = (
        (TS24008_MM.MMAbort, ),
        None
        )
    
    Init = (5, 41)
    
    def output(self):
        # build the Abort msg, Cause has to be set by the caller
        self.encode_msg(5, 41)
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.rm_from_mm_stack()
        return self.Iu.ret_ranap_dt(self._nas_tx)


class MMInformation(MMSigProc):
    """MM information: TS 24.008, section 4.3.6
    
    MM common procedure
    CN-initiated
    
    CN message:
        MMInformation (PD 5, Type 50), IEs:
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
        (TS24008_MM.MMInformation, ),
        None
        )
    
    Init = (5, 50)
    
    def output(self):
        # build the Information msg, network name and/or time info
        # have to be set by the caller
        self.encode_msg(5, 50)
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self._log('INF', '%r' % self.Encod[(5, 50)])
        self.rm_from_mm_stack()
        return self.Iu.ret_ranap_dt(self._nas_tx)


#------------------------------------------------------------------------------#
# MM specific procedures: TS 24.008, section 4.4
#------------------------------------------------------------------------------#

class MMLocationUpdating(MMSigProc):
    """Location updating: TS 24.008, section 4.4.1 to 4.4.4
    
    MM specific procedure
    UE-initiated
    
    CN message:
        MMLocationUpdatingAccept (PD 5, Type 2), IEs:
        - Type3V    : LAI
        - Type4TLV  : ID (T: 23)
        - Type2     : FollowOnProceed (T: 161)
        - Type2     : CTSPerm (T: 162)
        - Type4TLV  : EquivPLMNList (T: 74)
        - Type4TLV  : EmergNumList (T: 52)
        - Type4TLV  : MST3212 (T: 53)

        MMLocationUpdatingReject (PD 5, Type 4), IEs:
        - Type3V    : RejectCause
        - Type4TLV  : T3246 (T: 54)
    
    UE message:
        MMLocationUpdatingRequest (PD 5, Type 8), IEs:
        - Type1V    : CKSN
        - Type1V    : LocUpdateType
        - Type3V    : LAI
        - Type3V    : MSCm1
        - Type4LV   : ID
        - Type4TLV  : MSCm2 (T: 51)
        - Type1TV   : AddUpdateParams (T: 12)
        - Type1TV   : DeviceProp (T: 13)
        - Type1TV   : MSNetFeatSupp (T: 14)
    """
    
    Cont = (
        (TS24008_MM.MMLocationUpdatingAccept, TS24008_MM.MMLocationUpdatingReject),
        (TS24008_MM.MMLocationUpdatingRequest, )
        )
    
    Decod = {
        (5, 8): {
            'CKSN' : lambda x: x[0].get_val(),
            'LAI'  : lambda x: x[0].decode(),
            'ID'   : lambda x: x[1].decode(),
            }
        }
    
    Cap = ('MSCm1', 'MSCm2", "AddUpdateParams', 'DeviceProp', 'MSNetFeatSupp')
    
    def process(self, pdu):
        # got an MMLocationUpdatingRequest
        # preempt the MM stack
        self.mm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.errcause, self.UEInfo = None, {}
        self.decode_msg(pdu, self.UEInfo)
        #
        if self.UEInfo['ID'][0] == NAS.IDTYPE_TMSI and self.UE.TMSI is None:
            self.UE.TMSI = self.UEInfo['ID'][1]
        #
        lu_type = self.UEInfo['LocUpdateType']['Type']#
        self._log('INF', 'request type %i (%s) from LAI %s.%.4x'\
                  % (lu_type(), lu_type._dic[lu_type()],
                     self.UEInfo['LAI'][0], self.UEInfo['LAI'][1]))
        # collect capabilities
        self._collect_cap()
        #
        if self.UE.IMEI is None and self.MM.IDENT_IMEI_REQ:
            self._req_imei = True
        else:
            self._req_imei = False
        #
        # check local ID
        if self.UE.IMSI is None:
            # UEd was created based on a TMSI provided at the RRC layer
            # -> we need to get its IMSI before continuing
            # we remove it from the Server's provisory dict of UE
            try:
                del self.UE.Server._UEpre[self.UE.TMSI]
            except Exception:
                pass
            #
            if self.UEInfo['ID'][0] == 1:
                # IMSI is provided at the NAS layer
                self.UE.set_ident_from_ue(*self.UEInfo['ID'], dom='CS')
                if not self._chk_imsi():
                    # IMSI not allowed
                    return self.output()
            else:
                return self._ret_req_imsi()
        #
        elif self.Iu.require_auth(self, cksn=self.UEInfo['CKSN']):
            return self._ret_auth()
        #
        elif self.Iu.require_smc(self):
            # if we are here, there was no auth procedure,
            # hence the cksn submitted by the UE is considered valid
            return self._ret_smc(self.UEInfo['CKSN'], False)
        #
        elif self._req_imei:
            return self._ret_req_imei()
        #
        # otherwise, go directly to postprocess
        return self.postprocess()
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, MMIdentification):
            if Proc.IDType == NAS.IDTYPE_IMSI:
                # got the UE's IMSI, check if it's allowed
                if self.UE.IMSI is None:
                    # UE did actually not responded with its IMSI, this is bad !
                    # error 96: invalid mandatory info
                    self.errcause = 96
                    return self.output()
                elif not self._chk_imsi():
                    return self.output()
                elif self.Iu.require_auth(self):
                    return self._ret_auth()
                elif self.Iu.require_smc(self):
                    # if we are here, there was no auth procedure,
                    # hence the cksn submitted by the UE is considered valid
                    return self._ret_smc(self.UEInfo['CKSN'], False)
                elif self._req_imei:
                    return self._ret_req_imei()
            elif Proc.IDType in (NAS.IDTYPE_IMEI, NAS.IDTYPE_IMEISV):
                # got the UE's IMEI, check if it is allowed
                if self.UE.IMEI is None or \
                not self.UE.Server.is_imei_allowed(self.UE.IMEI):
                    self.errcause = self.MM.IDENT_IMEI_NOT_ALLOWED
                    return self.output()
        #
        elif isinstance(Proc, MMAuthentication):
            if not Proc.success:
                self.abort()
                return []
            elif self.Iu.require_smc(self):
                # if we are here, the valid cksn is the one established during
                # the auth procedure
                return self._ret_smc(Proc.cksn, True)
            elif self._req_imei:
                return self._ret_req_imei()
        #
        elif isinstance(Proc, RANAPSecurityModeControl):
            if not Proc.success:
                self.abort()
                return self._end()
            # self.Iu.SEC['CKSN'] has been taken into use at the RRC layer
            elif self._req_imei:
                return self._ret_req_imei()
        #
        elif isinstance(Proc, MMTMSIReallocation):
            # everything went fine, end of the procedure
            return self._end()
        #
        elif Proc == self:
            # something bad happened with one of the MM common procedure
            pass
        #
        elif Proc is not None:
            self._err = Proc
            assert()
        #
        return self.output()
    
    def output(self):
        if self.errcause:
            # prepare LUReject IE
            if self.errcause == self.MM.LU_IMSI_PROV_REJECT:
                self.set_msg(5, 4, Cause=self.errcause, T3246=self.MM.LU_T3246)
            else:
                self.set_msg(5, 4, Cause=self.errcause)
            self.encode_msg(5, 4)
            self.tmsi_realloc = False
            self._log('INF', 'reject, %r' % self._nas_tx['RejectCause'][0])
        else:
            # prepare LUAccept IEs
            IEs = {'LAI': {'PLMN': self.UE.PLMN, 'LAC': self.UE.LAC}}
            # in case we want to realloc a TMSI, we start a TMSIRealloc,
            # but don't forward its output
            if self.MM.LU_TMSI_REALLOC:
                NasProc = self.MM.init_proc(MMTMSIReallocation)
                NasProc.output(embedded=True)
                if NasProc.tmsi is not None:
                    IEs['ID'] = {'type': NAS.IDTYPE_TMSI, 'ident': NasProc.tmsi}
                    self.tmsi_realloc = True
                else:
                    self.tmsi_realloc = False
            else:
                self.tmsi_realloc = False
            #
            # follow on proceed
            if self.MM.LU_FOP:
                IEs['FollowOnProceed'] = None
            if self.Iu.Config['EquivPLMNList'] is not None:
                IEs['EquivPLMNList'] = self.Iu.Config['EquivPLMNList']
            if isinstance(self.Iu.Config['EmergNumList'], bytes_types):
                IEs['EmergNumList'] = self.Iu.Config['EmergNumList']
            elif self.Iu.Config['EmergNumList'] is not None:
                IEs['EmergNumList'] = [{'ServiceCat': {c:1 for c in cat}, 'Num': num} for \
                                       (cat, num) in self.Iu.Config['EmergNumList']]
            if self.MM.LU_T3212 is not None:
                IEs['MST3212'] = self.MM.LU_T3212
            #
            # encode the msg with all its IEs
            self.set_msg(5, 2, **IEs)
            self.encode_msg(5, 2)
        #
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        ret = self.Iu.ret_ranap_dt(self._nas_tx)
        if not self.tmsi_realloc:
            ret.extend( self._end() )
        return ret
    
    def _end(self):
        ret = []
        if self.MM.LU_IUREL and \
        (self.errcause or not self.UEInfo['LocUpdateType']['FollowOnReq'].get_val()):
            # trigger an IuRelease with Cause NAS normal-release (83)
            RanapProcRel = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=('nAS', 83))
            if RanapProcRel:
                ret.append(RanapProcRel)
        self.rm_from_mm_stack()
        return ret


class RRPagingResponse(MMSigProc):
    """MM connection establishment initiated by the network: 
    TS 24.008, section 4.5.1.3
    
    Custom procedure for handling the Paging Response sent by the UE, 
    forwarded up to the core network in the CS domain
    UE-initiated
    
    CN message:
        None
    
    UE message:
        RRPagingResponse (PD 6, Type 39), IEs:
        - Type1V    : spare
        - Type1V    : CKSN
        - Type4LV   : MSCm2
        - Type4LV   : ID
        - Type1TV   : AddUpdateParams (T: 12)
    """
    
    Decod = {
        (6, 39): {
            'CKSN' : lambda x: x[0].get_val(),
            'ID'   : lambda x: x[1].decode(),
            }
        }
    
    Cap = ('MSCm2", "AddUpdateParams') 
    
    def process(self, pdu):
        # preempt the MM stack
        self.mm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        #
        if self.Iu.require_auth(self, cksn=self.UEInfo['CKSN']):
            return self._ret_auth()
        #
        elif self.Iu.require_smc(self):
            # if we are here, there was no auth procedure,
            # hence the cksn submitted by the UE is considered valid
            return self._ret_smc(self.UEInfo['CKSN'], False)
        #
        return self.postprocess()
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, MMAuthentication):
            if not Proc.success:
                self.abort()
                return []
            elif self.Iu.require_smc(self):
                # if we are here, the valid cksn is the one established during
                # the auth procedure
                return self._ret_smc(Proc.cksn, True)
        elif isinstance(Proc, RANAPSecurityModeControl):
            if not Proc.success:
                self.abort()
                return []
            # self.Iu.SEC['CKSN'] has been taken into use at the RRC layer
        elif Proc == self:
            # something bad happened with one of the MM common procedure
            pass
        elif Proc is not None:
            self._err = Proc
            assert()
        #
        self.rm_from_mm_stack()
        return []


#------------------------------------------------------------------------------#
# Connection management oriented MM proceudres: TS 24.008, section 4.5
#------------------------------------------------------------------------------#

class MMConnectionEstablishment(MMSigProc):
    """MM connection establishment: TS 24.008, section 4.5.1
    
    Connection-oriented procedure
    UE-initiated
    
    CN message:
        MMCMServiceAccept (PD 5, Type 33), IEs:
          None

        MMCMServiceReject (PD 5, Type 34), IEs:
        - Type3V    : RejectCause
        - Type4TLV  : T3246 (T: 54)
    
    UE message:
        MMCMServiceRequest (PD 5, Type 36), IEs:
        - Type1V    : CKSN
        - Type1V    : Service
        - Type4LV   : MSCm2
        - Type4LV   : ID
        - Type1TV   : Priority (T: 8)
        - Type1TV   : AddUpdateParams (T: 12)
        - Type1TV   : DeviceProp (T: 13)
    """
    
    Cont = (
        (TS24008_MM.MMCMServiceAccept, TS24008_MM.MMCMServiceReject),
        (TS24008_MM.MMCMServiceRequest, )
        )
    
    Decod = {
        (5, 36): {
            'CKSN' : lambda x: x[0].get_val(),
            'ID'   : lambda x: x[1].decode(),
            }
        }
    
    Cap = ('MSCm2", "AddUpdateParams', 'DeviceProp') 
    
    def process(self, pdu):
        # preempt the MM stack
        self.mm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.errcause, self.UEInfo, self._smc = None, {}, False
        self.decode_msg(pdu, self.UEInfo)
        #
        if self.Iu.require_auth(self, cksn=self.UEInfo['CKSN']):
            return self._ret_auth()
        #
        elif self.Iu.require_smc(self):
            # if we are here, there was no auth procedure,
            # hence the cksn submitted by the UE is considered valid
            return self._ret_smc(self.UEInfo['CKSN'], False)
        #
        return self.postprocess()
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, MMAuthentication):
            if not Proc.success:
                self.abort()
                return []
            elif self.Iu.require_smc(self):
                # if we are here, the valid cksn is the one established during
                # the auth procedure
                return self._ret_smc(Proc.cksn, True)
        elif isinstance(Proc, RANAPSecurityModeControl):
            if not Proc.success:
                self.abort()
                return []
            else:
                self._smc = True
            # self.Iu.SEC['CKSN'] has been taken into use at the RRC layer
        elif Proc == self:
            # something bad happened with one of the MM common procedure
            pass
        elif Proc is not None:
            self._err = Proc
            assert()
        #
        return self.output()
    
    def output(self):
        serv = self.UEInfo['Service'].get_val()
        if serv in self.MM.CON_REJ:
            self.errcause = self.MM.CON_REJ[serv]
            if self.MM.CON_T3246:
                self.set_msg(5, 34, Cause=self.errcause, T3246=self.MM.CON_T3246)
            else:
                self.set_msg(5, 34, Cause=self.errcause)
            self.encode_msg(5, 34)
            self._log('INF', 'reject, %r, on request %r'\
                      % (self._nas_tx['RejectCause'][0], self.UEInfo['Service']))
        else:
            if not self._smc:
                # in case an SMC has been completed, no need to accept explicitely
                self.encode_msg(5, 33)
            if 'Priority' in self.UEInfo:
                self._log('INF', 'accept, request %r / %r'\
                          % (self.UEInfo['Service'], self.UEInfo['Priority']))
            else:
                self._log('INF', 'accept, request %r' % self.UEInfo['Service'])
        #
        if self._nas_tx:
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            ret = self.Iu.ret_ranap_dt(self._nas_tx)
        else:
            ret = []
        ret.extend( self._end() )
        return ret
    
    def _end(self):
        ret = []
        if self.MM.CON_IUREL and self.errcause:
            # trigger an IuRelease with Cause NAS normal-release (83)
            RanapProcRel = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=('nAS', 83))
            if RanapProcRel:
                ret.append(RanapProcRel)
        self.rm_from_mm_stack()
        return ret


class MMMOCMActivity(MMSigProc):
    """Mobile Originating CM Activity $(CCBS)$: TS 24.008, section 4.5.1.3.2
    
    Connection-oriented procedure
    CN-initiated
    
    CN message:
        MMCMServicePrompt (PD 5, Type 37), IEs:
        - Type1V    : SAPI
        - Type1V    : PD
    
    UE message:
        None
    """
    
    Cont = (
        (TS24008_MM.MMCMServicePrompt, ),
        None
        )
    
    Init = (5, 37)
    
    def output(self):
        self.encode_msg(5, 37)
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.rm_from_mm_stack()
        return self.Iu.ret_ranap_dt(self._nas_tx)


class MMCMCallReestablishment(MMSigProc):
    """Call re-establishment: TS 24.008, section 4.5.1.6
    
    Connection-oriented procedure
    UE-initiated
    
    CN message:
        MMCMServiceAccept (PD 5, Type 33), IEs:
          None

        MMCMServiceReject (PD 5, Type 34), IEs:
        - Type3V    : RejectCause
        - Type4TLV  : T3246 (T: 54)
    
    UE message:
        MMCMReestablishmentRequest (PD 5, Type 40), IEs:
        - Type1V    : spare
        - Type1V    : CKSN
        - Type4LV   : MSCm2
        - Type4LV   : ID
        - Type3TV   : LAI (T: 19)
        - Type1TV   : DeviceProp (T: 13)
    """
    
    Cont = (
        (TS24008_MM.MMCMServiceAccept, TS24008_MM.MMCMServiceReject),
        (TS24008_MM.MMCMReestablishmentRequest, )
        )
    
    def process(self, pdu):
        # preempt the MM stack
        self.mm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.errcause, self.UEInfo = None, {}
        self.decode_msg(pdu, self.UEInfo)
        # TODO: should return at least an MMServiceReject
        
        self.rm_from_mm_stack()
        return []


class MMCMForcedRelease(MMSigProc):
    """Forced release during MO MM connection establishment: TS 24.008, section 4.5.1.7
    
    Connection-oriented procedure
    UE-initiated
    
    CN message:
        None
    
    UE message:
        MMCMServiceAbort (PD 5, Type 35), IEs:
          None
    """
    
    Cont = (
        None,
        (TS24008_MM.MMCMServiceAbort, )
        )
    
    def process(self, pdu):
        # preempt the MM stack
        self.mm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # TODO
        
        self.rm_from_mm_stack()
        return []


# filter_init=1, indicates we are the core network side
MMTMSIReallocation.init(filter_init=1)
MMAuthentication.init(filter_init=1)
MMIdentification.init(filter_init=1)
MMIMSIDetach.init(filter_init=1)
MMAbort.init(filter_init=1)
MMInformation.init(filter_init=1)
MMLocationUpdating.init(filter_init=1)
MMConnectionEstablishment.init(filter_init=1)
MMMOCMActivity.init(filter_init=1)
MMCMCallReestablishment.init(filter_init=1)
MMCMForcedRelease.init(filter_init=1)

# MM UE-initiated procedures dispatcher
MMProcUeDispatcher = {
    1 : MMIMSIDetach,
    8 : MMLocationUpdating,
    35: MMCMForcedRelease,
    36: MMConnectionEstablishment,
    40: MMCMCallReestablishment
    }
MMProcUeDispatcherStr = {ProcClass.Cont[1][0]()._name: ProcClass \
                         for ProcClass in MMProcUeDispatcher.values()}
MMProcUeDispatcherStr['RRPagingResponse'] = RRPagingResponse

# MM CN-initiated procedures dispatcher
MMProcCnDispatcher = {
    18: MMAuthentication,
    24: MMIdentification,
    26: MMTMSIReallocation,
    37: MMMOCMActivity,
    41: MMAbort,
    50: MMInformation
    }
MMProcCnDispatcherStr = {ProcClass.Cont[0][0]()._name: ProcClass \
                         for ProcClass in MMProcCnDispatcher.values()}

