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
# * File Name : pycrate_corenet/ProcCNMM.py
# * Created : 2017-07-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcProto   import *
from .ProcCNRanap import *


TESTING = False

#------------------------------------------------------------------------------#
# NAS Mobility Management signaling procedure
# TS 24.008, version d90
# Core Network side
#------------------------------------------------------------------------------#

class MMSigProc(NASSigProc):
    """Mobility Management signaling procedure handler
    
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
        def __init__(self, mmd, encod=None):
            self._prepare(encod)
            self.MM   = mmd
            self.Iu   = mmd.Iu
            self.UE   = mmd.UE
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            self.MM._log(logtype, '[%s] %s' % (self.Name, msg))
    
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
        ind = self.MM.Proc.index(self)
        if ind >= 0:
            for p in self.MM.Proc[ind+1:]:
                p.abort()
            del self.MM.Proc[ind:]
        self._log('INF', 'aborting')
    
    def rm_from_mm_stack(self):
        # remove the procedure from the MM stack of procedures
        if self.MM.Proc[-1] == self:
            del self.MM.Proc[-1]
    
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
    
    Timer = 'T3250'
    
    def output(self, embedded=False):
        # embedded=True is used to embed this procedure within a LUR
        # hence the output message is not built, only the .tmsi is available
        # but the procedure still runs and waits for the UE response 
        # after all
        self.tmsi = self.UE.get_new_tmsi()
        if not embedded:
            # prepare IEs
            self.set_msg(5, 26, LAI={'plmn': self.UE.PLMN, 'lac': self.UE.LAC},
                                ID={'type': NAS.IDTYPE_TMSI, 'ident': self.tmsi})
            self.encode_msg(5, 26)
            # log the NAS msg
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            #
            self.init_timer()
            # send it over RANAP
            return self._nas_tx
        else:
            self.init_timer()
            return None
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        # just take the new tmsi in use
        self.UE.set_tmsi(self.tmsi)
        self._log('INF', 'new TMSI set, %.8x' % self.tmsi)
        self.rm_from_mm_stack()
        return None


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
        - Type2     : Cause
        - Type4TLV  : AUTS (T: 34)
    """
    
    Cont = (
        (TS24008_MM.MMAuthenticationRequest,
         TS24008_MM.MMAuthenticationReject),
        (TS24008_MM.MMAuthenticationResponse,
         TS24008_MM.MMAuthenticationFailure)
        )
    
    Timer = 'T3260'
    
    Decod = {
        (5, 20): {
            'RES':      lambda x: x(),
            'RESExt':   lambda x: x['V']()
            },
        (5, 28): {
            'AUTS':     lambda x: x['V']()
            }
        }
    
    def output(self):
        # get a new CKSN
        self.cksn = self.Iu.get_new_cksn()
        # in case a RAND is configured as a class encoder, we use it for 
        # generating the auth vector
        if 'RAND' in self.__class__.Encod[(5, 18)]:
            RAND = self.__class__.Encod[(5, 18)]['RAND']
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
            return None
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
        return self._nas_tx
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        if pdu['Type']() == 20:
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
                self.encode_msg(5, 17)
                rej = True
            else:
                self._log('DBG', '2G authentication accepted')
                rej = False
                # set a 2G security context
                self.Iu.set_sec_ctx(self.cksn, 2, self.vect)
        #
        self.rm_from_mm_stack()
        if rej:
            return self._nas_tx
        else:
            return None
     
    def _process_fail(self):
        if self.UEInfo['Cause']() == 21 and 'AUTS' in self.UEInfo:
            # synch failure
            # resynchronize the SQN and if done successfully, restart an auth procedure
            ret = self.UE.Server.AUCd.synch_sqn(self.UE.IMSI, self.vect[0], self.UEInfo['AUTS'])
            if ret is None:
                # something did not work
                self._log('ERR', 'unable to resynchronize SQN in AuC')
                self.encode_msg(5, 17)
                self.rm_from_mm_stack()
                return self._nas_tx
            #
            elif ret:
                # USIM did not authenticate correctly
                self._log('WNG', 'USIM authentication failed for resynch')
                self.encode_msg(5, 17)
                self.rm_from_mm_stack()
                return self._nas_tx
            #
            else:
                # resynch OK
                self._log('INF', 'USIM SQN resynchronization done')
                self.rm_from_mm_stack()
                # restart a new auth procedure
                NasProc = self.MM.init_proc(MMAuthentication)
                return NasProc.output()
        #
        else:
            # UE refused our auth request...
            self._log('ERR', 'UE rejected AUTN, %s' % self.UEInfo['Cause'])
            self.rm_from_mm_stack()
            return None


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
    
    Timer = 'T3270'
    
    Decod = {
        (5, 25): {
            'ID': lambda x: x[1].decode(),
            }
        }
    
    def output(self):
        # build the Id Request msg, Id type has to be set by the caller
        self.encode_msg(5, 24)
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
        self.rm_from_mm_stack()
        return None


class MMIMSIDetach(MMSigProc):
    """IMSI detach: TS 24.008, section 4.3.4
    
    MM common procedure
    UE-initiated
    
    CN message:
        None
    
    UE message:
        MMIMSIDetachIndication (PD 5, Type 1), IEs:
        - Type2     : MSCm1
        - Type4LV   : ID
    """
    
    Cont = (
        None,
        (TS24008_MM.MMIMSIDetachIndication, )
        )
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        # abort all other ongoing CS procedures
        self.Iu.clear_nas_proc()
        # set MM state
        self.MM.state = 'INACTIVE'
        #
        # in case of PS connectivity established, need to clear it too
        if self.UE.IuPS is not None:
            self.UE.IuPS.clear_nas_proc()
            self.UE.IuPS.GMM.state = 'INACTIVE'
        #
        self._log('INF', 'detaching')
        # set a RANAP callback to trigger an Iu release
        # with Cause NAS normal-release (83)
        RanapProc = self.Iu.init_ranap_proc(RANAPIuRelease, Cause=('nAS', 83))
        if RanapProc:
            self.Iu.RanapTx = [RanapProc]
        return None


class MMAbort(MMSigProc):
    """Abort: TS 24.008, section 4.3.5
    
    MM common procedure
    CN-initiated
    
    CN message:
        MMAbort (PD 5, Type 41), IEs:
        - Type2     : Cause
    
    UE message:
        None
    """
    
    Cont = (
        (TS24008_MM.MMAbort, ),
        None
        )
    
    # TODO


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
    
    # TODO


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
        - Type2     : Cause
        - Type4TLV  : T3246 (T: 54)
    
    UE message:
        MMLocationUpdatingRequest (PD 5, Type 8), IEs:
        - Type1V    : CKSN
        - Type1V    : LocUpdateType
        - Type3V    : LAI
        - Type2     : MSCm1
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
            'CKSN':             lambda x: x(),
            'LAI':              lambda x: (x['PLMN'].decode(), x['LAC']()),
            #'MSCm1': lambda x: x,
            'ID':               lambda x: x[1].decode(),
            }
        }
    
    # UE capabilities to be collected
    Cap = ('MSCm1', 'MSCm2", "AddUpdateParams', 'DeviceProp', 'MSNetFeatSupp') 
    
    def process(self, pdu):
        # got an MMLocationUpdatingRequest
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.errcause, self.UEInfo = None, {}
        self.decode_msg(pdu, self.UEInfo)
        #
        lu_type = self.UEInfo['LocUpdateType']['Type']
        # collect capabilities
        self._collect_cap()
        #
        self._log('INF', 'request type %i (%s) from LAI %s.%.4x'\
                  % (lu_type(), lu_type._dic[lu_type()],
                     self.UEInfo['LAI'][0], self.UEInfo['LAI'][1]))
        #
        # check local ID
        if self.UE.IMSI is None:
            # UEd was created based on a TMSI provided at the RRC layer
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
                NasProc = self.MM.init_proc(MMIdentification)
                NasProc.set_msg(5, 24, IDType=NAS.IDTYPE_IMSI)
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
            self.errcause = self.MM.IDENT_IMSI_NOT_ALLOWED
            return False
        else:
            if imsi in Server.UE:
                # a profile already exists for this IMSI
                self._log('WNG', 'profile for IMSI %s already exists, need to reject for reconnection'\
                          % imsi)
                # update the TMSI table and reject self, so that it will reconnect
                # and get the already existing profile
                Server.TMSI[self.UE.TMSI] = imsi
                self.errcause = self.MM.LU_IMSI_PROV_REJECT
                return False
            else:
                # update the Server UE's tables
                Server.UE[imsi] = self.UE
                Server.TMSI[self.UE.TMSI] = imsi
                if imsi in Server.ConfigUE:
                    # update UE's config with it's dedicated config
                    self.UE.set_config( Server.ConfigUE[imsi] )
                return True
    
    def _ret_auth(self):
        NasProc = self.MM.init_proc(MMAuthentication)
        return NasProc.output()
    
    def _ret_smc(self, cksn=None, newkey=False):
        # set a RANAP callback in the Iu stack for triggering an SMC
        RanapProc = self.Iu.init_ranap_proc(RANAPSecurityModeControl,
                                            **self.Iu.get_smc_ies(cksn, newkey))
        RanapProc._cb = self
        if RanapProc:
            self.Iu.RanapTx = [RanapProc]
        return None
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, MMIdentification):
            # got the UE's IMSI, check if it's allowed
            if self.UE.IMSI is None or not self._set_imsi(self.UE.IMSI):
                return self.output()
            elif self.Iu.require_auth(self):
                return self._ret_auth()
            elif self.Iu.require_smc(self):
                # if we are here, there was no auth procedure,
                # hence the cksn submitted by the UE is valid
                return self._ret_smc(self.UEInfo['CKSN'], False)
        elif isinstance(Proc, MMAuthentication):
            if self.Iu.require_smc(self):
                # if we are here, the valid cksn is the one established during
                # the auth procedure
                return self._ret_smc(Proc.cksn, True)
        elif isinstance(Proc, RANAPSecurityModeControl):
            if not Proc.success:
                self.abort()
                self._end(nas_tx=False)
                return None
            # self.Iu.SEC['CKSN'] has been taken into action as the RRC layer
        elif isinstance(Proc, MMTMSIReallocation):
            # everything went fine, end of the procedure
            self._end(nas_tx=False)
            return None
        elif Proc is not None:
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
        else:
            # prepare LUAccept IEs
            IEs = {'LAI': {'plmn': self.UE.PLMN, 'lac': self.UE.LAC}}
            # in case we want to realloc a TMSI, we start a TMSIRealloc,
            # but don't forward its output
            if self.MM.LU_TMSI_REALLOC:
                NasProc = self.MM.init_proc(MMTMSIReallocation)
                void = NasProc.output(embedded=True)
                IEs['ID'] = {'type': NAS.IDTYPE_TMSI, 'ident': NasProc.tmsi}
                self.tmsi_realloc = True
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
                IEs['EmergNumList'] = [{'ServiceCat': uint_to_bitlist(cat), 'Num': num} for \
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
        if not self.tmsi_realloc:
            self._end(nas_tx=True)
        # send LU reject / accept
        return self._nas_tx
    
    def _end(self, nas_tx=True): 
        if self.MM.LU_IUREL and \
        (self.errcause or not self.UEInfo['LocUpdateType']['FollowOnReq']()):
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
        self.rm_from_mm_stack()


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
        - Type2     : Cause
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


class MMCMCallReestablishment(MMSigProc):
    """Call re-establishment: TS 24.008, section 4.5.1.6
    
    Connection-oriented procedure
    UE-initiated
    
    CN message:
        MMCMServiceAccept (PD 5, Type 33), IEs:
          None

        MMCMServiceReject (PD 5, Type 34), IEs:
        - Type2     : Cause
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

# MM CN-initiated procedures dispatcher
MMProcCnDispatcher = {
    18: MMAuthentication,
    24: MMIdentification,
    26: MMTMSIReallocation,
    37: MMMOCMActivity,
    41: MMAbort,
    50: MMInformation
    }

