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
# * File Name : pycrate_corenet/ProcCNEMM.py
# * Created : 2017-12-05
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'EMMSigProc',
    'EMMGUTIReallocation',
    'EMMAuthentication',
    'EMMSecurityModeControl',
    'EMMIdentification',
    'EMMInformation',
    'EMMAttach',
    'EMMDetachUE',
    'EMMDetachCN',
    'EMMTrackingAreaUpdate',
    'EMMServiceRequest',
    'EMMExtServiceRequest',
    'EMMCPServiceRequest',
    'EMMDLNASTransport',
    'EMMULNASTransport',
    'EMMDLGenericNASTransport',
    'EMMULGenericNASTransport',
    #
    'EMMProcUeDispatcher',
    'EMMProcUeDispatcherStr',
    'EMMProcCnDispatcher',
    'EMMProcCnDispatcherStr'
    ]

from .utils      import *
from .ProcProto  import *
from .ProcCNS1ap import *


TESTING = False

#------------------------------------------------------------------------------#
# NAS EPS Mobility Management signalling procedure
# TS 24.301, version da0
# Core Network side
#------------------------------------------------------------------------------#

class EMMSigProc(NASSigProc):
    """EPS Mobility Management signalling procedure handler
    
    instance attributes:
        - Name : procedure name
        - EMM  : reference to the UEEMMd instance running this procedure
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
    
    # network initiator message id
    Init = None
    
    if TESTING:
        def __init__(self, encod=None):
            self._prepare(encod)
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            log('[TESTING] [%s] [EMMSigProc] [%s] %s' % (logtype, self.Name, msg))
    
    else:
        def __init__(self, emmd, encod=None, emm_preempt=False, sec=True):
            self._prepare(encod)
            self.EMM  = emmd
            self.S1   = emmd.S1
            self.UE   = emmd.UE
            self._emm_preempt = emm_preempt
            if emm_preempt:
                self.EMM.ready.clear()
            self._sec = sec
            self._log('DBG', 'instantiating procedure')
        
        def _log(self, logtype, msg):
            self.EMM._log(logtype, '[%s] %s' % (self.Name, msg))
    
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
        self.rm_from_emm_stack()
        return []
    
    def abort(self):
        # abort this procedure, and all procedures started within this one
        ind = self.EMM.Proc.index(self)
        if ind >= 0:
            for p in self.EMM.Proc[ind+1:]:
                p.abort()
            del self.EMM.Proc[ind:]
        if self._emm_preempt:
            # release the EMM stack
            self.EMM.ready.set()
        self._log('INF', 'aborting')
    
    def rm_from_emm_stack(self):
        # remove the procedure from the EMM stack of procedures
        try:
            if self.EMM.Proc[-1] == self:
                del self.EMM.Proc[-1]
        except Exception:
            self._log('WNG', 'EMM stack corrupted')
        else:
            if self._emm_preempt:
                # release the EMM stack
                self.EMM.ready.set()
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.EMM, self.Timer, self.TimerDefault)
            self.TimerStart = time()
            self.TimerStop  = self.TimerStart + self.TimerValue
    
    def get_timer(self):
        if self.Timer is None:
            return None
        else:
            return getattr(self.EMM, self.Timer)
    
    def emm_preempt(self):
        self._emm_preempt = True
        self.EMM.ready.clear()
    
    #--------------------------------------------------------------------------#
    # common helpers
    #--------------------------------------------------------------------------#
    
    def _collect_cap(self):
        if not hasattr(self, 'Cap') or not hasattr(self, 'UEInfo'):
            return
        setseccap = False
        for Cap in self.Cap:
            if Cap in self.UEInfo:
                self.UE.Cap[Cap] = self.UEInfo[Cap]
                if Cap == 'UENetCap':
                    setseccap = True
        if setseccap:
            self._log('DBG', 'setting UE security capabilities')
            self.EMM.set_sec_cap()
    
    def _chk_imsi(self):
        # arriving here means the UE's IMSI was unknown at first
        Server, imsi = self.UE.Server, self.UE.IMSI
        if not Server.is_imsi_allowed(imsi):
            self.errcause = self.EMM.IDENT_IMSI_NOT_ALLOWED
            return False
        else:
            # update the MTMSI table
            Server.MTMSI[self.UE.MTMSI] = imsi
            #
            if imsi in Server.UE:
                if self.UE != self.UE.Server.UE[imsi]:
                    ue = Server.UE[imsi]
                    if not ue.merge_eps_handler(self.S1):
                        # unable to merge to the existing profile
                        self._log('WNG', 'profile for IMSI %s already exists, '\
                                  'need to reject for reconnection' % imsi)
                        # reject so that it will reconnect
                        # and get the already existing profile
                        self.errcause = self.EMM.ATT_IMSI_PROV_REJECT
                        return False
                    else:
                        return True
                else:
                    return True
            else:
                Server.UE[imsi] = self.UE
                # update the Server UE's tables
                if imsi in Server.ConfigUE:
                    # update UE's config with it's dedicated config
                    self.UE.set_config( Server.ConfigUE[imsi] )
                elif '*' in Server.ConfigUE:
                    self.UE.set_config( Server.ConfigUE['*'] )
                return True
    
    def _ret_req_imsi(self):
        NasProc = self.EMM.init_proc(EMMIdentification)
        NasProc.set_msg(7, 85, IDType=NAS.IDTYPE_IMSI)
        return NasProc.output()
    
    def _ret_auth(self):
        NasProc = self.EMM.init_proc(EMMAuthentication)
        return NasProc.output()
    
    def _ret_smc(self, ksi=None, emerg=False):
        NasProc = self.EMM.init_proc(EMMSecurityModeControl)
        if ksi:
            ksi = (ksi[0]<<3) + ksi[1]
        NasProc._set_ksi(ksi, emerg)
        return NasProc.output()
    
    def _act_bear(self):
        # reactivate all PDN connections
        erablist, ebilist, brdl, brul = [], [], 0, 0
        for ebi, pdncfg in self.S1.ESM.PDN.items():
            if 'RAB' in pdncfg:
                rabcfg = pdncfg['RAB']
                ebilist.append(ebi)
                # erab ext IE can be Correlation-ID and/or BearerType
                erablist.append({
                        'id': 52,
                        'criticality': 'reject',
                        'value': ('E-RABToBeSetupItemCtxtSUReq', {
                            'e-RAB-ID': ebi,
                            'e-RABlevelQoSParameters': rabcfg['E-RABlevelQoSParameters'],
                            'transportLayerAddress': (bytes_to_uint(inet_aton(rabcfg['SGW-TLA']), 32), 32),
                            'gTP-TEID': uint_to_bytes(rabcfg['SGW-GTP-TEID'], 32),
                            #'iE-Extensions': [],
                            })
                        })
                brdl += rabcfg['BitrateDL']
                brul += rabcfg['BitrateUL']
        if not erablist:
            # no PDN connection to reactivate
            return None
        #
        # get the current sec context to setup the eNB security layer
        secctx = self.S1.get_sec_ctx()
        if secctx and 'UESecCap' in self.UE.Cap:
            # create the KeNB
            self._log('DBG', 'NAS UL count for Kenb derivation, %i' % secctx['UL_enb'])
            Kenb, UESecCap = conv_401_A3(secctx['Kasme'], secctx['UL_enb']), self.UE.Cap['UESecCap'][1]
            secctx['Kenb'] = Kenb
            secctx['NCC']  = 0
            secctx['NH']   = conv_401_A4(secctx['Kasme'], Kenb)
        else:
            self._log('WNG', 'no active NAS security context, using the null AS security context')
            Kenb, UESecCap = self.S1.SECAS_NULL_CTX
        #
        IEs = {
            'E_RABToBeSetupListCtxtSUReq': erablist,
            'UEAggregateMaximumBitrate': {
                'uEaggregateMaximumBitRateDL': brdl,
                'uEaggregateMaximumBitRateUL': brul
                },
            'SecurityKey': (bytes_to_uint(Kenb, 256), 256),
            'UESecurityCapabilities': {
                'encryptionAlgorithms': ((UESecCap[1].get_val()<<15) + \
                                         (UESecCap[2].get_val()<<14) + \
                                         (UESecCap[3].get_val()<<13), 16),
                'integrityProtectionAlgorithms': ((UESecCap[9].get_val()<<15) + \
                                                  (UESecCap[10].get_val()<<14) + \
                                                  (UESecCap[11].get_val()<<13), 16)
                }
            }
        #
        if self.S1.ICS_RADCAP_INCL and 'UERadioCap' in self.UE.Cap:
            IEs['UERadioCapability'] = self.UE.Cap['UERadioCap'][0]
        if self.S1.ICS_GUMMEI_INCL:
            IEs['GUMMEI'] = gummei_to_asn(self.UE.Server.PLMN,
                                          self.UE.Server.MME_GID,
                                          self.UE.Server.MME_CODE)
        if self.S1.ICS_TRACE_ACT:
            IEs['TraceActivation'] = self.S1.ICS_TRACE_ACT
        #
        S1apProc = self.S1.init_s1ap_proc(S1APInitialContextSetup, **IEs)
        if S1apProc:
            # pass the info required for setting the GTPU tunnel
            S1apProc._gtp_add_mobile_ebi = ebilist
            return S1apProc
        else:
            return None


#------------------------------------------------------------------------------#
# EMM common procedures: TS 24.301, section 5.4
#------------------------------------------------------------------------------#

class EMMGUTIReallocation(EMMSigProc):
    """GUTI reallocation procedure: TS 24.301, section 5.4.1
    
    CN-initiated
    
    CN message:
        EMMGUTIReallocCommand (PD 7, Type 80), IEs:
        - Type4LV   : GUTI
        - Type4TLV  : TAIList
    
    UE message:
        EMMGUTIReallocComplete (PD 7, Type 81), IEs:
          None
    """
    
    Cont = (
        (TS24301_EMM.EMMGUTIReallocCommand, ),
        (TS24301_EMM.EMMGUTIReallocComplete, )
        )
    
    Init  = (7, 80)
    Timer = 'T3450'
    
    def output(self, embedded=False):
        # embedded=True is used to embed this procedure within an Attach or TAU
        # hence the output message is not built, only the .mtmsi is available
        # but the procedure still runs and waits for the UE response 
        # after all
        # Warning, when the GUTI IE is set by hand, it is not taken into account
        # by EMM procedures
        if 'GUTI' not in self.Encod[self.Init]:
            self.mtmsi = self.UE.get_new_tmsi()
            self.guti  = (self.UE.Server.PLMN, self.UE.Server.MME_GID, self.UE.Server.MME_CODE, self.mtmsi)
            self.set_msg(7, 80, GUTI={'type': NAS.IDTYPE_GUTI, 'ident': self.guti})
        else:
            self.mtmsi = None
            self.guti = None
        #
        if not embedded:
            self.encode_msg(7, 80)
            if not self._sec:
                self._nas_tx._sec = False
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            self.init_timer()
            return self.S1.ret_s1ap_dnt(self._nas_tx)
        else:
            self.rm_from_emm_stack()
            return []
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # just take the new mtmsi in use
        if self.mtmsi is not None:
            self.UE.set_mtmsi(self.mtmsi)
            self._log('INF', 'new M-TMSI set, 0x%.8x' % self.mtmsi)
        else:
            self._log('WNG', 'handcrafted GUTI sent, not updating the local M-TMSI')
        self.rm_from_emm_stack()
        return []


class EMMAuthentication(EMMSigProc):
    """Authentication procedure: TS 24.301, section 5.4.2
    
    CN-initiated
    
    CN messages:
        EMMAuthenticationRequest (PD 7, Type 82), IEs:
        - Type1V    : spare
        - Type1V    : NAS_KSI
        - Type3V    : RAND
        - Type4LV   : AUTN

        EMMAuthenticationReject (PD 7, Type 84), IEs:
          None
    
    UE messages:
        EMMAuthenticationResponse (PD 7, Type 83), IEs:
        - Type4LV   : RES

        EMMAuthenticationFailure (PD 7, Type 92), IEs:
        - Type3V    : EMMCause
        - Type4TLV  : AUTS
    """
    
    Cont = (
        (TS24301_EMM.EMMAuthenticationRequest, TS24301_EMM.EMMAuthenticationReject),
        (TS24301_EMM.EMMAuthenticationResponse, TS24301_EMM.EMMAuthenticationFailure)
        )
    
    Decod = {
        (7, 83): {
            'RES'  : lambda x: x[1].get_val()
            },
        (7, 92): {
            'AUTS' : lambda x: x[2].get_val()
            }
        }
    
    Init  = (7, 82)
    Timer = 'T3460'
    
    def output(self):
        # get a new KSI (0..6)
        ksi = self.EMM.get_new_ksi()
        #
        EncodReq = self.Encod[self.Init]
        # in case NAS_KSI is handcrafted, just warn (will certainly fail)
        if 'NAS_KSI' in EncodReq:
            self._log('WNG', 'handcrafted NAS_KSI (%r), generated KSI (%i)'\
                      % (EncodReq['NAS_KSI'], self.ksi))
        # in case RAND is handcrafted, we use it for generating the auth vector
        if 'RAND' in EncodReq:
            RAND = EncodReq['RAND']
        else:
            RAND = None
        #
        if not self.UE.USIM or self.EMM.AUTH_2G:
            # WNG: 2G authentication, this is illegal and won't work
            self._log('WNG', 'trying an LTE authentication with a 2G vector')
            self.ctx = 2
            self.ksi = (1, ksi) # mapped ctx
            self.vect = self.UE.Server.AUCd.make_2g_vector(self.UE.IMSI, RAND)
        elif self.EMM.AUTH_3G:
            # WNG: 3g authentication, this is also illegal and should not work
            self.ctx = 3
            self.ksi = (1, ksi) # mapped ctx
            self.vect = self.UE.Server.AUCd.make_3g_vector(self.UE.IMSI, self.EMM.AUTH_AMF, RAND)
        else:
            # 4G authentication
            self.ctx = 4
            self.ksi = (0, ksi) # native ctx
            if self.EMM.AUTH_PLMN:
                self.snid = plmn_str_to_buf(self.EMM.AUTH_PLMN)
            else:
                self.snid = plmn_str_to_buf(self.UE.Server.PLMN)
            self.vect = self.UE.Server.AUCd.make_4g_vector(self.UE.IMSI, self.snid, self.EMM.AUTH_AMF, RAND)
        #
        if self.vect is None:
            # IMSI is not in the AuC db
            self._log('ERR', 'unable to get an authentication vector from AuC')
            self.rm_from_emm_stack()
            return []
        #
        # prepare IEs
        if self.ctx == 2:
            autn = b''
        else:
            autn = self.vect[2]
        if self.EMM.AUTH_AUTN_EXT:
            autn += self.EMM.AUTH_AUTN_EXT
        #
        self.set_msg(7, 82, NAS_KSI=self.ksi, RAND=self.vect[0], AUTN=autn)
        self.encode_msg(7, 82)
        if not self._sec:
            self._nas_tx._sec = False
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.init_timer()
        return self.S1.ret_s1ap_dnt(self._nas_tx)
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        if pdu._name == 'EMMAuthenticationResponse':
            return self._process_resp()
        else:
            return self._process_fail()
    
    def _process_resp(self):
        # check if the whole UE response is corresponding to the expected one
        if self.ctx != 2:
            if self.UEInfo['RES'] != self.vect[1]:
                # incorrect response from the UE: auth reject
                self._log('WNG', '%iG authentication reject, XRES %s, RES %s'\
                          % (self.ctx, hexlify(self.vect[1]).decode('ascii'),
                             hexlify(self.UEInfo['RES']).decode('ascii'))) 
                self.encode_msg(7, 84)
                self.success = False
            else:
                self._log('DBG', '%iG authentication accepted' % self.ctx)
                self.success = True
                # set the security context
                self.EMM.set_sec_ctx(self.ksi, self.ctx, self.vect)
        else:
            # 2G auth context
            if self.UEInfo['RES'] != self.vect[1][:4]:
                # incorrect response from the UE: auth reject
                self._log('WNG', '2G authentication reject, XRES %s, RES %s'\
                          % (hexlify(self.vect[1][:4]).decode('ascii'),
                             hexlify(self.UEInfo['RES']).decode('ascii')))
                self.encode_msg(8, 20)
                self.success = False
            else:
                self._log('WNG', '2G authentication accepted')
                self.success = True
                # set a 2G security context
                self.EMM.set_sec_ctx(self.ksi, 2, self.vect)
        #
        self.rm_from_emm_stack()
        if not self.success:
            if not self._sec:
                self._nas_tx._sec = False
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            return self.S1.ret_s1ap_dnt(self._nas_tx)
        else:
            return []
    
    def _process_fail(self):
        self.success = False
        if self.UEInfo['EMMCause'].get_val() == 21 and 'AUTS' in self.UEInfo:
            # synch failure
            ret = self.UE.Server.AUCd.synch_sqn(self.UE.IMSI, self.vect[0], self.UEInfo['AUTS'])
            #
            if ret is None:
                # something did not work
                self._log('ERR', 'unable to resynchronize SQN in AuC')
                self.encode_msg(8, 20)
                self.rm_from_emm_stack()
                if not self._sec:
                    self._nas_tx._sec = False 
                if self.TRACK_PDU:
                    self._pdu.append( (time(), 'DL', self._nas_tx) )
                return self.S1.ret_s1ap_dnt(self._nas_tx)
            #
            elif ret:
                # USIM did not authenticate correctly
                self._log('WNG', 'USIM authentication failed for resynch')
                self.encode_msg(8, 20)
                self.rm_from_emm_stack()
                if not self._sec:
                    self._nas_tx._sec = False
                if self.TRACK_PDU:
                    self._pdu.append( (time(), 'DL', self._nas_tx) )
                return self.S1.ret_s1ap_dnt(self._nas_tx)
            #
            else: 
                # resynch OK: restart an auth procedure
                self._log('INF', 'USIM SQN resynchronization done')
                self.rm_from_emm_stack()
                # restart a new auth procedure
                NasProc = self.EMM.init_proc(EMMAuthentication)
                return NasProc.output()
        #
        else:
            # UE refused our auth request...
            self._log('ERR', 'UE rejected AUTN, %s' % self.UEInfo['EMMCause'])
            self.rm_from_emm_stack()
            return []


class EMMSecurityModeControl(EMMSigProc):
    """Security mode control procedure: TS 24.301, section 5.4.3
    
    CN-initiated
    
    CN message:
        EMMSecurityModeCommand (PD 7, Type 93), IEs:
        - Type3V    : NASSecAlgo
        - Type1V    : spare
        - Type1V    : NAS_KSI
        - Type4LV   : UESecCap
        - Type1TV   : IMEISVReq
        - Type3TV   : NonceUE
        - Type3TV   : NonceMME
    
    UE messages:
        EMMSecurityModeComplete (PD 7, Type 94), IEs:
        - Type4TLV  : IMEISV

        EMMSecurityModeReject (PD 7, Type 95), IEs:
        - Type3V    : EMMCause
    """
    
    Cont = (
        (TS24301_EMM.EMMSecurityModeCommand, ),
        (TS24301_EMM.EMMSecurityModeComplete, TS24301_EMM.EMMSecurityModeReject)
        )
    
    Decod = {
        (7, 94): {
            'IMEISV': lambda x: x[2].decode()
            }
        }
        
    Init  = (7, 94)
    Timer = 'T3460'

    def _set_ksi(self, ksi, emerg):
        if ksi is None:
            self.ksi = self.EMM.get_any_ksi()
        else:
            self.ksi = ksi
        if not emerg:
            self.EMM.set_sec_ctx_smc(self.ksi)
        self.S1.SEC['KSI'] = self.ksi
    
    def output(self):
        if not hasattr(self, 'ksi'):
            if 'NAS_KSI' in self.Encod[self.Init]:
                nasksi = self.Encod[self.Init]['NAS_KSI']
                ksi = (nasksi[0]<<3) + nasksi[1]
            else:
                ksi = None
            self._set_ksi(ksi, emerg=False)
        try:
            self.secctx = self.S1.SEC[self.ksi]
        except KeyError:
            # no security ctxt available at all
            self._log('WNG', 'no security context available, using an emergency one with KSI %i' % self.ksi)
            self.EMM.set_sec_ctx_emerg(self.ksi)
            self.secctx = self.S1.SEC[self.ksi]
        EncodReq = self.Encod[self.Init]
        # in case any of the IEs is handcrafted, we warn (will certainly fail)
        if 'NASSecAlgo' in EncodReq or 'NAS_KSI' in EncodReq or 'UESecCap' in EncodReq:
            self._log('WNG', 'handcrafted IEs: %r' % EncodReq)
        # prepare IEs for the SMC 
        IEs = {'NASSecAlgo': {'CiphAlgo': self.secctx['EEA'], 'IntegAlgo': self.secctx['EIA']},
               'NAS_KSI'   : (self.ksi>>3, self.ksi&0x7),
               'UESecCap'  : self.EMM.get_sec_cap()}
        if self.UE.IMEISV is None and self.EMM.SMC_IMEISV_REQ:
            IEs['IMEISVReq'] = 1
        # TODO: check support of NonceUE / NonceMME for mobility procedures
        #
        self.set_msg(7, 93, **IEs)
        self.encode_msg(7, 93)
        if not self._sec:
            self._nas_tx._sec = False
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.init_timer()
        return self.S1.ret_s1ap_dnt(self._nas_tx)
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        self.rm_from_emm_stack()
        if pdu._name == 'EMMSecurityModeComplete':
            self.success = True
            if 'IMEISV' in self.UEInfo:
                self.UE.set_ident_from_ue(*self.UEInfo['IMEISV'], dom='EPS')
            self._log('INF', 'success, EEA%i / EIA%i selected' % (self.secctx['EEA'], self.secctx['EIA']))
            return []
        else:
            self.success = False
            self._log('WNG', 'failure, %r' % self.UEInfo['EMMCause'])
            return []


class EMMIdentification(EMMSigProc):
    """Identification procedure: TS 24.301, section 5.4.4
    
    CN-initiated
    
    CN message:
        EMMIdentityRequest (PD 7, Type 85), IEs:
        - Type1V    : spare
        - Type1V    : IDType
    
    UE message:
        EMMIdentityResponse (PD 7, Type 86), IEs:
        - Type4LV   : ID
    """
    
    Cont = (
        (TS24301_EMM.EMMIdentityRequest, ),
        (TS24301_EMM.EMMIdentityResponse, )
        )
    
    Decod = {
        (7, 86): {
            'ID': lambda x: x[1].decode(),
            }
        }
    
    Init  = (7, 85)
    Timer = 'T3470'
    
    def output(self):
        # build the Id Request msg, Id type has to be set by the caller
        self.encode_msg(7, 85)
        if not self._sec:
            self._nas_tx._sec = False
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.init_timer()
        return self.S1.ret_s1ap_dnt(self._nas_tx)
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # get the identity IE value
        self.IDType = self._nas_tx['IDType'][0].get_val()
        #
        if self.UEInfo['ID'][0] != self.IDType :
            self._log('WNG', 'identity responded not corresponding to type requested '\
                      '(%i instead of %i)' % (self.UEInfo['ID'][0], self.IDType))
        self._log('INF', 'identity responded, %r' % self._nas_rx['ID'][1])
        self.UE.set_ident_from_ue(*self.UEInfo['ID'], dom='EPS')
        #
        self.rm_from_emm_stack()
        return []


class EMMInformation(EMMSigProc):
    """EMM information procedure: TS24.301, section 5.4.5
    
    CN-initiated
    
    CN message:
        EMMInformation (PD 7, Type 97), IEs:
        - Type4TLV  : NetFullName
        - Type4TLV  : NetShortName
        - Type3TV   : LocalTimeZone
        - Type3TV   : UnivTimeAndTimeZone
        - Type4TLV  : DLSavingTime
    
    UE message:
        None
    """
    
    Cont = (
        (TS24301_EMM.EMMInformation, ),
        None
        )
    
    Init = (7, 97)
    
    def output(self):
        self.encode_msg(7, 97)
        if not self._sec:
            self._nas_tx._sec = False
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self._log('INF', '%r' % self.Encod[(7, 97)])
        self.rm_from_emm_stack()
        return self.S1.ret_s1ap_dnt(self._nas_tx)


#------------------------------------------------------------------------------#
# EMM specific procedures: TS 24.301, section 5.5
#------------------------------------------------------------------------------#

class EMMAttach(EMMSigProc):
    """Attach procedure: TS 24.301, section 5.5.1
    
    UE-initiated
    
    CN messages:
        EMMAttachAccept (PD 7, Type 66), IEs:
        - Type1V    : spare
        - Type1V    : EPSAttachResult
        - Type3V    : T3412
        - Type4LV   : TAIList
        - Type6LVE  : ESMContainer
        - Type4TLV  : GUTI
        - Type3TV   : LAI
        - Type4TLV  : ID
        - Type3TV   : EMMCause
        - Type3TV   : T3402
        - Type3TV   : T3423
        - Type4TLV  : EquivPLMNList
        - Type4TLV  : EmergNumList
        - Type4TLV  : EPSNetFeat
        - Type1TV   : AddUpdateRes
        - Type4TLV  : T3412Ext
        - Type4TLV  : T3324
        - Type4TLV  : ExtDRXParam
        - Type1TV   : SMSServStat

        EMMAttachReject (PD 7, Type 68), IEs:
        - Type3V    : EMMCause
        - Type6TLVE : ESMContainer
        - Type4TLV  : T3346
        - Type4TLV  : T3402
        - Type1TV   : ExtEMMCause
    
    UE messages:
        EMMAttachRequest (PD 7, Type 65), IEs:
        - Type1V    : NAS_KSI
        - Type1V    : EPSAttachType
        - Type4LV   : EPSID
        - Type4LV   : UENetCap
        - Type6LVE  : ESMContainer
        - Type3TV   : OldPTMSISign
        - Type4TLV  : AddGUTI
        - Type3TV   : OldTAI
        - Type3TV   : DRXParam
        - Type4TLV  : MSNetCap
        - Type3TV   : OldLAI
        - Type1TV   : TMSIStatus
        - Type4TLV  : MSCm2
        - Type4TLV  : MSCm3
        - Type4TLV  : SuppCodecs
        - Type1TV   : AddUpdateType
        - Type4TLV  : VoiceDomPref
        - Type1TV   : DeviceProp
        - Type1TV   : OldGUTIType
        - Type1TV   : MSNetFeatSupp
        - Type4TLV  : TMSIBasedNRICont
        - Type4TLV  : T3324
        - Type4TLV  : T3412Ext
        - Type4TLV  : ExtDRXParam

        EMMAttachComplete (PD 7, Type 67), IEs:
        - Type6LVE  : ESMContainer
    """
    
    Cont = (
        (TS24301_EMM.EMMAttachAccept, TS24301_EMM.EMMAttachReject),
        (TS24301_EMM.EMMAttachRequest, TS24301_EMM.EMMAttachComplete)
        )
    
    Decod = {
        (7, 65): {
            'NAS_KSI' : lambda x: (x[0][0].get_val(), x[0][1].get_val()),
            'EPS_ID'  : lambda x: x[1].decode(),
            'OldTAI'  : lambda x: x[1].decode(),
            'OldLAI'  : lambda x: x[1].decode(),
            },
        }
    
    Cap = ('UENetCap', 'DRXParam', 'MSNetCap', 'MSCm2', 'MSCm3', 'SuppCodecs',
           'VoiceDomPref', 'DeviceProp', 'MSNetFeatSupp', 'ExtDRXParam')
    
    Timer = 'T3450'
    
    def process(self, pdu):
        # preempt the EMM stack
        self.emm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        if pdu._name == 'EMMAttachRequest':
            # AttachRequest
            self.errcause, self.UEInfo = None, {}
            self.decode_msg(pdu, self.UEInfo)
            return self._process_req()
        else:
            # AttachComplete
            self.errcause, self.CompInfo = None, {}
            self.decode_msg(pdu, self.CompInfo)
            return self._process_comp()
    
    def _process_req(self):
        #
        if self.UEInfo['EPSID'][0] == NAS.IDTYPE_GUTI and self.UE.MTMSI is None:
            self.UE.MTMSI = self.UEInfo['EPSID'][1][3]
        #
        att_type = self.UEInfo['EPSAttachType']
        self.att_type = att_type.get_val()
        #if self.att_type == 2 and 'TMSIStatus' not in self.UEInfo \
        #and 'TMSIBasedNRICont' not in self.UEInfo:
        #    # downgrade to EPS-only attachment
        #    self.att_type = 1
        self._log('INF', 'request type %i (%s)' % (self.att_type, att_type._dic[self.att_type]))
        # collect capabilities
        self._collect_cap()
        #
        # check for emergency attach
        if self.att_type == 6:
            if self.EMM.ATT_EMERG:
                self.errcause = self.EMM.ATT_EMERG
                return self.output()
            else:
                # jump directly to the smc with EEA0 / EIA0
                self.EMM.set_sec_ctx_emerg()
                # emergency ctx has always ksi 0
                return self._ret_smc((0, 0), emerg=True)
        #
        # check local ID
        elif self.UE.IMSI is None:
            # UEd was created based on a S-TMSI provided at the RRC layer
            # -> we need to get its IMSI before continuing
            try:
                del self.UE.Server._UEpre[self.UE.MTMSI]
            except Exception:
                pass
            #
            if self.UEInfo['EPSID'][0] == 1:
                # IMSI is provided at the NAS layer
                self.UE.set_ident_from_ue(*self.UEInfo['EPSID'], dom='EPS')
                if not self._chk_imsi():
                    # IMSI not allowed
                    return self.output()
            else:
                # need to request the IMSI, prepare an id request procedure
                return self._ret_req_imsi()
        #
        if self.EMM.require_auth(self, ksi=self.UEInfo['NAS_KSI']):
            return self._ret_auth()
        else:
            # no auth procedure, ksi submitted by the UE is valid
            # set UL NAS count for further KeNB derivation
            try:
                secctx = self.S1.SEC[self.S1.SEC['KSI']]
                secctx['UL_enb'] = self._nas_rx._ulcnt
            except Exception:
                pass
            if self.EMM.require_smc(self):
                return self._ret_smc(self.UEInfo['NAS_KSI'])
            else:
                # otherwise, go directly to postprocess
                return self.postprocess()
    
    def _process_comp(self):
        #
        if self.mtmsi_realloc >= 0:
            self.UE.set_mtmsi(self.mtmsi_realloc)
            if self.att_type == 2:
                self.UE.set_tmsi(self.mtmsi_realloc)
                self._log('INF', 'new M-TMSI and TMSI set, 0x%.8x' % self.mtmsi_realloc)
            else:
                self._log('INF', 'new M-TMSI set, 0x%.8x' % self.mtmsi_realloc)
        #
        # transfer to the ESM stack, which will terminate the ongoing ESM procedure
        # and shoud return an empty list
        ret = self.S1.ESM.process_buf(self.CompInfo['ESMContainer'].get_val(),
                                      sec=self._nas_rx._sec)
        ret.extend(self._end())
        return ret
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, EMMIdentification):
            assert( Proc.IDType == NAS.IDTYPE_IMSI)
            # got the UE's IMSI, check if it's allowed
            if self.UE.IMSI is None:
                # UE did actually not responded with its IMSI, this is bad !
                # error 96: invalid mandatory info
                self.errcause = 96
                return self.output()
            elif not self._chk_imsi():
                return self.output()
            if self.EMM.require_auth(self, ksi=self.UEInfo['NAS_KSI']):
                return self._ret_auth()
            else:
                try:
                    secctx = self.S1.SEC[self.S1.SEC['KSI']]
                    secctx['UL_enb'] = self._nas_rx._ulcnt
                except Exception:
                    pass
                if self.EMM.require_smc(self):
                    return self._ret_smc(self.UEInfo['NAS_KSI'])
        #
        elif isinstance(Proc, EMMAuthentication):
            if not Proc.success:
                self.abort()
                return []
            elif self.EMM.require_smc(self):
                # ksi established during the auth procedure
                return self._ret_smc(Proc.ksi)
        #
        elif isinstance(Proc, EMMSecurityModeControl):
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
        if self.att_type == 2 and self.EMM.ATT_IMSI:
            # IMSI attach not supported
            self.errcause = self.EMM.ATT_IMSI
        #
        if self.errcause:
            # prepare AttachReject IE
            if self.errcause == self.EMM.ATT_IMSI_PROV_REJECT:
                self.set_msg(7, 68, EMMCause=self.errcause, T3346=self.EMM.ATT_T3346)
            else:
                self.set_msg(7, 68, EMMCause=self.errcause)
            self.encode_msg(7, 68)
            if not self._nas_rx._sec:
                self._nas_tx._sec = False
            self.mtmsi_realloc = -1
            self._log('INF', 'reject, %r' % self._nas_tx['EMMCause'])
            ret = self.S1.ret_s1ap_dnt(self._nas_tx)
            ret.extend( self._end() )
        else:
            #
            # prepare the TAIList for the UE:
            # it only contains a single PartialTAIList of type 0 with the TAI of the eNB
            # to which the UE is connected
            tailist = [{'Type':0, 'PLMN':self.UE.PLMN, 'TACValues':[self.UE.TAC]}]
            #
            # prepare AttachAccept IEs
            IEs = {'EPSAttachResult': self.att_type,
                   'T3412'          : self.EMM.ATT_T3412,
                   'TAIList'        : tailist,
                   }
            #
            # in case we want to realloc a GUTI, we start a GUTIRealloc,
            # but don't forward its output
            if self.EMM.ATT_GUTI_REALLOC:
                NasProc = self.EMM.init_proc(EMMGUTIReallocation)
                NasProc.output(embedded=True)
                if NasProc.guti is not None:
                    IEs['GUTI'] = {'type': NAS.IDTYPE_GUTI, 'ident': NasProc.guti}
                    self.mtmsi_realloc = NasProc.mtmsi
                else:
                    self.mtmsi_realloc = -1
            else:
                self.mtmsi_realloc = -1
            #
            if self.att_type == 2:
                # combined attachment: we set the TAC as the LAC
                self.UE.LAC = self.UE.TAC
                if self.mtmsi_realloc >= 0:
                    # including a TMSI realloc: we set the M-TMSI as CS TMSI
                    IEs['LAI'] = {'PLMN': self.UE.PLMN, 'LAC': self.UE.LAC}
                    IEs['ID']  = {'type': NAS.IDTYPE_TMSI, 'ident': self.mtmsi_realloc}
            #
            if self.EMM.ATT_T3402 is not None:
                IEs['T3402'] = self.EMM.ATT_T3402
            if self.S1.Config['EquivPLMNList'] is not None:
                IEs['EquivPLMNList'] = self.S1.Config['EquivPLMNList']
            if isinstance(self.S1.Config['EmergNumList'], bytes_types):
                IEs['EmergNumList'] = self.S1.Config['EmergNumList']
            elif self.S1.Config['EmergNumList'] is not None:
                IEs['EmergNumList'] = [{'ServiceCat': {c:1 for c in cat}, 'Num': num} for \
                                       (cat, num) in self.S1.Config['EmergNumList']]
            #
            if self.EMM.ATT_EPS_NETFEAT_SUPP:
                IEs['EPSNetFeat'] = self.EMM.ATT_EPS_NETFEAT_SUPP
            #
            # power saving mode
            if 'MSNetFeatSupp' in self.UEInfo and self.UEInfo['MSNetFeatSupp'][1].get_val():
                if self.EMM.ATT_T3412_EXT:
                    IEs['T3412Ext'] = self.EMM.ATT_T3412_EXT
                elif 'T3412Ext' in self.UEInfo:
                    IEs['T3412Ext'] = self.UEInfo['T3412Ext'].get_val()
            if 'T3324' in self.UEInfo:
                if self.EMM.ATT_T3324:
                    IEs['T3324'] = self.EMM.ATT_T3324
                else:
                    IEs['T3324'] = self.UEInfo['T3324'].get_val()
            #
            if 'ExtDRXParam' in self.UEInfo:
                if self.EMM.ATT_EXTDRX:
                    IEs['ExtDRXParam'] = self.EMM.ATT_EXTDRX
                else:
                    IEs['ExtDRXParam'] = self['ExtDRXParam'].get_val()
            #
            if self.EMM.ATT_SMS_SERV_STAT:
                IEs['SMSServStat'] = self.EMM.ATT_SMS_SERV_STAT
            #
            self.set_msg(7, 66, **IEs)
            self.encode_msg(7, 66)
            #
            # Transfer the UE ESMContainer to the ESM stack, which will populate 
            # the ESMContainer in the AttachAccept and setup the proper S1AP procedure.
            # In case of ESM failure, the ESM procedure handler will set self.errcause
            # to 19 (ESM failure) and rebuild an AttachReject through its ._EMMProc
            # attribute.
            ret = self.S1.ESM.process_buf(self.UEInfo['ESMContainer'].get_val(), 
                                          sec=self._sec,
                                          EMMProc=self)
        #
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        if self.errcause:
            ret.extend( self._end() )
        else:
            self.init_timer()
        return ret
    
    def _end(self):
        ret = []
        if self.EMM.ATT_S1REL or self.errcause and self.EMM.ATT_S1REL_ONERR:
            S1apProcRel = self.S1.init_s1ap_proc(S1APUEContextRelease, Cause=('nas', 'normal-release'))
            if S1apProcRel:
                ret.append(S1apProcRel)
        self.rm_from_emm_stack()
        return ret


class EMMDetachUE(EMMSigProc):
    """Detach procedure: TS 24.301, section 5.5.2
    
    UE-initiated
    
    CN message:
        EMMDetachAccept (PD 7, Type 70), IEs:
          None

    UE message:
        EMMDetachRequestMO (PD 7, Type 69), IEs:
        - Type1V    : NAS_KSI
        - Type1V    : EPSDetachType
        - Type4LV   : EPSID
    """
    
    Cont = (
        (TS24301_EMM.EMMDetachAccept, ),
        (TS24301_EMM.EMMDetachRequestMO, )
        )
    
    def _detach(self):
        if self.S1.SEC['KSI'] is not None and not self._nas_rx._sec:
            # security is activated, but the detach request is not protected
            # this is not acceptable
            self._log('WNG', 'invalid detach request with no security layer')
        else:
            # set EMM state
            self.EMM.state = 'INACTIVE'
            self._log('INF', 'detaching')
            #
            self.rm_from_emm_stack()
            # abort all ongoing EPS procedures and PDN ctxt
            self.S1.clear_nas_proc()
            self.S1.ESM.pdn_clear()
            #
            if self.UE.IMSI is None:
                # UEd was created based on a S-TMSI provided at the RRC layer
                # just delete it
                try:
                    del self.UE.Server._UEpre[self.UE.MTMSI]
                except Exception:
                    pass
    
    def process(self, pdu):
        # preempt the EMM stack
        self.emm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        if self.UEInfo['EPSDetachType']['SwitchOff'].get_val():
            # if UE is to power-off, procedure ends here
            ret = self.output(poff=True)
        else:
            # TODO: implement require_auth() / require_smc()
            #
            ret = self.output(poff=False)
        self._detach()
        return ret
    
    def output(self, poff=False):
        # prepare a stack of S1AP procedure(s)
        S1apTxProc = []
        if not poff:
            # set a S1ap direct transfer to transport the DetachAccept
            #self.set_msg(7, 70)
            self.encode_msg(7, 70)
            if not self._nas_rx._sec:
                self._nas_tx._sec = False 
            if self.TRACK_PDU:
                self._pdu.append( (time(), 'DL', self._nas_tx) )
            S1apProc = self.S1.ret_s1ap_dnt(self._nas_tx)
            if S1apProc:
                S1apTxProc.extend( S1apProc )
        S1apProcRel = self.S1.init_s1ap_proc(S1APUEContextRelease, Cause=('nas', 'detach'))
        if S1apProcRel:
            S1apTxProc.append( S1apProcRel )
        return S1apTxProc


class EMMDetachCN(EMMSigProc):
    """Detach procedure: TS 24.301, section 5.5.2
    
    CN-initiated
    
    CN message:
        EMMDetachRequestMT (PD 7, Type 69), IEs:
        - Type1V    : spare
        - Type1V    : EPSDetachType
        - Type3TV   : EMMCause
    
    UE message:
        EMMDetachAccept (PD 7, Type 70), IEs:
          None
    """
    
    Cont = (
        (TS24301_EMM.EMMDetachRequestMT, ),
        (TS24301_EMM.EMMDetachAccept, )
        )
    
    Init  = (7, 69)
    Timer = 'T3422'
    
    def _detach(self):
        if self.S1.SEC['KSI'] is not None and not self._nas_rx._sec:
            # security is activated, but the detach request is not protected
            # this is not acceptable
            self._log('WNG', 'invalid detach response with no security layer')
        else:
            # set EMM state
            self.EMM.state = 'INACTIVE'
            self._log('INF', 'detaching')
            #
            self.rm_from_emm_stack()
            # abort all ongoing EPS procedures and PDN ctxt
            self.S1.clear_nas_proc()
            self.S1.ESM.pdn_clear()
    
    def output(self):
        self.encode_msg(7, 69)
        if not self._sec:
            self._nas_tx._sec = False
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self._log('INF', self._nas_tx['EPSDetachType'].repr())
        # in case of IMSI-detach, a TAU with IMSI attach is expected in response
        if self._nas_tx['EPSDetachType']['Type'].get_val() != 3:
            self.init_timer()
        else:
            self.rm_from_emm_stack()
        return self.S1.ret_s1ap_dnt(self._nas_tx)
    
    def process(self, pdu):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        self._detach()
        S1apProcRel = self.S1.init_s1ap_proc(S1APUEContextRelease, Cause=('nas', 'detach'))
        if S1apProcRel:
            return [S1apProcRel]
        return []


class EMMTrackingAreaUpdate(EMMSigProc):
    """Tracking area updating procedure: TS 24.301, section 5.5.3
    
    UE-initiated
    
    CN messages:
        EMMTrackingAreaUpdateAccept (PD 7, Type 73), IEs:
        - Type1V    : spare
        - Type1V    : EPSUpdateResult
        - Type3TV   : T3412
        - Type4TLV  : GUTI
        - Type4TLV  : TAIList
        - Type4TLV  : EPSBearerCtxtStat
        - Type3TV   : LAI
        - Type4TLV  : ID
        - Type3TV   : EMMCause
        - Type3TV   : T3402
        - Type3TV   : T3423
        - Type4TLV  : EquivPLMNList
        - Type4TLV  : EmergNumList
        - Type4TLV  : EPSNetFeat
        - Type1TV   : AddUpdateRes
        - Type4TLV  : T3412Ext
        - Type4TLV  : T3324
        - Type4TLV  : ExtDRXParam
        - Type4TLV  : HdrCompConfigStat
        - Type1TV   : SMSServStat

        EMMTrackingAreaUpdateReject (PD 7, Type 75), IEs:
        - Type3V    : EMMCause
        - Type4TLV  : T3346
        - Type1TV   : ExtEMMCause
    
    UE messages:
        EMMTrackingAreaUpdateRequest (PD 7, Type 72), IEs:
        - Type1V    : NAS_KSI
        - Type1V    : EPSUpdateType
        - Type4LV   : OldGUTI
        - Type1TV   : Native_NAS_KSI
        - Type1TV   : GPRS_CKSN
        - Type3TV   : OldPTMSISign
        - Type4TLV  : AddGUTI
        - Type3TV   : NonceUE
        - Type4TLV  : UENetCap
        - Type3TV   : OldTAI
        - Type3TV   : DRXParam
        - Type1TV   : UERACapUpdateNeed
        - Type4TLV  : EPSBearerCtxtStat
        - Type4TLV  : MSNetCap
        - Type3TV   : OldLAI
        - Type1TV   : TMSIStatus
        - Type4TLV  : MSCm2
        - Type4TLV  : MSCm3
        - Type4TLV  : SuppCodecs
        - Type1TV   : AddUpdateType
        - Type4TLV  : VoiceDomPref
        - Type1TV   : OldGUTIType
        - Type1TV   : DeviceProp
        - Type1TV   : MSNetFeatSupp
        - Type4TLV  : TMSIBasedNRICont
        - Type4TLV  : T3324
        - Type4TLV  : T3412Ext
        - Type4TLV  : ExtDRXParam

        EMMTrackingAreaUpdateComplete (PD 7, Type 74), IEs:
          None
    """
    
    Cont = (
        (TS24301_EMM.EMMTrackingAreaUpdateAccept, TS24301_EMM.EMMTrackingAreaUpdateReject),
        (TS24301_EMM.EMMTrackingAreaUpdateRequest, TS24301_EMM.EMMTrackingAreaUpdateComplete)
        )
    
    Decod = {
        (7, 72): {
            'NAS_KSI' : lambda x: (x[0][0].get_val(), x[0][1].get_val()),
            'OldGUTI' : lambda x: x[1].decode(),
            'OldTAI'  : lambda x: x[1].decode(),
            'OldLAI'  : lambda x: x[1].decode(),
            },
        }
    
    Cap = ('UENetCap', 'DRXParam', 'MSNetCap', 'MSCm2', 'MSCm3', 'SuppCodecs',
           'VoiceDomPref', 'DeviceProp', 'MSNetFeatSupp', 'ExtDRXParam')
    
    Timer = 'T3450'
    
    def process(self, pdu):
        # preempt the EMM stack
        self.emm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        #
        if pdu._name == 'EMMTrackingAreaUpdateRequest':
            self.errcause, self.UEInfo = None, {}
            self.decode_msg(pdu, self.UEInfo)
            return self._process_req()
        else:
            # EMMTrackingAreaUpdateComplete
            self.errcause, self.CompInfo = None, {}
            self.decode_msg(pdu, self.CompInfo)
            return self._process_comp()
    
    def _process_req(self):
        #
        upd_type = self.UEInfo['EPSUpdateType']
        self.upd_type = upd_type.get_val()
        if self.upd_type[1] in (1, 2):
            # combined TA / LA update
            self.upd_res = 1
            if 'TMSIStatus' not in self.UEInfo and 'TMSIBasedNRICont' not in self.UEInfo:
                self._log('INF', 'combined TA/LA requested, but not TMSIStatus neither '\
                          'TMSIBasedNRICont provided')
        else:
            self.upd_res = 0
        self._log('INF', upd_type.repr())
        # collect capabilities
        self._collect_cap()
        #
        # check local ID
        if self.UE.IMSI is None:
            # UEd was created based on a S-TMSI provided at the RRC layer
            # -> we need to get its IMSI before continuing
            try:
                del self.UE.Server._UEpre[self.UE.MTMSI]
            except Exception:
                pass
            # need to request the IMSI, prepare an id request procedure
            return self._ret_req_imsi()
        #
        elif self.EMM.require_auth(self, ksi=self.UEInfo['NAS_KSI']):
            return self._ret_auth()
        else:
            # no auth procedure, ksi submitted by the UE is valid
            # set UL NAS count for further KeNB derivation
            try:
                secctx = self.S1.SEC[self.S1.SEC['KSI']]
                secctx['UL_enb'] = self._nas_rx._ulcnt
            except Exception:
                pass
            if self.EMM.require_smc(self):
                return self._ret_smc(self.UEInfo['NAS_KSI'])
            else:
                # otherwise, go directly to postprocess
                return self.postprocess()
    
    def _process_comp(self):
        if self.mtmsi_realloc >= 0:
            self.UE.set_mtmsi(self.mtmsi_realloc)
            if self.upd_res in (1, 5):
                self.UE.set_tmsi(self.mtmsi_realloc)
                self._log('INF', 'new M-TMSI and TMSI set, 0x%.8x' % self.mtmsi_realloc)
            else:
                self._log('INF', 'new M-TMSI set, 0x%.8x' % self.mtmsi_realloc)
        return self._end()
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, EMMIdentification):
            assert( Proc.IDType == NAS.IDTYPE_IMSI)
            # got the UE's IMSI, check if it's allowed
            if self.UE.IMSI is None:
                # UE did actually not responded with its IMSI, this is bad !
                # error 96: invalid mandatory info
                self.errcause = 96
                return self.output()
            elif not self._chk_imsi():
                return self.output()
            if self.EMM.require_auth(self, ksi=self.UEInfo['NAS_KSI']):
                return self._ret_auth()
            else:
                try:
                    secctx = self.S1.SEC[self.S1.SEC['KSI']]
                    secctx['UL_enb'] = self._nas_rx._ulcnt
                except Exception:
                    pass
                if self.EMM.require_smc(self):
                    return self._ret_smc(self.UEInfo['NAS_KSI'])
        #
        elif isinstance(Proc, EMMAuthentication):
            if not Proc.success:
                self.abort()
                return []
            elif self.EMM.require_smc(self):
                # ksi established during the auth procedure
                return self._ret_smc(Proc.ksi)
        #
        elif isinstance(Proc, EMMSecurityModeControl):
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
        if self.errcause:
            # prepare TAUReject IE
            self.set_msg(7, 75, EMMCause=self.errcause)
            self.encode_msg(7, 75)
            if not self._nas_rx._sec:
                self._nas_tx._sec = False
            self.mtmsi_realloc = -1
            self._log('INF', 'reject, %r' % self._nas_tx['EMMCause'])
            ret = self.S1.ret_s1ap_dnt(self._nas_tx)
            self.BearActProc = None
            ret.extend(self._end())
        else:
            # prepare TAU Accept IEs
            IEs = {'EPSUpdateResult': self.upd_res}
            #
            # check EPSBearerCtxtStat, and deactivate PDN not enabled at the UE
            if 'EPSBearerCtxtStat' in self.UEInfo:
                EBCtxtStat = self.UEInfo['EPSBearerCtxtStat']
                EBCtxtStatResp = []
                for Stat in EBCtxtStat:
                    uestat = Stat.get_val()
                    ebi = int(Stat._name[4:])
                    if uestat == 1 and ebi not in self.S1.ESM.PDN:
                        self._log('WNG', 'EPS bearer %i activated in the UE but not the network' % ebi)
                        EBCtxtStatResp.append(0)
                    elif uestat == 0 and ebi in self.S1.ESM.PDN:
                        self._log('INF', 'EPS bearer %i activated in the network but not the UE' % ebi)
                        pdncfg = self.S1.ESM.PDN[ebi]
                        if pdncfg['state'] == 1:
                            self.UE.Server.GTPUd.rem_mobile(pdncfg['RAB']['SGW-GTP-TEID'])
                        del self.S1.ESM.PDN[ebi]
                        EBCtxtStatResp.append(0)
                    else:
                        EBCtxtStatResp.append(uestat)
                IEs['EPSBearerCtxtStat'] = EBCtxtStatResp
            #
            # check UERACapUpdateNeed, and delete UERadCap if needed
            if 'UERACapUpdateNeed' in self.UEInfo \
            and self.UEInfo['UERACapUpdateNeed'].get_val() \
            and 'UERadioCap' in self.UE.Cap:
                del self.UE.Cap['UERadioCap']     
            #
            if self.EMM.TAU_T3402 is not None:
                IEs['T3402'] = self.EMM.TAU_T3402
            if self.EMM.TAU_T3412 is not None:
                IEs['T3412'] = self.EMM.TAU_T3412
            #
            # in case we want to realloc a GUTI, we start a GUTIRealloc,
            # but don't forward its output
            if self.EMM.TAU_GUTI_REALLOC:
                NasProc = self.EMM.init_proc(EMMGUTIReallocation)
                NasProc.output(embedded=True)
                if NasProc.guti is not None:
                    IEs['GUTI'] = {'type': NAS.IDTYPE_GUTI, 'ident': NasProc.guti}
                    self.mtmsi_realloc = NasProc.mtmsi
                else:
                    self.mtmsi_realloc = -1
            else:
                self.mtmsi_realloc = -1
            # 
            if self.upd_res in (1, 5):
                # combined TAU / LAU: we set the TAC as the LAC
                self.UE.LAC = self.UE.TAC
                if self.mtmsi_realloc >= 0:
                    # including a TMSI realloc: we set the M-TMSI as CS TMSI
                    IEs['LAI'] = {'PLMN': self.UE.PLMN, 'LAC': self.UE.LAC}
                    IEs['ID']  = {'type': NAS.IDTYPE_TMSI, 'ident': self.mtmsi_realloc}     
            #
            # power saving mode
            if 'MSNetFeatSupp' in self.UEInfo and self.UEInfo['MSNetFeatSupp'][1].get_val():
                if self.EMM.ATT_T3412_EXT:
                    IEs['T3412Ext'] = self.EMM.ATT_T3412_EXT
                elif 'T3412Ext' in self.UEInfo:
                    IEs['T3412Ext'] = self.UEInfo['T3412Ext'].get_val()
            if 'T3324' in self.UEInfo:
                if self.EMM.ATT_T3324:
                    IEs['T3324'] = self.EMM.ATT_T3324
                else:
                    IEs['T3324'] = self.UEInfo['T3324'].get_val()
            #
            if 'ExtDRXParam' in self.UEInfo:
                if self.EMM.ATT_EXTDRX:
                    IEs['ExtDRXParam'] = self.EMM.ATT_EXTDRX
                else:
                    IEs['ExtDRXParam'] = self['ExtDRXParam'].get_val()
            #
            if self.S1.Config['EquivPLMNList'] is not None:
                IEs['EquivPLMNList'] = self.S1.Config['EquivPLMNList']
            if isinstance(self.S1.Config['EmergNumList'], bytes_types):
                IEs['EmergNumList'] = self.S1.Config['EmergNumList']
            elif self.S1.Config['EmergNumList'] is not None:
                IEs['EmergNumList'] = [{'ServiceCat': {c:1 for c in cat}, 'Num': num} for \
                                       (cat, num) in self.S1.Config['EmergNumList']]
            if self.EMM.TAU_EPS_NETFEAT_SUPP:
                IEs['EPSNetFeat'] = self.EMM.TAU_EPS_NETFEAT_SUPP
            if self.EMM.TAU_SMS_SERV_STAT:
                IEs['SMSServStat'] = self.EMM.TAU_SMS_SERV_STAT
            #
            self._IEs = IEs
            self.set_msg(7, 73, **IEs)
            self.encode_msg(7, 73)
            #
            if self.upd_type[0]:
                # reactivate EPS bearers
                self.BearActProc = self.S1.bearer_act()
            else:
                self.BearActProc = None
            #
            ret = self.S1.ret_s1ap_dnt(self._nas_tx)
            if self.BearActProc:
                ret.append(self.BearActProc)
            if self.mtmsi_realloc >= 0:
                self.init_timer()
            else:
                ret.extend(self._end())
        #
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        return ret
    
    def _end(self):
        ret = []
        if self.EMM.TAU_S1REL and not self.BearActProc:
            S1apProcRel = self.S1.init_s1ap_proc(S1APUEContextRelease, Cause=('nas', 'normal-release'))
            if S1apProcRel:
                ret.append(S1apProcRel)
        self.rm_from_emm_stack()
        return ret


#------------------------------------------------------------------------------#
# EMM connection management procedures (S1 mode only): TS 24.301, section 5.6
#------------------------------------------------------------------------------#

class EMMServiceRequest(EMMSigProc):
    """Service request procedure: TS 24.301, section 5.6.1
    
    UE-initiated
    
    CN message:
        None
    
    UE message:
        EMMServiceRequest (SH 12, PD 7), IEs:
            None
    """
    
    Cont = (
        None,
        (TS24301_EMM.EMMServiceRequest, )
        )
    
    def process(self, pdu):
        # preempt the EMM stack
        self.emm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.errcause, self.UEInfo = None, {}
        self.decode_msg(pdu, self.UEInfo)
        #
        # check local ID
        if self.UE.IMSI is None:
            # UEd was created based on a S-TMSI provided at the RRC layer
            # -> we need to get its IMSI before continuing
            try:
                del self.UE.Server._UEpre[self.UE.MTMSI]
            except Exception:
                pass
            # need to request the IMSI, prepare an id request procedure
            return self._ret_req_imsi()
        #
        elif self.EMM.require_auth(self, ksi=(0, self.UEInfo['KSI'].get_val())):
            return self._ret_auth()
        else:
            # no auth procedure, ksi submitted by the UE is valid
            # set UL NAS count for further KeNB derivation
            try:
                secctx = self.S1.SEC[self.S1.SEC['KSI']]
                secctx['UL_enb'] = self._nas_rx._ulcnt
            except Exception:
                pass
            if self.EMM.require_smc(self) and self.EMM.SER_SMC_ALW:
                return self._ret_smc((0, self.UEInfo['KSI'].get_val()))
            else:
                # otherwise, go directly to postprocess
                return self.postprocess()
    
    def postprocess(self, Proc=None):
        if isinstance(Proc, EMMIdentification):
            assert( Proc.IDType == NAS.IDTYPE_IMSI)
            # got the UE's IMSI, check if it's allowed
            if self.UE.IMSI is None:
                # UE did actually not responded with its IMSI, this is bad !
                # error 96: invalid mandatory info
                self.errcause = 96
                return self.output()
            elif not self._chk_imsi():
                return self.output()
            if self.EMM.require_auth(self, ksi=(0, self.UEInfo['KSI'].get_val())):
                return self._ret_auth()
            else:
                try:
                    secctx = self.S1.SEC[self.S1.SEC['KSI']]
                    secctx['UL_enb'] = self._nas_rx._ulcnt
                except Exception:
                    pass
                if self.EMM.require_smc(self) and self.EMM.SER_SMC_ALW:
                    return self._ret_smc((0, self.UEInfo['KSI'].get_val()))
        #
        elif isinstance(Proc, EMMAuthentication):
            if not Proc.success:
                self.abort()
                return []
            elif self.EMM.require_smc(self):
                # ksi established during the auth procedure
                return self._ret_smc(Proc.ksi)
        #
        elif isinstance(Proc, EMMSecurityModeControl):
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
        self.rm_from_emm_stack()
        if self.errcause:
            self._nas_tx = NAS.EMMStatus(EMMCause=self.errcause)
            return self.S1.ret_s1ap_dnt(self._nas_tx)
        #
        else:
            if not self.S1.ESM.PDN:
                if self.EMM.SER_PDN_ALW:
                    esmd = self.S1.ESM
                    # in case no PDN were activated, create a minimal one
                    if esmd.APN_DEFAULT not in esmd.PDNConfig:
                        self._log('INF', 'no PDN config available')
                        return []
                    pdncfg = esmd.PDNConfig[esmd.APN_DEFAULT]
                    # always use the IPv4 address only
                    ipaddr, err = esmd._get_pdn_addr(pdncfg, 1)
                    if err:
                        return []
                    esmd.rab_set_default(5, self.S1.ESM.APN_DEFAULT, ipaddr, pdncfg)
                else:
                    self._log('WNG', 'no PDN config available')
                    return []
            elif self.EMM.SER_RAB_NEVER:
                return []
            # reactivate all PDN connections
            S1apProc = self.S1.bearer_act()
            if S1apProc:
                return [S1apProc]
            else:
                return []


class EMMExtServiceRequest(EMMSigProc):
    """Extended service request procedure: TS 24.301, section 5.6.1
    
    UE-initiated
    
    CN message:
        None
    
    UE message:
        EMMExtServiceRequest (PD 7, Type 76), IEs:
        - Type1V    : NAS_KSI
        - Type1V    : ServiceType
        - Type4LV   : MTMSI
        - Type1TV   : CSFBResponse
        - Type4TLV  : EPSBearerCtxtStat
        - Type1TV   : DeviceProp
    """
    
    Cont = (
        None,
        (TS24301_EMM.EMMExtServiceRequest, )
        )
    
    def process(self, pdu):
        # preempt the EMM stack
        self.emm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # TODO
        
        self.rm_from_emm_stack()
        return []
     

class EMMCPServiceRequest(EMMSigProc):
    """Control-Plane service request procedure: TS 24.301, section 5.6.1
    
    UE-initiated
    
    CN message:
        None
    
    UE message:
        EMMCPServiceRequest (PD 7, Type 77), IEs:
        - Type1V    : NAS_KSI
        - Type1V    : CPServiceType
        - Type6TLVE : ESMContainer
        - Type4TLV  : NASContainer
        - Type4TLV  : EPSBearerCtxtStat
        - Type1TV   : DeviceProp
    """
    
    Cont = (
        None,
        (TS24301_EMM.EMMCPServiceRequest, )
        )
    
    def process(self, pdu):
        # preempt the EMM stack
        self.emm_preempt()
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # TODO
        
        self.rm_from_emm_stack()
        return []


class EMMDLNASTransport(EMMSigProc):
    """Transport of NAS messages procedure: TS 24.301, section 5.6.3
    
    CN-initiated
    
    CN message:
        EMMDLNASTransport (PD 7, Type 98), IEs:
        - Type4LV   : NASContainer
    
    UE message:
        None
    """
    
    Cont = (
        (TS24301_EMM.EMMDLNASTransport, ),
        None
        )
    
    Init = (7, 98)
    
    def output(self):
        self.encode_msg(7, 98)
        if not self._sec:
            self._nas_tx._sec = False
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.rm_from_emm_stack()
        return self.S1.ret_s1ap_dnt(self._nas_tx)


class EMMULNASTransport(EMMSigProc):
    """Transport of NAS messages procedure: TS 24.301, section 5.6.3
    
    UE-initiated
    
    CN message:
        None
    
    UE message:
        EMMULNASTransport (PD 7, Type 99), IEs:
        - Type4LV   : NASContainer
    """
    
    Cont = (
        None,
        (TS24301_EMM.EMMULNASTransport, )
        )
    
    def process(self, pdu):
        # preempt the EMM stack
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        #
        # decode the SMS CP layer
        SMSRx, self.errcause = NAS.parse_NAS_MO(self.UEInfo['NASContainer'].get_val())
        if not self.errcause and SMSRx[0][0]['ProtDisc'].get_val() != 9:
            self.errcause = 96
        if self.errcause:
            self._nas_tx = NAS.EMMStatus(EMMCause=self.errcause)
            ret = self.S1.ret_s1ap_dnt(self._nas_tx)
        else:
            ret = []
            # transfer the CP message to the SMS stack
            retcp = self.S1.SMS.process(SMSRx)
            for SMSTx in retcp:
                # pack them into EMMDLNASTransport procedure
                NasProc = self.EMM.init_proc(EMMDLNASTransport,
                                             encod={(7, 98): {'NASContainer': SMSTx.to_bytes()}})
                ret.extend( NasProc.output() )
        self.rm_from_emm_stack()
        return ret


class EMMDLGenericNASTransport(EMMSigProc):
    """Generic transport of NAS messages procedure: TS 24.301, section 5.6.4
    
    CN-initiated
    
    CN message:
        EMMDLGenericNASTransport (PD 7, Type 104), IEs:
        - Type3V    : GenericContType
        - Type6LVE  : GenericContainer
        - Type4TLV  : AddInfo
    
    UE message:
        None
    """
    
    Cont = (
        (TS24301_EMM.EMMDLGenericNASTransport, ),
        None
        )
    
    Init = (7, 104)
    
    def output(self):
        self.encode_msg(7, 104)
        if not self._sec:
            self._nas_tx._sec = False
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', self._nas_tx) )
        self.rm_from_emm_stack()
        return self.S1.ret_s1ap_dnt(self._nas_tx)


class EMMULGenericNASTransport(EMMSigProc):
    """Generic transport of NAS messages procedure: TS 24.301, section 5.6.4
    
    UE-initiated
    
    CN message:
        None
    
    UE message:
        EMMULGenericNASTransport (PD 7, Type 105), IEs:
        - Type3V    : GenericContType
        - Type6LVE  : GenericContainer
        - Type4TLV  : AddInfo
    """
    
    Cont = (
        None,
        (TS24301_EMM.EMMULGenericNASTransport, )
        )
    
    def process(self, pdu):
        # preempt the EMM stack
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', pdu) )
        self.UEInfo = {}
        self.decode_msg(pdu, self.UEInfo)
        # TODO
        
        self.rm_from_emm_stack()
        return []


EMMGUTIReallocation.init(filter_init=1)
EMMAuthentication.init(filter_init=1)
EMMSecurityModeControl.init(filter_init=1)
EMMIdentification.init(filter_init=1)
EMMInformation.init(filter_init=1)
EMMAttach.init(filter_init=1)
EMMDetachUE.init(filter_init=1)
EMMDetachCN.init(filter_init=1)
EMMTrackingAreaUpdate.init(filter_init=1)
EMMServiceRequest.init(filter_init=1)
EMMExtServiceRequest.init(filter_init=1)
EMMCPServiceRequest.init(filter_init=1)
EMMDLNASTransport.init(filter_init=1)
EMMULNASTransport.init(filter_init=1)
EMMDLGenericNASTransport.init(filter_init=1)
EMMULGenericNASTransport.init(filter_init=1)

# EMM UE-initiated procedures dispatcher
EMMProcUeDispatcher = {
    0  : EMMServiceRequest,
    65 : EMMAttach,
    69 : EMMDetachUE,
    72 : EMMTrackingAreaUpdate,
    76 : EMMExtServiceRequest,
    77 : EMMCPServiceRequest,
    99 : EMMULNASTransport,
    105 : EMMULGenericNASTransport
    }
EMMProcUeDispatcherStr = {ProcClass.Cont[1][0]()._name: ProcClass \
                          for ProcClass in EMMProcUeDispatcher.values()}

# EMM CN-initiated procedures dispatcher
EMMProcCnDispatcher = {
    69 : EMMDetachCN,
    80 : EMMGUTIReallocation,
    82 : EMMAuthentication,
    85 : EMMIdentification,
    93 : EMMSecurityModeControl,
    97 : EMMInformation,
    98 : EMMDLNASTransport,
    104 : EMMDLGenericNASTransport
    }
EMMProcCnDispatcherStr = {ProcClass.Cont[0][0]()._name: ProcClass \
                          for ProcClass in EMMProcCnDispatcher.values()}

