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
# * File Name : pycrate_corenet/HdlrUES1.py
# * Created : 2017-07-11
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils      import *
from .ProcCNS1ap import *
from .ProcCNEMM  import *
from .ProcCNESM  import *
from .HdlrUESMS  import *


# WNG: all procedures that call .require_smc() method need to be set in this LUT
ProcAbbrLUT = {
    'EMMAttach'                : 'ATT',
    'EMMTrackingAreaUpdate'    : 'TAU',
    'EMMDetachUE'              : 'DET',
    'EMMServiceRequest'        : 'SER',
    'EMMExtServiceRequest'     : 'SER',
    'EMMCPServiceRequest'      : 'SER',
    }


class UEEMMd(SigStack):
    """UE EMM handler within a UES1d instance
    responsible for EPS Mobility Management signalling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the UES1d
    S1 = None
    
    # state: INACTIVE (cannot be paged) <-> ACTIVE <-> IDLE
    state = 'INACTIVE'
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    # additional time for letting background task happen in priority
    _WAIT_ADD = 0.005
    
    # list of EMM message types that do not require NAS security to be
    # activated to be processed
    SEC_NOTNEED = {
        'EMMAttachRequest',
        'EMMIdentityResponse', # only for IMSI
        'EMMAuthenticationResponse',
        'EMMAuthenticationFailure',
        'EMMSecurityModeReject',
        'EMMDetachRequestMO', # if sent before security activation
        'EMMDetachAccept',
        'EMMTrackingAreaUpdateRequest',
        'EMMServiceRequest',
        'EMMExtServiceRequest'
       }
    # to disable completely the check for secured NAS message
    SEC_DISABLED = False
    
    #--------------------------------------------------------------------------#
    # EMM common parameters
    #--------------------------------------------------------------------------#
    # T3412, periodic TAU timer: dict {'Unit': uint3, 'Value': uint5}
    # Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    _T3412             = {'Unit': 2, 'Value': 2} # 12mn
    #_T3412             = {'Unit': 7, 'Value': 0} # deactivated
    # 
    # Reattach attempt after a failure timer: dict {'Unit': uint3, 'Value': uint5}
    # Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    _T3402              = {'Unit': 1, 'Value': 2} # 2mn
    #
    # T3412Ext, power saving mode, TAU extended timer: None or dict {'Unit': uint3, 'Value': uint5}
    # Unit: 0: 10mn, 1: 1h, 2: 10h, 3: 2s, 4: 30s, 5: 1mn, 6: 320h, 7: deactivated
    _T3412_EXT          = None
    #
    # T3324, power saving mode, time the UE stays active after idle mode following
    # Attach or TAU: None or dict {'Unit': uint3, 'Value': uint5}
    # # Unit: 0: 2s, 1: 1mxn, 2: 6mn, 7: deactivated
    _T3324              = None
    #
    # EPS Network features support: if None, not sent, otherwise dict
    # {'CP_CIoT': uint1, 'ERwoPDN': uint1, 'ESR_PS': uint1, 'CS_LCS': uint2,
    #  'EPC_LCS': uint1, 'EMC_BS': uint1, 'IMS_VoPS': uint1, 'EPCO': uint1,
    #  'HC_CP_CIoT': uint1, 'S1U_Data': uint1, 'UP_CIoT': uint1}
    _EPS_NETFEAT_SUPP   = None
    #
    # Extended DRX support: if None and sent by the UE, value returned it the one
    # from the UE ; otherwise dict {'PTX': uint4, 'eDRX': uint4}
    _EXTDRX             = None
    #
    # SMS service status: if defined (status cause 0 to 3), denies SMS service 
    # for EPS-only attach
    _SMS_SERV_STAT      = None
    
    #--------------------------------------------------------------------------#
    # EMMStatus policy
    #--------------------------------------------------------------------------#
    # behaviour when receiving EMM STATUS
    # 0: do nothing,
    # 1: abort the top-level EMM procedure,
    # 2: abort the whole stack of EMM procedures
    STAT_CLEAR          = 2
    
    #--------------------------------------------------------------------------#
    # EMMGUTIReallocation policy
    #--------------------------------------------------------------------------#
    # EMM procedure timer
    T3450               = 4
    
    #--------------------------------------------------------------------------#
    # EMMAuthentication policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all authentication procedures
    AUTH_DISABLED       = False
    # EMM procedure timer for auth and smc
    T3460               = 4
    # Authentication Management Field
    AUTH_AMF            = b'\x80\0'
    # if AUTH_PLMN is not None, it will be used for building the 4G auth vector
    # otherwise the main Corenet PLMN will be used
    AUTH_PLMN           = None
    # this is to force a 2G or 3G authentication instead of a 4G one
    AUTH_2G             = False
    AUTH_3G             = False
    # this is to extend AUTN with arbitrary data
    AUTH_AUTN_EXT       = None
    #
    # re-authentication policy:
    # this forces an auth procedure every X EMM TAU / (Ext/CP) SER procedures
    # even if a valid KSI is provided by the UE
    AUTH_TAU            = 1
    AUTH_SER            = 5
    AUTH_DET            = 1 # only applied to Detach without UE power off
    
    #--------------------------------------------------------------------------#
    # EMMSecurityModeControl policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all NAS SMC procedures during UE signalling
    SMC_DISABLED        = False
    # this will bypass the NAS SMC procedure into specific UE signalling procedure
    # set proc abbreviation in the list: 'ATT', 'TAU', 'SER'
    SMC_DISABLED_PROC   = []
    # list of algorithm priorities
    #SMC_EEA_PRIO        = [2, 1, 0]
    SMC_EEA_PRIO        = [0]
    SMC_EIA_PRIO        = [2, 1]
    #
    # UE security capabilities: add dummy 3G sec cap if GPRS sec cap available
    SMC_SECCAP_W2G      = False
    # UE default algorithm identifier, when everything else is failing...
    SMC_EEA_DEF         = 0
    SMC_EIA_DEF         = 1
    # request IMEISV during a NAS SMC when IMEISV is unknown
    SMC_IMEISV_REQ      = True
    #
    # dummy security cap / context when security is disabled
    # the SMC_EMERG_USE will change the output of self.require_smc() to still 
    # trigger an SMC even if there is no security context
    # then the SMC procedure will use the SMC_DUMMY_CTX
    SMC_EMERG_USE       = False
    SMC_DUMMY_SECCAP    = NAS.UESecCap(val={'EEA0':1, 'EEA1_128':1, 'EEA2_128':1,
                                            'EIA0':1, 'EIA1_128':1, 'EIA2_128':1}).to_bytes()[:2]
    
    #--------------------------------------------------------------------------#
    # EMMIdentification policy
    #--------------------------------------------------------------------------#
    # EMM procedure timer
    T3470               = 2
    #
    # potential reject causes:
    # 2: 'IMSI unknown in HLR', -> kill the cellular connectivity until SIM card is removed
    # 3: 'Illegal MS', -> maybe same as 2
    # 4: 'IMSI unknown in VLR',
    # 5: 'IMEI not accepted', -> maybe same as 2
    # 6: 'Illegal ME',
    # 11: 'PLMN not allowed',
    # 12: 'Location Area not allowed',
    # 13: 'Roaming not allowed in this location area',
    # 15: 'No Suitable Cells In Location Area',
    # 17: 'Network failure',
    # 22: 'Congestion'
    # ...
    IDENT_IMSI_NOT_ALLOWED = 11
    IDENT_IMEI_NOT_ALLOWED = 5
    
    #--------------------------------------------------------------------------#
    # EMMAttach policy
    #--------------------------------------------------------------------------#
    ATT_T3412           = _T3412
    ATT_T3402           = _T3402
    ATT_T3412_EXT       = _T3412_EXT
    ATT_T3324           = _T3324
    ATT_EPS_NETFEAT_SUPP = _EPS_NETFEAT_SUPP
    ATT_EXTDRX          = _EXTDRX
    ATT_SMS_SERV_STAT   = _SMS_SERV_STAT
    # if 0, enable IMSI attach from EPS; if > 0, use it as error code
    # e.g. 18: CS domain not available
    ATT_IMSI            = 0
    # if 0, enable emergency attach; if > 0, use it as error code 
    # e.g. 8: EPS services and non-EPS services not allowed)
    ATT_EMERG           = 0
    # if we want to run a GUTI Reallocation within the EMM Attach Accept
    ATT_GUTI_REALLOC    = True
    # if we want to release the S1 ue context after the procedure ends 
    ATT_S1REL           = False
    # if we want to release the S1 ue context after the procedure fails
    ATT_S1REL_ONERR     = True
    #
    # when a UEd with MTMSI was created, that in fact corresponds to a UE
    # already set in Server.UE, we need to reject it after updating Server.MTMSI
    ATT_IMSI_PROV_REJECT = 17
    # timer within Attach Reject, Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    ATT_T3346           = {'Unit': 0, 'Value': 2}
    
    #--------------------------------------------------------------------------#
    # EMMTrackingAreaUpdate policy
    #--------------------------------------------------------------------------#
    TAU_T3412           = _T3412
    TAU_T3402           = _T3402
    TAU_T3412_EXT       = _T3412_EXT
    TAU_T3324           = _T3324
    TAU_EPS_NETFEAT_SUPP = _EPS_NETFEAT_SUPP
    TAU_EXTDRX          = _EXTDRX
    TAU_SMS_SERV_STAT   = _SMS_SERV_STAT
    # if we want to run a GUTI Reallocation within the EMM TAU Accept
    TAU_GUTI_REALLOC    = True
    # if we want to release the S1 ue context after the procedure ends 
    TAU_S1REL           = True
    
    #--------------------------------------------------------------------------#
    # EMMServiceRequest policy
    #--------------------------------------------------------------------------#
    # to always start an SMC after a service request, even if no auth happened
    SER_SMC_ALW         = False
    # to create a default PDN config in case it was deleted
    SER_PDN_ALW         = False
    # to never setup a radio bearer
    SER_RAB_NEVER       = False
    
    
    def _log(self, logtype, msg):
        self.S1._log(logtype, '[EMM] %s' % msg)
    
    def __init__(self, ued, ues1d):
        self.UE = ued
        self.set_s1(ues1d)
        #
        # ready event, used by foreground tasks (network / interpreter initiated)
        self.ready = Event()
        self.ready.set()
        # stack of ongoing EMM procedures (i.e. common procedures can be run 
        # within specific procedure)
        self.Proc   = []
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc  = []
    
    def set_s1(self, ues1d):
        self.S1 = ues1d
    
    def process(self, NasRx):
        """process a NAS EMM message (NasRx) sent by the UE,
        and return a list (possibly empty) of S1AP procedure(s) to be sent back 
        to the eNB
        
        NasRx has 2 additional attributes (_sec [bool], _ulcnt [uint])
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        name = NasRx._name
        # 1) in case sec check failed, see if request is still to be accepted
        if not NasRx._sec and not self.SEC_DISABLED and name not in self.SEC_NOTNEED:
            # discard the msg
            self._log('INF', 'discarding %s message, failed security check' % name)
            return []
        #
        # 2) check if it is a Detach Request
        if name == 'EMMDetachRequestMO':
            Proc = EMMDetachUE(self)
            self.Proc.append( Proc )
            if self.TRACK_PROC:
                self._proc.append(Proc)
            # GMMDetachUE.process() will abort every other ongoing NAS procedures
            # for the PS domain
            return Proc.process(NasRx)
        #
        # 3) check if there is any ongoing EMM procedure
        elif self.Proc:
            # 2.1) in case of STATUS, disable ongoing procedure(s)
            if name == 'EMMStatus':
                self._log('WNG', 'STATUS received with %r' % NasRx['EMMCause'])
                if self.STAT_CLEAR == 1:
                    #self._log('WNG', 'STATUS, disabling %r' % self.Proc[-1])
                    self.Proc[-1].abort()
                elif self.STAT_CLEAR == 2:
                    #self._log('WNG', 'STATUS, disabling %r' % self.Proc)
                    self.clear()
                return []
            #
            # 2.2) in case of expected response
            elif name in self.Proc[-1].FilterStr:
                Proc = self.Proc[-1]
                S1apTxProc = Proc.process(NasRx)
                while self.Proc and not S1apTxProc:
                    # while the top-level NAS procedure has nothing to respond and terminates,
                    # we postprocess() lower-level NAS procedure(s) until we have something
                    # to send, or the stack is empty
                    ProcLower = self.Proc[-1]
                    S1apTxProc = ProcLower.postprocess(Proc)
                    Proc = ProcLower
                return S1apTxProc
            #
            # 2.3) in case of unexpected NasRx
            else:
                self._log('WNG', 'unexpected %s message, sending STATUS 98' % name)
                # cause 98: Message type not compatible with the protocol state
                return self.S1.ret_s1ap_dnt(NAS.EMMStatus(val={'EMMCause':98}, sec=NasRx._sec))
        #
        # 3) start a new UE-initiated procedure
        elif name in EMMProcUeDispatcherStr:
            Proc = EMMProcUeDispatcherStr[name](self)
            self.Proc.append( Proc )
            if self.TRACK_PROC:
                self._proc.append(Proc)
            return Proc.process(NasRx)
        #
        # 4) unexpected NasRx
        else:
            self._log('WNG', 'unexpected %s message, sending STATUS 96' % name)
            # cause 96: Invalid mandatory information
            return self.S1.ret_s1ap_dnt(NAS.EMMStatus(val={'EMMCause':96}, sec=NasRx._sec))
    
    def init_proc(self, ProcClass, encod=None, emm_preempt=False, sec=True):
        """initialize a CN-initiated EMM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        Proc = ProcClass(self, encod=encod, emm_preempt=emm_preempt, sec=sec)
        self.Proc.append( Proc )
        if self.TRACK_PROC:
            self._proc.append( Proc )
        return Proc
    
    def clear(self):
        """abort all running procedures
        """
        for Proc in self.Proc[::-1]:
            Proc.abort()
    
    #--------------------------------------------------------------------------#
    # SMC and security-related methods
    #--------------------------------------------------------------------------#
    
    def require_auth(self, Proc, ksi=None):
        # ksi is a 2-tuple (TSC 0..1, Value 0..7)
        # check if an EMMAuthentication procedure is required
        if self.S1.SECNAS_DISABLED or self.AUTH_DISABLED:
            return False
        elif ksi is None or ksi[1] == 7:
            self.S1.SEC['KSI'] = None
            return True
        #
        ksi = (ksi[0]<<3) + ksi[1]
        if ksi not in self.S1.SEC:
            self.S1.SEC['KSI'] = None
            return True
        #
        else:
            # auth policy per EMM procedure
            if isinstance(Proc, EMMAttach):
                # always authenticate within an Attach
                return True
            elif isinstance(Proc, EMMTrackingAreaUpdate):
                self.S1.SEC['POL']['TAU'] += 1
                if self.AUTH_TAU and self.S1.SEC['POL']['TAU'] % self.AUTH_TAU == 0:
                    self.S1.SEC['KSI'] = None
                    return True
                else:
                    self.S1.SEC['KSI'] = ksi
                    return False
            elif isinstance(Proc, EMMDetachUE):
                self.S1.SEC['POL']['DET'] += 1
                if self.AUTH_DET and self.S1.SEC['POL']['TAU'] % self.AUTH_DET == 0:
                    self.S1.SEC['KSI'] = None
                    return True
                else:
                    self.S1.SEC['KSI'] = ksi
                    return False
            elif isinstance(Proc, (EMMServiceRequest, EMMExtServiceRequest, EMMCPServiceRequest)):
                self.S1.SEC['POL']['SER'] += 1
                if self.AUTH_SER and self.S1.SEC['POL']['SER'] % self.AUTH_SER == 0:
                    self.S1.SEC['KSI'] = None
                    return True
                else:
                    self.S1.SEC['KSI'] = ksi
                    return False
            else:
                # auth not required, use the UE-provided cksn in use
                self.S1.SEC['KSI'] = ksi
                return False
    
    def require_smc(self, Proc):
        # check if an EMMSecurityModeControl procedure is required
        if self.S1.SECNAS_DISABLED or self.SMC_DISABLED:
            return False
        #
        elif ProcAbbrLUT[Proc.Name] in self.SMC_DISABLED_PROC:
            return False
        #
        elif not self.SMC_EMERG_USE and \
        (self.S1.SEC['KSI'] is None or self.S1.SEC['KSI'] not in self.S1.SEC):
            # no security context established, cannot run an smc
            self._log('WNG', 'require_smc: no KSI set, unable to run an SMC')
            return False
        #
        else:
            return True
    
    def get_any_ksi(self):
        cur = self.S1.SEC['KSI']
        if cur is not None:
            if cur in self.S1.SEC:
                return cur
            else:
                self.S1.SEC['KSI'] = None
        #
        for i in range(0, 7):
            if i in self.S1.SEC:
                self.S1.SEC['KSI'] = i
                return i
        for i in range(8, 15):
            if i in self.S1.SEC:
                self._log('INF', 'selecting a mapped KSI %i' % i)
                self.S1.SEC['KSI'] = i
                return i
        return None
    
    def get_new_ksi(self):
        for i in range(0, 7):
            if i not in self.S1.SEC:
                return i
        # all native KSI have been used, clear all of them except the current one
        # if defined
        cur = self.S1.SEC['KSI']
        for i in range(0, 7):
            if i != cur:
                del self.S1.SEC[i]
        if cur == 0:
            return 1
        else:
            return 0
    
    def set_sec_ctx(self, ksi, ctx, vect):
        ksi = (ksi[0]<<3) + ksi[1]
        if ctx == 3:
            if self.AUTH_PLMN:
                snid = plmn_str_to_buf(self.AUTH_PLMN)
            else:
                snid = plmn_str_to_buf(self.UE.PLMN)
            Kasme  = conv_401_A2(vect[3], vect[4], snid, vect[2][:6])
            secctx = {'VEC'  : vect,
                      'CTX'  : ctx,
                      'CK'   : vect[3],
                      'IK'   : vect[4],
                      'Kasme': Kasme}
        elif ctx == 2:
            # WNG: this is undefined / illegal and won't work (hopefully)
            CK, IK = conv_102_C4(vect[2]), conv_102_C5(vect[2])
            if self.AUTH_PLMN:
                snid = plmn_str_to_buf(self.AUTH_PLMN)
            else:
                snid = plmn_str_to_buf(self.UE.PLMN)
            Kasme  = conv_401_A2(CK, IK, snid, b'\0\0\0\0\0\0')
            secctx = {'VEC'  : vect,
                      'CTX'  : ctx,
                      'Kc'   : vect[2],
                      'CK'   : CK,
                      'IK'   : IK,
                      'Kasme': Kasme}
        else:
            # ctx == 4
            secctx = {'VEC'  : vect,
                      'CTX'  : ctx,
                      'Kasme': vect[3]}
        #
        secctx['UL'], secctx['DL'], secctx['UL_enb'] = 0, 0, 0
        self.S1.SEC[ksi] = secctx
        self.S1.SEC['KSI'] = ksi
    
    def set_sec_ctx_emerg(self, ksi=0):
        secctx = {'CTX'    : 0,
                  'Kasme'  : 32*b'\0',
                  'Knasenc': 16*b'\0',
                  'Knasint': 16*b'\0',
                  'EEA'    : 0,
                  'EIA'    : 0,
                  'UL'     : 0,
                  'DL'     : 0,
                  'UL_enb' : 0}
        self.S1.SEC[ksi] = secctx
    
    def set_sec_ctx_smc(self, ksi):
        try:
            secctx = self.S1.SEC[ksi]
        except Exception:
            pass
        else:
            secctx['EEA'], secctx['EIA'] = self._get_sec_eea(), self._get_sec_eia()
            secctx['Knasenc'] = conv_401_A7(secctx['Kasme'], 1, secctx['EEA'])[16:32]
            secctx['Knasint'] = conv_401_A7(secctx['Kasme'], 2, secctx['EIA'])[16:32]
    
    def set_sec_cap(self):
        # build UESecCap from UENetCap
        if 'UENetCap' in self.UE.Cap:
            ueseccap = self.UE.Cap['UENetCap'][0]
            if len(ueseccap) > 4:
                # we have more than 3G and 4G sec cap
                ueseccap = ueseccap[:4]
            if len(ueseccap) == 4:
                # void UCS2 support
                lastoct  = ord(ueseccap[3:4])
                if lastoct & 0x80:
                    ueseccap = ueseccap[:3] + bchr(lastoct^0x80)
                if 'MSNetCap' in self.UE.Cap:
                    ueseccap += self._get_sec_gea_cap()
            else:
                assert( len(ueseccap) == 2 )
                if self.SMC_SECCAP_W2G and 'MSNetCap' in self.UE.Cap:
                    ueseccap += b'\0\0'
                    ueseccap += self._get_sec_gea_cap()
            UESecCap = NAS.UESecCap()
            UESecCap.from_bytes(ueseccap)
            self.UE.Cap['UESecCap'] = (ueseccap, UESecCap)
    
    def _get_sec_gea_cap(self):
        msnetcap = self.UE.Cap['MSNetCap'][1]()
        v = msnetcap[0]<< 6 # GEA1
        if isinstance(msnetcap[8], list):
            # Extended_GEA_bits
            for i, b in enumerate(msnetcap[8]):
                v += b << (5-i)
        # TODO: add GIA sec cap
        return bchr(v)
    
    def get_sec_cap(self):
        if 'UESecCap' not in self.UE.Cap:
            # build UESecCap from UENetCap
            if 'UENetCap' in self.UE.Cap:
                self.set_sec_cap()
                return self.UE.Cap['UESecCap'][0]
            else:
                # build UESecCap from SMC_DUMMY_SECCAP
                self._log('WNG', 'no security capabilities available, using dummy ones')
                return self.SMC_DUMMY_SECCAP
        else:
            return self.UE.Cap['UESecCap'][0]
    
    def _get_sec_eea(self):
        if 'UESecCap' not in self.UE.Cap:
            self._log('WNG', 'no security capabilities available, using EEA%i' % self.SMC_EEA_DEF)
            return self.SMC_EEA_DEF
        else:
            UESecCap = self.UE.Cap['UESecCap'][1]
            for eea in self.SMC_EEA_PRIO:
                if UESecCap._content[eea].get_val():
                    return eea
            self._log('INF', 'no matching EEA identifier, using EEA%i' % self.SMC_EEA_DEF)
            return self.SMC_EEA_DEF
    
    def _get_sec_eia(self):
        if 'UESecCap' not in self.UE.Cap:
            self._log('WNG', 'no security capabilities available, using EIA%i' % self.SMC_EIA_DEF)
            return self.SMC_EIA_DEF
        else:
            UESecCap = self.UE.Cap['UESecCap'][1]
            for eia in self.SMC_EIA_PRIO:
                if UESecCap._content[8+eia].get_val():
                    return eia
            self._log('INF', 'no matching EIA identifier, using EIA%i' % self.SMC_EIA_DEF)
            return self.SMC_EEA_DEF
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    def _net_init_con(self):
        if not self.S1.page_block():
            return False
        # need to wait for potential EMM serving / common procedures to happen and end
        sleep(self._WAIT_ADD)
        if not self.ready.wait(10):
            # something is blocking in the serving / common procedures
            return False
        elif not self.S1.connected.is_set():
            # something went wrong during the serving / common procedures
            return False
        else:
            return True
    
    def run_proc(self, ProcClass, sec=True, **IEs):
        """run a network-initiated procedure ProcClass in the context of the EMM
        stack, after setting the given IEs in the NAS message to be sent to the 
        UE
        
        returns a 2-tuple (success, proc)
            success is a bool
            proc is the instance of ProcClass or None
        """
        if ProcClass.Init is None:
            self._log('ERR', 'invalid network-initiated procedure %s' % ProcClass.Name)
            return False, None
        if not self._net_init_con():
            return False, None
        #
        Proc = self.init_proc(ProcClass, encod={ProcClass.Init: IEs}, emm_preempt=True, sec=sec)
        try:
            S1apTxProc = Proc.output()
        except Exception:
            self._log('ERR', 'invalid IEs for network-initiated procedure %s' % Proc.Name)
            Proc.abort()
            return False, Proc
        if not self.S1.transmit_s1ap_proc(S1apTxProc):
            return False, Proc
        #
        # check if a response is expected
        if not hasattr(Proc, 'TimerValue'):
            return True, Proc
        elif not self.ready.wait(Proc.TimerValue + self._WAIT_ADD):
            # procedure is stuck, will be aborted in the server loop
            # WNG: this means the routine for cleaning NAS procedures in timeout 
            # should be enabled in CorenetServer
            return False, Proc
        #
        # check is a response was received
        if hasattr(Proc, 'UEInfo'):
            return True, Proc
        else:
            return False, Proc
     
    def req_ident(self, idtype=NAS.IDTYPE_IMSI):
        """start an EMM Identification procedure toward the UE and wait for the
        response or timeout
        """
        return self.run_proc(EMMIdentification, IDType=idtype)
    
    def detach(self, type=1, cause=None):
        """send an EMM Detach with type and cause (optional) and wait for the
        response or timeout
        """
        if cause is not None:
            return self.run_proc(EMMDetachCN, EPSDetachTypeMT={'Type': type}, EMMCause=cause)
        else:
            return self.run_proc(EMMDetachCN, EPSDetachTypeMT={'Type': type})
    
    def inform(self, **info):
        """send an EMM information with given info
        """
        return self.run_proc(EMMInformation, **info)


class UEESMd(SigStack):
    """UE ESM handler within a UES1d instance
    responsible for EPS Session Management signalling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the UES1d
    S1 = None
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    # list of ESM message types that do not require NAS security to be
    # activated to be processed
    SEC_NOTNEED = {'ESMPDNConnectivityRequest'}
    # to disable completely the check for secured NAS message
    SEC_DISABLED = False
    
    # default Radio Access Bearer settings for PDN config, per APN
    # QCI (being LTE + EPS) is copied from the CorenetServer.ConfigPDN at UE init
    RABConfig = {
        '*'      : {'PriorityLevel': 15, # 0..15, 1: highest, 14: lowest, 15: no priority
                    'PreemptCap'   : 'shall-not-trigger-pre-emption', # or 'may-trigger-pre-emption'
                    'PreemptVuln'  : 'not-pre-emptable', # or 'pre-emptable'
                    'BitrateDL'    : 100000000, # aggregate max bitrate downlink (b/s)
                    'BitrateUL'    : 50000000, # aggregate max bitrate uplink (b/s)
                    },
        'corenet': {'PriorityLevel': 14, # 0..15, 1: highest, 14: lowest, 15: no priority
                    'PreemptCap'   : 'shall-not-trigger-pre-emption', # or 'may-trigger-pre-emption'
                    'PreemptVuln'  : 'not-pre-emptable', # 'pre-emptable'
                    'BitrateDL'    : 100000000, # aggregate max bitrate downlink (b/s)
                    'BitrateUL'    : 50000000, # aggregate max bitrate uplink (b/s)
                    }
        }
    # when the UE 1st attach it gets a specific PDNConfig dict with a copy of this content
    # under the key 'RAB'
    
    # Default APN in case the UE does not indicate any APN for the default connectivity
    # If None, an APN must be explicitely requested by the UE
    # Otherwise, it must be a standard APN from the configuration
    APN_DEFAULT = 'corenet'
    
    # Protocol config option with authentication
    # if bypass enabled, the PAP / CHAP authentication will not be checked against
    # the CorenetServer.PDNConfig and always return authentication success
    AUTH_PAP_BYPASS  = True
    AUTH_CHAP_BYPASS = True
    
    #--------------------------------------------------------------------------#
    # ESMStatus policy
    #--------------------------------------------------------------------------#
    # behaviour when receiving ESM STATUS
    # 0: do nothing,
    # 1: abort the top ESM procedure for the indicated EPS bearer ID
    # 2: abort the whole ESM procedure stack for the indicated EPS bearer ID
    # 3: abort all the ESM procedures stacks
    STAT_CLEAR = 3
    
    #--------------------------------------------------------------------------#
    # ESMDefaultEPSBearerCtxtAct / ESMDedicatedEPSBearerCtxtAct policy
    #--------------------------------------------------------------------------#
    T3485 = 2
    
    #--------------------------------------------------------------------------#
    # ESMEPSBearerCtxtModif policy
    #--------------------------------------------------------------------------#
    T3486 = 2
    
    #--------------------------------------------------------------------------#
    # ESMEPSBearerCtxtDeact policy
    #--------------------------------------------------------------------------#
    T3495 = 2
    
    #--------------------------------------------------------------------------#
    # ESMInfoRequest policy
    #--------------------------------------------------------------------------#
    T3489 = 2
    
    
    def _log(self, logtype, msg):
        self.S1._log(logtype, '[ESM] %s' % msg)
    
    def __init__(self, ued, ues1d):
        self.UE = ued
        self.set_s1(ues1d)
        #
        # dict of ongoing ESM procedures, indexed by EPS bearer ID
        self.Proc  = {i: [] for i in range(16)}
        # dict of configured PDN, indexed by EPS bearer ID
        self.PDN   = {}
        # dict of ongoing ESM transactions IEs
        self.Trans = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_s1(self, ues1d):
        self.S1 = ues1d
    
    def process_buf(self, buf, sec, EMMProc=None):
        """process a NAS ESM message buffer (buf) sent by the UE,
        if the decoding is correct, return the result of process()
        """
        ESMRx, err = NAS.parse_NASLTE_MO(buf, inner=False)
        if err:
            # invalid ESM message
            self._log('WNG', 'invalid EPS NAS ESM message: %s' % hexlify(buf).decode('ascii'))
            ESMTx = NAS.ESMStatus(val={'ESMCause':err}, sec=sec)
            return self.S1.ret_s1ap_dnt(self.output_nas_esm(ESMTx, EMMProc))
        #
        elif ESMRx[0]['ProtDisc'].get_val() != 2:
            # cause 96: Invalid mandatory information
            self._log('WNG', 'invalid EPS NAS ESM message: %r' % ESMRx)
            ESMTx = NAS.ESMStatus(val={'ESMCause':96}, sec=sec)
            return self.S1.ret_s1ap_dnt(self.output_nas_esm(ESMTx, EMMProc))
        #
        elif self.UE.TRACE_NAS_EPS:
            self._log('TRACE_NAS_EPS_UL', '\n' + ESMRx.show())
        ESMRx._sec = sec
        return self.process(ESMRx, EMMProc=EMMProc)
    
    def process(self, NasRx, EMMProc=None):
        """process a NAS ESM message (NasRx) sent by the UE,
        and return a list (possibly empty) of S1AP procedure(s) to be sent back 
        to the eNB
        
        NasRx has 2 additional attributes (_sec [bool], _ulcnt [uint])
        
        EMMProc [EMMSigProc or None], indicates if the NAS ESM message is handled in 
        the context of an EMM procedure 
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        name = NasRx._name
        # 1) in case sec check failed, see if request is still to be accepted
        if not NasRx._sec and not self.SEC_DISABLED and name not in self.SEC_NOTNEED:
            # discard the msg
            self._log('INF', 'discarding %s message, failed security check' % name)
            return self.S1.ret_s1ap_dnt(self.output_nas_esm(None, EMMProc))
        #
        # 2) check if there is any ongoing ESM procedure for the given EPS bearer id
        ebi = NasRx[0][0].get_val()
        if self.Proc[ebi]:
            ProcStack = self.Proc[ebi]
            # 2.1) in case of STATUS, disable ongoing procedure(s)
            if name == 'ESMStatus':
                self._log('WNG', 'STATUS received with %r' % NasRx['ESMCause'])
                if self.STAT_CLEAR == 1:
                    #self._log('WNG', 'STATUS, disabling %r' % ProcStack[-1])
                    ProcStack[-1].abort()
                elif self.STAT_CLEAR == 2:
                    #self._log('WNG', 'STATUS, disabling %r' % ProcStack)
                    self.clear(ebi)
                elif self.STAT_CLEAR == 3:
                    #self._log('WNG', 'STATUS, disabling %r' % self.Proc)
                    self.clear()
                return self.S1.ret_s1ap_dnt(self.output_nas_esm(None, EMMProc))
            #
            # 2.2) in case of expected response
            elif name in ProcStack[-1].FilterStr:
                Proc = ProcStack[-1]
                S1apTxProc = Proc.process(NasRx)
                while ProcStack and not S1apTxProc:
                    # while the top-level NAS procedure has nothing to respond and terminates,
                    # we postprocess() lower-level NAS procedure(s) until we have something
                    # to send, or the stack is empty
                    ProcLower = ProcStack[-1]
                    S1apTxProc = ProcLower.postprocess(Proc)
                    Proc = ProcLower
                return S1apTxProc
            #
            # 2.3) in case of unexpected NasRx
            else:
                self._log('WNG', 'unexpected %s message, sending STATUS 98' % name)
                # cause 98: Message type not compatible with the protocol state
                ESMTx = NAS.ESMStatus(val={'ESMCause':96}, sec=NasRx._sec)
                return self.S1.ret_s1ap_dnt(self.output_nas_esm(ESMTx, EMMProc))
        #
        # 3) start a new UE-initiated procedure
        elif name in ESMProcUeDispatcherStr:
            Proc = ESMProcUeDispatcherStr[name](self, ebi=ebi, EMMProc=EMMProc)
            self.Proc[ebi].append(Proc)
            if self.TRACK_PROC:
                self._proc.append(Proc)
            return Proc.process(NasRx)
        #
        # 4) unexpected NasRx
        else:
            self._log('WNG', 'unexpected %s message, sending STATUS 96' % name)
            # cause 96: Invalid mandatory information
            ESMTx = NAS.ESMStatus(val={'ESMCause':96}, sec=NasRx._sec)
            return self.S1.ret_s1ap_dnt(self.output_nas_esm(ESMTx, EMMProc))
    
    def output_nas_esm(self, ESMTx, EMMProc):
        if not ESMTx:
            if EMMProc:
                self._log('WNG', 'output_nas_esm: no ESMTx but an EMMTx to be sent')
                return EMMProc._nas_tx
            else:
                return None
        elif EMMProc:
            ESMTx._sec = False
            EMMTx = EMMProc._nas_tx
            ESMCont = EMMTx['ESMContainer']
            ESMCont['V'].set_val(self.S1.output_nas_sec(ESMTx))
            if ESMCont.get_trans():
                ESMCont.set_trans(False)
            return EMMTx
        else:
            return ESMTx
    
    def init_proc(self, ProcClass, **kw):
        """initialize a CN-initiated ESM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        if 'ebi' in kw:
            ebi = kw['ebi']
            assert( 0 <= ebi <= 15 )
            del kw['ebi']
        else:
            ebi = 0
        Proc = ProcClass(self, ebi=ebi, **kw)
        self.Proc[ebi].append( Proc )
        if self.TRACK_PROC:
            self._proc.append( Proc )
        return Proc
    
    def clear(self, ebi=None):
        """abort all running procedures, eventually for a single EPS Bearer ID
        """
        self.Trans.clear()
        if ebi is None:
            for ebi in range(16):
                for Proc in self.Proc[ebi][::-1]:
                    Proc.abort()
        else:
            for Proc in self.Proc[ebi][::-1]:
                Proc.abort()
    
    def pdn_clear(self, ebi=None):
        if ebi is None:
            for ebi, pdncfg in list(self.PDN.items()):
                self.UE.Server.GTPUd.rem_mobile(pdncfg['RAB']['SGW-GTP-TEID'])
                del self.PDN[ebi]
        elif ebi in self.PDN:
            self.UE.Server.GTPUd.rem_mobile(self.PDN[ebi]['RAB']['SGW-GTP-TEID'])
            del self.PDN[ebi]
    
    def pdn_suspend(self, ebi=None):
        if ebi is None:
            for ebi, pdncfg in self.PDN.items():
                if pdncfg['state'] == 1:
                    self.UE.Server.GTPUd.rem_mobile(pdncfg['RAB']['SGW-GTP-TEID'])
                    pdncfg['state'] = 0
        elif ebi in self.PDN and self.PDN[ebi]['state'] == 1:
            self.UE.Server.GTPUd.rem_mobile(self.PDN[ebi]['RAB']['SGW-GTP-TEID'])
            self.PDN[ebi]['state'] = 0
    
    #--------------------------------------------------------------------------#
    # transaction processing
    #--------------------------------------------------------------------------#
    
    def process_trans(self, trans_id):
        """process an ESM transaction initiated by the UE, and return a network-initiated
        procedure with IEs configured and None, or None and the ESM error code
        """
        try:
            trans = self.Trans[trans_id]
        except Exception:
            # err cause 47: PTI mismatch
            return None, 47
        #
        if trans['Type'] == 'Default':
            IEs = {}
            #
            # 1) need APN
            if trans['APN'] is None:
                if self.APN_DEFAULT is not None:
                    apn = self.APN_DEFAULT
                    b_apn = apn.encode('ascii')
                    IEs['APN'] = bchr(len(b_apn)) + b_apn
                else:
                    # err cause 27: missing or unknown APN
                    return None, 27
            else:
                apn = trans['APN'][0][1].get_val()
                IEs['APN'] = trans['APN'].get_val()
            #
            if apn in self.PDNConfig:
                pdncfg = self.PDNConfig[apn]
            elif '*' in self.PDNConfig:
                pdncfg = self.PDNConfig['*']
            else:
                # err cause 27: missing or unknown APN
                return None, 27
            #
            # 2) check the ue request against pdncfg
            # 2.1) check the PDN type
            pdntue = trans['PDNType'].get_val()
            ipaddr, err  = self._get_pdn_addr(pdncfg, pdntue)
            if err is not None:
                return None, err
            IEs['PDNAddr'] = {'Type': ipaddr[0], 'Addr': inet_aton_cn(*ipaddr, dom='EPS')}
            #
            # 2.2) check the protocol config options
            if trans['ProtConfig']:
                IEs['ProtConfig'], pdnaddrreq = self.process_protconfig(pdncfg, trans['ProtConfig'])
                if not pdnaddrreq:
                    IEs['PDNAddr'] = b''
            #
            if 'NBIFOMContainer' in trans:
                self._log('WNG', 'NBIFOMContainer IE unsupported')
            if 'HdrCompConfig' in trans:
                self._log('WNG', 'HdrCompConfig IE unsupported')
            if 'ExtProtConfig' in trans:
                self._log('WNG', 'ExtProtConfig IE unsupported')
            #
            # 3) get the default QCI for the given APN
            IEs['EPSQoS'] = {'QCI': pdncfg.get('QCI', 0x80)}
            #
            # 4) get the 1st available EPS bearer ID
            ebi, err = self._get_ebi()
            if err is not None:
                return None, err
            #
            # 5) set the default RAB for the given APN / EPS bearer ID
            self.rab_set_default(ebi, apn, ipaddr, pdncfg)
            #
            # initialize an ESMDefaultEPSBearerCtxtAct with the given EPS Bearer ID and IEs
            return self.init_proc(ESMDefaultEPSBearerCtxtAct, ebi=ebi, encod={(2, 193): IEs}), None
        #
        elif trans['Type'] == 'Dedicated':
            # TODO
            return None, None
        elif trans['Type'] == 'Modif':
            # TODO
            return None, None
        elif trans['Type'] == 'Deact':
            # TODO
            return None, None
        else:
            assert()
    
    def _get_pdn_addr(self, pdncfg, pdntype_ue):
        pdntype_net = pdncfg['Addr'][0]
        if pdntype_ue == 1:
            if pdntype_net not in (1, 3):
                # err cause 51: PDN type IPv6 only allowed
                return None, 51
            else:
                return (1, pdncfg['Addr'][1]), None
        elif pdntype_ue == 2:
            if pdntype_net not in (2, 3):
                # err cause 50: PDN type IPv4 only allowed
                return None, 50
            else:
                return (2, pdncfg['Addr'][2]), None
        elif pdntype_ue == 3:
            if not 1 <= pdntype_net <= 3:
                # err cause 111: Protocol error, unspecified
                return None, 111
            else:
                return pdncfg['Addr'], None
        else:
            # err cause 28: Unknown PDN type
            return None, 28
    
    def _get_ebi(self):
        for i in range(5, 16):
            if i not in self.PDN:
                return i, None
        # err cause 65: Maximum number of EPS bearers reached
        return None, 65
    
    def rab_set_default(self, ebi, apn, pdnaddr, pdncfg):
        rabcfg = pdncfg['RAB']
        del pdncfg['RAB']
        pdn = cpdict(pdncfg)
        pdncfg['RAB'] = rabcfg
        #
        pdn['PDNAddr'] = pdnaddr
        pdn['APN'] = apn
        pdn['RAB'] = {
            'E-RABlevelQoSParameters': {
                'qCI': pdncfg['QCI'],
                'allocationRetentionPriority': {
                    'priorityLevel': rabcfg['PriorityLevel'],
                    'pre-emptionCapability': rabcfg['PreemptCap'],
                    'pre-emptionVulnerability': rabcfg['PreemptVuln']
                    },
                },
            'SGW-TLA'     : self.UE.Server.SERVER_ENB['GTPU'],
            'ENB-TLA'     : None, # enb gtpu ip, will be updated after the eNB setup the ERAB
            'SGW-GTP-TEID': self.UE.Server.get_gtp_teid(), # teid_ul
            'ENB-GTP-TEID': None, # teid_dl, will be updated after the eNB setup the ERAB
            'BitrateDL'   : rabcfg['BitrateDL'],
            'BitrateUL'   : rabcfg['BitrateUL']
            }
        #
        pdn['state'] = 0 # 0: suspended (no GTP tunnel exist), 1: active (GTP tunnel exists)
        self.PDN[ebi] = pdn
    
    #--------------------------------------------------------------------------#
    # protocol configuration processing
    #--------------------------------------------------------------------------#
    
    def process_protconfig(self, config, request):
        RespElt, pdnaddrreq = self.UE.process_protconfig(self, config, request)
        return {'Config': RespElt}, pdnaddrreq


class UES1d(SigStack):
    """UE S1 handler within a CorenetServer instance
    responsible for UE-associated S1AP signalling
    """
    
    # to keep track of all S1AP procedures
    TRACK_PROC = True
    
    # domain
    DOM = 'EPS'
    
    # reference to the UEd
    UE  = None
    # reference to the ENBd, SCTP stream id
    ENB = None
    SID = None
    
    # to bypass the process_nas() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    # for pure S1AP procedure (no NAS trafic, neither ERAB-oriented stuff)
    # should we page the UE to run the procedure successfully when UE is idle
    S1AP_FORCE_PAGE = False
    
    #--------------------------------------------------------------------------#
    # global security policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all auth and smc procedures,
    # NAS MAC and UL count verification in the uplink
    # and setting of the EMM security header (and encryption) in the downlink
    SECNAS_DISABLED = False
    #
    # finer grained NAS security checks:
    # True to drop NAS PDU when NAS MAC verification fails
    SECNAS_UL_MAC = False
    # True to drop NAS PDU when NAS UL count verification fails
    SECNAS_UL_CNT  = False
    # WNG: EMM and ESM stacks have further control on accepting or not certain
    # NAS message even if security control have failed
    #
    # this will disable the setting of the EMM security header (and encryption)
    # in the downlink for given NAS message (by name)
    SECNAS_PDU_NOSEC = set()
    #
    # format of the security context dict self.SEC:
    # self.SEC is a dict of available 3G / 4G security contexts indexed by KSI,
    # and current KSI in use
    #
    # when self.SEC['KSI'] is not None, the context is enabled at the NAS level, e.g.
    # self.SEC = {'KSI': 0,
    #             0: {'Kasme': b'...', 'Knasenc': b'...', 'Knasint': b'...', 
    #                 'UL': 0, 'DL': 0, 'EEA': 1, 'EIA': 1,
    #                 'Kenb': b'...', 'CTX': 4},
    #             ...,
    #             'POL': {'TAU': 0, 'SER': 0}}
    # 
    # a single security context contains:
    # Kasme, Kenb: 32 bytes buffer, key used at the NAS layer and sent to the eNB
    #    handling the UE
    # Knasenc, Knasint: 16 bytes buffer, key used at the NAS layer together with
    #    EEA and EIA algorithms
    # UL, DL: NAS UL and DL count
    # EEA, EIA: NAS security algorithms index selected
    # CTX: context of the authentication,
    #    3 means 3G auth converted to 4G context, in this case, CK and IK are also 
    #    available in the security context
    #    4 means 4G auth and native context
    # The POL dict indicates the authentication policy for each procedure
    #
    # in case an E-RAB get activated, but no security context exists
    # we use this dummy AS security context for the eNB
    SECAS_NULL_CTX = (
        32*b'\0', # Kenb
        get_ueseccap_null_alg_lte() # UESecCap
        )
    
    #--------------------------------------------------------------------------#
    # S1APPaging policy
    #--------------------------------------------------------------------------#
    # if we want to page with the IMSI, instead of the M-TMSI
    PAG_IMSI     = False
    # default paging domain, if not provided as page() arg
    # 'ps' or 'cs'
    PAG_DOM_DEF  = 'ps'
    # specific default priority defined for paging, if not provided as page() arg
    # None or 1..8 or 'priolevel1'..'priolevel8'
    PAG_PRIO_DEF = None
    #
    # page_block() parameters:
    # number of retries when not successful
    PAG_RETR = 2
    # timer in sec between retries
    PAG_WAIT = 2
    
    #--------------------------------------------------------------------------#
    # S1APInitialContextSetup policy
    #--------------------------------------------------------------------------#
    # to include UERadioCap in request when available (bool)
    ICS_RADCAP_INCL = True
    # to include GUMMEI in request when available (bool)
    ICS_GUMMEI_INCL = True
    # to activate traces (None or dict of values to be passed to the TraceActivation IEs)
    ICS_TRACE_ACT = None
    
    #--------------------------------------------------------------------------#
    # S1APTraceStart policy
    #--------------------------------------------------------------------------#
    # TraceActivation content:
    # interfaces to trace, uint8, bitmap (S1-MME | X2 | UU | 5-bit reserved)
    TRA_IF = 0b11100000
    # depth: minimum, medium, maximum, ...
    TRA_DEPTH = 'medium'
    # traceCollectionEntityIPAddress
    TRA_TLA = (1, '127.0.1.100')
    # MDT configuration: None or dict
    TRA_MDT_CFG = {
        'mdt-Activation': 'immediate-MDT-and-Trace',
        'areaScopeOfMDT': ('pLMNWide', 0),
        'mDTMode': ('immediateMDT', {
            'measurementsToActivate': 0b11111110, # uint8 bitmap, M1 to M7
            'm1reportingTrigger': 'periodic'
            })
        }
    TRA_MDT_CFG = None # comment this to send the MDT config in trace activation
    
    
    def _log(self, logtype, msg):
        self.UE._log(logtype, '[UES1d:   %3i] %s' % (self.CtxId, msg))
    
    def __init__(self, ued, enbd=None, ctx_id=-1, sid=None):
        self.UE  = ued
        self.Server = ued.Server
        self.Config = self.Server.ConfigS1
        #
        # dict of ongoing S1AP procedures (indexed by their procedure code)
        self.Proc = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
        #
        # dict of available LTE security contexts, indexed by KSI
        # and current KSI in use
        self.SEC = {}
        self.reset_sec_ctx()
        #
        self.connected = Event()
        if enbd is not None:
            self.set_ran(enbd)
        else:
            self.CtxId = -1
        #
        # init EMM and ESM sig stacks
        self.EMM = UEEMMd(ued, self)
        self.ESM = UEESMd(ued, self)
        self.SMS = UESMSd(ued, self)
    
    def set_ran(self, enbd):
        self.SEC['KSI'] = None
        self.ENB = enbd
        self.connected.set()
    
    def unset_ran(self):
        self.ENB.unset_ue_s1(self.CtxId)
        del self.ENB
        self.SEC['KSI'] = None
        self.clear()
        self.connected.clear()
    
    def set_ran_unconnected(self, enbd):
        # required for paging
        self.SEC['KSI'] = None
        self.ENB = enbd
    
    def unset_ran_unconnected(self):
        # required for paging
        del self.ENB
        self.SEC['KSI'] = None
    
    def is_connected(self):
        #return self.RNC is not None
        return self.connected.is_set()
    
    def set_ctx(self, ctx_id, sid):
        self.CtxId = ctx_id
        self.SID   = sid
    
    def unset_ctx(self):
        self.CtxId = -1
        del self.SID
    
    def reset_sec_ctx(self):
        self.SEC.clear()
        self.SEC['KSI'] = None
        self.SEC['POL'] = {'TAU': 0, 'DET': 0, 'SER': 0}
        if 'UESecCap' in self.UE.Cap:
            del self.UE.Cap['UESecCap']
    
    def get_sec_ctx(self):
        return self.SEC.get(self.SEC['KSI'], None)
    
    #--------------------------------------------------------------------------#
    # handling of S1AP procedures
    #--------------------------------------------------------------------------#
    
    def process_s1ap_pdu(self, pdu_rx):
        """process an S1AP PDU sent by the eNB for UE-associated signalling
        and return a list of S1AP PDU(s) to be sent back to it
        """
        errcause = None
        if pdu_rx[0] == 'initiatingMessage':
            # eNB-initiated procedure, instantiate it
            try:
                Proc = S1APProcEnbDispatcher[pdu_rx[1]['procedureCode']](self)
            except Exception:
                self._log('ERR', 'invalid S1AP PDU, initiatingMessage, code %i'\
                          % pdu_rx[1]['procedureCode'])
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = self.init_s1ap_proc(S1APErrorIndCN, Cause=errcause)
                if not Proc:
                    return []
            else:
                if self.TRACK_PROC:
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.Class == 2 and Proc.errcause:
                Err = self.init_s1ap_proc(S1APErrorIndCN, Cause=Proc.errcause)
                if not Err:
                    return []
                self.ProcLast = Err.Code
                return Err.send()
            elif Proc.Class == 1 or errcause:
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcLast = ProcRet.Code
                return pdu_tx
        #
        else:
            # CN-initiated procedure, transfer the PDU to it
            try:
                Proc = self.Proc[pdu_rx[1]['procedureCode']]
            except Exception:
                self._log('ERR', 'invalid S1AP PDU, %s, code %i'\
                          % (pdu_rx[0], pdu_rx[1]['procedureCode']))
                errcause = ('protocol', 'message-not-compatible-with-receiver-state')
                Proc = self.init_s1ap_proc(S1APErrorIndCN, Cause=errcause)
                if not Proc:
                    return []
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.errcause:
                Err = self.init_s1ap_proc(S1APErrorIndCN, Cause=Proc.errcause)
                if not Err:
                    return []
                self.ProcLast = Err.Code
                return Err.send()
            elif errcause:
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcLast = ProcRet.Code
                return pdu_tx
    
    def init_s1ap_proc(self, ProcClass, **IEs):
        """initialize a CN-initiated S1AP procedure of class `ProcClass' for 
        UE-associated signalling, encode the initiatingMessage PDU with given 
        **IEs and return the procedure
        """
        Proc = self._init_s1ap_proc(ProcClass)
        if not Proc:
            return None
        else:
            self._encode_s1ap_proc(Proc, **IEs)
            return Proc
    
    def _init_s1ap_proc(self, ProcClass):
        if not issubclass(ProcClass, S1APSigProc):
            self._log('WNG', 'starting an invalid procedure for UE-associated S1 signalling')
        if ProcClass.Code in self.Proc:
            self._log('ERR', 'an S1AP procedure %s is already ongoing' % ProcClass.__name__)
            return None
        try:
            Proc = ProcClass(self)
        except Exception:
            # no active S1 link
            self._log('ERR', 'no active S1 link to initialize the S1AP procedure %s'\
                      % ProcClass.__name__)
            return None
        if Proc.Code in S1APProcCnDispatcher and Proc.Class == 1:
            # store the procedure, which requires a response from the eNB
            self.Proc[Proc.Code] = Proc
        if self.TRACK_PROC:
            self._proc.append( Proc )
        return Proc
    
    def _encode_s1ap_proc(self, Proc, **IEs):
        if Proc.Name != 'S1APUEContextRelease':
            IEs['MME_UE_S1AP_ID'], IEs['ENB_UE_S1AP_ID'] = self.CtxId, self.CtxId
        else:
            IEs['UE_S1AP_IDs'] = ('uE-S1AP-ID-pair', {'mME-UE-S1AP-ID': self.CtxId,
                                                      'eNB-UE-S1AP-ID': self.CtxId})
        Proc.encode_pdu('ini', **IEs)
    
    def start_s1ap_proc(self, ProcClass, **IEs):
        """initialize a CN-initiated S1AP procedure of class `ProcClass' for 
        UE-associated signalling, encode the initiatingMessage PDU with given 
        **IEs and send the PDU generated by the procedure to the eNB
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_s1ap_proc(ProcClass, **IEs)
        if Proc is None:
            return 0
        self.ProcLast, cnt = Proc.Code, 0
        for pdu_tx in Proc.send():
            if self.UE.Server.send_s1ap_pdu(self.ENB, pdu_tx, self.SID):
                cnt += 1
        return cnt
    
    def transmit_s1ap_proc(self, S1apTxProc):
        """send the S1AP PDU as returned by the .send() method of the S1AP procedures
        in the S1apTxProc list to the eNB
        """
        cnt = 0
        for Proc in S1apTxProc:
            self.ProcLast = Proc.Code
            for pdu_tx in Proc.send():
                if self.UE.Server.send_s1ap_pdu(self.ENB, pdu_tx, self.SID):
                    cnt += 1
        return cnt
    
    def clear(self):
        # clears all running S1AP procedures
        for Proc in list(self.Proc.values()):
            Proc.abort()
    
    #--------------------------------------------------------------------------#
    # handling of NAS messages dispatching
    #--------------------------------------------------------------------------#
    
    def process_nas(self, buf):
        """process a NAS message buffer for the EPS domain sent by the mobile
        and return a list (possibly empty) of S1AP procedure(s) to be sent back 
        to the eNB
        """
        if self.RX_HOOK:
            return self.RX_HOOK(buf)
        NasRxSec, err = NAS.parse_NASLTE_MO(buf, inner=False)
        if err:
            self._log('WNG', 'invalid EPS NAS message: %s' % hexlify(buf).decode('ascii'))
            return self.ret_s1ap_dnt(NAS.EMMStatus(val={'EMMCause':err}, sec=False))
        #
        # LTE NAS security handling
        sh, pd = NasRxSec[0]['SecHdr'].get_val(), NasRxSec[0]['ProtDisc'].get_val()
        if sh == 0:
            # clear-text NAS message
            NasRxSec._sec   = False
            NasRxSec._ulcnt = 0
            if self.UE.TRACE_NAS_EPS:
                self._log('TRACE_NAS_EPS_UL', '\n' + NasRxSec.show())
            if pd == 7:
                S1apTxProc = self.EMM.process(NasRxSec)
            else:
                assert( pd == 2 ) # this won't happen due to parse_NASLTE_MO()
                S1apTxProc = self.ESM.process(NasRxSec)
        elif sh == 12:
            # NAS service request
            if self.UE.TRACE_NAS_EPS:
                self._log('TRACE_NAS_EPS_UL', '\n' + NasRxSec.show())
            try:
                NasRx, err = self.process_nas_sec_servreq(NasRxSec)
            except Exception as err:
                self._log('ERR', 'unable to process the NAS EMMServiceRequest security, %s' % err)
                return self._s1ap_nas_sec_err()
            if not NasRx:
                return self._s1ap_nas_sec_err()
            else:
                S1apTxProc = self.EMM.process(NasRx)
        elif sh in (1, 2, 3, 4) and pd == 7:
            if self.UE.TRACE_NAS_EPS_SEC:
                self._log('TRACE_NAS_EPS_UL_SEC', '\n' + NasRxSec.show())
            if sh in (1, 3):
                # integrity-protected NAS message
                NasRx, err = self.process_nas_sec_noenc(NasRxSec, sh)
            else:
                # integrity-protected and ciphered NAS message
                NasRx, err = self.process_nas_sec_enc(NasRxSec, sh)
            if err & 0xff:
                # non-security related error
                S1apTxProc = self.ret_s1ap_dnt(NAS.EMMStatus(val={'EMMCause':err}, sec=True))
            elif not NasRx:
                # deciphering failed
                return self._s1ap_nas_sec_err()
            else:
                if self.UE.TRACE_NAS_EPS:
                    self._log('TRACE_NAS_EPS_UL', '\n' + NasRx.show())
                if NasRx[0]['ProtDisc'].get_val() == 7:
                    S1apTxProc = self.EMM.process(NasRx)
                else:
                    S1apTxProc = self.ESM.process(NasRx)
        else:
            # cause: invalid mandatory information
            self._log('WNG', 'invalid EPS NAS message: %r' % NasRxSec)
            S1apTxProc = self.ret_s1ap_dnt(NAS.EMMStatus(val={'EMMCause':96}, sec=False))
        #
        return S1apTxProc
    
    def process_nas_sec_servreq(self, ServReq):
        """Check the security on the EMM Service Request.
        Returns the request or None (if security checks are enforced), and the
        security error code.
        
        Security error codes:
        0: no error
        0x100: NAS KSI unknown
        0x200: MAC verification failed
        0x300: NAS UL count not matching
        
        The returned request gets 2 attributes (_sec [bool], _ulcnt [uint])
        """
        if self.SECNAS_DISABLED:
            ServReq._sec   = True
            ServReq._ulcnt = 0
            return ServReq, 0
        #
        ue_ksi, ue_sqn = ServReq['KSI'].get_val(), ServReq['SeqnShort'].get_val()
        if ue_ksi not in self.SEC:
            self._log('WNG', 'NAS SEC: unknown NAS KSI %i in EMMServiceRequest' % ue_ksi)
            self.reset_sec_ctx()
            ServReq._sec   = False
            ServReq._ulcnt = ue_sqn # we are missing the MSB...
            return ServReq, 0x100
        else:
            self.SEC['KSI'] = ue_ksi
        secctx = self.SEC[ue_ksi]
        #
        sqnmsb, sqnlsb = secctx['UL'] & 0xffffffe0, secctx['UL'] & 0x1f
        verif_mac = ServReq.mac_verify(secctx['Knasint'], 0, secctx['EIA'], sqnmsb)
        verif_sqn = True if ue_sqn == sqnlsb else False
        #
        if not verif_mac:
            if self.SECNAS_UL_MAC:
                self._log('ERR', 'NAS SEC UL: MAC short verif failed, dropping EMMServiceRequest')
                return None, 0x200
            else:
                self._log('WNG', 'NAS SEC UL: MAC short verif failed in EMMServiceRequest')
                ServReq._sec   = False
                ServReq._ulcnt = sqnmsb + ue_sqn
                return ServReq, 0x200
        elif not verif_sqn:
            if self.SECNAS_UL_CNT:
                self._log('ERR', 'NAS SEC UL: UL count verif failed, dropping EMMServiceRequest')
                return None, 0x300
            else:
                self._log('WNG', 'NAS SEC UL: UL count verif failed in EMMServiceRequest')
                # resynch uplink count
                ServReq._sec   = False
                ServReq._ulcnt = sqnmsb + ue_sqn
                secctx['UL'] = sqnmsb + ue_sqn + 1
                return ServReq, 0x300
        #
        ServReq._sec   = True
        ServReq._ulcnt = secctx['UL']
        secctx['UL']  += 1
        return ServReq, 0
    
    def process_nas_sec_mac(self, NasRxSec, secctx, inner_name):
        #
        sqnmsb, sqnlsb = secctx['UL'] & 0xffffff00, secctx['UL'] & 0xff
        verif_mac = NasRxSec.mac_verify(secctx['Knasint'], 0, secctx['EIA'], sqnmsb)
        ue_sqn    = NasRxSec['Seqn'].get_val()
        verif_sqn = True if ue_sqn == sqnlsb else False
        if not inner_name:
            inner_name = NasRxSec._name
        #
        if not verif_mac:
            if self.SECNAS_UL_MAC:
                self._log('ERR', 'NAS SEC UL: MAC verif failed, dropping %s' % inner_name)
                return False, 0x200, False, 0
            else:
                self._log('WNG', 'NAS SEC UL: MAC verif failed in %s' % inner_name)
                return True, 0x200, False, sqnmsb+ue_sqn
        elif not verif_sqn:
            if self.SECNAS_UL_CNT:
                self._log('ERR', 'NAS SEC UL: UL count verif failed, dropping %s' % inner_name)
                return False, 0x300, False, 0
            else:
                self._log('WNG', 'NAS SEC UL: UL count verif failed in %s' % inner_name)
                # resynch uplink count
                secctx['UL'] = sqnmsb+ue_sqn+1
                return True, 0x300, False, sqnmsb+ue_sqn
        else:
            self._log('DBG', 'NAS SEC UL: MAC verified, UL count %i' % secctx['UL'])
            ulcnt = secctx['UL']
            secctx['UL'] += 1
            return True, 0, True, ulcnt
    
    def process_nas_sec_noenc(self, NasRxSec, sh):
        """Check the security on all UL EMM messages which are not encrypted, 
        except the Service Request.
        Returns the message or None (if security checks are enforced), and the
        security error code.
        
        Security error codes:
        0: no error
        0x100: NAS KSI unknown
        0x200: MAC verification failed
        0x300: NAS UL count not matching
        
        The returned message gets 2 attributes (_sec [bool], _ulcnt [uint])
        """
        # decode the inner NAS message
        buf = NasRxSec['NASMessage'].get_val()
        NasRx, err = NAS.parse_NASLTE_MO(buf, inner=False)
        if err:
            self._log('WNG', 'invalid EPS NAS message: %s' % hexlify(buf).decode('ascii'))
        #
        if self.SECNAS_DISABLED:
            if err:
                return None, err
            else:
                NasRx._sec   = True
                NasRx._ulcnt = 0
                return NasRx, 0
        #
        if 'NAS_KSI' in NasRx._by_name:
            ue_ksi = NasRx['NAS_KSI'][-1].get_val()
            if ue_ksi[0] == 1:
                self._log('INF', 'NAS SEC UL: mapped NAS KSI %i in %s' % (ue_ksi[1], NasRxSec._name))
                ue_ksi = (ue_ksi[0]<<3) + ue_ksi[1]
                # TODO: map the 3G corresponding sec context to a 4G one
            else:
                ue_ksi = ue_ksi[1]
            if ue_ksi not in self.SEC:
                # UE KSI unknown
                self.reset_sec_ctx()
                if not err:
                    self._log('INF', 'NAS SEC UL: unknown NAS KSI %i in %s' % (ue_ksi, NasRx._name))
                    NasRx._sec   = False
                    NasRx._ulcnt = NasRxSec['Seqn'].get_val()
                    return NasRx, 0x100
                else:
                    # there is nothing we can do here
                    self._log('INF', 'NAS SEC UL: unknown NAS KSI %i' % ue_ksi)
                    return None, err + 0x100
            else:
                self.SEC['KSI'] = ue_ksi
                secctx = self.SEC[ue_ksi]
        else:
            if self.SEC['KSI'] not in self.SEC:
                # no correct active KSI: happens when restarting corenet, and UE using a forgotten sec ctx
                self.reset_sec_ctx()
                if not err:
                    self._log('INF', 'NAS SEC UL: no NAS KSI in %s neither valid active KSI' % NasRx._name)
                    NasRx._sec   = False
                    NasRx._ulcnt = NasRxSec['Seqn'].get_val()
                    return NasRx, 0x100
                else:
                    # there is nothing we can do here
                    self._log('INF', 'NAS SEC UL:  no NAS KSI')
                    return None, err + 0x100
            else:
                secctx = self.SEC[self.SEC['KSI']]
        #
        if NasRx:
            chk, err, NasRx._sec, NasRx._ulcnt = self.process_nas_sec_mac(NasRxSec, secctx, NasRx._name)
        else:
            chk, err, sec, ulcnt = self.process_nas_sec_mac(NasRxSec, secctx, '_unknown_')
        if not chk:
            return None, err
        else:
            return NasRx, err
    
    def process_nas_sec_enc(self, NasRxSec, sh):
        """Check the security on all UL EMM messages which are encrypted.
        Returns the message or None (if security checks are enforced), and the
        security error code.
        
        Security error codes:
        0: no error
        0x100: no active NAS KSI
        0x200: MAC verification failed
        0x300: NAS UL count not matching
        
        The returned message gets 2 attributes (_sec [bool], _ulcnt [uint])
        """
        if self.SECNAS_DISABLED:
            # TODO: try to decode the inner NAS message, in case EEA0 is in use ?
            self._log('WNG', 'unable to decode the inner NAS message')
            return None, 0
        #
        if self.SEC['KSI'] not in self.SEC:
            # no active KSI: happens when restarting corenet, and UE using a forgotten sec ctx
            self._log('WNG', 'NAS SEC UL: no active NAS KSI')
            return None, 0x100
        else:
            secctx = self.SEC[self.SEC['KSI']]
        #
        chk, err, sec, ulcnt = self.process_nas_sec_mac(NasRxSec, secctx, '_unknown_')
        if not chk:
            return None, err
        #
        if secctx['EEA'] == 0:
            buf = NasRxSec['NASMessage'].get_val()
        else:
            NasRxSec.decrypt(secctx['Knasenc'], 0, secctx['EEA'], ulcnt & 0xffffff00)
            buf = NasRxSec._dec_msg
        NasRx, err2 = NAS.parse_NASLTE_MO(buf, inner=False)
        if err2:
            # decrypted decoded part is malformed
            self._log('WNG', 'invalid EPS NAS message: %s' % hexlify(buf).decode('ascii'))
        NasRx._sec   = sec
        NasRx._ulcnt = ulcnt
        return NasRx, err + err2
    
    def output_nas_sec(self, NasTx):
        """Apply the security on all DL ESM / EMM messages.
        Returns the encoded bytes buffer or None if error.
        """
        if self.UE.TRACE_NAS_EPS:
            self._log('TRACE_NAS_EPS_DL', '\n' + NasTx.show())
        if self.SECNAS_DISABLED or NasTx._name in self.SECNAS_PDU_NOSEC or \
        NasTx._sec == False:
            sec = False
        else:
            ksi = self.SEC['KSI']
            if ksi is None:
                # NAS security not activated
                #NasTx[0]['SecHdr'].set_val(0)
                sec = False
            elif ksi not in self.SEC:
                # invalid KSI: this should not happen
                self._log('ERR', 'NAS SEC DL: invalid NAS KSI %i, unable to secure the NAS message %s'\
                          % (ksi, NasTx._name))
                self.reset_sec_ctx()
                return None
            else:
                secctx = self.SEC[self.SEC['KSI']]
                sqnmsb, sqnlsb = secctx['DL'] & 0xffffff00, secctx['DL'] & 0xff
                if NasTx._name == 'EMMSecurityModeCommand':
                    # integrity protextion only + new security context
                    sh = 3
                else:
                    # integrity protection + ciphering
                    sh = 2
                try:
                    NasTxSec = NAS.EMMSecProtNASMessage(val={'EMMHeaderSec': {'SecHdr': sh},
                                                             'Seqn': sqnlsb,
                                                             'NASMessage': NasTx.to_bytes()})
                    if sh == 2:
                        NasTxSec.encrypt(secctx['Knasenc'], 1, secctx['EEA'], sqnmsb)
                    NasTxSec.mac_compute(secctx['Knasint'], 1, secctx['EIA'], sqnmsb)
                except Exception:
                    self._log('ERR', 'NAS SEC DL: unable to protect the NAS message %s' % NasTx._name)
                    #self.reset_sec_ctx()
                    return None
                else:
                    secctx['DL'] += 1
                    sec = True
        if sec:
            if self.UE.TRACE_NAS_EPS_SEC:
                self._log('TRACE_NAS_EPS_DL_SEC', '\n' + NasTxSec.show())
            try:
                return NasTxSec.to_bytes()
            except Exception as err:
                self._log('ERR', 'unable to encode the NAS message %s, %r' % (NasTxSec._name, err))
                return None
        else:
            try:
                return NasTx.to_bytes()
            except Exception as err:
                self._log('ERR', 'unable to encode the NAS message %s, %r' % (NasTx._name, err))
                return None
    
    def ret_s1ap_dnt(self, NasTx, **IEs):
        """returns an S1APDownlinkNASTransport procedure initialized with the 
        NAS PDU and optional IEs to be sent
        """
        if not NasTx:
            return []
        else:
            buf = self.output_nas_sec(NasTx)
            if buf is None:
                return self._s1ap_nas_sec_err()
            IEs['NAS_PDU'] = buf
            NgapProc = self.init_ngap_proc(NGAPDownlinkNASTransport, **IEs)
            if S1apProc:
                return [S1apProc]
            else:
                return []
    
    def _s1ap_nas_sec_err(self):
        # TODO: maybe release the S1-UE link ?
        return []
    
    def clear_nas_proc(self):
        # clears all NAS EPS procedures
        self.EMM.clear()
        self.ESM.clear()
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    def _get_paging_ies(self, dom, prio):
        # prepare the S1APPaging IEs
        IEs = {}
        #
        if not self.UE.IMSI or not self.UE.PLMN or self.UE.TAC is None:
            return IEs
        #
        if self.PAG_IMSI or self.UE.MTMSI is None:
            # paging with IMSI
            self._log('INF', 'paging with IMSI')
            IEs['UEPagingID'] = ('iMSI', NAS.encode_bcd(self.UE.IMSI))
        else:
            IEs['UEPagingID'] = ('s-TMSI', {'mMEC': uint_to_bytes(self.UE.Server.MME_CODE, 8),
                                            'm-TMSI': uint_to_bytes(self.UE.MTMSI, 32)})
        #
        if 'DRXParam' in self.UE.Cap:
            drx = self.UE.Cap['DRXParam'][1]['DRXCycleLen'].get_val()
            if drx in (6, 7, 8, 9):
                IEs['PagingDRX'] = S1AP.S1AP_IEs.PagingDRX._cont_rev[drx-6]
        #
        IEs['TAIList'] = [{
            'id': 47,
            'criticality': 'ignore',
            'value': ('TAIItem', {'tAI': {'pLMNidentity': plmn_str_to_buf(self.UE.PLMN),
                                          'tAC': uint_to_bytes(self.UE.TAC, 16)}})
            }]
        #
        IEs['UEIdentityIndexValue'] = (int(self.UE.IMSI) % 1024, 10)
        #
        if isinstance(dom, str_types) and dom.lower() == 'cs' \
        or self.PAG_DOM_DEF.lower() == 'cs':
            IEs['CNDomain'] = 'cs'
        else:
            IEs['CNDomain'] = 'ps'
        #
        if prio is not None or self.PAG_PRIO_DEF is not None:
            if isinstance(prio, integer_types) and 1 <= prio <= 8:
                IEs['PagingPriority'] = 'priolevel%i' % prio
            elif isinstance(prio, str_types) and re.match(r'priolevel[1-8]', prio):
                IEs['PagingPriority'] = prio
            elif isinstance(self.PAG_PRIO_DEF, integer_types) and 1 <= self.PAG_PRIO_DEF <= 8:
                IEs['PagingPriority'] = 'priolevel%i' % self.PAG_PRIO_DEF
            elif isinstance(self.PAG_PRIO_DEF, str_types) \
            and re.match(r'priolevel[1-8]', self.PAG_PRIO_DEF):
                IEs['PagingPriority'] = self.PAG_PRIO_DEF
        #
        if 'UERadioCapPaging' in self.UE.Cap:
            IEs['UERadioCapabilityForPaging'] = self.UE.Cap['UERadioCapPaging'][0]
        #
        return IEs
     
    def page(self, dom=None, prio=None):
        """send S1AP Paging command to eNB responsible for the UE TAI
        """
        # send a S1APPaging for the EPS domain
        if self.connected.is_set():
            self._log('DBG', 'paging: UE already connected')
            return
        # get the set of eNBs serving the UE TAI
        # eNB id is 2-tuple whereas gNB id is 3-tuple
        tai = (self.UE.PLMN, self.UE.TAC)
        try:
            enbs = [self.Server.RAN[enbid] for enbid in self.Server.TAI[tai] if len(enbid) == 2]
        except Exception:
            self._log('ERR', 'paging: no eNB serving the UE TAI %s.%.4x' % tai)
            return
        #
        IEs = self._get_paging_ies(dom, prio)
        if not IEs:
            self._log('ERR', 'paging: missing basic information')
            return
        #
        # start an S1APPaging procedure on all eNBs
        for enb in enbs:
            enb.page(**IEs)
        self._log('INF', 'paging: ongoing')
    
    def page_block(self, dom=None, prio=None):
        """page the UE and wait for it to connect, or the paging procedure to timeout.
        Returns True if UE gets connected, False otherwise.
        """
        # send a S1APPaging for the EPS domain
        if self.connected.is_set():
            self._log('DBG', 'paging: UE already connected')
            return True
        # get the set of eNBs serving the UE TAI
        # eNB id is 2-tuple whereas gNB id is 3-tuple
        tai = (self.UE.PLMN, self.UE.TAC)
        try:
            enbs = [self.Server.RAN[enbid] for enbid in self.Server.TAI[tai] if len(enbid) == 2]
        except Exception:
            self._log('ERR', 'paging: no eNB serving the UE TAI %s.%.4x' % tai)
            return False
        #
        IEs = self._get_paging_ies(dom, prio)
        if not IEs:
            self._log('ERR', 'paging: missing basic information')
            return False
        #
        # retries paging as defined in case UE does not connect
        i = 0
        while i <= self.PAG_RETR:
            # start an S1APPaging procedure on all RNCs
            for enb in enbs:
                enb.page(**IEs)
            # check until UE gets connected or timer expires
            if self.connected.wait(self.PAG_WAIT):
                self._log('INF', 'paging: UE connected')
                return True
            else:
                # timeout
                i += 1
        self._log('WNG', 'paging: timeout, UE not connected')
        return False
    
    def release(self, cause=('nas', 'normal-release')):
        """release the S1 link with the given S1AP cause
        """
        if not self.connected.is_set():
            # nothing to release
            self._log('DBG', 'release: UE not connected')
            return True
        # prepare the S1APUEContextRelease procedure
        S1apProc = self.init_s1ap_proc(S1APUEContextRelease, Cause=cause)
        if not S1apProc:
            return False
        if not self.transmit_s1ap_proc([S1apProc]):
            return False
        else:
            return True
    
    def send_error_ind(self, cause, **IEs):
        """start a S1APErrorIndCN with the given S1AP cause
        
        IEs can contain any of the optional or extended IEs
        """
        if not self.connected.is_set():
            # S1AP link disconnected
            if self.S1AP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the S1AP procedure
        IEs['Cause'] = cause
        S1apProc = self.init_s1ap_proc(S1APErrorIndCN, **IEs)
        if not S1apProc:
            return False
        if not self.transmit_s1ap_proc([S1apProc]):
            return False
        else:
            return True
   
    def _get_trace_act_ie(self, traceref, interfaces=None, depth=None, addr=None, mdtcfg=None):
        # prepare the TraceActivation IE
        #
        if interfaces is None:
            interfaces = self.TRA_IF
        #
        if depth is None:
            depth = self.TRA_DEPTH
        elif isinstance(depth, integer_types):
            depth = S1AP.S1AP_IEs.TraceDepth._cont_rev[depth]
        #
        if addr is None:
            if self.TRA_TLA is None:
                addr = b'\0'
            else:
                addr = inet_aton_cn(*self.TRA_TLA)
        else:
            addr = inet_aton_cn(*addr)
        #
        traceact = {
            'e-UTRAN-Trace-ID': plmn_str_to_buf(self.Server.PLMN) + b'\0\0\0' + traceref,
            'interfacesToTrace': (interfaces, 8),
            'traceDepth': depth,
            'traceCollectionEntityIPAddress': (bytes_to_uint(addr, 8*len(addr)), 8*len(addr)),
            }
        #
        if mdtcfg is None and self.TRA_MDT_CFG is not None:
            mdtcfg = self.TRA_MDT_CFG
        if mdtcfg is not None:
            traceact['iE-Extensions'] = [{
                'id': 162,
                'criticality': 'ignore',
                'extensionValue': ('MDT-Configuration', mdtcfg)
                }]
        #
        return traceact
    
    def start_trace(self, traceref, interfaces=None, depth=None, addr=None, mdtcfg=None):
        """start a S1APTraceStart with the given traceref (2 bytes) and other parameters:
        
        interfaces: None or uint8, bitmap (S1-MME | X2 | UU | 5-bit reserved)
        depth : None or uint 0..5 or str (see TraceDepth)
        addr  : None or PDN-like addr (1, IPv4 ascii) or (2, IPv6 ascii)
        mdtcfg: None or dict, MDT-Configuration IE value
        """
        if not self.connected.is_set():
            # S1AP link disconnected
            if self.S1AP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the S1AP procedure
        if not isinstance(traceref, bytes_types) or len(traceref) != 2:
            return False
        traceact = self._get_trace_act_ie(traceref, interfaces, depth, addr, mdtcfg)
        S1apProc = self.init_s1ap_proc(S1APTraceStart, TraceActivation=traceact)
        if not S1apProc:
            return False
        if not self.transmit_s1ap_proc([S1apProc]):
            return False
        else:
            return True
    
    def deactivate_trace(self, traceref):
        """start a S1APDeactivateTrace with the given traceref (2 bytes)
        """ 
        if not self.connected.is_set():
            # S1AP link disconnected
            if self.S1AP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the S1AP procedure
        if not isinstance(traceref, bytes_types) or len(traceref) != 2:
            return False
        traceid = plmn_buf_to_str(self.Server.PLMN) + b'\0\0\0' + traceref
        S1apProc = self.init_s1ap_proc(S1APDeactivateTrace, E_UTRAN_Trace_ID=traceid)
        if not S1apProc:
            return False
        if not self.transmit_s1ap_proc([S1apProc]):
            return False
        else:
            return True
    
    def report_loc_ctrl(self, reqtype={'eventType': 'direct', 'reportArea': 'ecgi'}):
        """start a S1APLocationReportingControl with a given request type
        RequestType is a sequence of {EventType (enum), ReportArea (enum)}
        """
        if not self.connected.is_set():
            # S1AP link disconnected
            if self.S1AP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the S1AP procedure
        S1apProc = self.init_s1ap_proc(S1APLocationReportingControl, RequestType=reqtype)
        if not S1apProc:
            return False
        if not self.transmit_s1ap_proc([S1apProc]):
            return False
        else:
            return True
    
    # this is used by send_raw() and other network-initiated procedures
    def _net_init_con(self):
        return self.EMM._net_init_con()
    
    #--------------------------------------------------------------------------#
    # to send arbitrary NAS buffers to the UE
    #--------------------------------------------------------------------------#
    
    def send_nas_raw(self, naspdu, sec=True, rx_hook=lambda x:[], wait_t=1):
        """Sends whatever bytes, or list of bytes, to the UE as NAS PDU(s)
        """
        if not self._net_init_con():
            return False
        #
        if isinstance(naspdu, bytes_types):
            return self._send_nas_raw(naspdu, sec, rx_hook, wait_t)
        #
        elif isinstance(naspdu, (tuple, list)):
            for pdu in naspdu:
                ret = self.send_nas_raw(pdu, sec, rx_hook, wait_t=wait_t)
                if not ret:
                    return False
            return True
    
    def _send_nas_raw(self, naspdu, sec=True, rx_hook=lambda x:[], wait_t=1):
        # overwrite the class attribute
        self.RX_HOOK = rx_hook
        #
        if sec:
            # need to wrap the naspdu into a pseudo NasTx structure
            NasTx = Envelope('NASDummy', GEN=(Uint8('SecHdr', trans=True),
                                              Buf('NASPDU', val=naspdu)))
            NasTx._sec = True
            naspdu = self.output_nas_sec(NasTx)
            if naspdu is None:
                del self.RX_HOOK
                return False
        #
        S1apProc = self.init_s1ap_proc(S1APDownlinkNASTransport,
                                       NAS_PDU=naspdu)
        if S1apProc:
            if not self.transmit_s1ap_proc([S1apProc]):
                ret = False
            else:
                self._log('INF', 'send_nas_raw: 0x%s' % hexlify(naspdu).decode('ascii'))
                sleep(wait_t)
                ret = True
        else:
            ret = False
        #
        # restore the class attribute
        del self.RX_HOOK
        return ret
    
    #--------------------------------------------------------------------------#
    # EPS bearers activation
    #--------------------------------------------------------------------------#
    
    def bearer_act(self):
        # reactivate all PDN connections
        erablist, ebilist, brdl, brul = [], [], 0, 0
        for ebi, pdncfg in self.ESM.PDN.items():
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
        secctx = self.get_sec_ctx()
        if secctx and 'UESecCap' in self.UE.Cap:
            # create the KeNB
            self._log('DBG', 'NAS UL count for Kenb derivation, %i' % secctx['UL_enb'])
            Kenb, UESecCap = conv_401_A3(secctx['Kasme'], secctx['UL_enb']), self.UE.Cap['UESecCap'][1]
            secctx['Kenb'] = Kenb
            secctx['NCC']  = 0
            secctx['NH']   = conv_401_A4(secctx['Kasme'], Kenb)
        else:
            self._log('WNG', 'no active NAS security context, using the null AS security context')
            Kenb, UESecCap = self.SECAS_NULL_CTX
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
        if self.ICS_RADCAP_INCL and 'UERadioCap' in self.UE.Cap:
            IEs['UERadioCapability'] = self.UE.Cap['UERadioCap'][0]
        if self.ICS_GUMMEI_INCL:
            IEs['GUMMEI'] = gummei_to_asn(self.UE.Server.PLMN,
                                          self.UE.Server.MME_GID,
                                          self.UE.Server.MME_CODE)
        if self.ICS_TRACE_ACT:
            IEs['TraceActivation'] = self.ICS_TRACE_ACT
        #
        S1apProc = self.init_s1ap_proc(S1APInitialContextSetup, **IEs)
        if S1apProc:
            # pass the info required for setting the GTPU tunnel
            S1apProc._gtp_add_mobile_ebi = ebilist
            return S1apProc
        else:
            return None
