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
# * File Name : pycrate_corenet/HdlrUEIuPS.py
# * Created : 2017-09-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcCNRanap import *
from .ProcCNGMM   import *
from .HdlrUEIu    import UEIuSigStack

#------------------------------------------------------------------------------#
# UE-related Iu interface handler for the PS domain
# including GMM and SM stacks
#------------------------------------------------------------------------------#

class UEGMMd(SigStack):
    """UE GMM handler within a UEIuPSd instance
    responsible for GPRS Mobility Management signaling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the IuCSd
    Iu = None
    
    # state: INACTIVE (cannot be paged) <-> ACTIVE <-> IDLE
    state = 'INACTIVE'
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    #--------------------------------------------------------------------------#
    # GMM common parameters
    #--------------------------------------------------------------------------#
    # if we want to set "Force to StandBy" to force the MS to stop the READY timer 
    # in order to prevent the MS to perform cell updates (must not be enabled in Iu mode)
    _FSTDBY             = 0
    # READY Timer: if None and requested by the UE, timer returned is the one
    # from the UE ; otherwise dict {'Unit', 'Value'}
    _READY_TIMER        = None
    # Periodic RAU timer: dict {'Unit': uint3, 'Value': uint5}
    # Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    #_RAU_TIMER          = {'Unit': 1, 'Value': 5} # 5mn
    _RAU_TIMER          = {'Unit': 7, 'Value': 0} # deactivated
    # Reattach attempt after a failure timer: dict {'Unit': uint3, 'Value': uint5}
    # Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    _T3302              = {'Unit': 1, 'Value': 2}
    # RAU extended timer: None or dict {'Unit': uint3, 'Value': uint5}
    # Unit: 0: 10mn, 1: 1h, 2: 10h, 3: 2s, 4: 30s, 5: 1mn, 6: 320h, 7: deactivated
    _T3312_EXT          = None
    # Network features support: if None, not sent, otherwise dict
    # {'LCS_MOLR': uint1, 'IMS_VoPS': uint1, 'EMC_BS': uint1}
    _NETFEAT_SUPP       = None
    # MS Info request: if None, not requested, otherwise dict 
    # {'I_RAT': uint1, 'I_RAT2': uint1}
    _MSINF_REQ          = None
    # Additional network features support: if None, not sent, otherwise dict
    # {'GPRS_SMS': uint1}
    _ADDNETFEAT_SUPP    = None
    # Extended DRX support: if None and sent by the UE, value returned it the one
    # from the UE ; otherwise dict {'PTX': uint4, 'eDRX': uint4}
    _EXTDRX             = None
    
    #--------------------------------------------------------------------------#
    # GMMStatus policy
    #--------------------------------------------------------------------------#
    # behaviour when receiving GMM STATUS
    # 0: do nothing,
    # 1: abort the top-level GMM procedure,
    # 2: abort the whole stack of GMM procedures
    STAT_CLEAR          = 2
    
    #--------------------------------------------------------------------------#
    # GMMPTMSIReallocation policy
    #--------------------------------------------------------------------------#
    # GMM procedure timer
    T3350               = 4
    #
    REA_FSTDBY          = _FSTDBY
    
    #--------------------------------------------------------------------------#
    # GMMAuthenticationCiphering policy
    #--------------------------------------------------------------------------#
    # GMM procedure timer
    T3360               = 4
    # if we want to set "Force to StandBy" to force the MS to stop the READY timer 
    # in order to prevent the MS to perform cell updates (must not be enabled in Iu mode)
    AUTH_FSTDBY         = _FSTDBY
    # Authentication Management Field
    AUTH_AMF            = b'\0\0'
    # this is to force a 2G authentication instead of a 3G one
    AUTH_2G             = False
    # this is to extend AUTN with arbitrary data
    AUTH_AUTN_EXT       = None
    # request IMEISV in the response (hence in clear), uint4
    AUTH_IMEI_REQ       = 0
    #
    # re-authentication policy:
    # this forces an auth procedure every X GMM RAU / SER procedures
    # even if a valid CKSN is provided by the UE
    AUTH_RAU            = 3
    AUTH_SER            = 3
    
    #--------------------------------------------------------------------------#
    # GMMIdentification policy
    #--------------------------------------------------------------------------#
    # GMM procedure timer
    T3370               = 2
    #
    IDENT_FSTDBY        = _FSTDBY
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
    #
    # request IMEISV during an Attach when IMEISV is unknown
    IDENT_IMEISV_REQ = True
    
    #--------------------------------------------------------------------------#
    # GMMAttach policy
    #--------------------------------------------------------------------------#
    ATT_FSTDBY          = _FSTDBY
    ATT_RAU_TIMER       = _RAU_TIMER
    ATT_T3302           = _T3302
    ATT_T3312_EXT       = _T3312_EXT
    ATT_READY_TIMER     = _READY_TIMER
    ATT_NETFEAT_SUPP    = _NETFEAT_SUPP
    ATT_MSINF_REQ       = _MSINF_REQ
    ATT_ADDNETFEAT_SUPP = _ADDNETFEAT_SUPP
    ATT_EXTDRX          = _EXTDRX
    #
    # if we want to run a PTMSI Reallocation within the GPRS Attach Accept
    ATT_PTMSI_REALLOC   = True
    # radio priority for TOM8 / SMS (uint3, 1 -highest- to 4 -slowest-)
    ATT_PRIO_TOM8       = 4
    ATT_PRIO_SMS        = 4
    # if we want to release the IuPS after the procedure ends 
    # and there is no follow on request
    ATT_IUREL           = True
    #
    # when a UEd with PTMSI was created, that in fact corresponds to a UE
    # already set in Server.UE, we need to reject it after updating Server.PTMSI
    ATT_IMSI_PROV_REJECT = 17
    # Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    ATT_T3346           = {'Unit': 0, 'Value': 2}
    
    #--------------------------------------------------------------------------#
    # GMMDetach policy
    #--------------------------------------------------------------------------#
    # if we want to set "Force to StandBy" to force the MS to stop the READY timer 
    # in order to prevent the MS to perform cell updates (must not be enabled in Iu mode)
    DET_FSTDBY          = _FSTDBY
    # network-initiated detach timer
    T3322               = 2
    
    #--------------------------------------------------------------------------#
    # GMMRoutingAreaUpdating policy
    #--------------------------------------------------------------------------#
    RAU_FSTDBY          = _FSTDBY
    RAU_RAU_TIMER       = _RAU_TIMER
    RAU_T3302           = _T3302
    RAU_T3312_EXT       = _T3312_EXT
    RAU_READY_TIMER     = _READY_TIMER
    RAU_NETFEAT_SUPP    = _NETFEAT_SUPP
    RAU_MSINF_REQ       = _MSINF_REQ
    RAU_ADDNETFEAT_SUPP = _ADDNETFEAT_SUPP
    RAU_EXTDRX          = _EXTDRX
    # if we want to run a PTMSI Reallocation within the GPRS Attach Accept
    RAU_PTMSI_REALLOC   = True
    # if we want to release the IuPS after the procedure ends 
    # and there is no follow on request
    RAU_IUREL           = True
    
    #--------------------------------------------------------------------------#
    # interpreter-initiated procedure policy
    #--------------------------------------------------------------------------#
    # all methods made to be run from the interpreter
    # schedule resolution for looking at the procedure presence in the stack
    _INI_SCHED = 0.05
    
    
    def _log(self, logtype, msg):
        self.Iu._log(logtype, '[GMM] %s' % msg)
    
    def __init__(self, ued, iupsd):
        self.UE = ued
        self.set_iu(iupsd)
        #
        # stack of ongoing GMM procedures (i.e. common procedures can be run 
        # within specific or CM-oriented procedure)
        self.Proc = []
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_iu(self, iupsd):
        self.Iu = iupsd
    
    def process(self, NasRx):
        """process a NAS GMM message (NasRx) sent by the UE,
        and return a NAS message (NasTx) response or None
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        ProtDisc, Type = NasRx['ProtDisc'](), NasRx['Type']()
        # 1) check if it is a Detach request
        if Type == 5:
            Proc = GMMDetachUE(self)
            self.Proc.append( Proc )
            if self.TRACK_PROC:
                self._proc.append(Proc)
            # GMMDetachUE.process() will abort every other ongoing NAS procedures
            # for the CS domain
            NasTx = Proc.process(NasRx)
            return NasTx
        #
        # 2) check if there is any ongoing GMM procedure
        elif self.Proc:
            # 2.1) in case of STATUS, disable all ongoing procedures
            if Type == 32:
                self._log('WNG', 'STATUS received with %r' % NasRx['GMMCause'])
                if self.STAT_CLEAR == 1:
                    #self._log('WNG', 'STATUS, disabling %r' % self.Proc[-1])
                    self.Proc[-1].abort()
                elif self.STAT_CLEAR == 2:
                    #self._log('WNG', 'STATUS, disabling %r' % self.Proc)
                    self.clear()
                return None
            #
            # 2.2) in case of expected response
            elif (ProtDisc, Type) in self.Proc[-1].Filter:
                Proc = self.Proc[-1]
                NasTx = Proc.process(NasRx)
                while self.Proc and NasTx is None and self.Iu.RanapTx is None:
                    # while the top-level NAS procedure has nothing to respond and terminates,
                    # we postprocess() lower-level NAS procedure(s) until we have something
                    # to send, or the stack is empty
                    ProcLower = self.Proc[-1]
                    NasTx = ProcLower.postprocess(Proc)
                    Proc = ProcLower
                return NasTx
            #
            # 2.3) in case of unexpected NasRx
            else:
                self._log('WNG', 'unexpected GMM message %r, sending STATUS' % NasRx['Type'])
                # cause 98: Message type not compatible with the protocol state
                return TS24008_GMM.GMMStatus(GMMCause=98)
        #
        # 3) start a new UE-initiated procedure
        elif Type in GMMProcUeDispatcher:
            Proc = GMMProcUeDispatcher[Type](self)
            self.Proc.append( Proc )
            if self.TRACK_PROC:
                self._proc.append(Proc)
            return Proc.process(NasRx)
        #
        # 4) unexpected NasRx
        else:
            self._log('WNG', 'unexpected GMM message %r, sending STATUS' % NasRx['Type'])
            # cause 101: Message not compatible with the protocol state
            return TS24008_GMM.GMMStatus(Cause=101)
    
    def init_proc(self, ProcClass, encod=None):
        """initialize a CN-initiated GMM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        Proc = ProcClass(self, encod=encod)
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
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    def _ini_con(self):
        if not self.Iu.page_block():
            return False
        while self.Proc:
            # wait for GMM common procedures to end
            sleep(self._INI_SCHED)
        if not self.Iu.is_connected():
            # something went wrong during the common procedures
            return False
        else:
            return True
    
    def req_ident(self, idtype=NAS.IDTYPE_IMSI):
        """start an Identity Request procedure toward the UE and wait for the
        response, or timeout
        
        returns True if a response is received, False otherwise
        
        if True, the UEInfo from the response is available in self._ini_ret
        """
        if not self._ini_con():
            return False
        Proc = self.init_proc(GMMIdentification)
        Proc.set_msg(8, 21, IDType=idtype)
        try:
            NasTx = Proc.output().to_bytes()
        except:
            self._log('ERR', 'NAS message encoding failed')
            Proc.abort()
            return False
        self.Iu._send_to_ue(NasTx)
        #
        # check the procedure stack until our ident procedure is not there anymore
        while Proc in self.Proc:
            sleep(self._INI_SCHED)
        # after the procedure has been removed from the stack, 
        # we check if a response was received
        if hasattr(Proc, 'UEInfo'):
            self._ini_ret = Proc.UEInfo
            return True
        else:
            return False
    
    def detach(self, type=1, cause=None):
        """send a GMM Detach with type and cause (optional) and wait for the
        response if type != 3, or timeout
        
        type: 1, re-attach required
              2, re-attach not required
              3, IMSI detach
        
        returns True if a response is received, False otherwise
        
        if True, the UEInfo from the response is available in self._ini_ret
        """
        if not self._ini_con():
            return False
        Proc = self.init_proc(GMMDetachCN)
        if cause is not None:
            Proc.set_msg(8, 5, DetachTypeMT={'Type': type}, GMMCause=cause)
        else:
            Proc.set_msg(8, 5, DetachTypeMT={'Type': type})
        try:
            NasTx = Proc.output().to_bytes()
        except:
            self._log('ERR', 'NAS message encoding failed')
            Proc.abort()
            return False
        self.Iu._send_to_ue(NasTx)
        #
        # check the procedure stack until our detach procedure is not there anymore
        while Proc in self.Proc:
            sleep(self._INI_SCHED)
        # after the procedure has been removed from the stack, 
        # we check if a response was received
        if hasattr(Proc, 'UEInfo'):
            self._ini_ret = Proc.UEInfo
            return True
        else:
            return False
    
    def inform(self, **info):
        """send an GMM information with given info
        """
        if not self._ini_con():
            return False
        Proc = self.init_proc(GMMInformation)
        Proc.set_msg(8, 33, **info)
        try:
            NasTx = Proc.output().to_bytes()
        except:
            self._log('ERR', 'NAS message encoding failed')
            Proc.abort()
            return False
        self.Iu._send_to_ue(NasTx)


class UESMd(SigStack):
    """UE SM handler within a UEIuPSd instance
    responsible for Session Management signaling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the IuCSd
    Iu = None
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    def _log(self, logtype, msg):
        self.Iu._log(logtype, '[SM] %s' % msg)
    
    def __init__(self, ued, iupsd):
        self.UE = ued
        self.set_iu(iupsd)
        #
        # dict of ongoing SM procedures (indexed by transaction identifier)
        self.Proc = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_iu(self, iupsd):
        self.Iu = iupsd
    
    def process(self, NasRx):
        """process a NAS SM message (NasRx) sent by the UE,
        and return a NAS message (NasTx) response or None
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        # returns SM STATUS, cause feature not supported
        return Buf('SM_STATUS', val=b'\x0A\x55\x28', bl=24)
    
    def init_proc(self, Proc, **kw):
        """initialize a CN-initiated SM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        assert()
    
    def clear(self):
        """abort all running procedures
        """
        pass


class UEIuPSd(UEIuSigStack):
    """UE IuPS handler within a CorenetServer instance
    responsible for UE-related RANAP signaling
    """
    
    # to keep track of all PS domain NAS procedures
    TRACK_PROC = True
    
    # domain
    DOM = 'PS'
    
    #--------------------------------------------------------------------------#
    # global security policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all auth and smc procedures during 
    # UE signaling
    SEC_DISABLED = False
    #
    # format of the security context dict self.SEC:
    # self.SEC is a dict of available 2G / 3G security contexts indexed by CKSN,
    # and current CKSN in use
    #
    # when self.SEC['CKSN'] is not None, the context is enabled at the RNC, e.g.
    # self.SEC = {'CKSN': 0,
    #             0: {'CK': b'...', 'IK': b'...', 'UEA': 1, 'UIA': 0, 'CTX': 3},
    #             ...}
    # 
    # a single security context contains:
    # CK, IK: 16 bytes buffer, keys to be sent to the RNC during the smc procedure
    # UEA, UIA: algo index, indicated by the RNC at the end of a successful smc procedure
    # CTX: context of the authentication,
    #    2 means 2G auth converted to 3G context
    #    3 means 3G auth and native context
    
    #--------------------------------------------------------------------------#
    # RANAPSecurityModeControl policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all smc procedures during UE signaling
    SMC_DISABLED = False
    # this will bypass the smc procedure into specific UE signaling procedure
    SMC_DISABLED_PROC = []
    #
    # lists of algorithms priority
    # -> il will be sent as is to the RNC into the SMC
    # -> the RNC will deal with the UE to select one
    SMC_UEA = [2, 1, 0] # UEA2, UEA1, UEA0
    SMC_UIA = [1, 0]    # UIA2, UIA1, UIA0 is not defined in UMTS
    #
    # dummy security context in case an SMC has to be run 
    # but no security context exists
    SMC_DUMMY = {'CK': 16*b'\0', 'IK': 16*b'\0', 'UEA': None, 'UIA': []}
    
    #--------------------------------------------------------------------------#
    # RANAPPaging policy
    #--------------------------------------------------------------------------#
    # if we want to page with the IMSI, instead of the (P)TMSI
    PAG_IMSI = False
    #
    # page_block() parameters:
    # number of retries when not successful
    PAG_RETR = 2
    # timer in sec between retries
    PAG_WAIT = 2
    # schedule resolution for looking at the Iu connection state change
    PAG_SCHED = 0.05
    
    
    def __init__(self, ued, hnbd, ctx_id):
        # init GMM and SM sig stacks
        self.GMM = UEGMMd(ued, self)
        self.SM  = UESMd(ued, self)
        # init the Iu interface
        UEIuSigStack.__init__(self, ued, hnbd, ctx_id)
        # reference the Config from the server
        self.Config = self.Server.ConfigIuPS
        # track states for PDP and MBMS contexts
        self.PDP  = {i: 0 for i in range(16)}
        self.MBMS = {i: 0 for i in range(16)}
    
    def reset_sec_ctx(self):
        self.SEC.clear()
        self.SEC['CKSN'] = None
        self.SEC['POL'] = {'RAU': 0, 'SER': 0}
    
    def _ret_ranap_proc(self, NasTx):
        if NasTx is not None:
            if self.UE.TRACE_NAS_PS:
                self._log('TRACE_NAS_PS_DL', '\n' + NasTx.show())
            if self.RanapTx is None:
                # no specific RANAP Procedure to be used
                # wrap the NAS PDU into a RANAPDirectTransfer
                return self.ret_ranap_dt(NasTx)
            else:
                # some specific RANAP Procedure(s) have already been prepared by 
                # the NAS stack and will embed the NAS PDU in a specific way
                RanapTx = self.RanapTx
                self.RanapTx = None
                return RanapTx
        elif self.RanapTx:
            # some specific RANAP Procedure(s) have been prepared by the NAS stack
            # without embedding NAS_PDU
            RanapTx = self.RanapTx
            self.RanapTx = None
            return RanapTx
        else:
            # nothing to return
            return []
    
    def process_nas(self, buf):
        """process a NAS message buffer for the PS domain sent by the mobile
        and return a potential NAS response to be sent back to it
        """
        NasRx, err = NAS.parse_NAS_MO(buf)
        if NasRx is None:
            self._log('WNG', 'invalid PS NAS message: %s' % hexlify(buf).decode('ascii'))
            # returns MM STATUS
            NasTx = TS24008_GMM.GMMStatus(Cause=err)
            if self.UE.TRACE_NAS_PS:
                self._log('TRACE_NAS_PS_DL', '\n' + NasTx.show())
            return self.ret_ranap_dt(NasTx)
        elif self.UE.TRACE_NAS_PS:
            self._log('TRACE_NAS_PS_UL', '\n' + NasRx.show())
        #
        pd = NasRx['ProtDisc']()
        if pd == 8:
            NasTx = self.GMM.process(NasRx)
        elif pd == 6:
            # Radio Resource Management (e.g. PAGING RESPONSE)
            NasTx = self.GMM.process(NasRx)
        elif pd == 10:
            NasTx = self.SM.process(NasRx)
        else:
            # invalid PD
            self._log('WNG', 'invalid Protocol Discriminator for PS NAS message, %i' % pd)
            # returns GMM STATUS, with cause message-type non-existent 
            # or not implemented
            NasTx = TS24008_GMM.GMMStatus(GMMCause=97)
        #
        return self._ret_ranap_proc(NasTx)
    
    def clear_nas_proc(self):
        # clears all NAS PS procedures
        self.GMM.clear()
        self.SM.clear()
    
    def require_auth(self, Proc, cksn=None):
        # check if an MMAuthentication procedure is required
        if self.SEC_DISABLED:
            return False
        #
        elif cksn is None or cksn not in self.SEC:
            self.SEC['CKSN'] = None
            return True
        #
        else:
            # auth policy per GMM procedure
            if isinstance(Proc, GMMAttach):
                # always authenticate within an Attach
                return True
            elif isinstance(Proc, GMMRoutingAreaUpdating):
                self.SEC['POL']['RAU'] += 1
                if self.GMM.AUTH_RAU and self.SEC['POL']['RAU'] % self.GMM.AUTH_RAU == 0:
                    self.SEC['CKSN'] = None
                    return True
                else:
                    self.SEC['CKSN'] = cksn
                    return False
            elif isinstance(Proc, GMMServiceRequest):
                self.SEC['POL']['SER'] += 1
                if self.GMM.AUTH_SER and self.SEC['POL']['SER'] % self.GMM.AUTH_SER == 0:
                    self.SEC['CKSN'] = None
                    return True
                else:
                    self.SEC['CKSN'] = cksn
                    return False
            else:
                # auth not required, use the UE-provided cksn in use
                self.SEC['CKSN'] = cksn
                return False
    
    def page(self, cause=None):
        """sends RANAP Paging command to RNC responsible for the UE RAI
        
        cause [RANAP_IEs.PagingCause, ENUMERATED]: str or int (0..5)
        """
        # send a RANAPPaging for the PS domain
        if self.RNC is not None:
            self._log('DBG', 'paging: UE already connected')
            return
        # get the set of RNCs serving the UE RAI
        rai = (self.UE.PLMN, self.UE.LAC, self.UE.RAC)
        try:
            rncs = [self.Server.RAN[rncid] for rncid in self.Server.RAI[rai]]
        except:
            self._log('ERR', 'paging: no RNC serving the UE RAI %s.%.4x.%.2x' % rai)
            return
        #
        # prepare the RANAPPaging IEs
        IEs = {'CN_DomainIndicator' : self._cndomind,
               'PermanentNAS_UE_ID' : ('iMSI', NAS.encode_bcd(self.UE.IMSI))}
        if 'DRXParam' in self.UE.Cap:
            drx = self.UE.Cap['DRXParam']['DRXCycleLen']()
            if drx in (6, 7, 8, 9):
                IEs['DRX_CycleLengthCoefficient'] = drx
        if not self.PAG_IMSI:
            IEs['TemporaryUE_ID'] = ('p-TMSI', pack('>I', self.UE.PTMSI))
        if isinstance(cause, integer_types):
            try:
                IEs['PagingCause'] = RANAP.RANAP_IEs.PagingCause._cont_rev[cause]
            except:
                pass
        elif isinstance(cause, str_types):
            IEs['PagingCause'] = cause
        #
        # start a RANAPPaging procedure on all RNCs
        for rnc in rncs:
            self._send_paging(rnc, IEs)
        self._log('INF', 'paging: ongoing')
    
    def page_block(self, cause=None):
        """Pages the UE and wait for it to connect, or the paging procedure to timeout.
        Returns True if UE gets connected, False otherwise.
        
        cause [RANAP_IEs.PagingCause, ENUMERATED]: str or int (0..5)
        """
        # send a RANAPPaging for the PS domain
        if self.RNC is not None:
            self._log('DBG', 'paging: UE already connected')
            return True
        # get the set of RNCs serving the UE RAI
        rai = (self.UE.PLMN, self.UE.LAC, self.UE.RAC)
        try:
            rncs = [self.Server.RAN[rncid] for rncid in self.Server.RAI[rai]]
        except:
            self._log('ERR', 'paging: no RNC serving the UE RAI %s.%.4x.%.2x' % rai)
            return False
        #
        # prepare the RANAPPaging IEs
        IEs = {'CN_DomainIndicator' : self._cndomind,
               'PermanentNAS_UE_ID' : ('iMSI', NAS.encode_bcd(self.UE.IMSI))}
        if 'DRXParam' in self.UE.Cap:
            drx = self.UE.Cap['DRXParam']['DRXCycleLen']()
            if drx in (6, 7, 8, 9):
                IEs['DRX_CycleLengthCoefficient'] = drx
        if not self.PAG_IMSI:
            IEs['TemporaryUE_ID'] = ('p-TMSI', pack('>I', self.UE.PTMSI))
        if isinstance(cause, integer_types):
            try:
                IEs['PagingCause'] = RANAP.RANAP_IEs.PagingCause._cont_rev[cause]
            except:
                pass
        elif isinstance(cause, str_types):
            IEs['PagingCause'] = cause
        #
        # retries paging as defined in case UE does not connect
        i = 0
        while i <= self.PAG_RETR:
            T0 = time()
            # start a RANAPPaging procedure on all RNCs
            for rnc in rncs:
                self._send_paging(rnc, IEs)
            # check until UE gets connected or timer expires
            while not self.is_connected() and time() - T0 < self.PAG_WAIT:
                sleep(self.PAG_SCHED)
            if self.is_connected():
                self._log('INF', 'paging: UE connected')
                return True
            else:
                i += 1
        self._log('WNG', 'paging: timeout, UE not connected')
        return False

