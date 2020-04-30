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
# * File Name : pycrate_corenet/HdlrUEIuCS.py
# * Created : 2017-09-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcCNRanap import *
from .ProcCNMM    import *
from .HdlrUEIu    import UEIuSigStack
from .HdlrUESMS   import UESMSd


#------------------------------------------------------------------------------#
# UE-related Iu interface handler for the CS domain
# including MM, CC and SMS stacks
#------------------------------------------------------------------------------#

class UEMMd(SigStack):
    """UE MM handler within a UEIuCSd instance
    responsible for Mobility Management signalling procedures
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
    
    # additional time for letting background task happen in priority
    _WAIT_ADD = 0.005
    
    #--------------------------------------------------------------------------#
    # MMStatus policy
    #--------------------------------------------------------------------------#
    # behaviour when receiving MM STATUS
    # 0: do nothing,
    # 1: abort the top-level MM procedure,
    # 2: abort the whole stack of MM procedures
    STAT_CLEAR = 2
    
    #--------------------------------------------------------------------------#
    # MMTMSIReallocation policy
    #--------------------------------------------------------------------------#
    # MM common procedure timer
    T3250 = 4
    
    #--------------------------------------------------------------------------#
    # MMAuthentication policy
    #--------------------------------------------------------------------------#
    # MM common procedure timer
    T3260 = 4
    # Authentication Management Field
    AUTH_AMF = b'\0\0'
    # this is to force a 2G authentication instead of a 3G one
    AUTH_2G = False
    # this is to extend AUTN with arbitrary data
    AUTH_AUTN_EXT = None
    #
    # re-authentication policy:
    # this forces an auth procedure every X LUR / PAG / CON procedures
    # even if a valid CKSN is provided by the UE
    AUTH_LUR = 3
    AUTH_PAG = 3
    AUTH_CON = 3
    
    #--------------------------------------------------------------------------#
    # MMIdentification policy
    #--------------------------------------------------------------------------#
    # MM common procedure timer
    T3270 = 2
    # potential causes:
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
    # request IMEI during a LUR when IMEI is unknown
    IDENT_IMEI_REQ = True
    
    #--------------------------------------------------------------------------#
    # MMLocationUpdating policy
    #--------------------------------------------------------------------------#
    # if we want to run a TMSI Reallocation within the Location Updating Accept
    LU_TMSI_REALLOC = True
    # if we want to enable "Follow on proceed"
    LU_FOP = True
    # UE-specific T3212 (periodic LUR), should be different from the broadcasted one
    # dict {'Unit': uint3, 'Value': uint5} or None
    # Unit: 0: 10mn, 1: 1h, 2: 10h, 3: 2s, 4: 30s, 5: 1mn, 6: 320h, 7: deactivated
    #LU_T3212 = {'Unit': 5, 'Value': 10} # 10min
    #LU_T3212 = {'Unit': 1, 'Value': 1} # 1h
    LU_T3212 = None
    # if we want to release the IuCS after the procedure ends 
    # and there is no follow on request
    LU_IUREL = True
    #
    # when a UEd with TMSI was created, that in fact corresponds to a UE
    # already set in Server.UE, we need to reject it after updating Server.TMSI
    LU_IMSI_PROV_REJECT = 17
    # Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    LU_T3246 = {'Unit': 0, 'Value': 2}
    
    #--------------------------------------------------------------------------#
    # MMConnectionEstablishment policy
    #--------------------------------------------------------------------------#
    # dict of services rejected with associated cause
    # otherwise, connection is accepted
    # 1: Mobile originating call / packet mode connection,
    # 2: Emergency call,
    # 4: SMS,
    # 8: Supplementary service,
    # 9: Voice group call,
    # 10: Voice broadcast call,
    # 11: Location service
    CON_REJ = {}
    # when a con estab is rejected, a retry timer wil be sent, if not None
    # Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    CON_T3246 = {'Unit': 7, 'Value': 0}
    # if we want to release the IuCS after the procedure ends on a reject case
    CON_IUREL = True
    
    #--------------------------------------------------------------------------#
    # interpreter-initiated procedure policy
    #--------------------------------------------------------------------------#
    # all methods made to be run from the interpreter
    # schedule resolution for looking at the procedure presence in the stack
    _INI_SCHED = 0.05
    
    
    def _log(self, logtype, msg):
        self.Iu._log(logtype, '[MM] %s' % msg)
    
    def __init__(self, ued, iucsd):
        self.UE = ued
        self.set_iu(iucsd)
        #
        # ready event, used by foreground tasks (network / interpreter initiated)
        self.ready = Event()
        self.ready.set()
        # stack of ongoing MM procedures (i.e. common procedures can be run 
        # within specific or CM-oriented procedure)
        self.Proc   = []
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc  = []
    
    def set_iu(self, iucsd):
        self.Iu = iucsd
    
    def process(self, NasRx):
        """process a NAS MM message (NasRx) sent by the UE,
        and return a list (potentially empty) of RANAP procedure(s) to be sent
        back to the RNC
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        name = NasRx._name
        # 1) check if it is a Detach Indication
        if name == 'MMIMSIDetachIndication':
            Proc = MMIMSIDetach(self)
            self.Proc.append( Proc )
            if self.TRACK_PROC:
                self._proc.append(Proc)
            # MMIMSIDetach.process() will abort every other ongoing NAS procedures
            # for the CS domain
            return Proc.process(NasRx)
        #
        # 2) check if there is any ongoing MM procedure
        elif self.Proc:
            # 2.1) in case of STATUS, disable ongoing procedure(s)
            if name == 'MMStatus':
                self._log('WNG', 'STATUS received with %r' % NasRx['RejectCause'][0])
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
                RanapTxProc = Proc.process(NasRx)
                while self.Proc and not RanapTxProc:
                    # while the top-level NAS procedure has nothing to respond and terminates,
                    # we postprocess() lower-level NAS procedure(s) until we have something
                    # to send, or the stack is empty
                    ProcLower = self.Proc[-1]
                    RanapTxProc = ProcLower.postprocess(Proc)
                    Proc = ProcLower
                return RanapTxProc
            #
            # 2.3) in case of unexpected NasRx
            else:
                self._log('WNG', 'unexpected %s message, sending STATUS 98' % name)
                # cause 98: Message type not compatible with the protocol state
                return  self.Iu.ret_ranap_dt(NAS.MMStatus(val={'RejectCause':98}))
        #
        # 3) start a new UE-initiated procedure
        elif name in MMProcUeDispatcherStr:
            # the dispatcher include the support of the RRPagingResponse message
            Proc = MMProcUeDispatcherStr[name](self)
            self.Proc.append( Proc )
            if self.TRACK_PROC:
                self._proc.append(Proc)
            return Proc.process(NasRx)
        #
        # 4) unexpected NasRx
        elif name != 'MMStatus':
            self._log('WNG', 'unexpected %s message, sending STATUS 96' % name)
            # cause 96: Invalid mandatory information
            return  self.Iu.ret_ranap_dt(NAS.MMStatus(val={'RejectCause':96}))
        else:
            self._log('WNG', 'unexpected STATUS received with %r' % NasRx['RejectCause'][0])
            return []
    
    def init_proc(self, ProcClass, encod=None, mm_preempt=False):
        """initialize a CN-initiated MM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        Proc = ProcClass(self, encod=encod, mm_preempt=mm_preempt)
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
    
    def _net_init_con(self):
        if not self.Iu.page_block():
            return False
        # need to wait for potential MM common procedures to happen and end
        sleep(self._WAIT_ADD)
        if not self.ready.wait(10):
            # something is blocking in the common procedures
            return False
        elif not self.Iu.connected.is_set():
            # something went wrong during the common procedures
            return False
        else:
            return True
    
    def run_proc(self, ProcClass, **IEs):
        """run a network-initiated procedure ProcClass in the context of the MM
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
        Proc = self.init_proc(ProcClass, encod={ProcClass.Init: IEs}, mm_preempt=True)
        try:
            RanapTxProc = Proc.output()
        except Exception:
            self._log('ERR', 'invalid IEs for network-initiated procedure %s' % Proc.Name)
            Proc.abort()
            return False, Proc
        if not self.Iu._send_to_rnc_ranap(RanapTxProc):
            # something bad happened while sending the message
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
        """start a GMM Identification procedure toward the UE and wait for the
        response or timeout
        """
        return self.run_proc(GMMIdentification, IDType=idtype)
    
    def detach(self, type=1, cause=None):
        """send a GMM Detach with type and cause (optional) and wait for the
        response (if type != 3) or timeout
        """
        if cause is not None:
            return self.run_proc(GMMDetachCN, DetachTypeMT={'Type': type}, GMMCause=cause)
        else:
            return self.run_proc(GMMDetachCN, DetachTypeMT={'Type': type})
    
    def inform(self, **info):
        """send a GMM Information with given info
        """
        return self.run_proc(GMMInformation, **info)
    
    def req_ident(self, idtype=NAS.IDTYPE_IMSI):
        """start an MM Identification procedure toward the UE and wait for the
        response or timeout
        """
        return self.run_proc(MMIdentification, IDType=idtype)
    
    def inform(self, **info):
        """send an MM information with given info
        """
        return self.run_proc(MMInformation, **info)


class UECCd(SigStack):
    """UE CC handler within a UEIuCSd instance
    responsible for Call Control signalling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the IuCSd
    Iu = None
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    def _log(self, logtype, msg):
        self.Iu._log(logtype, '[CC] %s' % msg)
    
    def __init__(self, ued, iucsd):
        self.UE = ued
        self.set_iu(iucsd)
        #
        # dict of ongoing CC procedures (indexed by transaction identifier)
        self.Proc  = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_iu(self, iucsd):
        self.Iu = iucsd
    
    def process(self, NasRx):
        """process a NAS CC message (NasRx) sent by the UE,
        and return a list (potentially empty) of RANAP procedure(s) to be sent
        back to the RNC
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        # returns CC STATUS, cause network failure
        return self.Iu.ret_ranap_dt(Buf('CCStatus', val=b'\x03\x61\0', bl=24))
    
    def init_proc(self, ProcClass, encod=None):
        """initialize a CN-initiated CC procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        assert()
    
    def clear(self):
        """abort all running procedures
        """
        pass


class UESSd(SigStack):
    """UE SS handler within a UEIuCSd instance
    responsible for Supplementary Service signalling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the IuCSd
    Iu = None
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    def _log(self, logtype, msg):
        self.Iu._log(logtype, '[SS] %s' % msg)
    
    def __init__(self, ued, iucsd):
        self.UE = ued
        self.set_iu(iucsd)
        #
        # dict of ongoing SS procedures (indexed by transaction identifier)
        self.Proc  = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
        
    def set_iu(self, iucsd):
        self.Iu = iucsd
    
    def process(self, NasRx):
        """process a NAS SS message (NasRx) sent by the UE,
        and return a list (potentially empty) of RANAP procedure(s) to be sent
        back to the RNC
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        # returns SSReleaseComplete, cause network failure
        return self.Iu.ret_ranap_dt(Buf('SSReleaseComplete', val=b'\x0B\x2A\x11', bl=24))
    
    def init_proc(self, ProcClass, encod=None):
        """initialize a CN-initiated SS procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        assert()
    
    def clear(self):
        """abort all running procedures
        """
        pass


class UEIuCSd(UEIuSigStack):
    """UE IuCS handler within a CorenetServer instance
    responsible for UE-related RANAP signalling
    """
    
    # to keep track of all CS domain RANAP / NAS procedures
    TRACK_PROC = True
    
    # domain
    DOM = 'CS'
    
    # to bypass the process_nas() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
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
    #             ...,
    #             'POL': {'LUR': 0, 'CON': 0, 'PAG': 0}}
    # 
    # a single security context contains:
    # CK, IK: 16 bytes buffer, keys to be sent to the RNC during the smc procedure
    # UEA, UIA: algo index, indicated by the RNC at the end of a successful smc procedure
    # CTX: context of the authentication,
    #    2 means 2G auth converted to 3G context, in this case, Kc is also available
    #    in the security context
    #    3 means 3G auth and native context
    # The POL dict indicates the authentication policy for each procedure
    
    #--------------------------------------------------------------------------#
    # RANAPSecurityModeControl policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all smc procedures during UE signaling
    SMC_DISABLED = False
    # this will bypass the smc procedure into specific UE signalling procedure
    # set proc abbreviation in the list: 'LU', 'CON', 'PAG'
    SMC_DISABLED_PROC = []
    #
    # lists of algorithms priority
    # -> il will be sent as is to the RNC into the SMC
    # -> the RNC will deal with the UE to select one
    #SMC_UEA = [2, 1, 0] # UEA2, UEA1, UEA0
    SMC_UEA = [1, 0]
    #SMC_UIA = [1, 0]    # UIA2, UIA1, UIA0 is not defined in UMTS
    SMC_UIA = [0]
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
    
    
    def __init__(self, ued, hnbd=None, ctx_id=-1):
        # init the Iu interface
        UEIuSigStack.__init__(self, ued, hnbd, ctx_id)
        # reference the Config from the server
        self.Config = self.Server.ConfigIuCS
        #
        # init MM, CC, SMS and SS sig stacks
        self.MM  = UEMMd(ued, self)
        self.CC  = UECCd(ued, self)
        self.SMS = UESMSd(ued, self)
        self.SS  = UESSd(ued, self)
    
    def reset_sec_ctx(self):
        self.SEC.clear()
        self.SEC['CKSN'] = None
        self.SEC['POL'] = {'LUR': 0, 'CON': 0, 'PAG': 0}
    
    def process_nas(self, buf):
        """process a NAS message buffer for the CS domain sent by the mobile
        and return a list (possibly empty) of RANAP procedure(s) to be sent back 
        to the RNC
        """
        if self.RX_HOOK:
            return self.RX_HOOK(buf)
        NasRx, err = NAS.parse_NAS_MO(buf)
        if err:
            self._log('WNG', 'invalid CS NAS message: %s' % hexlify(buf).decode('ascii'))
            # returns MM STATUS
            return self.ret_ranap_dt(NAS.MMStatus(val={'RejectCause':err}))
        #
        Hdr = NasRx[0]
        if Hdr[0]._name == 'TIPD':
            pd = Hdr[0]['ProtDisc'].get_val()
        else:
            pd = Hdr['ProtDisc'].get_val()
        #
        if self.UE.TRACE_NAS_CS and pd != 9:
            # SMS are traced within the SMS stack
            self._log('TRACE_NAS_CS_UL', '\n' + NasRx.show())
        #
        if pd in (5, 6):
            # including Radio Resource Management (e.g. PAGING RESPONSE)
            RanapTxProc = self.MM.process(NasRx)
        elif pd == 3:
            RanapTxProc = self.CC.process(NasRx)
        elif pd == 9:
            SMSTx = self.SMS.process(NasRx)
            RanapTxProc = []
            for smscp in SMSTx:
                RanapTxProc.extend( self.ret_ranap_dt(smscp, sapi=3) )
                #if smscp._name == 'CP_DATA':
                #    RanapTxProc.extend( self.ret_ranap_dt(smscp, sapi=3) )
                #else:
                #    RanapTxProc.extend( self.ret_ranap_dt(smscp, sapi=0) )
        elif pd == 11:
            RanapTxProc = self.SS.process(NasRx)
        else:
            # invalid PD
            self._log('WNG', 'invalid Protocol Discriminator for CS NAS message, %i' % pd)
            # returns MM STATUS, with cause message-type non-existent 
            # or not implemented
            RanapTxProc = self.ret_ranap_dt(NAS.MMStatus(val={'RejectCause':97}))
        #
        return RanapTxProc
    
    def clear_nas_proc(self):
        # clears all NAS CS procedures
        self.SS.clear()
        self.SMS.clear()
        self.CC.clear()
        self.MM.clear()
    
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
            # auth policy per MM procedure
            ident = None
            if isinstance(Proc, MMLocationUpdating):
                self.SEC['POL']['LUR'] += 1
                if self.MM.AUTH_LUR and self.SEC['POL']['LUR'] % self.MM.AUTH_LUR == 0:
                    self.SEC['CKSN'] = None
                    return True
                else:
                    self.SEC['CKSN'] = cksn
                    return False
            elif isinstance(Proc, RRPagingResponse):
                self.SEC['POL']['PAG'] += 1
                if self.MM.AUTH_PAG and self.SEC['POL']['PAG'] % self.MM.AUTH_PAG == 0:
                    self.SEC['CKSN'] = None
                    return True
                else:
                    self.SEC['CKSN'] = cksn
                    return False
            elif isinstance(Proc, MMConnectionEstablishment):
                self.SEC['POL']['CON'] += 1
                if self.MM.AUTH_CON and self.SEC['POL']['CON'] % self.MM.AUTH_CON == 0:
                    self.SEC['CKSN'] = None
                    return True
                else:
                    self.SEC['CKSN'] = cksn
                    return False
            else:
                # auth not required, use the UE-provided cksn in use
                self.SEC['CKSN'] = cksn
                return False
    
    #--------------------------------------------------------------------------#
    # paging and network-initiated procedures' routines
    #--------------------------------------------------------------------------#
    
    def _get_paging_ies(self, cause):
        # prepare the RANAPPaging IEs
        # CN domain and IMSI
        IEs = {'CN_DomainIndicator' : self._cndomind,
               'PermanentNAS_UE_ID' : ('iMSI', NAS.encode_bcd(self.UE.IMSI))}
        # DRX paging cycle
        if 'DRXParam' in self.UE.Cap:
            drx = self.UE.Cap['DRXParam'][1]['DRXCycleLen'].get_val()
            if drx in (6, 7, 8, 9):
                IEs['DRX_CycleLengthCoefficient'] = drx
        # paging with IMSI instead of TMSI
        if not self.PAG_IMSI:
            IEs['TemporaryUE_ID'] = ('tMSI', pack('>I', self.UE.TMSI))
        # paging cause
        if isinstance(cause, integer_types):
            try:
                IEs['PagingCause'] = RANAP.RANAP_IEs.PagingCause._cont_rev[cause]
            except Exception:
                pass
        elif isinstance(cause, str_types):
            IEs['PagingCause'] = cause
        return IEs
    
    def page(self, cause=None):
        """sends RANAP Paging command to RNC responsible for the UE LAI
        
        cause [RANAP_IEs.PagingCause, ENUMERATED]: str or int (0..5)
        """
        # send a RANAPPaging for the CS domain
        if self.connected.is_set():
            self._log('DBG', 'paging: UE already connected')
            return
        # get the set of RNCs serving the UE LAI
        try:
            rncs = [self.Server.RAN[rncid] for \
                    rncid in self.Server.LAI[(self.UE.PLMN, self.UE.LAC)]]
        except Exception:
            self._log('ERR', 'paging: no RNC serving the UE LAI %s.%.4x'\
                      % (self.UE.PLMN, self.UE.LAC))
            return
        #
        IEs = self._get_paging_ies(cause)
        # start a RANAPPaging procedure on all RNCs
        for rnc in rncs:
            rnc.page(**IEs)
        self._log('INF', 'paging: ongoing')
    
    def page_block(self, cause=None):
        """Pages the UE and wait for it to connect, or the paging procedure to timeout.
        Returns True if UE gets connected, False otherwise.
        
        cause [RANAP_IEs.PagingCause, ENUMERATED]: str or int (0..5)
        """
        # send a RANAPPaging for the CS domain
        if self.connected.is_set():
            self._log('DBG', 'paging: UE already connected')
            return True
        # get the set of RNCs serving the UE LAI
        try:
            rncs = [self.Server.RAN[rncid] for \
                    rncid in self.Server.LAI[(self.UE.PLMN, self.UE.LAC)]]
        except Exception:
            self._log('ERR', 'paging: no RNC serving the UE LAI %s.%.4x'\
                      % (self.UE.PLMN, self.UE.LAC))
            return False
        #
        IEs = self._get_paging_ies(cause)
        # retries paging as defined in case UE does not connect
        i = 0
        while i <= self.PAG_RETR:
            # start a RANAPPaging procedure on all RNCs
            for rnc in rncs:
                rnc.page(**IEs)
            # check until UE gets connected or timer expires
            if self.connected.wait(self.PAG_WAIT):
                self._log('INF', 'paging: UE connected')
                return True
            else:
                # timeout
                i += 1
        self._log('WNG', 'paging: timeout, UE not connected')
        return False
    
    # this is used by send_raw() and other network-initiated procedures common to CS and PS
    # defined in UEIuSigStack in HdlrUEIu.py
    def _net_init_con(self):
        return self.MM._net_init_con()

