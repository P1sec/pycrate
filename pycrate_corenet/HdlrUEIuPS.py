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
# * File Name : pycrate_corenet/HdlrUEIuPS.py
# * Created : 2017-09-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcCNRanap import *
from .ProcCNGMM   import *
from .ProcCNSM    import *
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
    
    # additional time for letting background task happen in priority
    _WAIT_ADD = 0.005
    
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
    # if 0, enable IMSI attach from PS; if > 0, use it as error code
    # e.g. 16: MSC temporarily not reachable
    ATT_IMSI            = 0
    # if 0, enable emergency attach; if > 0, use it as error code 
    # e.g. 8: GPRS services and non-GPRS services not allowed
    ATT_EMERG           = 0
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
    # timer within AttachReject, Unit: 0: 2s, 1: 1mn, 2: 6mn, 7: deactivated
    ATT_T3346           = {'Unit': 0, 'Value': 2}
    
    #--------------------------------------------------------------------------#
    # GMMDetach policy
    #--------------------------------------------------------------------------#
    # network-initiated detach timer
    T3322               = 2
    #
    DET_FSTDBY          = _FSTDBY
    
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
        # ready event, used by foreground tasks (network / interpreter initiated)
        self.ready = Event()
        self.ready.set()
        # stack of ongoing GMM procedures
        self.Proc   = []
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc  = []
    
    def set_iu(self, iupsd):
        self.Iu = iupsd
    
    def process(self, NasRx):
        """process a NAS GMM message (NasRx) sent by the UE,
        and return a list (potentially empty) of RANAP procedure(s) to be sent
        back to the RNC
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        name = NasRx._name
        # 1) check if it is a Detach request
        if name == 'GMMDetachRequestMO':
            Proc = GMMDetachUE(self)
            self.Proc.append( Proc )
            if self.TRACK_PROC:
                self._proc.append(Proc)
            # GMMDetachUE.process() will abort every other ongoing NAS procedures
            # for the PS domain
            return Proc.process(NasRx)
        #
        # 2) check if there is any ongoing GMM procedure
        elif self.Proc:
            # 2.1) in case of STATUS, disable ongoing procedure(s)
            if name == 'GMMStatus':
                self._log('WNG', 'STATUS received with %r' % NasRx['GMMCause'])
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
                return self.Iu.ret_ranap_dt(NAS.GMMStatus(val={'GMMCause':98}))
        #
        # 3) start a new UE-initiated procedure
        elif name in GMMProcUeDispatcherStr:
            Proc = GMMProcUeDispatcherStr[name](self)
            self.Proc.append( Proc )
            if self.TRACK_PROC:
                self._proc.append(Proc)
            return Proc.process(NasRx)
        #
        # 4) unexpected NasRx
        elif name != 'GMMStatus':
            self._log('WNG', 'unexpected %s message, sending STATUS 96' % name)
            # cause 96: Invalid mandatory information
            return  self.Iu.ret_ranap_dt(NAS.GMMStatus(val={'GMMCause':96}))
        else:
            self._log('WNG', 'unexpected STATUS received with %r' % NasRx['GMMCause'][0])
            return []
    
    def init_proc(self, ProcClass, encod=None, gmm_preempt=False):
        """initialize a CN-initiated GMM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        Proc = ProcClass(self, encod=encod, gmm_preempt=gmm_preempt)
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
    
    # default Radio Access Bearer settings for PDP config, per APN
    # QCI (being LTE + EPS) is copied from the CorenetServer.ConfigPDN at UE init
    RABConfig = {
        '*'      : {
            ### RAB ItemFirst
            # RAB-Parameters
            'TrafficClass'  : 'background',
                # 'conversational', 'streaming', 'interactive', or 'background'
            'RAB-AsymmetryIndicator': 'asymmetric-bidirectional',
                # or 'symmetric-bidirectional', 
                #    'asymmetric-unidirectional-downlink',
                #    'asymmetric-unidirectional-uplink'
            'MaxBitrate'    : [16000000, 8000000], # 0..16000000, (DL, UL)
                # for more than 16Mb/s (e.g. with HSDPA+)
                # use the IE-Extension RAB-Parameter-ExtendedMaxBitrateList
            'DeliveryOrder' : 'delivery-order-not-requested',
                # or 'delivery-order-not-requested'
            'MaxSDU-Size'   : 8000, # 0..32768
            'SDU-Parameters': [{
                'sDU-ErrorRatio'        : {'mantissa': 1, 'exponent': 3}, # m * 10^-e
                'residualBitErrorRatio' : {'mantissa': 1, 'exponent': 5}, # m * 10^-e
                'deliveryOfErroneousSDU': 'no'
                }],
            #'TrafficHandlingPriority': 15, # 0..15, optional
                # TrafficHandlingPriority or AllocationOrRetentionPriority, but not both
                # 1: highest, 14: lowest, 15: no priority
            'AllocationOrRetentionPriority': {
                'priorityLevel' : 15, # 0..15, 1: highest, 14: lowest, 15: no priority
                'pre-emptionCapability'   : 'shall-not-trigger-pre-emption', # or 'may-trigger-pre-emption'
                'pre-emptionVulnerability': 'not-pre-emptable', # or 'pre-emptable'
                'queuingAllowed': 'queueing-not-allowed' # or 'queueing-allowed'
                }, # optional
            #'RelocationRequirement': 'none', # or 'lossless', 'realtime', optional
            #
            # RAB-Parameters Extensions
            #'SignallingIndication': 'signalling',
            #'RAB-Parameter-ExtendedGuaranteedBitrateList': , # 0..16000000, (DL, UL)
            #'RAB-Parameter-ExtendedMaxBitrateList': [42000000], # 16000001..256000000, (DL[, UL])
            #'SupportedRAB-ParameterBitrateList': , # 1..1000000000, (DL, UL)
            #
            # UserPlaneInformation
            'UserPlaneMode'  : 'transparent-mode',
            'UP-ModeVersions': (1, 16), # version 1
            #
            # extended max bitrate
            #'ExtMaxBitrate'  : 42000000,
            #
            ### RAB ItemSecond
            'DataVolumeReportingIndication': 'do-not-report', # or 'do-report', optional
            },
        #
        'corenet': {
            ### RAB ItemFirst
            # RAB-Parameters
            'TrafficClass'  : 'streaming',
                # 'conversational', 'streaming', 'interactive', or 'background'
            'RAB-AsymmetryIndicator': 'asymmetric-bidirectional',
                # or 'symmetric-bidirectional', 
                #    'asymmetric-unidirectional-downlink',
                #    'asymmetric-unidirectional-uplink'
            'MaxBitrate'    : [16000000, 8000000], # 0..16000000, (DL, UL)
                # for more than 16Mb/s (e.g. with HSDPA+)
                # use the IE-Extension RAB-Parameter-ExtendedMaxBitrateList
            'DeliveryOrder' : 'delivery-order-not-requested',
            'MaxSDU-Size'   : 8000, # 0..32768
            'SDU-Parameters': [{
                'sDU-ErrorRatio'        : {'mantissa': 1, 'exponent': 4}, # m * 10^-e
                'residualBitErrorRatio' : {'mantissa': 1, 'exponent': 5}, # m * 10^-e
                'deliveryOfErroneousSDU': 'no'
                }],
            'TrafficHandlingPriority': 14, # 0..15, optional
                # 1: highest, 14: lowest, 15: no priority
            'AllocationOrRetentionPriority': {
                'priorityLevel' : 14, # 0..15, 1: highest, 14: lowest, 15: no priority
                'pre-emptionCapability'   : 'shall-not-trigger-pre-emption', # or 'may-trigger-pre-emption'
                'pre-emptionVulnerability': 'not-pre-emptable', # or 'pre-emptable'
                'queuingAllowed': 'queueing-not-allowed' # or 'queueing-allowed'
                }, # optional
            'RelocationRequirement': 'none', # or 'lossless', 'realtime', optional
            #
            # UserPlaneInformation
            'UserPlaneMode'  : 'transparent-mode',
            'UP-ModeVersions': (1, 16), # version 1
            #
            ### RAB ItemSecond
            'DataVolumeReportingIndication': 'do-not-report', # or 'do-report', optional
            }
        }
    # when the UE 1st attach it gets a specific PDPConfig dict with a copy of this content
    # plus specific content from the CorenetServer.ConfigPDP and CorenetServer.ConfigUE
    
    # Protocol config option with authentication
    # if bypass enabled, the PAP / CHAP authentication will not be checked against
    # the CorenetServer.PDPConfig and always return authentication success
    AUTH_PAP_BYPASS  = True
    AUTH_CHAP_BYPASS = True
    
    # TransportLayerAddress format exchanged over RANAP
    TLA_X213 = False
    
    # some hardcoded SM PDP QoS values (to be set within a dict)
    # otherwise, those values are computed mostly from the RAB config
    PDP_QOS = {
        #'DelayClass'        : 4, # 1..4
        #'ReliabilityClass'  : 2, # 1..5
        #'PeakThroughput'    : 9, # 1..9 (256kO/s / 2Mb/s)
        #'PrecedenceClass'   : 2, # 1..3
        #'MeanThroughput'    : 31, # 1..31 (best effort)
        #'TrafficClass'      : 3, # 1 (convers) .. 4 (bckgnd)
        #'DeliveryOrder'     : 2, # 1 (requested) or 2 (not requested)
        #'ErroneousSDU'      : 2, # 1 (no detect), 2 (yes), 3 (no)
        #'MaxSDUSize'        : 150, # 150 -> 1500 octets
        #'MaxULBitrate'      : 63,
        #'MaxDLBitrate'      : 63,
        #'ResidualBER'       : 1, # 1 (5.10^-2) .. 9 (6.10^-8)
        #'SDUErrorRatio'     : 1, # 1 (10^-2) .. 6 (10^-6) or 7 (10^-1)
        #'TransferDelay'     : 10, # 1..62 (1: 10ms, 10: 100ms, 62: 4s)
        #'TrafficHandlingPriority': 1, # 1, 2 or 3, should be ignored if not "interactive"
        #'GuaranteedULBitrate': 255, # no guarantee
        #'GuaranteedDLBitrate': 255, # no guarantee
        #'SignallingInd'     : 0, # 0 or 1
        #'SourceStatsDesc'   : 0, # 0 (unknown) or 1 (speech)
        #...
        }
    
    # enable the signalling of extended throughput within PDP QoS
    PDP_QOS_WEXT = True
    
    
    def _log(self, logtype, msg):
        self.Iu._log(logtype, '[SM] %s' % msg)
    
    def __init__(self, ued, iupsd):
        self.UE = ued
        self.set_iu(iupsd)
        #
        # dict of ongoing SM procedures, indexed by transaction identifiers
        # 0..127 : network-initiated, 128..255: UE-initiated
        self.Proc  = {}
        # mapping between transaction identifiers and NSAPI (which shall be honored)
        self.Trans = {}
        # dict of activated PDP config per NSAPI
        self.PDP   = {}
        # dict of activated MBMS config per MBMS_NSAPI
        self.MBMS  = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_iu(self, iupsd):
        self.Iu = iupsd
    
    def process(self, NasRx):
        """process a NAS SM message (NasRx) sent by the UE,
        and return a list (potentially empty) of RANAP procedure(s) to be sent
        back to the RNC
        """
        if self.RX_HOOK is not None:
            return self.RX_HOOK(NasRx)
        #
        name = NasRx._name
        tipd = NasRx[0][0]
        tif, ti = tipd[0].get_val(), tipd['TI'].get_val()
        if tif:
            # ti established by the CN
            tid = ti
        else:
            # ti established by the UE
            tid = 0x80 + ti
        # 
        # 1) check if this is a stack-wide STATUS
        if ti == 7 and name == 'SMStatus':
            self._log('WNG', 'STATUS global received with %r' % NasRx['SMCause'])
            self.clear()
            return []
        #
        # 1) check if there is any ongoing SM procedure for this tid
        elif ti in self.Proc:
            ProcStack = self.Proc[ti]
            #
            # 2.1) in case of STATUS, disable ongoing procedure(s)
            if name == 'SMStatus':
                self._log('WNG', 'STATUS for TI %i received with %r' % (ti, NasRx['SMCause']))
                self.clear(ti)
                return []
            #
            # 2.2) in case of expected response
            elif name in ProcStack[-1].FilterStr:
                Proc = ProcStack[-1]
                RanapTxProc = Proc.process(NasRx)
                while ProcStack and not RanapTxProc:
                    # while the top-level NAS procedure has nothing to respond and terminates,
                    # we postprocess() lower-level NAS procedure(s) until we have something
                    # to send, or the stack is empty
                    ProcLower = ProcStack[-1]
                    RanapTxProc = ProcLower.postprocess(Proc)
                    Proc = ProcLower
                return RanapTxProc
            #
            # 2.3) in case of unexpected NasRx
            else:
                self._log('WNG', 'unexpected %s message for TI %i, sending STATUS 98' % (ti, name))
                # cause 98: Message type not compatible with the protocol state
                return self.Iu.ret_ranap_dt(NAS.SMStatus(val={'SMHeader': {'TIPD': {'TIFlag': (1, 0)[tif],
                                                                                    'TI'    : ti}},
                                                              'SMCause':98}))
        #
        # 3) start a new UE-initiated procedure
        elif name in SMProcUeDispatcherStr:
            Proc = SMProcUeDispatcherStr[name](self, tid=tid)
            self.Proc[tid] = [ Proc ]
            if self.TRACK_PROC:
                self._proc.append(Proc)
            return Proc.process(NasRx)
        #
        # 4) unexpected NasRx
        elif name != 'SMStatus':
            self._log('WNG', 'unexpected %s message for TI %i, sending STATUS 96' % (ti, name))
            # cause 96: Invalid mandatory information
            return  self.Iu.ret_ranap_dt(NAS.SMStatus(val={'SMHeader': {'TIPD': {'TIFlag': 0,
                                                                                 'TI'    : 7}},
                                                           'SMCause':96}))
        else:
            self._log('WNG', 'unexpected STATUS for TI %i received with %r' % (ti, NasRx['SMCause'][0]))
            return []
    
    def init_proc(self, ProcClass, encod=None):
        """initialize a CN-initiated SM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        # get a new ti
        for ti in range(0, 7):
            if ti not in self.Proc:
                break
        if ti == 7:
            self._log('WNG', 'no TID available for starting a new procedure')
            return None
        Proc = ProcClass(self, tid=ti, encod=encod)
        self.Proc[ti] = [ Proc ]
        if self.TRACK_PROC:
            self._proc.append( Proc )
        return Proc
    
    def clear(self, ti=None):
        """abort running procedures
        """
        if ti is None:
            for ti in self.Proc:
                for Proc in self.Proc[ti][::-1]:
                    Proc.abort()
        elif ti in self.Proc:
            for Proc in self.Proc[ti][::-1]:
                Proc.abort()
    
    def pdp_clear(self, nsapi=None):
        if nsapi is None:
            for nsapi, pdpcfg in list(self.PDP.items()):
                self.UE.Server.GTPUd.rem_mobile(pdpcfg['RAB']['SGW-GTP-TEID'])
                del self.PDP[nsapi]
        elif nsapi in self.PDP:
            self.UE.Server.GTPUd.rem_mobile(self.PDP[nsapi]['RAB']['SGW-GTP-TEID'])
            del self.PDP[nsapi]
    
    def pdp_suspend(self, nsapi=None):
        if nsapi is None:
            for nsapi, pdpcfg in self.PDP.items():
                if pdpcfg['state'] == 1:
                    self.UE.Server.GTPUd.rem_mobile(pdpcfg['RAB']['SGW-GTP-TEID'])
                    pdpcfg['state'] = 0
        elif nsapi in self.PDP and self.PDP[nsapi]['state'] == 1:
            self.UE.Server.GTPUd.rem_mobile(self.PDP[nsapi]['RAB']['SGW-GTP-TEID'])
            self.PDP[nsapi]['state'] = 0
    
    def rab_set_default(self, nsapi, tid, apn, pdpaddr, pdpcfg):
        rabcfg = pdpcfg['RAB']
        del pdpcfg['RAB']
        pdp = cpdict(pdpcfg)
        pdpcfg['RAB'] = rabcfg
        #
        pdp['PDPAddr'] = pdpaddr
        pdp['APN'] = apn
        pdp['TID'] = tid
        pdp['RAB'] = {
            'SGW-TLA': self.UE.Server.SERVER_HNB['GTPU'],
            'HNB-TLA': None, # hnb gtpu ipn, will be updated after the HNB setup the RAB
            'SGW-GTP-TEID': self.UE.Server.get_gtp_teid(), # teid_ul
            'HNB-GTP-TEID': None, # teid_dl, will be updated after the HNB setup the RAB
            }
        #
        # RAB item is a field pair
        rab_first = {
            'rAB-ID': (nsapi, 8),
            'rAB-Parameters': {
                'trafficClass'   : rabcfg['TrafficClass'],
                'rAB-AsymmetryIndicator': rabcfg['RAB-AsymmetryIndicator'],
                'maxBitrate'     : rabcfg['MaxBitrate'],
                'deliveryOrder'  : rabcfg['DeliveryOrder'],
                'maxSDU-Size'    : rabcfg['MaxSDU-Size'],
                'sDU-Parameters' : rabcfg['SDU-Parameters']
                },
            'userPlaneInformation': {
                'userPlaneMode'  : rabcfg['UserPlaneMode'],
                'uP-ModeVersions': rabcfg['UP-ModeVersions']
                },
            'transportLayerInformation': {
                'iuTransportAssociation': ('gTP-TEI', uint_to_bytes(pdp['RAB']['SGW-GTP-TEID'], 32))
                }
            }
        #
        if self.TLA_X213:
            # 0x35: IANA ICP, 0x01: IPv4 addr
            rab_first['transportLayerInformation']['transportLayerAddress'] = \
                ((0x35<<152) + (0x01<<136) + (bytes_to_uint(inet_aton(pdp['RAB']['SGW-TLA']), 32)<<104),
                 160)
        else:
            rab_first['transportLayerInformation']['transportLayerAddress'] = \
                (bytes_to_uint(inet_aton(pdp['RAB']['SGW-TLA']), 32),
                 32)
        #
        if 'SignallingIndication' in rabcfg \
        or 'RAB-Parameter-ExtendedGuaranteedBitrateList' in rabcfg \
        or 'RAB-Parameter-ExtendedMaxBitrateList' in rabcfg \
        or 'SupportedRAB-ParameterBitrateList' in rabcfg:
            # RAB parameters extensions
            exts = []
            if 'SignallingIndication' in rabcfg:
                exts.append({'id': 116,
                             'criticality': 'ignore',
                             'extensionValue': ('SignallingIndication',
                                                rabcfg['SignallingIndication'])})
            if 'RAB-Parameter-ExtendedGuaranteedBitrateList' in rabcfg:
                exts.append({'id': 176,
                             'criticality': 'reject',
                             'extensionValue': ('RAB-Parameter-ExtendedGuaranteedBitrateList',
                                                rabcfg['RAB-Parameter-ExtendedGuaranteedBitrateList'])})
            if 'RAB-Parameter-ExtendedMaxBitrateList' in rabcfg:
                exts.append({'id': 177,
                             'criticality': 'reject',
                             'extensionValue': ('RAB-Parameter-ExtendedMaxBitrateList',
                                                rabcfg['RAB-Parameter-ExtendedMaxBitrateList'])})
            if 'SupportedRAB-ParameterBitrateList' in rabcfg:
                # TODO: check the diff between the Ext with id 218 and id 219
                exts.append({'id': 219,
                             'criticality': 'reject',
                             'extensionValue': ('SupportedRAB-ParameterBitrateList',
                                                rabcfg['SupportedRAB-ParameterBitrateList'])})
            rab_first['rAB-Parameters']['iE-Extensions'] = exts
        #
        if 'TrafficHandlingPriority' in rabcfg:
            rab_first['rAB-Parameters']['trafficHandlingPriority'] = rabcfg['TrafficHandlingPriority']
        if 'AllocationOrRetentionPriority' in rabcfg:
            rab_first['rAB-Parameters']['allocationOrRetentionPriority'] = rabcfg['AllocationOrRetentionPriority']
        if 'RelocationRequirement' in rabcfg:
            rab_first['rAB-Parameters']['relocationRequirement'] = rabcfg['RelocationRequirement']
        pdp['RAB']['First'] = rab_first
        #
        rab_second = {
            #'dl-GTP-PDU-SequenceNumber': 0,
            #'ul-GTP-PDU-SequenceNumber': 0
            }
        if pdpaddr[0] == 0:
            rab_second['pDP-TypeInformation'] = ['ppp']
        elif pdpaddr[0] == 1:
            rab_second['pDP-TypeInformation'] = ['ipv4']
        elif pdpaddr[0] == 2:
            rab_second['pDP-TypeInformation'] = ['ipv6']
        elif pdpaddr[0] == 3:
            rab_second['pDP-TypeInformation'] = ['ipv4', 'ipv6']
        if 'DataVolumeReportingIndication' in rabcfg:
            rab_second['dataVolumeReportingIndication'] = rabcfg['DataVolumeReportingIndication']
        pdp['RAB']['Second'] = rab_second
        #
        pdp['state']  = 0 # 0: suspended (no GTP tunnel exist), 1: active (GTP tunnel exists)
        pdp['linked'] = [] # will be expanded in case secondary ctxt are created
        self.PDP[nsapi] = pdp
    
    #--------------------------------------------------------------------------#
    # protocol configuration processing
    #--------------------------------------------------------------------------#
    
    def process_protconfig(self, config, request):
        RespElt, pdpaddrreq = self.UE.process_protconfig(self, config, request)
        return {'Config': RespElt}, pdpaddrreq


class UEIuPSd(UEIuSigStack):
    """UE IuPS handler within a CorenetServer instance
    responsible for UE-related RANAP signaling
    """
    
    # to keep track of all PS domain NAS procedures
    TRACK_PROC = True
    
    # domain
    DOM = 'PS'
    
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
    #             'POL': {'RAU': 0, 'SER': 0}}
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
    # set proc abbreviation in the list: 'ATT', 'RAU', 'SER'
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
        self.Config = self.Server.ConfigIuPS
        #
        # init GMM and SM sig stacks
        self.GMM = UEGMMd(ued, self)
        self.SM  = UESMd(ued, self)
    
    def reset_sec_ctx(self):
        self.SEC.clear()
        self.SEC['CKSN'] = None
        self.SEC['POL'] = {'RAU': 0, 'SER': 0}
    
    def process_nas(self, buf):
        """process a NAS message buffer for the PS domain sent by the mobile
        and return a list (possibly empty) of RANAP procedure(s) to be sent back 
        to the RNC
        """
        if self.RX_HOOK:
            return self.RX_HOOK(buf)
        NasRx, err = NAS.parse_NAS_MO(buf)
        if err:
            self._log('WNG', 'invalid PS NAS message: %s' % hexlify(buf).decode('ascii'))
            # returns GMM STATUS
            return self.ret_ranap_dt(NAS.GMMStatus(val={'GMMCause':err}))
        #
        Hdr = NasRx[0]
        if Hdr[0]._name == 'TIPD':
            pd = Hdr[0]['ProtDisc'].get_val()
        else:
            pd = Hdr['ProtDisc'].get_val()
        #
        if self.UE.TRACE_NAS_PS:
            self._log('TRACE_NAS_PS_UL', '\n' + NasRx.show())
        #
        if pd == 8:
            RanapTxProc = self.GMM.process(NasRx)
        elif pd == 6:
            # Radio Resource Management (e.g. PAGING RESPONSE)
            RanapTxProc = self.GMM.process(NasRx)
        elif pd == 10:
            RanapTxProc = self.SM.process(NasRx)
        else:
            # invalid PD
            self._log('WNG', 'invalid Protocol Discriminator for PS NAS message, %i' % pd)
            # returns GMM STATUS, with cause message-type non-existent 
            # or not implemented
            RanapTxProc = self.ret_ranap_dt(NAS.GMMStatus(val={'GMMCause':97}))
        #
        return RanapTxProc
    
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
        # paging with IMSI instead of P-TMSI
        if not self.PAG_IMSI:
            IEs['TemporaryUE_ID'] = ('p-TMSI', pack('>I', self.UE.PTMSI))
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
        """sends RANAP Paging command to RNC responsible for the UE RAI
        
        cause [RANAP_IEs.PagingCause, ENUMERATED]: str or int (0..5)
        """
        # send a RANAPPaging for the PS domain
        if self.connected.is_set():
            self._log('DBG', 'paging: UE already connected')
            return
        # get the set of RNCs serving the UE RAI
        rai = (self.UE.PLMN, self.UE.LAC, self.UE.RAC)
        try:
            rncs = [self.Server.RAN[rncid] for rncid in self.Server.RAI[rai]]
        except Exception:
            self._log('ERR', 'paging: no RNC serving the UE RAI %s.%.4x.%.2x' % rai)
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
        # send a RANAPPaging for the PS domain
        if self.connected.is_set():
            self._log('DBG', 'paging: UE already connected')
            return True
        # get the set of RNCs serving the UE RAI
        rai = (self.UE.PLMN, self.UE.LAC, self.UE.RAC)
        try:
            rncs = [self.Server.RAN[rncid] for rncid in self.Server.RAI[rai]]
        except Exception:
            self._log('ERR', 'paging: no RNC serving the UE RAI %s.%.4x.%.2x' % rai)
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
        return self.GMM._net_init_con()
    
    #--------------------------------------------------------------------------#
    # PS bearers activation
    #--------------------------------------------------------------------------#
    
    def bearer_act(self):
        # reactivate all PDP connections
        rablist, nsapilist, brdl, brul = [], [], 0, 0
        for nsapi, pdpcfg in self.SM.PDP.items():
            if 'RAB' in pdpcfg:
                rabcfg = pdpcfg['RAB']
                nsapilist.append(nsapi)
                rablist.append([{
                    'id': 53, # id-RAB-SetupOrModifyItem
                    'firstCriticality': 'reject',
                    'firstValue': ('RAB-SetupOrModifyItemFirst', rabcfg['First']),
                    'secondCriticality': 'ignore',
                    'secondValue': ('RAB-SetupOrModifyItemSecond', rabcfg['Second'])
                    }])
        if not nsapilist:
            return None
        #
        IEs = {'RAB_SetupOrModifyList': rablist}
        # initiate a RANAPRABAssignment
        RanapProc = self.init_ranap_proc(RANAPRABAssignment, **IEs)
        if RanapProc:
            # pass the info required for setting the GTPU tunnel
            RanapProc._gtp_add_mobile_nsapi = nsapilist
            return RanapProc
        else:
            return None

