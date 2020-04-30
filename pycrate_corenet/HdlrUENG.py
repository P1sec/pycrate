# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. ANSSI.
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
# * File Name : pycrate_corenet/HdlrUENG.py
# * Created : 2020-04-29
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils      import *
from .ProcCNNgap import *
# load all required 5G NAS protocol handlers and SMS handler
#from .ProcCNFGMM import *
#from .HdlrUESMS  import *


class UEFGMMd(SigStack):
    """UE 5GMM handler within a UENGd instance
    responsible for 5G Mobility Management signalling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the UENGd
    NG = None
    
    # state: INACTIVE (cannot be paged) <-> ACTIVE <-> IDLE
    state = 'INACTIVE'
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    # additional time for letting background task happen in priority
    _WAIT_ADD = 0.005
    
    # list of 5GMM message types that do not require NAS security to be
    # activated to be processed
    SEC_NOTNEED = {}
    # to disable completely the check for secured NAS message
    SEC_DISABLED = False
    
    
    
    
        
    
    def _log(self, logtype, msg):
        self.NG._log(logtype, '[5GMM] %s' % msg)
    
    def __init__(self, ued, uengd):
        self.UE = ued
        self.set_ng(uengd)
        #
        # ready event, used by foreground tasks (network / interpreter initiated)
        self.ready = Event()
        self.ready.set()
        # stack of ongoing 5GMM procedures (i.e. common procedures can be run 
        # within specific procedure)
        self.Proc   = []
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc  = []
    
    def set_ng(self, uengd):
        self.NG = uengd
    
    def process(self, NasRx):
        """process a NAS 5GMM message (NasRx) sent by the UE,
        and return a list (possibly empty) of NGAP procedure(s) to be sent back 
        to the gNB
        
        NasRx has 2 additional attributes (_sec [bool], _ulcnt [uint])
        """
        pass
    
    def init_proc(self, ProcClass, encod=None, fgmm_preempt=False, sec=True):
        """initialize a CN-initiated 5GMM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        pass
    
    def clear(self):
        """abort all running procedures
        """
        for Proc in self.Proc[::-1]:
            Proc.abort()
    
    #--------------------------------------------------------------------------#
    # SMC and security-related methods
    #--------------------------------------------------------------------------#
    
    
    
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    def _net_init_con(self):
        if not self.NG.page_block():
            return False
        # need to wait for potential 5GMM serving / common procedures to happen and end
        sleep(self._WAIT_ADD)
        if not self.ready.wait(10):
            # something is blocking in the serving / common procedures
            return False
        elif not self.NG.connected.is_set():
            # something went wrong during the serving / common procedures
            return False
        else:
            return True
    
    def run_proc(self, ProcClass, sec=True, **IEs):
        """run a network-initiated procedure ProcClass in the context of the 5GMM stack,
        after setting the given IEs in the NAS message to be sent to the UE
        
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
        Proc = self.init_proc(ProcClass, encod={ProcClass.Init: IEs}, fgmm_preempt=True, sec=sec)
        try:
            NgapTxProc = Proc.output()
        except Exception:
            self._log('ERR', 'invalid IEs for network-initiated procedure %s' % Proc.Name)
            Proc.abort()
            return False, Proc
        if not self.NG.transmit_ngap_proc(NgapTxProc):
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
        # check if a response was received
        if hasattr(Proc, 'UEInfo'):
            return True, Proc
        else:
            return False, Proc




class UEFGSMd(SigStack):
    """UE 5GSM handler within a UENGd instance
    responsible for 5G Session Management signalling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the UENGd
    NG = None
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    # list of ESM message types that do not require NAS security to be
    # activated to be processed
    SEC_NOTNEED = {
                   }
    # to disable completely the check for secured NAS message
    SEC_DISABLED = False
    
    
    
    
    def _log(self, logtype, msg):
        self.S1._log(logtype, '[5GSM] %s' % msg)
    
    def __init__(self, ued, uengd):
        self.UE = ued
        self.set_ng(uengd)
        #
        # dict of ongoing 5GSM procedures, indexed by 5GS bearer ID
        self.Proc  = {i: [] for i in range(16)}
        # dict of configured PDN, indexed by 5GS bearer ID
        self.PDN   = {}
        # dict of ongoing 5GSM transactions IEs
        self.Trans = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_ng(self, uengd):
        self.NG = uengd
    
    def process_buf(self, buf, sec, EMMProc=None):
        """process a NAS 5GSM message buffer (buf) sent by the UE,
        if the decoding is correct, return the result of process()
        """
        return []
    
    def process(self, NasRx, FMMProc=None):
        """process a NAS 5GSM message (NasRx) sent by the UE,
        and return a list (possibly empty) of NGAP procedure(s) to be sent back 
        to the gNB
        
        NasRx has 2 additional attributes (_sec [bool], _ulcnt [uint])
        
        FGMMProc [FMMSigProc or None], indicates if the NAS FGSM message is handled in 
        the context of an FGMM procedure 
        """
        return []
    
    
    def init_proc(self, ProcClass, **kw):
        """initialize a CN-initiated 5GSM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        pass
    
    def clear(self, ebi=None):
        """abort all running procedures, eventually for a single 5GS Bearer ID
        """
        pass
    
    
    #--------------------------------------------------------------------------#
    # transaction processing
    #--------------------------------------------------------------------------#
    
    def process_trans(self, trans_id):
        """process a 5GSM transaction initiated by the UE, and return a network-initiated
        procedure with IEs configured and None, or None and the 5GSM error code
        """
        pass
    
    
    #--------------------------------------------------------------------------#
    # protocol configuration processing
    #--------------------------------------------------------------------------#
    
    


class UENGd(SigStack):
    """UE NG handler within a CorenetServer instance
    responsible for UE-associated NGAP signalling
    """
    
    # to keep track of all NGAP procedures
    TRACK_PROC = True
    
    # domain
    DOM = '5GS'
    
    # reference to the UEd
    UE  = None
    # reference to the GNBd, SCTP stream id
    GNB = None
    SID = None
    
    # to bypass the process_nas() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    # for pure NGAP procedure (no NAS trafic, neither RAB-oriented stuff)
    # should we page the UE to run the procedure successfully when UE is idle
    NGAP_FORCE_PAGE = False
    
    #--------------------------------------------------------------------------#
    # global security policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all auth and smc procedures,
    # NAS MAC and UL count verification in the uplink
    # and setting of the 5GMM security header (and encryption) in the downlink
    SECNAS_DISABLED = False
    #
    # finer grained NAS security checks:
    # True to drop NAS PDU when NAS MAC verification fails
    SECNAS_UL_MAC = False
    # True to drop NAS PDU when NAS UL count verification fails
    SECNAS_UL_CNT  = False
    # WNG: 5GMM and 5GSM stacks have further control on accepting or not certain
    # NAS message even if security control have failed
    #
    # this will disable the setting of the 5GMM security header (and encryption)
    # in the downlink for given NAS message (by name)
    SECNAS_PDU_NOSEC = set()
    #
    # format of the security context dict self.SEC:
    # TODO
    
    
    #--------------------------------------------------------------------------#
    # NGAPPaging policy
    #--------------------------------------------------------------------------#
    #
    
    #--------------------------------------------------------------------------#
    # NGAPInitialContextSetup policy
    #--------------------------------------------------------------------------#
    # 
    
    #--------------------------------------------------------------------------#
    # NGAPTraceStart policy
    #--------------------------------------------------------------------------#
    # 
    
    
    def _log(self, logtype, msg):
        self.UE._log(logtype, '[UENGd:   %3i] %s' % (self.CtxId, msg))
    
    def __init__(self, ued, gnbd=None, ctx_id=-1, sid=None):
        self.UE  = ued
        self.Server = ued.Server
        self.Config = self.Server.ConfigNG
        #
        # dict of ongoing NGAP procedures (indexed by their procedure code)
        self.Proc = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
        #
        # dict of available 5G security contexts, indexed by KSI
        # and current KSI in use
        self.SEC = {}
        self.reset_sec_ctx()
        #
        self.connected = Event()
        if gnbd is not None:
            self.set_ran(gnbd)
        else:
            self.CtxId = -1
        #
        # init 5GMM and 5GSM sig stacks
        self.FGMM = UEFGMMd(ued, self)
        self.FGSM = UEFGSMd(ued, self)
        #self.SMS  = UESMSd(ued, self)
    
    def set_ran(self, gnbd):
        self.SEC['KSI'] = None
        self.GNB = gnbd
        self.connected.set()
    
    def unset_ran(self):
        self.GNB.unset_ue_ng(self.CtxId)
        del self.GNB
        self.SEC['KSI'] = None
        self.clear()
        self.connected.clear()
    
    def set_ran_unconnected(self, gnbd):
        # required for paging
        self.SEC['KSI'] = None
        self.GNB = gnbd
    
    def unset_ran_unconnected(self):
        # required for paging
        del self.GNB
        self.SEC['KSI'] = None
    
    def is_connected(self):
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
    # handling of NGAP procedures
    #--------------------------------------------------------------------------#
    
    def process_ngap_pdu(self, pdu_rx):
        """process a NGAP PDU sent by the gNB for UE-associated signalling
        and return a list of NGAP PDU(s) to be sent back to it
        """
        pass
    
    
    #--------------------------------------------------------------------------#
    # handling of NAS messages dispatching
    #--------------------------------------------------------------------------#
    
    def process_nas(self, buf):
        """process a NAS message buffer for the 5GS domain sent by the mobile
        and return a list (possibly empty) of NGAP procedure(s) to be sent back 
        to the gNB
        """
        pass
    
    
    def clear_nas_proc(self):
        # clears all NAS EPS procedures
        self.FGMM.clear()
        self.FGSM.clear()
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    
    
    
    #--------------------------------------------------------------------------#
    # to send arbitrary NAS buffers to the UE
    #--------------------------------------------------------------------------#
    
    
    
    
    #--------------------------------------------------------------------------#
    # 5G bearer activation
    #--------------------------------------------------------------------------#
    

