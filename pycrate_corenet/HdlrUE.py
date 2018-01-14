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
# * File Name : pycrate_corenet/HdlrUE.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils      import *
from .HdlrUEIuCS import *
from .HdlrUEIuPS import *
from .HdlrUES1   import *


class UEd(SigStack):
    """UE handler within a CorenetServer instance
    responsible for UE-related RAN signaling and NAS signaling
    """
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level
    DEBUG              = ('ERR', 'WNG', 'INF', 'DBG')
    # to log UE-related RANAP and S1AP for all UE
    TRACE_ASN_RANAP_CS = False
    TRACE_ASN_RANAP_PS = False
    TRACE_ASN_S1AP     = False
    # to log UE NAS MM / CC / SMS for all UE
    TRACE_NAS_CS       = False
    # to log UE NAS GMM / SM for all UE
    TRACE_NAS_PS       = False
    # to log UE LTE NAS (potentially) encrypted EMM / ESM for all UE
    TRACE_NAS_EPS_SEC  = False
    # to log UE LTE NAS clear-text EMM / ESM for all UE
    TRACE_NAS_EPS      = False
    # to log UE LTE NAS containing SMS for all UE
    TRACE_NAS_EPS_SMS  = False
    
    
    #--------------------------------------------------------------------------#
    # UE global informations
    #--------------------------------------------------------------------------#
    #
    # fixed identities
    IMSI   = None
    IMEI   = None
    IMEISV = None
    # capabilities
    Cap    = {}
    # security capabilities
    SecCap = {RAT_GERA: set(), RAT_UTRA: set(), RAT_EUTRA: set()} 
    # temporary identities (TMSI / PTMSI are uint32)
    TMSI   = None
    PTMSI  = None
    MTMSI  = None
    
    #--------------------------------------------------------------------------#
    # CorenetServer reference
    #--------------------------------------------------------------------------#
    #
    Server = None
    
    #--------------------------------------------------------------------------#
    # RAN-related infos
    #--------------------------------------------------------------------------#
    # 
    # Radio Access Technology (str)
    RAT = None
    # specific Iu / S1 signaling handler
    IuCS = None
    IuPS = None
    S1   = None
    #
    # location parameters
    PLMN = None # string of digits
    LAC  = None # uint16
    RAC  = None # uint8
    SAC  = None # uintX
    TAC  = None # uintX
    
    def _log(self, logtype, msg):
        if logtype[:3] == 'TRA':
            hdr, msg = msg.split('\n', 1)
            log('[TRA] [UE: %s] %s[%s]\n%s%s%s'\
                % (self.IMSI, hdr, logtype[6:], TRACE_COLOR_START, msg, TRACE_COLOR_END))
        elif logtype in self.DEBUG:
            log('[%s] [UE: %s] %s' % (logtype, self.IMSI, msg))
    
    def __init__(self, server, imsi, **kw):
        self.Server = server
        if imsi:
            self.IMSI = imsi
        elif 'tmsi' in kw:
            self.TMSI = kw['tmsi']
        elif 'ptmsi' in kw:
            self.PTMSI = kw['ptmsi']
        elif 'mtmsi' in kw:
            self.MTMSI = kw['mtmsi']
        #
        # set handler for IuCS, IuPS and S1 links
        self.IuCS = UEIuCSd(self)
        self.IuPS = UEIuPSd(self)
        self.S1   = UES1d(self)
        #
        if 'config' in kw:
            self.set_config(kw['config'])
    
    def set_config(self, config):
        self.MSISDN = config['MSISDN']
        self.USIM   = config['USIM']
        #
        self.IuPS.SM.PDPConfig = {}
        # cpdict(self.IuPS.SM.__class__.PDPConfig)
        # TODO: handle config for PDP networks
        #
        self.S1.ESM.PDNConfig = {}
        for pdnconfig in config['PDN']:
            apn, pdnaddr, apncfg = pdnconfig[0], pdnconfig[1:], {}
            # Server.ConfigPDN provides the DNS servers for each APN (and some 
            # more common parameters)
            # UE.S1.ESM.RABConfig provides the default RAB QoS for each APN
            if apn not in self.Server.ConfigPDN:
                self._log('WNG', 'unable to configure PDN connectivity for APN %s, '\
                          'no DNS servers' % apn)
            elif apn not in self.S1.ESM.RABConfig:
                self._log('WNG', 'unable to configure PDN connectivity for APN %s, '\
                          'no S1 QoS parameters' % apn)
            else:
                apncfg = cpdict(self.Server.ConfigPDN[apn])
                apncfg['PDNAddr'] = pdnaddr
                apncfg['RAB'] = cpdict(self.S1.ESM.RABConfig[apn])
                apncfg['RAB']['QCI'] = apncfg['QCI']
                self.S1.ESM.PDNConfig[apn] = apncfg
    
    def set_ran(self, ran, ctx_id, sid=None):
        # UE going connected
        if ran.__class__.__name__ == 'HNBd':
            #
            if self.S1.is_connected():
                # error: already linked with another ran
                raise(CorenetErr('UE already connected through a S1 link'))
            #
            # IuCS stack
            if not self.IuCS.is_connected():
                self.IuCS.set_ran(ran)
                self.IuCS.set_ctx(ctx_id)
            elif self.IuCS.RNC == ran:
                self.IuCS.set_ctx(ctx_id)
            else:
                # error: already linked with another HNB
                raise(CorenetErr('UE already connected through another IuCS link'))
            # IuPS stack
            if not self.IuPS.is_connected():
                self.IuPS.set_ran(ran)
                self.IuPS.set_ctx(ctx_id)
            elif self.IuPS.RNC == ran:
                self.IuPS.set_ctx(ctx_id)
            else:
                # error: already linked with another HNB
                raise(CorenetErr('UE already connected through another IuPS link'))
        #
        elif ran.__class__.__name__ == 'ENBd':
            #
            if self.IuCS.is_connected() or self.IuPS.is_connected():
                # error: already linked with another ran
                raise(CorenetErr('UE already connected through an Iu link'))
            #
            # S1 stack
            if not self.S1.is_connected():
                self.S1.set_ran(ran)
                self.S1.set_ctx(ctx_id, sid)
            elif self.S1.ENB == ran:
                self.S1.set_ctx(ctx_id, sid)
            else:
                # error: already linked with another ENB
                raise(CorenetErr('UE already connected through another S1 link'))
        #
        else:
            assert()
        #
        self.RAT = ran.RAT
    
    def unset_ran(self):
        # UE going IDLE
        if self.IuCS.is_connected():
            self.IuCS.unset_ran()
            self.IuCS.unset_ctx()
        if self.IuPS.is_connected():
            self.IuPS.unset_ran()
            self.IuPS.unset_ctx()
        if self.S1.is_connected():
            self.S1.unset_ran()
            self.S1.unset_ctx()
        del self.RAT
    
    def merge_cs_handler(self, iucsd):
        if self.IuCS is not None:
            if self.IuCS.MM.state == 'ACTIVE':
                self._log('WNG', 'unable to merge IuCS handler')
                return False
            else:
                self._log('INF', 'merging IuCS handler')
                # prepend passed proc into s1d
                iucsd._proc = self.IuCS._proc + iucsd._proc
                iucsd.MM._proc = self.IuCS.MM._proc + iucsd.MM._proc
                iucsd.CC._proc = self.IuCS.CC._proc + iucsd.CC._proc
                iucsd.SMS._proc = self.IuCS.SMS._proc + iucsd.SMS._proc
                iucsd.SS._proc = self.IuCS.SS._proc + iucsd.SS._proc
                # merge security contexts
                for cksn in range(8):
                    if cksn in self.IuCS.SEC and cksn not in iucsd.SEC:
                        iucsd.SEC[cksn] = self.IuCS.SEC[cksn]
        # transfer UE's reference
        self.IuCS   = iucs
        iucs.UE     = self
        iucs.MM.UE  = self
        iucs.CC.UE  = self
        iucs.SMS.UE = self
        iucs.SS.UE  = self
        return True
    
    def merge_ps_handler(self, iupsd):
        if self.IuPS is not None:
            if self.IuPS.GMM.state == 'ACTIVE':
                self._log('WNG', 'unable to merge IuPS handler')
                return False
            else:
                self._log('INF', 'merging IuPS handler')
                # prepend passed proc into s1d
                iupsd._proc = self.IuPS._proc + iupsd._proc
                iupsd.GMM._proc = self.IuPS.GMM._proc + iupsd.GMM._proc
                iupsd.SM._proc = self.IuPS.SM._proc + iupsd.SM._proc
                # merge security contexts
                for cksn in range(8):
                    if cksn in self.IuPS.SEC and cksn not in iupsd.SEC:
                        iupsd.SEC[cksn] = self.IuPS.SEC[cksn]
                # merge PDP contexts
                for ctx in range(16):
                    if ctx in self.IuPS.PDP and ctx not in iupsd.PDP:
                        iupsd.PDP[ksi] = self.IuPS.PDP[ctx]
        # transfer UE's reference
        self.IuPS   = iups
        iups.UE     = self
        iups.GMM.UE = self
        iups.SM.UE  = self
        return True
    
    def merge_eps_handler(self, s1d):
        if self.S1 is not None:
            if self.S1.EMM.state == 'ACTIVE':
                self._log('WNG', 'unable to merge S1 handler')
                return False
            else:
                self._log('INF', 'merging S1 handler')
                # prepend passed proc into s1d
                s1d._proc = self.S1._proc + s1d._proc
                s1d.EMM._proc = self.S1.EMM._proc + s1d.EMM._proc
                s1d.ESM._proc = self.S1.ESM._proc + s1d.ESM._proc
                s1d.SMS._proc = self.S1.SMS._proc + s1d.SMS._proc
                # merge security contexts
                for ksi in range(16):
                    if ksi in self.S1.SEC and ksi not in s1d.SEC:
                        s1d.SEC[ksi] = self.S1.SEC[ksi]
                # merge PDP contexts
                for ctx in range(16):
                    if ctx in self.S1.PDP and ctx not in s1d.PDP:
                        s1d.PDP[ctx] = self.S1.PDP[ctx]
        # transfer UE's reference
        self.S1    = s1d
        s1d.UE     = self
        s1d.EMM.UE = self
        s1d.ESM.UE = self
        s1d.SMS.UE = self
        return True
    
    #--------------------------------------------------------------------------#
    # UE identity
    #--------------------------------------------------------------------------#
    
    def set_ident_from_ue(self, idtype, ident, dom='CS'):
        # to be used only to set identities reported by the UE
        if idtype == 1:
            if self.IMSI is None:
                self.IMSI = ident
            elif ident != self.IMSI:
                self._log('WNG', 'incorrect IMSI, %s instead of %s' % (ident, self.IMSI))
        elif idtype == 2:
            if self.IMEI is None:
                self.IMEI = ident
            elif ident != self.IMEI:
                self._log('WNG', 'IMEI changed, new %s, old %s' % (ident, self.IMEI))
                self.IMEI = ident
        elif idtype == 3:
            if self.IMEISV is None:
                self.IMEISV = ident
            elif ident != self.IMEISV:
                self._log('WNG', 'IMEISV changed, new %s, old %s' % (ident, self.IMEISV))
                self.IMEISV = ident
        elif idtype == 4:
            if dom == 'CS':
                if self.TMSI is None:
                    self.TMSI = ident
                elif ident != self.TMSI:
                    self._log('WNG', 'incorrect TMSI, %s instead of %s' % (ident, self.TMSI))
            elif dom == 'PS':
                if self.PTMSI is None:
                    self.PTMSI = ident
                elif ident != self.PTMSI:
                    self._log('WNG', 'incorrect P-TMSI, %s instead of %s' % (ident, self.PTMSI))
        elif idtype == 6:
            if dom == 'EPS':
                if self.MTMSI is None:
                    self.MTMSI = ident[3]
                elif ident[3] != self.MTMSI:
                    self._log('WNG', 'incorrect M-TMSI, %s instead of %s' % (ident, self.MTMSI))
        else:
            self._log('INF', 'unhandled identity, type %i, ident %s' % (idtype, ident))
    
    def get_new_tmsi(self):
        # use the Python random generator
        return random.getrandbits(32)
    
    def set_tmsi(self, tmsi):
        # delete current TMSI from the Server LUT
        if self.TMSI is not None:
            try:
                del self.Server.TMSI[self.TMSI]
            except:
                pass
        # set the new TMSI
        self.TMSI = tmsi
        # update the Server LUT
        self.Server.TMSI[tmsi] = self.IMSI
    
    def set_ptmsi(self, ptmsi):
        # delete current PTMSI from the Server LUT
        if self.PTMSI is not None:
            try:
                del self.Server.PTMSI[self.PTMSI]
            except:
                pass
        # set the new PTMSI
        self.PTMSI = ptmsi
        # update the Server LUT
        self.Server.PTMSI[ptmsi] = self.IMSI
    
    def set_mtmsi(self, mtmsi):
        # delete current MTMSI from the Server LUT
        if self.MTMSI is not None:
            try:
                del self.Server.MTMSI[self.MTMSI]
            except:
                pass
        # set the new PTMSI
        self.MTMSI = mtmsi
        # update the Server LUT
        self.Server.MTMSI[mtmsi] = self.IMSI
    
    #--------------------------------------------------------------------------#
    # UE location
    #--------------------------------------------------------------------------#
    
    def set_plmn(self, plmn):
        if plmn != self.PLMN:
            self.PLMN = plmn
            self._log('INF', 'locate on PLMN %s' % self.PLMN)
    
    def set_lac(self, lac):
        if lac != self.LAC:
            self.LAC = lac
            self._log('INF', 'locate on LAC %.4x' % self.LAC)
    
    def set_rac(self, rac):
        if rac != self.RAC:
            self.RAC = rac
            self._log('INF', 'route on RAC %.2x' % self.RAC)
    
    def set_tac(self, tac):
        if tac != self.TAC:
            self.TAC = tac
            self._log('INF', 'track on TAC %.4x' % self.TAC)
    
    def set_lai(self, plmn, lac):
        self.set_plmn(plmn)
        self.set_lac(lac)
    
    def set_tai(self, plmn, tac):
        self.set_plmn(plmn)
        self.set_tac(tac)

