# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# * Copyright 2020. Benoit Michau. P1Sec.
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
# * File Name : pycrate_corenet/HdlrUE.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .HdlrUEIuCS import *
from .HdlrUEIuPS import *
from .HdlrUES1   import *
from .HdlrUENG   import *
from .utils      import *


class UEd(SigStack):
    """UE handler within a CorenetServer instance
    responsible for UE-related RAN signaling and NAS signaling
    """
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level
    DEBUG              = ('VLN', 'ERR', 'WNG', 'INF', 'DBG')
    # to log UE-related RANAP, S1AP and NGAP for all UE
    TRACE_ASN_RANAP_CS = False
    TRACE_ASN_RANAP_PS = False
    TRACE_ASN_S1AP     = False
    TRACE_ASN_NGAP     = False
    # to log UE NAS over IuCS (except SMS) for all UE
    TRACE_NAS_CS       = False
    # to log UE NAS over IuPS for all UE
    TRACE_NAS_PS       = False
    # to log UE LTE NAS (potentially) encrypted EMM / ESM for all UE
    TRACE_NAS_EPS_SEC  = False
    # to log UE LTE NAS clear-text EMM / ESM for all UE
    TRACE_NAS_EPS      = False
    # to log UE NAS containing SMS for all UE
    TRACE_NAS_SMS      = False
    # to log UE 5G NAS (potentially) encrypted signalling for all UE
    TRACE_NAS_5GS_SEC  = False
    # to log UE 5G NAS clear-text signalling for all UE
    TRACE_NAS_5GS      = False
    
    
    #--------------------------------------------------------------------------#
    # UE global informations
    #--------------------------------------------------------------------------#
    #
    # fixed identities
    IMSI   = None
    IMEI   = None
    IMEISV = None
    # temporary identities (TMSI / PTMSI / MTMSI / FGTMSI are uint32)
    TMSI   = None # CS domain
    PTMSI  = None # PS domain
    MTMSI  = None # EPS domain
    FGTMSI = None # 5GS domain
    
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
    RAT  = None
    # specific Iu / S1 / NG signaling handler
    IuCS = None
    IuPS = None
    S1   = None
    NG   = None
    #
    # location parameters
    PLMN = None # string of digits
    LAC  = None # uint16
    RAC  = None # uint8
    SAC  = None # uintX
    TAC  = None # uint16 (S1) or uint24 (NG)
    
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
            # CS domain, 3G
            self.TMSI = kw['tmsi']
        elif 'ptmsi' in kw:
            # PS domain, 3G
            self.PTMSI = kw['ptmsi']
        elif 'mtmsi' in kw:
            # EPS domain, 4G
            self.MTMSI = kw['mtmsi']
        elif 'fgtmsi' in kw:
            # 5GS domain, 5G
            self.FGTMSI = kw['fgtmsi']
        #
        # init capabilities
        self.Cap = {}
        #
        # set handler for IuCS, IuPS and S1 links
        self.IuCS = UEIuCSd(self)
        self.IuPS = UEIuPSd(self)
        self.S1   = UES1d(self)
        self.NG   = UENGd(self)
        self._last_ran = None
        #
        if 'config' in kw:
            self.set_config(kw['config'])
    
    def set_config(self, config):
        self.MSISDN = config['MSISDN']
        self.USIM   = config['USIM']
        #
        self.IuPS.SM.PDPConfig = {}
        for pdpconfig in config['PDP']:
            apn, pdpaddr, apncfg = pdpconfig[0], pdpconfig[1:], {}
            # Server.ConfigPDP provides the DNS servers for each APN (and some 
            # more common parameters)
            # UE.IuPS.SM.RABConfig provides the default RAB QoS for each APN
            if apn not in self.Server.ConfigPDP:
                self._log('WNG', 'unable to configure PDP connectivity for APN %s, '\
                          'no DNS servers' % apn)
            elif apn not in self.IuPS.SM.RABConfig:
                self._log('WNG', 'unable to configure PDP connectivity for APN %s, '\
                          'no IuPS QoS parameters' % apn)
            else:
                apncfg = cpdict(self.Server.ConfigPDP[apn])
                apncfg['Addr'] = pdpaddr
                apncfg['RAB'] = cpdict(self.IuPS.SM.RABConfig[apn])
                self.IuPS.SM.PDPConfig[apn] = apncfg
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
                apncfg['Addr'] = pdnaddr
                apncfg['RAB'] = cpdict(self.S1.ESM.RABConfig[apn])
                apncfg['RAB']['QCI'] = apncfg['QCI']
                self.S1.ESM.PDNConfig[apn] = apncfg
        #
        self.NG.FGSM.PDUConfig = {}
        for pduconfig in config['PDU']:
            # TODO: initialize 5G SM config with allowed PDU Sessions
            pass
    
    def set_ran(self, ran, ctx_id, sid=None, dom=None):
        # UE going connected
        if ran.__class__.__name__ == 'HNBd':
            #
            if self.S1.is_connected():
                # error: already linked with another ran
                raise(CorenetErr('UE already connected through a S1 link'))
            elif self.NG.is_connected():
                raise(CorenetErr('UE already connected through a NG link'))
            #
            if dom != 'PS':
                # IuCS stack
                if not self.IuCS.is_connected():
                    self.IuCS.set_ran(ran)
                    self.IuCS.set_ctx(ctx_id)
                elif self.IuCS.RNC == ran:
                    self.IuCS.set_ctx(ctx_id)
                else:
                    # error: already linked with another HNB
                    raise(CorenetErr('UE already connected through another IuCS link'))
            else:
                # IuPS stack
                if not self.IuPS.is_connected():
                    self.IuPS.set_ran(ran)
                    self.IuPS.set_ctx(ctx_id)
                elif self.IuPS.RNC == ran:
                    self.IuPS.set_ctx(ctx_id)
                else:
                    # error: already linked with another HNB
                    raise(CorenetErr('UE already connected through another IuPS link'))
            self._last_ran = self.IuCS
        #
        elif ran.__class__.__name__ == 'ENBd':
            #
            if self.IuCS.is_connected() or self.IuPS.is_connected():
                # error: already linked with another ran
                raise(CorenetErr('UE already connected through an Iu link'))
            elif self.NG.is_connected():
                raise(CorenetErr('UE already connected through a NG link'))
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
            self._last_ran = self.S1
        #
        elif ran.__class__.__name__ == 'GNBd':
            #
            if self.IuCS.is_connected() or self.IuPS.is_connected():
                # error: already linked with another ran
                raise(CorenetErr('UE already connected through an Iu link'))
            elif self.S1.is_connected():
                raise(CorenetErr('UE already connected through a S1 link'))
            #
            # NG stack
            if not self.NG.is_connected():
                self.NG.set_ran(ran)
                self.NG.set_ctx(ctx_id, sid)
            elif self.NG.GNB == ran:
                self.NG.set_ctx(ctx_id, sid)
            else:
                # error: already linked with another GNB
                raise(CorenetErr('UE already connected through another NG link'))
            self._last_ran = self.NG
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
        if self.NG.is_connected():
            self.NG.unset_ran()
            self.NG.unset_ctx()
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
                iupsd.SM.PDPConfig = self.SM.PDPConfig
                for nsapi in range(16):
                    if nsapi in self.IuPS.SM.PDP and nsapi not in iupsd.SM.PDP:
                        iupsd.SM.PDP[nsapi] = self.IuPS.SM.PDP[nsapi]
        # transfer UE's reference
        self.IuPS   = iupsd
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
                # merge PDN contexts
                s1d.ESM.PDNConfig = self.S1.ESM.PDNConfig
                for ebi in range(16):
                    if ebi in self.S1.ESM.PDN and ebi not in s1d.ESM.PDN:
                        s1d.ESM.PDN[ebi] = self.S1.ESM.PDN[ebi]
        # transfer UE's reference
        self.S1    = s1d
        s1d.UE     = self
        s1d.EMM.UE = self
        s1d.ESM.UE = self
        s1d.SMS.UE = self
        return True
    
    def merge_5gs_handler(self, ngd):
        # TODO
        pass
    
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
        # TODO: check what we can have within the 5GS domain
        # as per TS 24.501, 9.11.3.4
        else:
            self._log('INF', 'unhandled identity, type %i, ident %s' % (idtype, ident))
    
    def get_new_tmsi(self):
        # use the Python random generator
        # WARNING: not good for randomness, but good enough for corenet
        # and at least with some good uniqueness 
        return random.getrandbits(32)
    
    def set_tmsi(self, tmsi):
        # delete current TMSI from the Server LUT
        if self.TMSI is not None:
            try:
                del self.Server.TMSI[self.TMSI]
            except Exception:
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
            except Exception:
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
            except Exception:
                pass
        # set the new MTMSI
        self.MTMSI = mtmsi
        # update the Server LUT
        self.Server.MTMSI[mtmsi] = self.IMSI
    
    def set_fgtmsi(self, fgtmsi):
        # delete current 5GTMSI from the Server LUT
        if self.FGTMSI is not None:
            try:
                del self.Server.FGTMSI[self.FGTMSI]
            except Exception:
                pass
        # set the new 5G TMSI
        self.FGTMSI = fgtmsi
        # update the Server LUT
        self.Server.FGTMSI[fgtmsi] = self.FGTMSI
    
    
    #--------------------------------------------------------------------------#
    # UE location
    #--------------------------------------------------------------------------#
    
    def set_plmn(self, plmn):
        if plmn != self.PLMN:
            self.PLMN = plmn
            self._log('INF', 'located in PLMN %s' % self.PLMN)
    
    def set_lac(self, lac):
        if lac != self.LAC:
            self.LAC = lac
            self._log('INF', 'located in LAC %.4x' % self.LAC)
    
    def set_rac(self, rac):
        if rac != self.RAC:
            self.RAC = rac
            self._log('INF', 'routed in RAC %.2x' % self.RAC)
    
    def set_tac(self, tac):
        if tac != self.TAC:
            self.TAC = tac
            self._log('INF', 'tracked in TAC %.6x' % self.TAC)
    
    def set_lai(self, plmn, lac):
        self.set_plmn(plmn)
        self.set_lac(lac)
    
    def set_tai(self, plmn, tac):
        self.set_plmn(plmn)
        self.set_tac(tac)
    
    #--------------------------------------------------------------------------#
    # (E)SM protocol configuration options handling
    #--------------------------------------------------------------------------#
    
    def process_protconfig(self, smd, config, request):
        """process an (E)PS session management Protocol Configuration Options request,
        
        return the list of message's elements of the Protocol Configuration Options response, 
        and a bool indicating if the PDN address for the UE is required in the NAS signalling
        """
        RespElt, pdnaddrreq = [], False
        #
        if request[2].get_val() != 0:
            # not PPP with IP PDP
            smd._log('WNG', 'Protocol Config, not for PPP with IP PDP')
            return RespElt, pdnaddrreq
        #
        #smd._log('DBG', 'Protocol Config, config : %r' % config)
        #smd._log('DBG', 'Protocol Config, request: %r' % request)
        for ReqElt in request[3]:
            pcid = ReqElt[0].get_val()
            #
            if pcid == 0x8021:
                # IPCP
                if isinstance(ReqElt[2], NAS.NCP) and ReqElt[2][0].get_val() == 1 \
                and isinstance(ReqElt[2][3], NAS.NCPDataConf):
                    # NCP config req
                    ncpreq = []
                    for NcpOpt in ReqElt[2][3]:
                        ncpreq.append( NcpOpt[0].get_val() )
                    NcpOptResp, dnsind = [], 0
                    if 3 in ncpreq:
                        # IPv4 addr
                        ip = None
                        for ipaddr in config['Addr']:
                            if ipaddr[0] == 1:
                                ip = inet_aton_cn(*ipaddr)
                                break
                            elif ipaddr[0] == 3:
                                ip = inet_aton_cn(1, ipaddr[1])
                                break
                        if ip is None:
                            smd._log('WNG', 'Protocol Config, no config available for'\
                                     'the IPCP IPv4 address request')
                        else:
                            NcpOptResp.append({'Type': 3, 'Data': ip})
                        ncpreq.remove(3)
                    if 129 in ncpreq:
                        # 1st DNS IPv4 addr
                        dns = None
                        if 'DNS' in config:
                            for dnsaddr in config['DNS']:
                                dnsind += 1
                                if dnsaddr[0] == 1:
                                    dns = inet_aton_cn(*dnsaddr)
                                    break
                        if dns is None:
                            smd._log('WNG', 'Protocol Config, no config available for'\
                                     'the IPCP 1st DNS IPv4 request')
                        else:
                            NcpOptResp.append({'Type': 129, 'Data': dns})
                        ncpreq.remove(129)
                    if 131 in ncpreq:
                        # 2nd DNS IPv4 addr
                        dns = None
                        if 'DNS' in config:
                            for dnsaddr in config['DNS'][dnsind:]:
                                if dnsaddr[0] == 1:
                                    dns = inet_aton_cn(*dnsaddr)
                                    break
                        if dns is None:
                            smd._log('WNG', 'Protocol Config, no config available for'\
                                     'the IPCP 2nd DNS IPv4 request')
                        else:
                            NcpOptResp.append({'Type': 131, 'Data': dns})
                        ncpreq.remove(131)
                    if ncpreq:
                        smd._log('WNG', 'Protocol Config, unsupported IPCP requests, %r' % ncpreq)
                    RespElt.append({'ID': 32801,
                                    'Cont':{'Code': 2,
                                            'Id': ReqElt[2][1].get_val(),
                                            'Data': NcpOptResp}})
                else:
                    smd._log('WNG', 'Protocol Config, invalid IPCP request format, %r' % ReqElt)
            #
            elif pcid == 0xC021:
                # LCP
                if isinstance(ReqElt[2], NAS.LCP) and ReqElt[2][0].get_val() == 1 \
                and isinstance(ReqElt[2][3], NAS.LCPDataConf):
                    # NCP config req
                    lcpreq = []
                    for LcpOpt in ReqElt[2][2]:
                        lcpreq.append( LcpOpt[0].get_val() )
                    # TODO: handle LCP elements
                    #
                    if lcpreq:
                        smd._log('ERR', 'Protocol Config, unsupported LCP requests, %r' % ReqElt[2])
                else:
                    smd._log('WNG', 'Protocol Config, invalid LCP request format, %r' % ReqElt)
            #
            elif pcid == 0xC023:
                # PAP
                if isinstance(ReqElt[2], NAS.PAP) and ReqElt[2][0].get_val() == 1:
                    # PAP req
                    if smd.AUTH_PAP_BYPASS:
                        RespElt.append({'ID': 0xC023,
                                        'Cont': {'Code': 2, # Ack
                                                 'Id': ReqElt[2][1].get_val(),
                                                 'Data':{'Msg': b''}}})
                    
                    else:
                        authreq, ack = ReqElt[2][3], False
                        peerid, passwd = authreq[1].get_val(), authreq[3].get_val()
                        if 'PAP' in config and peerid in config['PAP'] and passwd == config['PAP'][peerid]:
                            RespElt.append({'ID': 0xC023,
                                            'Cont': {'Code': 2, # Ack
                                                     'Id': ReqElt[2][1].get_val(),
                                                     'Data':{'Msg': b''}}})
                        else:
                            if 'PAP' not in config:
                                smd._log('WNG', 'Protocol Config, no config available for'\
                                         'the PAP authentication')
                            RespElt.append({'ID': 0xC023,
                                            'Cont': {'Code': 3, # Nak
                                                     'Id': ReqElt[2][1].get_val(),
                                                     'Data':{'Msg': b'you loose'}}})
                else:
                    smd._log('WNG', 'Protocol Config, invalid PAP request format, %r' % ReqElt)
            #
            elif pcid == 0xC223:
                # CHAP
                if isinstance(ReqElt[2], NAS.CHAP) and ReqElt[2][0].get_val() == 1:
                    # CHAP req
                    if smd.AUTH_CHAP_BYPASS:
                        RespElt.append({'ID': 0xC223,
                                        'Cont': {'Code': 3, # success
                                                 'Id': ReqElt[2][1].get_val(),
                                                 'Data': b''}})
                    else:
                        # TODO: handle CHAP auth
                        smd._log('ERR',  'Protocol Config, unsupported CHAP authentication')
                        RespElt.append({'ID': 0xC223,
                                        'Cont': {'Code': 4, # failure
                                                 'Id': ReqElt[2][1].get_val(),
                                                 'Data': b''}})                    
                else:
                    smd._log('WNG', 'Protocol Config, invalid CHAP request format, %r' % ReqElt)
            #
            elif pcid == 0x3:
                # DNS IPv6
                dns = None
                if 'DNS' in config:
                    for dnsaddr in config['DNS']:
                        if dnsaddr[0] == 2:
                            dns = inet_aton_cn(*dnsaddr)
                            break
                if dns is None:
                    smd._log('WNG', 'Protocol Config, no config available for the DNS IPv6 request')
                else:
                    RespElt.append({'ID': 0x3, 'Cont': dns})
            #
            elif pcid == 0xA:
                # IP alloc via NAS
                pdnaddrreq = True
            #
            elif pcid == 0xD:
                # DNS IPv4
                dns = None
                if 'DNS' in config:
                    for dnsaddr in config['DNS']:
                        if dnsaddr[0] == 1:
                            dns = inet_aton_cn(*dnsaddr)
                            break
                if dns is None:
                    smd._log('WNG', 'Protocol Config, no config available for the DNS IPv4 request')
                else:
                    RespElt.append({'ID': 0xD, 'Cont': dns})
            #
            elif pcid == 0x10:
                # IPv4 link MTU
                if 'MTU' in config:
                    mtu = config['MTU'][0]
                    if isinstance(mtu, integer_types) and 0 <= mtu <= 65535:
                        mtu = pack('>H', mtu)
                    if isinstance(mtu, bytes_types):
                        RespElt.append({'ID': 0x10, 'Cont': mtu})
                else:
                    smd._log('DBG', 'Protocol Config, no config available for the IPv4 MTU request')
            #
            elif pcid == 0x15:
                # non-IP link MTU
                if 'MTU' in config:
                    mtu = config['MTU'][1]
                    if isinstance(mtu, integer_types) and 0 <= mtu <= 65535:
                        mtu = pack('>H', mtu)
                    if isinstance(mtu, bytes_types):
                        RespElt.append({'ID': 0x15, 'Cont': mtu})
                else:
                    smd._log('DBG', 'Protocol Config, no config available for the non-IP MTU request')
            #
            else:
                smd._log('WNG', 'Protocol Config, unsupported request element, %r' % ReqElt)  
        #
        return RespElt, pdnaddrreq
    
    #--------------------------------------------------------------------------#
    # SMS delivery
    #--------------------------------------------------------------------------#
    
    def smsrp_downlink(self, rp_msg):
        ran, con = self._last_ran, True
        if ran is None:
            con = False
        elif not ran.is_connected():
            if not ran._net_init_con():
                con = False
        if con:
            # UE connected over `ran'
            # init the CP procedure
            CPProc = ran.SMS.init_cpdata(rp_msg)
            if CPProc:
                SMSTx = CPProc.output()
                if len(SMSTx) == 1:
                    SMSTx = SMSTx[0]
                    # send the msg toward the hnb / enb
                    if isinstance(ran , UEIuCSd):
                        # wrap into a RANAP direct transfer
                        RanapProc = ran.init_ranap_proc(RANAPDirectTransferCN,
                                                        NAS_PDU=SMSTx.to_bytes(),
                                                        SAPI='sapi-3')
                        if RanapProc and ran._send_to_rnc_ranap([RanapProc]):
                            return True
                    elif isinstance(ran, UES1d):
                        # wrap into an EMM procedure first
                        EMMProc = ran.EMM.init_proc(EMMDLNASTransport,
                                                    encod={(7, 98): {'NASContainer': SMSTx.to_bytes()}})
                        if EMMProc and ran.transmit_s1ap_proc(EMMProc.output()):
                            return True
        # unable to send the SMS
        self.Server.SMSd.discard_rp(rp_msg, self.MSISDN)
        return False
    
    #--------------------------------------------------------------------------#
    # pretty-print all capabilities
    #--------------------------------------------------------------------------#
    
    def show_cap(self, with_measparams=False):
        """returns a string representing all capabilities reported by the UE
        ready for printing on screen or writing in file
        """
        try:
            from IPython.lib.pretty import pretty
        except Exception:
            pretty = repr
        else:
            txt = []
            if self.Cap:
                for k in self.Cap:
                    cap = self.Cap[k]
                    if k == 'UERadioCap' and isinstance(cap[2], dict):
                        for kb in cap[2]:
                            # special format:
                            txt.append('<<< Capability : UERadioCap.%s >>>' % kb)
                            c = cap[2][kb]
                            if kb == 'geran-cs' and isinstance(c, tuple):
                                txt.append(c[0].show())
                                txt.append(c[1].show())
                            elif kb == 'utra':
                                UEUTRACap = RRC3G.PDU_definitions.InterRATHandoverInfo
                                UEUTRACap.set_val(c)
                                txt.append(UEUTRACap.to_asn1())
                            elif kb == 'eutra':
                                UEEUTRACap = RRCLTE.EUTRA_RRC_Definitions.UE_EUTRA_Capability
                                if not with_measparams:
                                    meas_params_to_asn1_patch()
                                UEEUTRACap.set_val(c)
                                txt.append(UEEUTRACap.to_asn1())
                                if not with_measparams:
                                    meas_params_to_asn1_restore()
                            #
                            elif hasattr(c, 'show'):
                                txt.append(c.show())
                            else:
                                txt.append(pretty(c))
                    else:
                        txt.append('<<< Capability : %s >>>' % k)
                        c = cap[1]
                        if hasattr(c, 'show'):
                            txt.append(c.show())
                        else:
                            txt.append(pretty(c))
                return '\n\n'.join(txt)
            else:
                return ''

