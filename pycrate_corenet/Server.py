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
# * File Name : pycrate_corenet/Server.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# This is the main corenet server
# 
# It serves connection to:
# - eNodeB and Home-eNodeB over S1AP
# - Home-NodeB over HNBAP and RUA
# 
# It handles signalling trafic for UE
# and connects them to specific service handler (SMS, GTPU, ...)
#------------------------------------------------------------------------------#

from .utils      import *
from .HdlrHNB    import HNBd
from .HdlrENB    import ENBd
from .HdlrUE     import UEd
from .ServerAuC  import AuC
from .ServerGTPU import GTPUd


# to log all the SCTP socket send() / recv() calls
DEBUG_SK = False

# global HNB debug level
HNBd.DEBUG = ('ERR', 'WNG', 'INF') #, 'DBG')
HNBd.TRACE_ASN_HNBAP  = False
HNBd.TRACE_ASN_RUA    = False
HNBd.TRACE_ASN_RANAP  = False
# global eNB debug level
ENBd.DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
ENBd.TRACE_ASN_S1AP   = False
# global UE debug level
UEd.DEBUG  = ('ERR', 'WNG', 'INF', 'DBG')
UEd.TRACE_RANAP_CS    = False
UEd.TRACE_RANAP_PS    = False
UEd.TRACE_NAS_CS      = False
UEd.TRACE_NAS_PS      = False
UEd.TRACE_S1AP        = True
UEd.TRACE_NAS_EPS_ENC = True
UEd.TRACE_NAS_EPS     = True
UEd.TRACE_NAS_EPS_SMS = True


class CorenetServer(object):
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level: list of log types to display when calling self._log(logtype, msg)
    DEBUG    = ('ERR', 'WNG', 'INF', 'DBG')
    # to log SCTP socket send() / recv() content
    TRACE_SK = False
    
    #--------------------------------------------------------------------------#
    # network server settings
    #--------------------------------------------------------------------------#
    #
    # SCTP sockets recv() buffer length
    SERVER_BUFLEN = 16384
    SERVER_MAXCLI = 16
    #
    # HNBAP server
    SERVER_HNB = {'INET'  : socket.AF_INET,
                  'IP'    : '10.1.1.1',
                  'port'  : 29169,
                  'MAXCLI': SERVER_MAXCLI,
                  'errclo': True}
    #SERVER_HNB = {} # disabling HNB server
    # S1AP server
    SERVER_ENB = {'INET'  : socket.AF_INET,
                  'IP'    : '127.0.1.100',
                  'port'  : 36412,
                  'MAXCLI': SERVER_MAXCLI,
                  'errclo': False}
    #SERVER_ENB = {} # disabling S1AP server
    #
    # Server scheduler resolution:
    # This is the timeout on the main select() loop.
    SCHED_RES = 0.1
    # This is the resolution (in sec) for the Server to start a thread that 
    # checks the list of registered UE, and checks for ongoing NAS procedures 
    # potentially in timeout.
    # If set to 0, no check is made (so, NAS procedures can stall)
    # It is useless to make it lower than the SCHED_RES.
    SCHED_UE_TO = 0.5
    
    #--------------------------------------------------------------------------#
    # corenet service handlers
    #--------------------------------------------------------------------------#
    # These are references to services handlers
    #
    # Authentication Centre
    AUCd  = AuC
    # GTPU trafic forwarder
    GTPUd = GTPUd
    # SMS center
    SMSd  = None
    
    #--------------------------------------------------------------------------#
    # corenet global config parameters
    #--------------------------------------------------------------------------#
    #
    # main PLMN served
    PLMN = '20869'
    # MME GroupID and Code
    MME_GID  = 1
    MME_CODE = 1
    # equivalent PLMNs served
    # None or list of PLMNs ['30124', '763326', ...]
    EQUIV_PLMN = None
    # emergency number lists
    # None or list of 2-tuple [(number_category, number), ...]
    # number_category is a 5 bit uint set of flags (Police, Ambulance, Fire, Marine, Mountain)
    # number is a digits string
    EMERG_NUMS = None
    #
    # S1 connection MME parameters
    ConfigS1    = {
        'MMEName': 'CorenetMME',
        'GUMMEIs': [
            {'PLMNs': [PLMN], 'GroupIDs': [MME_GID], 'MMECs': [MME_CODE]},
            #{'PLMNs': [PLMN] + EQUIV_PLMN, 'GroupIDs': [MME_GID], 'MMECs': [MME_CODE]},
            ], # this is converted to a ServedGUMMEIs SEQUENCE at runtime
        'RelativeMMECapacity': 10,
        'EquivPLMNList' : EQUIV_PLMN,
        'EmergNumList'  : EMERG_NUMS,
        }
    # HNBAP connection GW parameters
    ConfigHNBAP = {}
    # RUA connection GW parameters
    ConfigRUA   = {}
    # RANAP connection IuCS core parameters
    ConfigIuCS  = {
        'EquivPLMNList': EQUIV_PLMN,
        'EmergNumList' : EMERG_NUMS,
        }
    # RANAP connection IuPS core parameters
    ConfigIuPS  = {
        'EquivPLMNList': EQUIV_PLMN,
        'EmergNumList' : EMERG_NUMS,
        }
    
    #--------------------------------------------------------------------------#
    # HNB and ENB parameters
    #--------------------------------------------------------------------------#
    #
    # Home-NodeB, eNodeB and Home-eNodeB, indexed by (PLMN, CellId)
    RAN = {}
    #
    # This is a flag to allow any RAN equipment to connect the CorenetServer
    # If enabled, HNB and ENB dict will be populated at runtime
    # If disabled, HNB and ENB keys (PLMN, CellID) needs to be setup by configuration
    RAN_CONNECT_ANY = True
    #
    # This is the list of accepted PLMN for RAN equipment connecting
    RAN_ALLOWED_PLMN = [PLMN]
    #
    # lookup dict to get the set of RAN ids (PLMN, CellId) that serves a given
    # LAI, RAI and TAI
    LAI = {}
    RAI = {}
    TAI = {}
    
    #--------------------------------------------------------------------------#
    # UE parameters
    #--------------------------------------------------------------------------#
    #
    # UE configuration parameters
    ConfigUE = {
        # $IMSI: {'PDN'   : [($APN -str-, $PDNType -1..3-, $IPAddr -str-), ...], 
        #         'MSISDN': $phone_num -str-,
        #         'USIM'  : $milenage_supported -bool-}
        # PDN type: 1:IPv4, 2:IPv6, 3:IPv4v6
        '*': {'PDP'   : [],
              'PDN'   : [('*', 1, '192.168.132.199')],
              'MSISDN': '0123456789',
              'USIM'  : True
              },
        '208691664001001': {'PDP'   : [],
                            'PDN'   : [('*', 1, '192.168.132.201')],
                            'MSISDN': '16641001',
                            'USIM'  : True
                            }
        }
    #
    # Packet Data Protocol config for 2G-3G PS domain, per APN
    ConfigPDP = {
        }
    #
    # Packet Data Network config for EPC, per APN
    ConfigPDN = {
        '*'      : {'DNS': ('192.168.253.1', '192.168.253.2')},
        'corenet': {'DNS': ('192.168.253.1', '192.168.253.2')},
        }
    #
    # UE, indexed by IMSI, and their UEd handler instance
    UE = {}
    # UE, indexed by TMSI when the IMSI is unknown (at attachment), 
    # and their UEd handler instance are set in ._UEpre, created at init
    #
    # TMSI / P-TMSI / M-TMSI to IMSI conversion
    TMSI  = {}
    PTMSI = {}
    MTMSI = {}
    #
    # This is a filter which enables the potential attachment of non-preconfigured 
    # UE to the CorenetServer
    # WNG: for IMSI that are not preconfigured (no Ki in the AuC database),
    # further UE-related procedure will fail because of missing crypto material.
    # When an non-preconfigured UE attaches the CorenetServer, ConfigUE['*'] is 
    # used to provide a default config and need to be defined.
    # use UE_ATTACH_FILTER = None to disable this permissive filter.
    UE_ATTACH_FILTER = '^20869'
    
    #--------------------------------------------------------------------------#
    # logging and init methods
    #--------------------------------------------------------------------------#
    
    def _log(self, logtype, msg):
        """Server logging facility
        
        DEBUG logtype: 'ERR', 'WNG', 'INF', 'DBG'
        TRACE logtype: 'TRACE_SK_[UL|DL]',
                       'TRACE_ASN_[HNBAP|RUA|S1AP]_[UL|DL]',
        """
        if logtype[:3] == 'TRA':
            if logtype[6:8] == 'SK':
                log('[TRA] [%s]\n%s%s%s'\
                    % (logtype[6:], TRACE_COLOR_START, hexlify(msg).decode('ascii'), TRACE_COLOR_END))
            else:
                log('[TRA] [%s]\n%s%s%s'\
                    % (logtype[6:], TRACE_COLOR_START, msg, TRACE_COLOR_END))
        elif logtype in self.DEBUG:
            log('[%s] %s' % (logtype, msg))
    
    def __init__(self, serving=True, threaded=True):
        # initialize the Python built-in Mersennes Twister LFSR for producing TMSI
        random.seed(random.SystemRandom().randint(0, 1<<64))
        # starting the server in background
        self._running = False
        if threaded:
            self._server = threadit(self.start, serving=serving)
        else:
            self.start(serving=serving)
    
    #--------------------------------------------------------------------------#
    # SCTP socket server
    #--------------------------------------------------------------------------#
    
    def start(self, serving=True):
        # start SCTP servers, bind() and listen()
        self.SCTPServ   = [] # will be casted to tuple
        if DEBUG_SK:
            self._skc   = []
        # LUT for connected SCTP client and ENBId / HNBId
        self.SCTPCli    = {}
        #
        if self.SERVER_HNB:
            self._start_hnb_server()
            self.SCTPServ.append( self._sk_hnb )
        else:
            self._sk_hnb = None
        #
        if self.SERVER_ENB:
            self._start_enb_server()
            self.SCTPServ.append( self._sk_enb )
        else:
            self._sk_enb = None
        self.SCTPServ = tuple(self.SCTPServ)
        #
        # init the dict for storing UE with unknown IMSI at attachment
        self._UEpre = {}
        # init the UE procedure cleaner holder
        # (with a dummy thread, which will be overridden at runtime)
        self._clean_ue_proc = threadit( lambda: 1 )
        #
        self.LAI.clear()
        self.RAI.clear()
        self.TAI.clear()
        #
        # start sub-servers
        if self.AUCd:
            self.AUCd  = self.__class__.AUCd()
        if self.GTPUd:
            self.GTPUd = self.__class__.GTPUd()
        if self.SMSd:
            self.SMSd  = self.__class__.SMSd()
        #
        if serving:
            # serve connections
            self._serve()
            # self._running has been set to False, main loop exited
            self._log('INF', 'SCTP server stopped')
    
    def is_running(self):
        return self._running
    
    def _start_hnb_server(self):
        # start SCTP server for Home-NodeBs
        server_addr = (self.SERVER_HNB['IP'], self.SERVER_HNB['port'])
        try:
            self._sk_hnb = sctp.sctpsocket_tcp(self.SERVER_HNB['INET'])
            self.sctp_set_events(self._sk_hnb)
        except Exception as err:
            raise(CorenetErr('cannot create SCTP socket: {0}'.format(err)))
        try:
            self._sk_hnb.bind(server_addr)
        except Exception as err:
            raise(CorenetErr('cannot bind SCTP socket on address {0!r}: {1}'\
                  .format(server_addr, err)))
        try:
            self._sk_hnb.listen(self.SERVER_HNB['MAXCLI'])
        except Exception as err:
            raise(CorenetErr('cannot listen to SCTP connection: {1}'.format(err)))
        #
        self._log('INF', 'SCTP HNB server started on address %r' % (server_addr, ))
    
    def _start_enb_server(self):
        # start SCTP server for eNodeBs
        server_addr = (self.SERVER_ENB['IP'], self.SERVER_ENB['port'])
        try:
            self._sk_enb = sctp.sctpsocket_tcp(self.SERVER_ENB['INET'])
            self.sctp_set_events(self._sk_enb)
        except Exception as err:
            raise(CorenetErr('cannot create SCTP socket: {0}'.format(err)))
        try:
            self._sk_enb.bind(server_addr)
        except Exception as err:
            raise(CorenetErr('cannot bind SCTP socket on address {0!r}: {1}'\
                  .format(server_addr, err)))
        try:
            self._sk_enb.listen(self.SERVER_ENB['MAXCLI'])
        except Exception as err:
            raise(CorenetErr('cannot listen to SCTP connection: {1}'.format(err)))
        #
        self._log('INF', 'SCTP ENB server started on address %r' % (server_addr, ))
    
    def _serve(self):
        # Main server loop, using select() to read sockets, the loop:
        # gets new SCTP clients,
        # gets new SCTP streams for connected SCTP clients,
        # and eventually timeouts running UE NAS procedures
        self._running, T0 = True, time()
        while self._running:
            skr = []
            try:
                skr = select(self.SCTPServ + tuple(self.SCTPCli), (), (), self.SCHED_RES)[0]
            except Exception as err:
                self._log('ERR', 'select() error: %s' % err)
                self._running = False
            #
            for sk in skr:
                if sk == self._sk_enb:
                    # new eNodeB STCP client (S1SetupRequest)
                    self.handle_new_enb()
                elif sk == self._sk_hnb:
                    # new Home-NodeB SCTP client (HNBRegisterRequest)
                    self.handle_new_hnb()
                else:
                    # read from connected SCTP client for a new stream 
                    # (whatever PDU)
                    self.handle_stream_msg(sk)
            #
            # clean-up potential signalling procedures in timeout
            if self.SCHED_UE_TO and time() - T0 > self.SCHED_UE_TO and \
            not self._clean_ue_proc.isAlive():
                # select() timeout or more than `SCHED_RES' seconds since 
                # last timeout
                self._clean_ue_proc = threadit(self.clean_ue_proc)
                T0 = time()
    
    def stop(self):
        self._running = False
        sleep(self.SCHED_RES + 0.01)
        if self._sk_hnb:
            self._sk_hnb.close()
        if self._sk_enb:
            self._sk_enb.close()
        self._clean_ue_proc.join()
        #
        # disconnect all RAN clients
        for cli in self.SCTPCli:
            cli.close()
            self.RAN[self.SCTPCli[cli]].disconnect()
        self.SCTPCli.clear()
        #
        # stop sub-servers
        self.AUCd.stop()
        self.GTPUd.stop()
    
    def sctp_handle_notif(self, sk, notif):
        self._log('DBG', 'SCTP notification: type %i, flags %i' % (notif.type, notif.flags))
        # TODO
    
    def sctp_set_events(self, sk):
        # configure the SCTP socket to receive adaptation layer and stream id
        # indications in sctp_recv() notification
        sk.events.data_io          = True
        sk.events.adaptation_layer = True
        #sk.events.association      = True
        sk.events.flush()
    
    #--------------------------------------------------------------------------#
    # SCTP stream handler
    #--------------------------------------------------------------------------#
    
    def _read_sk(self, sk):
        # we always arrive there after a select() call, 
        # hence, recv() should always return straight without blocking
        # TODO: loop on recv() to get the complete stream (in case of very long PDU...), 
        # then defragment those PDUs properly
        # TODO: in case notif has only 0, specific events need to be subscribed 
        # to get at least ppid and stream
        try:
            addr, flags, buf, notif = sk.sctp_recv(self.SERVER_BUFLEN)
        except TimeoutError as err:
            # the client disconnected
            if sk in self.SCTPCli:
                self._rem_sk(sk)
                return None, None
        except ConnectionError as err:
            # something went bad with the endpoint
            self._log('ERR', 'sctp_recv() failed, err: {0}'.format(err))
            if sk in self.SCTPCli:
                self._rem_sk(sk)
                return None, None
        if DEBUG_SK:
            self._skc.append( ('recv', time(), addr, flags, buf, notif) )
        if not buf:
            if flags & sctp.FLAG_NOTIFICATION:
                # SCTP notification
                self.sctp_handle_notif(sk, notif)
            elif sk in self.SCTPCli:
                # the client just disconnected
                self._rem_sk(sk)
        else:
            if self.TRACE_SK:
                self._log('TRACE_SK_UL', buf)
            if not flags & sctp.FLAG_EOR:
                self._log('WNG', 'SCTP message truncated') 
        return buf, notif
    
    def _rem_sk(self, sk):
        # close socket
        sk.close()
        # select RAN client
        cli = self.RAN[self.SCTPCli[sk]]
        if isinstance(cli, HNBd):
            self._log('DBG', 'HNB %r closed connection' % (cli.ID,))            
            # remove from the Server location tables
            if cli.Config:
                self._unset_hnb_loc(cli)
        elif isinstance(cli, ENBd):
            self._log('DBG', 'eNB %r closed connection' % (cli.ID,))
            # remove from the Server location tables
            if cli.Config:
                self._unset_enb_loc(cli)
        else:
            assert()
        # update HNB / ENB state
        cli.disconnect()
        # update list of clients socket, and dict of RAN clients
        del self.SCTPCli[sk]
    
    def _write_sk(self, sk, buf, ppid=0, stream=0):
        if self.TRACE_SK:
            self._log('TRACE_SK_DL', buf)
        if ppid:
            ppid = htonl(ppid)
        #if stream:
        #    stream = htonl(stream)
        ret = 0
        try:
            ret = sk.sctp_send(buf, ppid=ppid, stream=stream)
        except Exception as err:
            self._log('ERR', 'cannot send buf to SCTP client at address %r' % (sk.getpeername(), ))
            if DEBUG_SK:
                self._skc.append( ('send', time(), buf, ppid, stream, err) )
        else:
            if DEBUG_SK:
                self._skc.append( ('send', time(), buf, ppid, stream) )
        return ret
    
    def handle_stream_msg(self, sk):
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: it may be required to handle SCTP notifications, at some point...
            return
        # getting SCTP ppid, stream id and eNB/HNB handler
        ppid, sid, ranid = ntohl(notif.ppid), notif.stream, self.SCTPCli[sk]
        ran = self.RAN[ranid]
        #
        if ppid == SCTP_PPID_HNBAP:
            assert( isinstance(ran, HNBd) )
            hnb = ran
            if not asn_hnbap_acquire():
                hnb._log('ERR', 'unable to acquire the HNBAP module')
                return
            try:
                PDU_HNBAP.from_aper(buf)
            except:
                asn_hnbap_release()
                hnb._log('WNG', 'invalid HNBAP PDU transfer-syntax: %s'\
                         % hexlify(buf).decode('ascii'))
                Err = hnb.init_hnbap_proc(HNBAPErrorIndCN,
                                          Cause=('protocol', 'transfer-syntax-error'))
                Err.recv(buf)
                pdu_tx = Err.send()
            else:
                pdu_rx = PDU_HNBAP()
                if hnb.TRACE_ASN_HNBAP:
                    hnb._log('TRACE_ASN_HNBAP_UL', PDU_HNBAP.to_asn1())
                asn_hnbap_release()
                pdu_tx = hnb.process_hnbap_pdu(pdu_rx)
            for pdu in pdu_tx:
                self.send_hnbap_pdu(hnb, pdu)
        #
        elif ppid == SCTP_PPID_RUA:
            assert( isinstance(ran, HNBd) )
            hnb = ran
            if not asn_rua_acquire():
                hnb._log('ERR', 'unable to acquire the RUA module')
                return
            try:
                PDU_RUA.from_aper(buf)
            except:
                asn_rua_release()
                self._log('WNG', 'invalid RUA PDU transfer-syntax: %s'\
                          % hexlify(buf).decode('ascii'))
                Err = hnb.init_rua_proc(RUAErrorInd,
                                        Cause=('protocol', 'transfer-syntax-error'))
                Err.recv(buf)
                pdu_tx = Err.send()
            else:
                pdu_rx = PDU_RUA()
                if hnb.TRACE_ASN_RUA:
                    hnb._log('TRACE_ASN_RUA_UL', PDU_HNBAP.to_asn1())
                asn_rua_release()
                pdu_tx = hnb.process_rua_pdu(pdu_rx)
            for pdu in pdu_tx:
                self.send_rua_pdu(hnb, pdu)
        #
        elif ppid == SCTP_PPID_S1AP:
            assert( isinstance(ran, ENBd) )
            enb = ran
            if not asn_s1ap_acquire():
                enb._log('ERR', 'unable to acquire the S1AP module')
                return
            try:
                PDU_S1AP.from_aper(buf)
            except:
                asn_s1ap_release()
                enb._log('WNG', 'invalid S1AP PDU transfer-syntax: %s'\
                         % hexlify(buf).decode('ascii'))
                Err = enb.init_hnbap_proc(S1APErrorIndNonUECN,
                                          Cause=('protocol', 'transfer-syntax-error'))
                pdu_tx = Err.send()
            else:
                pdu_rx = PDU_S1AP()
                if enb.TRACE_ASN_S1AP:
                    enb._log('TRACE_ASN_S1AP_UL', PDU_S1AP.to_asn1())
                asn_s1ap_release()
                if sid == enb.SKSid:
                    # non-UE-associated signalling
                    pdu_tx = enb.process_s1ap_pdu(pdu_rx)
                else:
                    # UE-associated signalling
                    pdu_tx = enb.process_s1ap_ue_pdu(pdu_rx, sid)
            for pdu in pdu_tx:
                self.send_s1ap_pdu(enb, pdu, sid)
        #
        else:
            self._log('ERR', 'invalid SCTP PPID, %i' % ppid)
            if self.SERVER_HNB['errclo']:
                self._rem_sk(sk)
            return
    
    def send_hnbap_pdu(self, hnb, pdu):
        if not asn_hnbap_acquire():
            hnb._log('ERR', 'unable to acquire the HNBAP module')
            return
        PDU_HNBAP.set_val(pdu)
        if hnb.TRACE_ASN_HNBAP:
            hnb._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
        buf = PDU_HNBAP.to_aper()
        asn_hnbap_release()
        return self._write_sk(hnb.SK, buf, ppid=SCTP_PPID_HNBAP)
    
    def send_rua_pdu(self, hnb, pdu):
        if not asn_rua_acquire():
            hnb._log('ERR', 'unable to acquire the RUA module')
            return
        PDU_RUA.set_val(pdu)
        if hnb.TRACE_ASN_RUA:
            hnb._log('TRACE_ASN_RUA_DL', PDU_RUA.to_asn1())
        buf = PDU_RUA.to_aper()
        asn_rua_release()
        return self._write_sk(hnb.SK, buf, ppid=SCTP_PPID_RUA)
    
    def send_s1ap_pdu(self, enb, pdu, sid):
        if not asn_s1ap_acquire():
            enb._log('ERR', 'unable to acquire the S1AP module')
            return
        PDU_S1AP.set_val(pdu)
        if enb.TRACE_ASN_S1AP:
            enb._log('TRACE_ASN_S1AP_DL', PDU_S1AP.to_asn1())
        buf = PDU_S1AP.to_aper()
        asn_s1ap_release()
        return self._write_sk(enb.SK, buf, ppid=SCTP_PPID_S1AP, stream=sid)
    
    #--------------------------------------------------------------------------#
    # eNodeB connection
    #--------------------------------------------------------------------------#
    
    def _parse_s1setup(self, pdu):
        if pdu[0] != 'initiatingMessage' or pdu[1]['procedureCode'] != 17:
            # not initiating / S1Setup
            self._log('WNG', 'invalid S1AP PDU for setting up the eNB S1AP link')
            return
            
        pIEs, plmn, cellid = pdu[1]['value'][1], None, None
        IEs = pIEs['protocolIEs']
        if 'protocolExtensions' in pIEs:
            Exts = pIEs['protocolExtensions']
        else:
            Exts = []
        for ie in IEs:
            if ie['id'] == 59:
                # Global-ENB-ID
                globenbid = ie['value'][1]
                plmn      = globenbid['pLMNidentity']
                cellid    = globenbid['eNB-ID'][1] # both macro / home eNB-ID are BIT STRING
                break
        if plmn is None or cellid is None:
            self._log('WNG', 'invalid S1AP PDU for setting up the eNB S1AP link: '\
                      'missing PLMN and CellID')
            return
        # decode PLMN and CellID
        try:
            PLMN   = plmn_buf_to_str(plmn)
            CellID = cellid_bstr_to_str(cellid)
            return PLMN, CellID
        except:
            return None
    
    def _send_s1setuprej(self, sk, sid, cause):
        IEs = [{'criticality': 'ignore',
                'id': 2, # id-Cause
                'value': (('S1AP-IEs', 'Cause'), cause)}]
        pdu = ('unsuccessfulOutcome',
               {'criticality': 'ignore',
                'procedureCode': 17,
                'value': (('S1AP-PDU-Contents', 'S1SetupFailure'),
                          {'protocolIEs' : IEs})})
        if not asn_s1ap_acquire():
            self._log('ERR', 'unable to acquire the S1AP module')
        else:
            PDU_S1AP.set_val(pdu)
            if ENBd.TRACE_ASN_S1AP:
                self._log('TRACE_ASN_S1AP_DL', PDU_S1AP.to_asn1())
            self._write_sk(sk, PDU_S1AP.to_aper(), ppid=SCTP_PPID_S1AP, stream=sid)
            asn_s1ap_release()
        if self.SERVER_ENB['errclo']:
            sk.close()
    
    def handle_new_enb(self):
        sk, addr = self._sk_enb.accept()
        self._log('DBG', 'New eNB client from address %r' % (addr, ))
        #
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: maybe required to handle SCTP notification, at some point
            return
        # verifying SCTP Payload Protocol ID and setting stream ID for 
        # non-UE-associated trafic
        ppid, sid = ntohl(notif.ppid), notif.stream
        if ppid != SCTP_PPID_S1AP:
            self._log('ERR', 'invalid S1AP PPID, %i' % ppid)
            if self.SERVER_ENB['errclo']:
                sk.close()
            return
        #
        if not asn_s1ap_acquire():
            self._log('ERR', 'unable to acquire the S1AP module')
            return
        try:
            PDU_S1AP.from_aper(buf)
        except:
            self._log('WNG', 'invalid S1AP PDU transfer-syntax: %s'\
                      % hexlify(buf).decode('ascii'))
            # return nothing, no need to bother
            return
        if ENBd.TRACE_ASN_S1AP:
            self._log('TRACE_ASN_S1AP_UL', PDU_S1AP.to_asn1())
        pdu_rx = PDU_S1AP()
        asn_s1ap_release()
        #
        ENBId = self._parse_s1setup(pdu_rx)
        if ENBId is None:
            # send S1SetupReject
            self._send_s1setuprej(sk, cause=('protocol', 'abstract-syntax-error-reject'))
            return
        elif ENBId not in self.RAN:
            if not self.RAN_CONNECT_ANY:
                self._log('ERR', 'eNB %r not allowed to connect' % (ENBId, ))
                # send S1SetupReject
                self._send_s1setuprej(sk, cause=('radioNetwork', 'unspecified'))
                return
            elif ENBId[0] not in self.RAN_ALLOWED_PLMN:
                self._log('ERR', 'eNB %r not allowed to connect, bad PLMN' % (ENBId, ))
                self._send_s1setuprej(sk, cause=('radioNetwork', 'unspecified'))
                return
            else:
                # creating an entry for this eNB
                enb = ENBd(self, sk, sid)
                self.RAN[ENBId] = enb
        else:
            if self.RAN[ENBId] is None:
                # eNB allowed, but not yet connected
                enb = ENBd(self, sk, sid)
                self.RAN[ENBId] = enb
            elif not self.RAN[ENBId].is_connected():
                # eNB already connected and disconnected in the past
                enb = self.RAN[ENBId]
                enb.__init__(self, sk, sid)
            else:
                # eNB already connected
                self._log('ERR', 'eNB %r already connected from address %r'\
                          % (ENBId, self.RAN[ENBId].SK.getpeername()))
                if self.SERVER_ENB['errclo']:
                    sk.close()
                return
        #
        # process the initial PDU
        pdu_tx = enb.process_s1ap_pdu(pdu_rx)
        # keep track of the client
        self.SCTPCli[sk] = ENBId
        # add the enb TAI to the Server location tables
        if enb.Config:
            self._set_enb_loc(enb)
        #
        # send available PDU(s) back
        if not asn_s1ap_acquire():
           enb._log('ERR', 'unable to acquire the S1AP module')
           return
        for pdu in pdu_tx:
            PDU_S1AP.set_val(pdu)
            if ENBd.TRACE_ASN_S1AP:
                enb._log('TRACE_ASN_S1AP_DL', PDU_S1AP.to_asn1())
            self._write_sk(sk, PDU_S1AP.to_aper(), ppid=SCTP_PPID_S1AP, stream=sid)
        asn_s1ap_release()
    
    def _set_enb_loc(self, enb):
        for tai in enb.Config['TAIs']:
            if tai in self.TAI:
                assert( enb.ID not in self.TAI[tai] )
                self.TAI[tai].add( enb.ID )
            else:
                self.TAI[tai] = set( (enb.ID, ) )
    
    def _unset_enb_loc(self, enb):
        for tai in enb.Config['TAIs']:
            try:
                self.TAI[tai].remove(enb.ID)
            except:
                self._log('ERR', 'ENB not referenced into the TAI table')
    
    #--------------------------------------------------------------------------#
    # Home-NodeB connection
    #--------------------------------------------------------------------------#
    
    def _parse_hnbregreq(self, pdu):
        if pdu[0] != 'initiatingMessage' or pdu[1]['procedureCode'] != 1:
            # not initiating / HNBRegisterRequest
            self._log('WNG', 'invalid HNBAP PDU for registering the HNB')
            return
        pIEs, plmn, cellid = pdu[1]['value'][1], None, None
        IEs = pIEs['protocolIEs']
        if 'protocolExtensions' in pIEs:
            Exts = pIEs['protocolExtensions']
        else:
            Exts = []
        for ie in IEs:
            if ie['id'] == 9:
                plmn = ie['value'][1]
            elif ie['id'] == 11:
                cellid = ie['value'][1]
            if plmn is not None and cellid is not None:
                break
        if plmn is None or cellid is None:
            self._log('WNG', 'invalid HNBAP PDU for registering the HNB: missing PLMN and CellID')
            return
        # decode PLMN and CellID
        try:
            PLMN   = plmn_buf_to_str(plmn)
            CellID = cellid_bstr_to_str(cellid)
            return PLMN, CellID
        except:
            return None
    
    def _send_hnbregrej(self, sk, cause):
        IEs = [{'criticality': 'ignore',
                'id': 1, # id-Cause
                'value': (('HNBAP-IEs', 'Cause'), cause)}]
        pdu = ('unsuccessfulOutcome',
               {'criticality': 'ignore',
                'procedureCode': 1,
                'value': (('HNBAP-PDU-Contents', 'HNBRegisterReject'),
                          {'protocolIEs' : IEs})})
        if not asn_hnbap_acquire():
            self._log('ERR', 'unable to acquire the HNBAP module')
        else:
            PDU_HNBAP.set_val(pdu)
            if HNBd.TRACE_ASN_HNBAP:
                self._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
            self._write_sk(sk, PDU_HNBAP.to_aper(), ppid=SCTP_PPID_HNBAP)
            asn_hnbap_release()
        if self.SERVER_HNB['errclo']:
            sk.close()
    
    def handle_new_hnb(self):
        sk, addr = self._sk_hnb.accept()
        self._log('DBG', 'New HNB client from address %r' % (addr, ))
        #
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: maybe required to handle SCTP notification, at some point
            return
        # verifying SCTP Payload Protocol ID
        ppid = ntohl(notif.ppid)
        if ppid != SCTP_PPID_HNBAP:
            self._log('ERR', 'invalid HNBAP PPID, %i' % ppid)
            if self.SERVER_HNB['errclo']:
                sk.close()
            return
        #
        if not asn_hnbap_acquire():
            self._log('ERR', 'unable to acquire the HNBAP module')
            return
        try:
            PDU_HNBAP.from_aper(buf)
        except:
            self._log('WNG', 'invalid HNBAP PDU transfer-syntax: %s'\
                      % hexlify(buf).decode('ascii'))
            # return nothing, no need to bother
            return
        if HNBd.TRACE_ASN_HNBAP:
            self._log('TRACE_ASN_HNBAP_UL', PDU_HNBAP.to_asn1())
        pdu = PDU_HNBAP()
        asn_hnbap_release()
        #
        # ensure we have a HNBRegisterRequest with PLMN and CellID provided
        HNBId = self._parse_hnbregreq(pdu)
        if HNBId is None:
            # send HNBRegisterReject
            self._send_hnbregrej(sk, cause=('protocol', 'abstract-syntax-error-reject'))
            return
        elif HNBId not in self.RAN:
            if not self.RAN_CONNECT_ANY:
                self._log('ERR', 'HNB %r not allowed to connect' % (HNBId,))
                # send HNBRegisterReject
                self._send_hnbregrej(sk, cause=('radioNetwork', 'unauthorised-HNB'))
                return
            elif HNBId[0] not in self.RAN_ALLOWED_PLMN:
                self._log('ERR', 'HNB %r not allowed to connect, bad PLMN' % (HNBId,))
                self._send_hnbregrej(sk, cause=('radioNetwork', 'unauthorised-HNB'))
                return
            else:
                # creating an entry for this HNB
                hnb = HNBd(self, sk)
                self.RAN[HNBId] = hnb
        else:
            if self.RAN[HNBId] is None:
                # HNB allowed, but not yet connected
                hnb = HNBd(self, sk)
                self.RAN[HNBId] = hnb
            elif not self.RAN[HNBId].is_connected():
                # HNB already connected and disconnected in the past
                hnb = self.RAN[HNBId]
                hnb.__init__(self, sk)
            else:
                # HNB already connected
                self._log('ERR', 'HNB %r already connected from address %r'\
                          % (HNBId, self.RAN[HNBId].SK.getpeername()))
                if self.SERVER_HNB['errclo']:
                    sk.close()
                return
        #
        # process the initial PDU
        ret = hnb.process_hnbap_pdu(pdu)
        # keep track of the client
        self.SCTPCli[sk] = HNBId
        # add the hnb LAI / RAI to the Server location tables
        if hnb.Config:
            self._set_hnb_loc(hnb)
        #
        # send available PDU(s) back
        if not asn_hnbap_acquire():
           hnb._log('ERR', 'unable to acquire the HNBAP module')
           return
        for retpdu in ret:
            PDU_HNBAP.set_val(retpdu)
            if HNBd.TRACE_ASN_HNBAP:
                hnb._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
            self._write_sk(sk, PDU_HNBAP.to_aper(), ppid=SCTP_PPID_HNBAP)
        asn_hnbap_release()
    
    def _set_hnb_loc(self, hnb):
        lai = (hnb.Config['PLMNidentity'], hnb.Config['LAC'])
        rai = lai + (hnb.Config['RAC'], )
        if lai in self.LAI:
            assert( hnb.ID not in self.LAI[lai] )
            self.LAI[lai].add( hnb.ID )
        else:
            self.LAI[lai] = set( (hnb.ID, ) )
        if rai in self.RAI:
            assert( hnb.ID not in self.RAI[rai] )
            self.RAI[rai].add( hnb.ID )
        else:
            self.RAI[rai] = set( (hnb.ID, ) )
    
    def _unset_hnb_loc(self, hnb):
        lai = (hnb.Config['PLMNidentity'], hnb.Config['LAC'])
        rai = lai + (hnb.Config['RAC'], )
        try:
            self.LAI[lai].remove(hnb.ID)
        except:
            self._log('ERR', 'HNB not referenced into the LAI table')
        try:
            self.RAI[rai].remove(hnb.ID)
        except:
            self._log('ERR', 'HNB not referenced into the RAI table')
    
    #--------------------------------------------------------------------------#
    # UE handler
    #--------------------------------------------------------------------------#
    
    def get_ued(self, **kw):
        """return a UEd instance or None, according to the UE identity provided
        
        kw: imsi (digit-str), tmsi (uint32), ptmsi (uint32) or mtmsi (uint32)
        
        If an imsi is provided, returns the UEd instance in case the IMSI is allowed
        If a tmsi or ptmsi is provided, returns
            the UEd instance corresponding to this TMSI if already available
            a new UEd instance which will take care of requesting the IMSI
        """
        if 'imsi' in kw:
            imsi = kw['imsi']
            if imsi in self.UE:
                # UEd already available
                return self.UE[imsi]
            elif imsi in self.ConfigUE:
                # UEd has to be instantiated
                self.UE[imsi] = UEd(self, imsi, config=self.ConfigUE[imsi])
                return self.UE[imsi]
            elif self.UE_ATTACH_FILTER and re.match(self.UE_ATTACH_FILTER, imsi) and \
            '*' in self.ConfigUE:
                self._log('WNG', 'attaching an UE without dedicated configuration, IMSI %s' % imsi)
                self.UE[imsi] = UEd(self, imsi, config=self.ConfigUE['*'])
                return self.UE[imsi]
        elif 'tmsi' in kw:
            tmsi = kw['tmsi']
            if tmsi in self.TMSI:
                return self.UE[self.TMSI[tmsi]]
            else:
                # creating a UEd instance which will request IMSI
                return self.create_dummy_ue(tmsi=tmsi)
        elif 'ptmsi' in kw:
            ptmsi = kw['ptmsi']
            if ptmsi in self.PTMSI:
                return self.UE[self.PTMSI[ptmsi]]
            else:
                # creating a UEd instance which will request IMSI
                return self.create_dummy_ue(ptmsi=ptmsi)
        elif 'mtmsi' in kw:
            mtmsi = kw['mtmsi']
            if mtmsi in self.MTMSI:
                return self.UE[self.MTMSI[mtmsi]]
            else:
                # creating a UEd instance which will request IMSI
                return self.create_dummy_ue(mtmsi=mtmsi)
        return None
    
    def create_dummy_ue(self, **kw):
        assert( len(kw) == 1 )
        ued = UEd(self, '', **kw)
        self._UEpre[tuple(kw.values())[0]] = ued
        return ued
    
    def is_imsi_allowed(self, imsi):
        if imsi in self.ConfigUE:
            # preconfigured UE
            return True
        elif re.match(self.UE_ATTACH_FILTER, imsi) and '*' in self.ConfigUE:
            # non-preconfigured UE
            return True
        else:
            return False
    
    def is_imei_allowed(self, imei):
        # to be implemented
        return True
    
    def is_imeisv_allowed(self, imeisv):
        # to be implemented
        return True
    
    def clean_ue_proc(self):
        #self._log('DBG', 'clean_ue_proc()')
        # go over all UE and abort() NAS signalling procedures in timeout
        T = time()
        for ue in self.UE.values():
            if ue.IuCS is not None:
                if ue.IuCS.MM.Proc:
                    for P in ue.IuCS.MM.Proc:
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
            
                #if ue.IuCS.CC.Proc:
                #    for P in ue.IuCS.CC.Proc.values():
                #        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                #            P._log('WNG', 'timeout: aborting')
                #            P.abort()
                
                #if ue.IuCS.SMS.Proc:
                #    for P in ue.IuCS.SMS.Proc.values():
                #        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                #            P._log('WNG', 'timeout: aborting')
                #            P.abort()
            
                #if ue.IuCS.SS.Proc:
                #    for P in ue.IuCS.SS.Proc.values():
                #        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                #            P._log('WNG', 'timeout: aborting')
                #            P.abort()
            
            
            if ue.IuPS is not None:
            
                if ue.IuPS.GMM.Proc:
                    for P in ue.IuPS.GMM.Proc:
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                #if ue.IuPS.SM.Proc:
                #    for P in ue.IuCS.CC.Proc.values():
                #        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                #            P._log('WNG', 'timeout: aborting')
                #            P.abort()
            
            #if ue.S1 is not None:
            #
                #if ue.S1.EMM.Proc:
                #    pass
                
                #if ue.S1.ESM.Proc:
                #    pass

