# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2013. Benoit Michau. ANSSI.
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
# * File Name : pycrate_corenet/ServerGTPU.py
# * Created : 2013-11-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# GTP-U handler works with Linux PF_PACKET RAW socket on the Internet side
# and with standard GTP-U 3GPP protocol on the RNC / eNB side
# RNC / eNB <== [IP/UDP/GTPU/IP_mobile] ==> GTPUd <== [RawEthernet/IP_mobile] ==> Internet
#
# This way, the complete IP interface of a mobile is exposed through this Gi interface.
# It requires the GTPUd to resolve ARP request on behalf of mobiles that it handles: 
# this is the role of ARPd
#------------------------------------------------------------------------------#

# filtering exports
__all__ = ['ARPd', 'GTPUd', 'DPI', 'MOD', 'DNSRESP', 'TCPSYNACK']

import os
import signal
#
if os.name != 'nt':
    from fcntl  import ioctl
    from socket import timeout
    from random import _urandom
else:
    print('[ERR] ServerGTPU : you\'re not on *nix system. It\'s not going to work:\n'\
          'You need PF_PACKET socket')

from pycrate_core.elt import Envelope
from pycrate_ether.IP import *
from .utils           import *

#------------------------------------------------------------------------------#
# setting / unsetting ethernet IF in promiscuous mode                          #
#------------------------------------------------------------------------------#
# copied from scapy (scapy/scapy/arch/linux.py)

SIOCGIFINDEX           = 0x8933 # name -> if_index mapping
SOL_PACKET             = 263
PACKET_MR_PROMISC      = 1
PACKET_ADD_MEMBERSHIP  = 1
PACKET_DROP_MEMBERSHIP = 2

def get_if(iff, cmd):
    """Ease SIOCGIF* ioctl calls"""
    sk = socket.socket()
    ifreq = ioctl(sk, cmd, pack('16s16x', iff.encode('utf8')))
    sk.close()
    return ifreq

def get_if_index(iff):
    return int(unpack('I', get_if(iff, SIOCGIFINDEX)[16:20])[0])

def set_promisc(sk, iff, val=1):
    mreq = pack('IHH8s', get_if_index(iff), PACKET_MR_PROMISC, 0, b'')
    if val:
        cmd = PACKET_ADD_MEMBERSHIP
    else:
        cmd = PACKET_DROP_MEMBERSHIP
    sk.setsockopt(SOL_PACKET, cmd, mreq)


#------------------------------------------------------------------------------#
# ARPd                                                                         #
#------------------------------------------------------------------------------#

class ARPd(object):
    '''
    ARP resolver
    resolves Ethernet / IPv4 address correspondence on behalf of UE connected over 
    GTP-U.
    
    The method .resolve(ipaddr) returns the MAC address for the requested IP 
    address.
    It runs a background thread too, that answers ARP requests on behalf of 
    connected mobiles.

    When handling mobiles' network interfaces over GTP-U, the following steps
    are followed:
    - for outgoing packets:
        1) for any destination IP outside of our network (e.g. 192.168.1.0/24),
        provide the ROUTER_MAC_ADDR directly
        2) for local destination IP address in our subnet,
        provide the corresponding MAC address after an ARP resolution
    - for incoming packets:
        we must answer the router's or local hosts' ARP requests
        before being able to receive IP packets to be transferred to the mobiles

    ARPd:
    maintains the ARP_RESOLV_TABLE
    listens on the ethernet interface for:
    - incoming ARP requests, and answer it for IP addresses from our IP_POOL
    - incoming ARP responses (due to the daemon sending ARP requests)
    - incoming IP packets (thanks to promiscous mode) to update the ARP_RESOLV_TABLE
      with new MAC addresses opportunistically
    sends ARP request when needed to be able then to forward IP packets from mobile
    '''
    #
    # verbosity level: list of log types to display when calling 
    # self._log(logtype, msg)
    DEBUG           = ('ERR', 'WNG', 'INF', 'DBG')
    #
    # recv() buffer length
    BUFLEN          = 2048
    # select() timeout and wait period
    SELECT_TO       = 0.1
    SELECT_SLEEP    = 0.05
    #
    # all Gi interface parameters
    # Our GGSN ethernet parameters (IF, MAC and IP addresses)
    # (and also the MAC address to be used for any mobiles through our GGSN)
    GGSN_ETH_IF     = 'eth0'
    GGSN_MAC_ADDR   = '08:00:00:01:02:03'
    GGSN_IP_ADDR    = '192.168.1.100'
    #
    # the set of IP address to be used by our mobiles
    IP_POOL         = {'192.168.1.201', '192.168.1.202', '192.168.1.203'}
    #
    # network parameters:
    # subnet prefix 
    # WNG: we only handle IPv4 /24 subnet
    SUBNET_PREFIX   = '192.168.1.0/24'
    # and 1st IP router (MAC and IP addresses)
    # this is to resolve directly any IP outside our subnet
    ROUTER_MAC_ADDR = 'f4:00:00:01:02:03'
    ROUTER_IP_ADDR  = '192.168.1.1'
    #
    CATCH_SIGINT = False
    
    def __init__(self, opportunist=False):
        #
        self.GGSN_MAC_BUF   = mac_aton(self.GGSN_MAC_ADDR)
        self.GGSN_IP_BUF    = inet_aton(self.GGSN_IP_ADDR)
        self.ROUTER_MAC_BUF = mac_aton(self.ROUTER_MAC_ADDR)
        self.ROUTER_IP_BUF  = inet_aton(self.ROUTER_IP_ADDR)
        # use an uint32 for the subnet prefix
        prefip, prefmask    = self.SUBNET_PREFIX.split('/')
        pref                = unpack('>I', inet_aton(prefip))[0]
        self.SUBNET_MASK    = (1<<32)-(1<<(32-int(prefmask)))
        self.SUBNET_PREFIX  = pref & self.SUBNET_MASK
        #
        # init RAW ethernet socket for ARP
        self.sk_arp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ntohs(0x0806))
        self.sk_arp.settimeout(0.1)
        #self.sk_arp.setsockopt(SOL_PACKET, SO_RCVBUF, 0)
        self.sk_arp.bind((self.GGSN_ETH_IF, 0x0806))
        #self.sk_arp.setsockopt(SOL_PACKET, SO_RCVBUF, 2**24)
        #
        # init RAW ethernet socket for IPv4
        self.sk_ip = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ntohs(0x0800))
        self.sk_ip.settimeout(0.1)
        #self.sk_ip.setsockopt(SOL_PACKET, SO_RCVBUF, 0)
        self.sk_ip.bind((self.GGSN_ETH_IF, 0x0800))
        #self.sk_ip.setsockopt(SOL_PACKET, SO_RCVBUF, 2**24)
        #
        # ARP resolution table
        self.ARP_RESOLV_TABLE = {
            self.ROUTER_IP_ADDR : self.ROUTER_MAC_BUF,
            self.GGSN_IP_ADDR   : self.GGSN_MAC_BUF,
            }
        for ip in self.IP_POOL:
            self.ARP_RESOLV_TABLE[ip] = self.GGSN_MAC_BUF
        #
        # interrupt handler
        if self.CATCH_SIGINT:
            def sigint_handler(signum, frame):
                if self.DEBUG > 1:
                    self._log('INF', 'CTRL+C caught')
                self.stop()
            signal.signal(signal.SIGINT, sigint_handler)
        #
        self.set_opportunist(opportunist)
        # starting main listening loop in background
        self._listening  = True
        self._listener_t = threadit(self.listen)
        self._log('INF', 'ARP resolver started')
        #
        # .resolve(ip) method is available for ARP resolution by GTPUd
    
    def _log(self, logtype='DBG', msg=''):
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        if logtype in self.DEBUG:
            log('[%s] [ARPd] %s' % (logtype, msg))
    
    def set_opportunist(self, state):
        if state:
            self.sk_list = (self.sk_arp, self.sk_ip)
        else:
            self.sk_list = (self.sk_arp, )
    
    def stop(self):
        if self._listening:
            self._listening = False
            sleep(self.SELECT_TO * 2)
            try:
                self.sk_arp.close()
                self.sk_ip.close()
            except Exception as err:
                self._log('ERR', 'socket error: {0}'.format(err))
    
    def listen(self):
        # select() until we receive arp or ip packet
        while self._listening:
            r = []
            r = select(self.sk_list, [], [], self.SELECT_TO)[0]
            for sk in r:
                try:
                    buf = sk.recvfrom(self.BUFLEN)[0]
                except Exception as err:
                    self._log('ERR', 'external network error (recvfrom): %s' % err)
                    buf = b''
                # dipatch ARP request / IP response
                if sk != self.sk_arp:
                    # sk == self.sk_ip
                    if len(buf) >= 34 and buf[12:14] == b'\x08\x00':
                        self._process_ipbuf(buf)
                else:
                    # sk == self.sk_arp
                    if len(buf) >= 42 and buf[12:14] == b'\x08\x06':
                        self._process_arpbuf(buf)
            #
            # if select() timeouts, take a little rest
            if len(r) == 0:
                sleep(self.SELECT_SLEEP)
        self._log('INF', 'ARP resolver stopped')
    
    def _process_arpbuf(self, buf):
        # this is an ARP request or response:
        arpop = ord(buf[21:22])
        # 1) check if it requests for one of our IP
        if arpop == 1:
            ipreq = inet_ntoa(buf[38:42])
            if ipreq in self.IP_POOL:
                # reply to it with our MAC ADDR
                try:
                    self.sk_arp.sendto(
                        b''.join((buf[6:12], self.GGSN_MAC_BUF,  # Ethernet hdr
                                  b'\x08\x06\0\x01\x08\0\x06\x04\0\x02',
                                  self.GGSN_MAC_BUF, buf[38:42], # ARP sender
                                  buf[6:12], buf[28:32],         # ARP target
                                  b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0')),    
                        (self.GGSN_ETH_IF, 0x0806))
                except Exception as err:
                    self._log('ERR', 'external network error (sendto) on ARP response: %s' % err)
                else:
                    self._log('DBG', 'ARP response sent for IP: %s' % ipreq)
        # 2) check if it responses something useful for us
        elif arpop == 2:
            ipres_buf = buf[28:32]
            if unpack('>I', ipres_buf)[0] & self.SUBNET_MASK == self.SUBNET_PREFIX:
                ipres = inet_ntoa(ipres_buf)
                if ipres not in self.ARP_RESOLV_TABLE:
                    # WNG: no protection (at all) against ARP cache poisoning
                    self.ARP_RESOLV_TABLE[ipres] = buf[22:28]
                    self._log('DBG', 'got ARP response for new local IP: %s' % ipres)
    
    def _process_ipbuf(self, buf):
        # this is an random IPv4 packet incoming into our interface: 
        # check if src IP is in our subnet and not already resolved,
        # then store the Ethernet MAC address
        # this is an opportunistic behaviour and disabled by default
        ipsrc_buf = buf[26:30]
        if unpack('>I', ipsrc_buf)[0] & self.SUBNET_MASK == self.SUBNET_PREFIX:
            ipsrc = inet_ntoa(ipsrc_buf)
            if ipsrc not in self.ARP_RESOLV_TABLE:
                # WNG: no protection (at all) against ARP cache poisoning
                self.ARP_RESOLV_TABLE[ipsrc] = buf[6:12]
                self._log('DBG', 'got MAC address from IPv4 packet for new local IP: %s' % ipsrc)
    
    def resolve(self, ip):
        # check if already resolved
        if ip in self.ARP_RESOLV_TABLE:
            return self.ARP_RESOLV_TABLE[ip]
        # or outside our local network
        ip_buf = inet_aton(ip)
        if unpack('>i', ip_buf)[0] & self.SUBNET_MASK != self.SUBNET_PREFIX:
            return self.ROUTER_MAC_BUF
        # requesting an IP within our local LAN
        # starting a resolution for it
        else:
            try:
                self.sk_arp.sendto(
                    b''.join((self.ROUTER_MAC_BUF, self.GGSN_MAC_BUF, # Ethernet hdr
                              b'\x08\x06\0\x01\x08\0\x06\x04\0\x01',
                              self.GGSN_MAC_BUF, self.GGSN_IP_BUF,    # ARP sender
                              b'\0\0\0\0\0\0', inet_aton(ip),         # ARP target
                              b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0')),
                    (self.GGSN_ETH_IF, 0x0806))
            except Exception as err:
                self._log('ERR', 'external network error (sendto) on ARP request: %s' % err)
            else:
                self._log('DBG', 'ARP request sent for local IP: %s' % ip)
            # wait for the answer
            cnt = 0
            while ip not in self.ARP_RESOLV_TABLE:
                sleep(self.SELECT_SLEEP)
                cnt += 1
                if cnt >= 3:
                    break
            if cnt < 3:
                return self.ARP_RESOLV_TABLE[ip]
            else:
                return 6*b'\xFF' # LAN broadcast, maybe a bit strong !


#------------------------------------------------------------------------------#
# GTPUd                                                                        #
#------------------------------------------------------------------------------#

BLACKHOLE_LAN   = 0b01
BLACKHOLE_WAN   = 0b10
IPV6_LOCAL_PREF = b'\xfe\x80\0\0\0\0\0\0'

class GTPUd(object):
    '''
    GTP-U forwarder
    bridges Ethernet to GTP-U to handle IPv4v6 data traffic of connected UE.
    
    This is to be instantiated as a unique handler for all GTP-U tunnels
    in the corenet mobile core network.
    To add GTP tunnel endpoints at will, for each mobile, use the methods:
    .add_mobile(teid_ul, mobile_addr, ran_ip, teid_dl)
      - teid_ul will be the key used to index the connection
      - mobile_addr is a 2-tuple (addr_type, ip_addr)
        addr_type: 1 for IPv4, 2 for IPv6, 3 for IPv4v6
        in case of IPv6 address, it is possible to set only the 64 1st bits 
        (the network prefix), the full address will be learnt from the 1st uplink
        packet
      - ran_ip is a list with the local IP address and RAN IP address for connecting
        the GTP-U UDP socket endpoints
      -> ran_ip and teid_dl can be None, and set afterwards by calling:
    .set_mobile_dl(teid_ul, ran_ip, teid_dl)
      -> this enables the forwarding of downlink traffic
    To delete GTP tunnel endpoints, use the method: 
    .rem_mobile(teid_ul) 

    When a GTP-U packet arrives on the internal interface,
    the IP payload is transferred to the external Gi interface over an Ethernet header.
    When an Ethernet packet arrives on the external Gi interface,
    the IP payload is transferred to the internal interface over a GTP-U header.

    A little traffic statistics feature can be used with the class attribute:
    .DPI = True
    Traffic statistics are then placed into the attribute .stats
    It is populated even if GTP-U trafic is not forwarded (see BLACKHOLING)

    A blackholing feature is integrated to disable the forwarding of GTP-U packet
    to the local LAN (with BLACKHOLE_LAN) and/or the routed WAN (with BLACKHOLE_WAN).
    This is done by setting the .BLACKHOLING class attribute.

    A whitelist feature (TCP/UDP, port) is also integrated.
    To activate if, set the class attribute:
    WL_ACTIVE = True
    Then, only packets for the given protocols / ports are transferred to the Gi,
    by looking into the class attribute:
    WL_PORTS = [('UDP', 53), ('UDP', 123), ('TCP', 80), ...]
    This is bypassing the blackholing feature.
    '''
    #
    # verbosity level: list of log types to display when calling 
    # self._log(logtype, msg)
    DEBUG         = ('ERR', 'WNG', 'INF', 'DBG')
    #
    # packet buffer space (over MTU...)
    BUFLEN        = 2048
    # select loop settings
    SELECT_TO     = 0.1
    #
    # Gi interface, with GGSN ethernet IF, MAC address and IPv6 /64 network prefix
    EXT_IF        = ARPd.GGSN_ETH_IF
    EXT_MAC_ADDR  = ARPd.GGSN_MAC_ADDR
    EXT_IPV6_PREF = '2001:123:456:abcd'
    #
    # list of internal IP interfaces, for handling GTP-U packets from RNCs / eNBs
    GTP_PORT      = 2152
    GTP_IF        = ('10.1.1.1', '10.2.1.1', )
    #
    # BLACKHOLING feature
    # to enable the whole traffic: 0
    # to disable traffic routed to the WAN: BLACKHOLE_WAN
    # to disable traffic to the local LAN: BLACKHOLE_LAN
    # to disable the whole forwarding of GTP-U packets: BLACKHOLE_LAN | BLACKHOLE_WAN
    BLACKHOLING   = 0
    # traffic that we want to allow, even if BLACKHOLING is activated
    WL_ACTIVE     = False
    WL_PORTS      = [('UDP', 53), ('UDP', 123)]
    #
    # in case we want to generate traffic statistics (then available in .stats)
    DPI           = True
    #
    # in case we want to check and drop spoofed IPv4/v6 source address 
    # in incoming GTP-U packet
    DROP_SPOOF    = True
    #
    # in case we want to stop the listener when typing CTRL+C
    CATCH_SIGINT = False
    
    def __init__(self):
        #
        self.EXT_MAC_BUF   = mac_aton(self.EXT_MAC_ADDR)
        self.IPV6_NET_PREF = inet_pton(AF_INET6, self.EXT_IPV6_PREF + '::')[:8]
        #
        # 2 dict for handling mobile GTP-U packets transfers:
        # key: mobile IPv4 address or v6 if suffix address (4 or 8 bytes)
        # value: teid_ul (uint)
        self._mobiles_addr = {}
        # key: teid_ul (uint)
        # value: [ran_info (3-tuple: local IP, remote IP, sk_int ref), 
        #         teid_dl (uint), 
        #         ipv4_addr (4-bytes or None),
        #         ipv6_addr (8-bytes -if addr suffix- or None),
        #         ctx_num (uint)]
        self._mobiles_teid = {}
        #
        # initialize the traffic statistics
        self.stats         = {}
        self._prot_dict    = {1:'ICMP', 6:'TCP', 17:'UDP'}
        # initialize the list of modules that can act on GTP-U payloads
        self.MOD           = []
        #
        # create two RAW PF_PACKET sockets on the `Internet` side (1 for IPv4, 1 for IPv6)
        self.sk_ext_v4     = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.sk_ext_v4.settimeout(0.001)
        #self.sk_ext_v4.setblocking(0)
        self.sk_ext_v4.bind((self.EXT_IF, 0x0800))
        set_promisc(self.sk_ext_v4, self.EXT_IF, 1)
        #
        self.sk_ext_v6     = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ntohs(0x86dd))
        self.sk_ext_v6.settimeout(0.001)
        #self.sk_ext_v6.setblocking(0)
        self.sk_ext_v6.bind((self.EXT_IF, 0x86dd))
        set_promisc(self.sk_ext_v6, self.EXT_IF, 1)
        #
        # create an UDP socket on the RNC / eNB side
        sk_int, sk_int_ind, ind = [], {}, 0
        for gtpip in self.GTP_IF:
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sk.settimeout(0.001)
            #sk.setblocking(0)
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sk.bind((gtpip, self.GTP_PORT))
            sk_int.append(sk)
            sk_int_ind[gtpip] = ind
            ind += 1
        self.sk_int = tuple(sk_int)
        self._sk_int_ind = sk_int_ind
        #
        # interrupt handler
        if self.CATCH_SIGINT:
            def sigint_handler(signum, frame):
                if self.DEBUG > 1:
                    self._log('INF', 'CTRL+C caught')
                self.stop()
            signal.signal(signal.SIGINT, sigint_handler)
        #
        # and start listening and transferring packets in background
        self.sk_list = (self.sk_ext_v4, self.sk_ext_v6) + self.sk_int
        self._listening = True
        self._listener_t = threadit(self.listen)
        self._log('INF', 'GTP-U tunnels handler started')
        #
        # and finally start ARP resolver
        self.arpd = ARPd()
    
    def _log(self, logtype='DBG', msg=''):
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        if logtype in self.DEBUG:
            log('[%s] [GTPUd] %s' % (logtype, msg))
    
    def init_stats(self, ip):
        stats = {
            'DNS'     : set(), # IP of DNS servers requested
            'NTP'     : set(), # IP of NTP servers requested
            'resolved': set(), # domain name resolved
            'ICMP'    : set(), # ICMP endpoint (IP) contacted
            'TCP'     : set(), # TCP endpoint (IP, port) contacted
            'UDP'     : set(), # UDP endpoint (IP, port) contacted
            'alien'   : set(), # other protocol packets
            }
        self.stats[ip] = stats
        return stats
    
    def stop(self):
        # stop ARP resolver
        self.arpd.stop()
        # stop local GTPU handler
        if self._listening:
            self._listening = False
            sleep(self.SELECT_TO * 2)
            try:
                set_promisc(self.sk_ext_v4, self.EXT_IF, 0)
                set_promisc(self.sk_ext_v6, self.EXT_IF, 0)
                # closing sockets
                self.sk_ext_v4.close()
                self.sk_ext_v6.close()
                for sk in self.sk_int:
                    sk.close()
            except Exception as err:
                self._log('ERR', 'socket error: %s' % err)
    
    def listen(self):
        # select() until we receive something on 1 side
        while self._listening:
            r = select(self.sk_list, [], [], self.SELECT_TO)[0]
            # read ext and int sockets until they are empty
            for sk in r:
                #
                if sk == self.sk_ext_v4:
                    # DL IPv4
                    try:
                        buf = sk.recvfrom(self.BUFLEN)[0]
                    #except timeout:
                    #    pass
                    except Exception as err:
                        self._log('ERR', 'sk_ext_v4 IF error (recvfrom): %s' % err)
                    else:
                        #self._log('DBG', 'sk_ext_v4, recvfrom()')
                        if len(buf) >= 34 and buf[:6] == self.EXT_MAC_BUF \
                        and buf[30:34] in self._mobiles_addr:
                            # IPv4 of a mobile, transfer over GTP-U
                            # after removing the Ethernet header
                            self.transfer_v4_to_int(buf[14:])
                            #threadit(self.transfer_v4_to_int, buf[14:])
                #
                elif sk == self.sk_ext_v6:
                    # DL IPv6
                    try:
                        buf = sk.recvfrom(self.BUFLEN)[0]
                    #except timeout:
                    #    pass
                    except Exception as err:
                        self._log('ERR', 'sk_ext_v6 IF error (recvfrom): %s' % err)
                    else:
                        #self._log('DBG', 'sk_ext_v6, recvfrom()')
                        if len(buf) >= 54 and buf[:6] == self.EXT_MAC_BUF \
                        and buf[46:54] in self._mobiles_addr:
                            # IPv6 of a mobile, transfer over GTP-U
                            # after removing the Ethernet header
                            self.transfer_v6_to_int(buf[14:])
                            #threadit(self.transfer_v6_to_int, buf[14:])
                #
                else:
                    #sk in self.sk_int
                    # UL, both IPv4 and IPv6 packets
                    try:
                        buf = sk.recv(self.BUFLEN)
                    #except timeout:
                    #    pass
                    except Exception as err:
                        self._log('ERR', 'sk_int IF error (recv): %s' % err)
                    else:
                        self.transfer_to_ext(buf)
                        #threadit(self.transfer_to_ext, buf)
        #
        self._log('INF', 'GTPU handler stopped')
    
    def resolve_mac(self, ipdst):
        if len(ipdst) == 4:
            return self.arpd.resolve(inet_ntoa(ipdst))
        else:
            # TODO: implement a minimal IPv6 NDP service ?
            return self.arpd.ROUTER_MAC_BUF
    
    #--------------------------------------------------------------------------#
    # UL transfer
    #--------------------------------------------------------------------------#
    
    def transfer_to_ext(self, buf):
        try:
            # extract the GTP header
            flags, msgtype, msglen, teid_ul = unpack('>BBHI', buf[:8])
            ran_info, teid_dl, ipv4buf, ipv6buf, ctx_num = self._mobiles_teid[teid_ul]
            if msgtype != 0xff:
                # TODO: handle GTP ECHO
                self._log('WNG', 'unsupported GTP type from RAN: 0x%.2x' % msgtype)
                return
            # get the IP packet: use the length in the GTP header to cut the buffer
            if flags & 0b111:
                # GTP header extended
                msglen -= 4
            ipbuf = buf[-msglen:]
            # get the IP version
            ipvers = ord(ipbuf[0:1])>>4
            if ipvers == 4:
                ipsrc = ipbuf[12:16]
                ipdst = ipbuf[16:20]
            elif ipvers == 6:
                ipsrc = ipbuf[8:24]
                ipdst = ipbuf[24:40]
            else:
                self._log('WNG', 'invalid IP packet from UE, dropping it')
                return
        except Exception:
            self._log('WNG', 'invalid GTP / IP packet from RAN / UE, dropping it')
            return
        #
        if ipvers == 4:
            if self.DROP_SPOOF and ipsrc != ipv4buf:
                self._log('WNG', 'spoofed IPv4 src addr, teid_ul 0x%.8x' % teid_ul)
                return
            if self.DPI:
                self._analyze(ipvers, inet_ntoa(ipsrc), ipbuf)
            if self.MOD:
                try:
                    for mod in self.MOD:
                        if mod.TYPE == 0:
                            ipbuf = mod.handle_ul(ipbuf)
                        else:
                            mod.handle_ul(ipbuf)
                except Exception as err:
                    self._log('ERR', 'MOD error: %s' % err)
            # resolve the dest MAC addr
            macdst = self.resolve_mac(ipdst)
            # apply blackholing
            if self.BLACKHOLING:
                if macdst != self.arpd.ROUTER_MAC_BUF:
                    if self.BLACKHOLING & BLACKHOLE_LAN:
                        drop = True
                    else:
                        drop = False
                else:
                    if self.BLACKHOLING & BLACKHOLE_WAN:
                        drop = True
                    else:
                        drop = False
                if drop and self.WL_ACTIVE:
                    ipdst, prot, pay = DPIv4.get_ip_info(ipbuf)
                    if prot in (6, 17) and pay:
                        # UDP / TCP
                        port = DPIv4.get_port(pay)
                        if (self._prot_dict[prot], port) in self.WL_PORTS:
                            self._transfer_v4_to_ext(macdst, ipbuf)
                        else:
                            return
            else:
                self._transfer_v4_to_ext(macdst, ipbuf)
        #
        else:
            #ipvers == 6
            if self.DROP_SPOOF and ipsrc[8:] != ipv6buf:
                self._log('WNG', 'spoofed IPv6 src addr, teid_ul 0x%.8x' % teid_ul)
                return
            if self.DPI:
                self._analyze(ipvers, inet_ntop(AF_INET6, ipsrc), ipbuf)
            if self.MOD:
                try:
                    for mod in self.MOD:
                        if mod.TYPE == 0:
                            ipbuf = mod.handle_ul(ipbuf)
                        else:
                            mod.handle_ul(ipbuf)
                except Exception as err:
                    self._log('ERR', 'MOD error: %s' % err)
            # resolve the dest MAC addr
            macdst = self.resolve_mac(ipdst)
            # apply blackholing
            if self.BLACKHOLING:
                if macdst != self.arpd.ROUTER_MAC_BUF:
                    if self.BLACKHOLING & BLACKHOLE_LAN:
                        drop = True
                    else:
                        drop = False
                else:
                    if self.BLACKHOLING & BLACKHOLE_WAN:
                        drop = True
                    else:
                        drop = False
                if drop and self.WL_ACTIVE:
                    ipdst, prot, pay = DPIv6.get_ip_info(ipbuf)
                    if prot in (6, 17) and pay:
                        # UDP / TCP
                        port = DPIv6.get_port(pay)
                        if (self._prot_dict[prot], port) in self.WL_PORTS:
                            self._transfer_v6_to_ext(macdst, ipbuf)
                        else:
                            return
            else:
                self._transfer_v6_to_ext_v6(macdst, ipbuf)
    
    def _transfer_v4_to_ext(self, macdst, ipbuf):
        # forward to the external PF_PACKET socket, over the Gi interface
        try:
            self.sk_ext_v4.sendto(b''.join((macdst, self.EXT_MAC_BUF, b'\x08\0', ipbuf)),
                                  (self.EXT_IF, 0x0800))
        except Exception as err:
            self._log('ERR', 'sk_ext_v4 IF error (sendto): %s' % err)
    
    def _transfer_v6_to_ext(self, macdst, ipbuf):
        # forward to the external PF_PACKET socket, over the Gi interface
        try:
            self.sk_ext_v6.sendto(b''.join((macdst, self.EXT_MAC_BUF, b'\x86\xdd', ipbuf)),
                                  (self.EXT_IF, 0x86dd))
        except Exception as err:
            self._log('ERR', 'sk_ext_v6 IF error (sendto): %s' % err)
    
    def _analyze(self, ipvers, ipsrc, ipbuf):
        #
        try:
            stats = self.stats[ipsrc]
        except Exception:
            stats = self.init_stats(ipsrc)
        #
        if ipvers == 4:
            dst, prot, pay = DPIv4.get_ip_info(ipbuf)
            DPI = DPIv4
        else:
            dst, prot, pay = DPIv6.get_ip_info(ipbuf)
            DPI = DPIv6
        #
        # UDP
        if prot == 17 and pay:
            port = DPI.get_port(pay)
            stats['UDP'].add((dst, port))
            # DNS
            if port == 53:
                stats['DNS'].add(dst)
                name = DPI.get_dn_req(pay[8:])
                stats['resolved'].add(name)
            elif port == 123:
                stats['NTP'].add(dst)
        # TCP
        elif prot == 6 and pay:
            port = DPI.get_port(pay)
            stats['TCP'].add((dst, port))
        # ICMP / ICMPv6
        elif prot in (1, 58) and pay:
            stats['ICMP'].add(dst)
        # alien
        else:
            stats['alien'].add(hexlify(ipbuf))
    
    #--------------------------------------------------------------------------#
    # DL transfer
    #--------------------------------------------------------------------------#
    
    def transfer_v4_to_int(self, buf):
        #self._log('DBG', 'transfer_v4_to_int()')
        # buf length is guaranteed >= 20 and ipdst in self._mobiles_addr
        #
        if self.MOD:
            # possibly process the DL GTP-U payload within modules
            try:
                for mod in self.MOD:
                    if mod.TYPE == 0:
                        buf = mod.handle_dl(buf)
                    else:
                        mod.handle_dl(buf)
            except Exception as err:
                self._log('ERR', 'MOD error: %s' % err)        
        #
        teid_ul = self._mobiles_addr[buf[16:20]]
        ran_info, teid_dl = self._mobiles_teid[teid_ul][:2]
        #
        # prepend GTP header and forward to the RAN IP
        if ran_info and teid_dl is not None:
            gtphdr = pack('>BBHI', 0x30, 0xff, len(buf), teid_dl)
            try:
                ret = ran_info[2].sendto(gtphdr + buf, (ran_info[1], self.GTP_PORT))
            except Exception as err:
                self._log('ERR', 'sk_int IF error (sendto): %s' % err)
        else:
            self._log('WNG', 'teid_ul 0x%.8x, downlink GTP parameters not set' % teid_ul)
    
    def transfer_v6_to_int(self, buf):
        #self._log('DBG', 'transfer_v6_to_int()')
        # buf length is guaranteed >= 40 and ipdst in self._mobiles_addr
        #
        if self.MOD:
            # possibly process the DL GTP-U payload within modules
            try:
                for mod in self.MOD:
                    if mod.TYPE == 0:
                        buf = mod.handle_dl(buf)
                    else:
                        mod.handle_dl(buf)
            except Exception as err:
                self._log('ERR', 'MOD error: %s' % err)        
        #
        teid_ul = self._mobiles_addr[buf[32:40]]
        ran_info, teid_dl = self._mobiles_teid[teid_ul][:2]
        #
        # prepend GTP header and forward to the RAN IP
        if ran_info and teid_dl is not None:
            gtphdr = pack('>BBHI', 0x30, 0xff, len(buf), teid_dl)
            try:
                ret = ran_info[2].sendto(gtphdr + buf, (ran_info[1], self.GTP_PORT))
            except Exception as err:
                self._log('ERR', 'sk_int IF error (sendto): %s' % err)
        else:
            self._log('WNG', 'teid_ul 0x%.8x, downlink GTP parameters not set' % teid_ul)
    
    #--------------------------------------------------------------------------#
    # UE management
    #--------------------------------------------------------------------------#
    
    def add_mobile(self, teid_ul, mobile_addr, ran_ip, teid_dl):
        if teid_ul in self._mobiles_teid:
            # just increment the ctx_num
            self._mobiles_teid[teid_ul][-1] += 1
        #
        else:
            if mobile_addr[0] == 1:
                # IPv4
                ipv4buf = inet_aton_cn(*mobile_addr)
                if len(ipv4buf) != 4:
                    self._log('ERR', 'invalid mobile addr %r' % (mobile_addr, ))
                    return
                ipv6buf = None
            elif mobile_addr[0] == 2:
                # IPv6 if suffix (8 bytes) or full IPv6 (then truncated to 8 bytes)
                ipv6buf = inet_aton_cn(*mobile_addr)
                if len(ipv6buf) == 16:
                    ipv6buf = ipv6buf[8:]
                elif len(ipv6buf) != 8:
                    self._log('ERR', 'invalid mobile addr %r' % (mobile_addr, ))
                    return
                ipv4buf = None
            elif mobile_addr[0] == 3:
                # IPv4v6
                # IPv4
                ipv4buf = inet_aton_cn(1, mobile_addr[1])
                if len(ipv4buf) != 4:
                    self._log('ERR', 'invalid mobile addr %r' % (mobile_addr, ))
                    return
                # IPv6 if suffix (8 bytes) or full IPv6
                ipv6buf = inet_aton_cn(2, mobile_addr[2])
                if len(ipv6buf) == 16:
                    ipv6buf = ipv6buf[8:]
                elif len(ipv6buf) != 8:
                    self._log('ERR', 'invalid mobile addr %r' % (mobile_addr, ))
                    return
            else:
                self._log('ERR', 'invalid mobile addr %r' % (mobile_addr, ))
            #
            if ran_ip and ran_ip[1] is not None:
                try:
                    # add the sk_int within ran_info
                    sk_int   = self.sk_int[self._sk_int_ind[ran_ip[0]]]
                    ran_info = (ran_ip[0], ran_ip[1], sk_int)
                except Exception:
                    self._log('ERR', 'invalid RAN IP, %r' % ran_ip)
                    ran_info = None
            else:
                ran_info = None
            # insert a new context
            self._mobiles_teid[teid_ul] = [ran_info, teid_dl, ipv4buf, ipv6buf, 1]
            if ipv4buf:
                self._mobiles_addr[ipv4buf] = teid_ul
            if ipv6buf:
                self._mobiles_addr[ipv6buf] = teid_ul
        #
        self._log('INF', 'setting GTP-U context for UE with IP %r, teid_ul 0x%.8x'\
                  % (mobile_addr, teid_ul))
    
    def set_mobile_dl(self, teid_ul, ran_ip=None, teid_dl=None):
        # enables to reconfigure the DL parameters (RAN IP, DL TEID)
        try:
            ran_info_ori, teid_dl_ori, ipv4buf, ipv6buf, ctx_num = self._mobiles_teid[teid_ul]
        except Exception as err:
            self._log('ERR', 'invalid teid_ul 0x%.8x' % teid_ul)
            return
        else:
            if ran_ip:
                try:
                    # add the sk_int within ran_info
                    sk_int   = self.sk_int[self._sk_int_ind[ran_ip[0]]]
                    ran_info = (ran_ip[0], ran_ip[1], sk_int)
                except Exception:
                    self._log('ERR', 'invalid RAN IP, %r' % ran_ip)
                    ran_info = None
            else:
                ran_info = None
            if teid_dl is None:
                teid_dl = teid_dl_ori
            self._mobiles_teid[teid_ul] = [ran_info, teid_dl, ipv4buf, ipv6buf, ctx_num]
    
    def rem_mobile(self, teid_ul):
        if teid_ul in self._mobiles_teid:
            mobile_ctx = self._mobiles_teid[teid_ul]
            if mobile_ctx[-1] > 1:
                # decrement the number of GTP contexts
                mobile_ctx[-1] -= 1
            else:
                # delete the mobile context
                del self._mobiles_teid[teid_ul]
                ran_info, teid_dl, ipv4buf, ipv6buf, ctx_num = mobile_ctx
                if ipv4buf:
                    ipv4addr = inet_ntoa(ipv4buf)
                    try:
                        del self._mobiles_addr[ipv4buf]
                    except Exception:
                        pass
                else:
                    ipv4addr = None
                if ipv6buf:
                    ipv6addr = inet_ntop(AF_INET6, self.IPV6_NET_PREF + ipv6buf)
                    try:
                        del self._mobiles_addr[ipv6buf]
                    except Exception:
                        pass
                else:
                    ipv6addr = None
                if ipv4addr and ipv6addr:
                    ipaddr = 'IPv4 %s / IPv6 %s' % (ipv4addr, ipv6addr)
                elif ipv6addr is None:
                    ipaddr = 'IPv4 ' + ipv4addr
                else:
                    ipaddr = 'IPv6 ' + ipv6addr
                self._log('DBG', 'deleting GTP-U context for UE with addr %s, teid_ul 0x%.8x'\
                          % (ipaddr, teid_ul))


class _DPI(object):
    
    @staticmethod
    def get_port(pay):
        """return the port TCP / UDP number
        """
        return unpack('!H', pay[2:4])[0]
        
    @staticmethod
    def __get_dn_req_py2(req):
        """return the DNS name requested
        """
        # remove fixed DNS header and Type / Class
        s = req[12:-4]
        n = []
        while len(s) > 1:
            l = ord(s[0])
            n.append( s[1:1+l] )
            s = s[1+l:]
        return b'.'.join(n)
    
    @staticmethod
    def __get_dn_req_py3(req):
        """return the DNS name requested
        """
        # remove fixed DNS header and Type / Class
        s = req[12:-4]
        n = []
        while len(s) > 1:
            l = s[0]
            n.append( s[1:1+l] )
            s = s[1+l:]
        return b'.'.join(n)
    
    if python_version < 3:
        get_dn_req = __get_dn_req_py2
    else:
        get_dn_req = __get_dn_req_py3


class DPIv4(_DPI):
    
    @staticmethod
    def __get_ip_info_py2(ipbuf):
        """return a 3-tuple: ipdst (asc), protocol (uint), payload (bytes)
        """
        # returns a 3-tuple: dst IP, protocol, payload buffer
        # get IP header length
        l = (ord(ipbuf[0]) & 0x0F) * 4
        # get dst IP
        dst = inet_ntoa(ipbuf[16:20])
        # get protocol
        prot = ord(ipbuf[9])
        #
        return (dst, prot, ipbuf[l:])
    
    @staticmethod
    def __get_ip_info_py3(ipbuf):
        """return a 3-tuple: ipdst (asc), protocol (uint), payload (bytes)
        """
        # returns a 3-tuple: dst IP, protocol, payload buffer
        # get IP header length
        l = (ipbuf[0] & 0x0F) * 4
        # get dst IP
        dst = inet_ntoa(ipbuf[16:20])
        # get protocol
        prot = ipbuf[9]
        #
        return (dst, prot, ipbuf[l:])
    
    if python_version < 3:
        get_ip_info = __get_ip_info_py2
    else:
        get_ip_info = __get_ip_info_py3


class DPIv6(_DPI):
    
    @staticmethod
    def __get_ip_info_py2(ipbuf):
        """return a 3-tuple: ipdst (asc), protocol (uint), payload (bytes)
        """
        # returns a 3-tuple: dst IP, protocol, payload buffer
        # get payload length
        pl = unpack('>H', ipbuf[4:6])[0]
        # get dst IP
        dst = inet_ntop(AF_INET6, ipbuf[24:40])
        # get protocol
        # TODO: unstack IPv6 opts
        prot = ord(ipbuf[6])
        #
        return (dst, prot, ipbuf[-pl:])
    
    @staticmethod
    def __get_ip_info_py3(ipbuf):
        """return a 3-tuple: ipdst (asc), protocol (uint), payload (bytes)
        """
        # returns a 3-tuple: dst IP, protocol, payload buffer
        # get payload length
        pl = unpack('>H', ipbuf[4:6])[0]
        # get dst IP
        dst = inet_ntop(AF_INET6, ipbuf[24:40])
        # get protocol
        # TODO: unstack IPv6 opts
        prot = ipbuf[6]
        #
        return (dst, prot, ipbuf[-pl:])
    
    if python_version < 3:
        get_ip_info = __get_ip_info_py2
    else:
        get_ip_info = __get_ip_info_py3


class MOD(object):
    # This is a skeleton for GTP-U payloads specific handler.
    # After It gets loaded by the GTPUd instance,
    # it acts on each GTP-U payloads (UL and DL)
    
    # In can work actively on GTP-U packets (possibly changing them) 
    # with TYPE = 0
    # or passively (not able to change them), only processing a copy of them,
    # with TYPE = 1
    TYPE = 0
    
    # reference to the GTPUd instance
    GTPUd = None
    
    @classmethod
    def _log(self, logtype, msg):
        self.GTPUd._log(logtype, '[MOD.%s] %s' % (self.__class__.__name__, msg))
    
    @classmethod
    def handle_ul(self, ippuf):
        pass
    
    @classmethod
    def handle_dl(self, ipbuf):
        pass


class DNSRESP(MOD):
    '''
    This module answers to any DNS request incoming from UE (UL direction) 
    with a single or random IP address, over IPv4
    
    To be used with GTPUd.BLACKHOLING capability to avoid UE getting real
    DNS responses from servers in parallel
    '''
    TYPE = 1
    
    # compute UDP checksum in DNS response
    UDP_CS = True
    # in case we want to answer random addresses
    RAND = False
    # the IPv4 address to answer all requests
    IP_RESP = '192.168.1.50'
    
    DEBUG = False
    
    @classmethod
    def handle_ul(self, ipbuf):
        # check if we have an UDP/53 request
        ip_vers, ip_proto, (udpsrc, udpdst) = \
            ord(ipbuf[0:1])>>4, ord(ipbuf[9:10]), unpack('!HH', ipbuf[20:24])
        if ip_vers != 4 or ip_proto != 53 or udp_dst != 53:
            # not IPv4, not UDP or not on DNS port 53
            return
        
        # build the UDP / DNS response: invert src / dst UDP ports
        if self.UDP_CS:
            udp = UDP(val={'src':udpdst, 'dst':udpsrc}, hier=1)
        else:
            udp = UDP(val={'src':udpdst, 'dst':udpsrc, 'cs':0}, hier=1)
        # DNS request: transaction id, flags, questions, queries
        dnsreq = ipbuf[28:]
        transac_id, questions, queries = dnsreq[0:2], \
                                         unpack('!H', dnsreq[4:6])[0], \
                                         dnsreq[12:]
        if questions > 1:
            # not supported
            self._log('WNG', '%i questions, unsupported' % questions)
        # DNS response: transaction id, flags, questions, answer RRs, 
        # author RRs, add RRs, queries, answers, autor nameservers, add records
        if self.RAND:
            ip_resp = _urandom(4)
        else:
            ip_resp = inet_aton(self.IP_RESP)
        dnsresp = b''.join((transac_id, b'\x81\x80\0\x01\0\x01\0\0\0\0', queries,
                            b'\xc0\x0c\0\x01\0\x01\0\0\0\x20\0\x04', ip_resp))
        
        # build the IPv4 header: invert src / dst addr
        ipsrc, ipdst = inet_ntoa(ipbuf[12:16]), inet_ntoa(ipbuf[16:20])
        iphdr = IPv4(val={'src':ipdst, 'dst':ipsrc}, hier=0)
        #
        pkt = Envelope('p', GEN=(iphdr, udp, Buf('dns', val=dnsresp, hier=2)))
        # send back the DNS response
        self.GTPUd.transfer_v4_to_int(pkt.to_bytes())
        if self.DEBUG:
            self.GTPUd._log('DBG', '[DNSRESP] DNS response sent')


class TCPSYNACK(MOD):
    '''
    This module answers to TCP SYN request incoming from UE (UL direction) 
    over IPv4 with a TCP SYN-ACK, enabling to get the 1st TCP data packet 
    from the UE
    
    To be used with GTPUd.BLACKHOLING capability to avoid UE getting SYN-ACK 
    from real servers in parallel
    '''
    TYPE = 1
    
    DEBUG = False
    
    @classmethod
    def handle_ul(self, ipbuf):
        # check if we have a TCP SYN
        ip_vers, ip_proto, ip_pay = ord(ipbuf[0:1])>>4, ord(ipbuf[9:10]), ipbuf[20:]
        if ip_vers != 4 or ip_proto != 6 or ip_pay[13:14] != b'\x02':
            # not IPv4, not TCP, not SYN
            return
        
        # build the TCP SYN-ACK: invert src / dst ports, seq num (random),
        # ack num (SYN seq num + 1)
        tcpsrc, tcpdst, seq = unpack('!HHI', ip_pay[:8])
        tcp_synack = TCP(val={'seq': randint(1, 4294967295),
                              'ack': (1+seq)%4294967296,
                              'src': tcpdst, 'dst': tcpsrc, 
                              'SYN': 1, 'ACK': 1, 'win': 0x1000}, hier=1)
        
        # build the IPv4 header: invert src / dst addr
        ipsrc, ipdst = inet_ntoa(ipbuf[12:16]), inet_ntoa(ipbuf[16:20])
        iphdr = IPv4(val={'src':ipdst, 'dst':ipsrc}, hier=0)
        #
        pkt = Envelope('p', GEN=(iphdr, tcp_synack))
        # send back the TCP SYN-ACK
        self.GTPUd.transfer_v4_to_int(pkt.to_bytes())
        if self.DEBUG:
            self.GTPUd._log('DBG', '[TCPSYNACK] TCP SYN ACK response sent')

