# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich
# * Version : 0.3.0
# *
# * Copyright © 2013. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_corenet/ServerGTPU.py
# * Created : 2013-11-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

'''
HOWTO:

1) in order to use this GTP tunnels handler, the following parameters need to be configured:

-> some internal parameters
ARPd.GGSN_ETH_IF    = 'eth0', ethernet interface toward external networks (e.g. Internet)
APRd.GGSN_MAC_ADDR  = '08:00:00:01:02:03', MAC address of the ethernet interface toward external networks
APRd.GGSN_IP_ADDR   = '192.168.1.100', IP address set to the ethernet interface toward external networks
GTPUd.EXT_IF        = 'eth0', same as ARPd.GGSN_ETH_IF
GTPUd.GGSN_MAC_ADDR = '08:00:00:01:02:03', same as ARPd.GGSN_MAC_ADDR

-> some external network parameters (toward e.g. Internet)
APRd.SUBNET_PREFIX  = '192.168.1.0/24', subnet prefix of the LAN connecting to external networks
APRd.ROUTER_MAC_ADDR = 'f4:00:00:01:02:03', the LAN router (1st IP hop) MAC address
APRd.ROUTER_IP_ADDR = '192.168.1.1', the LAN router (1st IP hop) IP address

-> some internal network parameters (toward RNC / eNodeB)
GTPUd.INT_IP        = '10.1.1.1', IP address exposed on the RAN side
GTPUd.INT_PORT      = 2152, GTPU UDP port to be used by RAN equipments

-> some mobiles parameters
APRd.IP_POOL        = {'192.168.1.201', '192.168.1.202'}, the pool of IP addresses to be used by our set of mobiles
GTPUd.BLACKHOLING   = 0, BLACKHOLE_LAN, BLACKHOLE_WAN or BLACKHOLE_LAN|BLACKHOLE_WAN, 
                      to filter out all the mobile trafic, no trafic at all, or IP packets to external network only
GTPUd.WL_ACTIVE     = True or False, to allow specific IP packets to be forwarded to the external network, 
                      bypassing the BLACKHOLING directive
GTPUd.WL_PORTS      = [('UDP', 53), ('UDP', 123)], to specify to list of IP protocol / port to allow in case WL_ACTIVE is True
GTPUd.DPI           = True or False, to store packet statistics (protocol / port / DNS requests, see the class DPI) in GTPUd.stats 

2) To use the GTPUd, you need to be root or have the capability to start raw sockets:

-> launch the demon, and add_mobile() / rem_mobile() to add or remove GTPU tunnel endpoint.
>>> gsn = GTPUd()

-> to start forwarding IP packets between the external interface and the GTP tunnel
if you want to let the GTPUd manage the attribution of TEID_to_rnc (GTPUd.GTP_TEID_EXT = False)
>>> teid_to_ran = gsn.add_mobile(mobile_ip='192.168.1.201', ran_ip='10.1.1.2', teid_from_ran=0x1)
if you want to manage teid_to_rnc by yourself and just provide its value to GTPUd (GTPUd.GTP_TEID_EXT = True)
>>> gsn.add_mobile(self, mobile_ip='192.168.1.201', ran_ip='10.1.1.2', teid_from_rnc=0x1, teid_to_rnc=0x2)

-> to stop forwading IP packets
>>> gsn.rem_mobile(mobile_ip='192.168.1.201')

-> modules that act on GTPU packets can be added to the GTPUd instance, they must be put in the MOD attribute
Two example modules DNSRESP and TCPSYNACK are provided.
>>> gsn.MOD.append( TCPSYNACK )

3) That's all !
'''

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

from .utils           import *
from pycrate_core.elt import Envelope
from pycrate_ether.IP import *

#------------------------------------------------------------------------------#
# GTP-U handler works with Linux PF_PACKET RAW socket on the Internet side
# and with standard GTP-U 3GPP protocol on the RNC / eNB side
# RNC / eNB <=== IP/UDP/GTPU/IP_mobile ===> GTPU_handler
#                GTPU_handler <=== RawEthernet/IP_mobile ===> Internet
#
# This way, the complete IP interface of a mobile is exposed through 
# this Gi interface.
# It requires the GTPmgr to resolve ARP request on behalf of mobiles 
# that it handles: this is the role of ARPd
#------------------------------------------------------------------------------#

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
    resolves Ethernet / IP address correspondence on behalf of UE connected over 
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
    DEBUG  = ('ERR', 'WNG', 'INF', 'DBG')
    #
    # recv() buffer length
    BUFLEN = 2048
    # select() timeout and wait period
    SELECT_TO    = 0.1
    SELECT_SLEEP = 0.05
    #
    # all Gi interface parameters
    # Our GGSN ethernet parameters (IF, MAC and IP addresses)
    # (and also the MAC address to be used for any mobiles through our GGSN)
    GGSN_ETH_IF   = 'eth0'
    GGSN_MAC_ADDR = '08:00:00:01:02:03'
    GGSN_IP_ADDR  = '192.168.1.100'
    #
    # the set of IP address to be used by our mobiles
    IP_POOL = {'192.168.1.201', '192.168.1.202', '192.168.1.203'}
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
    
    def _process_arpbuf(self, buf=bytes()):
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
                               b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'))     
                     (self.GGSN_ETH_IF, 0x0806))
                except Exception as err:
                    self._log('ERR', 'external network error (sendto) on ARP '\
                              'response: %s' % err)
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
    
    def _process_ipbuf(self, buf=b''):
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
    
    def resolve(self, ip='192.168.1.2'):
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
                           b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'))
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
                return 6*'b\xFF' # LAN broadcast, maybe a bit strong !


#------------------------------------------------------------------------------#
# GTPUd                                                                        #
#------------------------------------------------------------------------------#

BLACKHOLE_LAN = 0b01
BLACKHOLE_WAN = 0b10

class GTPUd(object):
    '''
    GTP-U forwarder
    bridges Ethernet to GTP-U to handle IPv4 data traffic of connected UE.
    
    This is to be instanciated as a unique handler for all GTP-U tunnels
    in the corenet mobile core network.
    Then, it is possible to add or remove GTP tunnel endpoints at will, 
    for each mobile with methods:
    .add_mobile(mobile_ip, rnc_ip, teid_from_rnc)
      -> returns teid_to_rnc for the given mobile
    .rem_mobile(mobile_ip)
      -> returns None 

    When a GTP-U packet arrives on the internal interface,
    the IPv4 payload is transferred to the external Gi interface over an Ethernet header.
    When an Ethernet packet arrives on the external Gi interface,
    the IPv4 payload is transferred to the internal interface over a GTP-U header.

    A little traffic statistics feature can be used with the class attribute:
    DPI = True
    Traffic statistics are then placed into the attribute .stats
    It is populated even if GTP-U trafic is not forwarded (see BLACKHOLING)

    A blackholing feature is integrated to disable the forwarding of GTP-U packet
    to the local LAN (with BLACKHOLE_LAN) and/or the routed WAN (with BLACKHOLE_WAN).
    This is done by setting the BLACKHOLING class attribute.

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
    DEBUG     = ('ERR', 'WNG', 'INF', 'DBG')
    #
    # packet buffer space (over MTU...)
    BUFLEN    = 1536
    # select loop settings
    SELECT_TO = 0.2
    #
    # Gi interface, with GGSN ethernet IF and mobile IP address
    EXT_IF        = ARPd.GGSN_ETH_IF
    GGSN_MAC_ADDR = ARPd.GGSN_MAC_ADDR
    # IPv4 protocol only, to be forwarded
    EXT_PROT      = 0x0800
    #
    # internal IP interface, for handling GTP-U packets from RNC / eNB
    INT_IP        = '127.0.1.100'
    INT_PORT      = 2152
    #
    # GTP TEID toward RNC / eNodeBs (for DL traffic)
    GTP_TEID      = 0
    GTP_TEID_MAX  = 2**32 - 1
    # in case the GTP TEID is assigned by an external entity
    GTP_TEID_EXT  = True
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
    # in case we want to check and drop spoofed IPv4 source address in incoming
    # GTP-U packet
    DROP_SPOOF    = True
    #
    CATCH_SIGINT = False
    
    def __init__(self):
        #
        self.GGSN_MAC_BUF  = mac_aton(self.GGSN_MAC_ADDR)
        #
        # 2 dict for handling mobile GTP-U packets transfers:
        # key: mobile IPv4 addr (buf)
        # value: (ran_ip (asc), teid_from_ran (int), teid_to_ran (int))
        self._mobiles_ip   = {}
        # key: teid_from_ran (int)
        # value: mobile IPv4 addr (buf)
        self._mobiles_teid = {}
        # global TEID to RAN value, to be incremented from here
        if not self.GTP_TEID_EXT:
            self.GTP_TEID  = randint(0, 200000)
        #
        # initialize the traffic statistics
        self.stats         = {}
        self._prot_dict    = {1:'ICMP', 6:'TCP', 17:'UDP'}
        # initialize the list of modules that can act on GTP-U payloads
        self.MOD           = []
        #
        # create a RAW PF_PACKET socket on the `Internet` side
        # python is not convinient to configure dest mac addr 
        # when using SOCK_DGRAM (or I missed something...), 
        # so we use SOCK_RAW and build our own ethernet header:
        self.sk_ext        = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ntohs(self.EXT_PROT))
        # configure timeouting and interface binding
        self.sk_ext.settimeout(0.001)
        #self.sk_ext.setblocking(0)
        self.sk_ext.bind((self.EXT_IF, self.EXT_PROT))
        # put the interface in promiscuous mode
        set_promisc(self.sk_ext, self.EXT_IF, 1)
        #
        # create an UDP socket on the RNC / eNB side, on port 2152
        self.sk_int        = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # configure timeout, binding and rebinding on same address
        self.sk_int.settimeout(0.001)
        #self.sk_int.setblocking(0)
        self.sk_int.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sk_int.bind((self.INT_IP, self.INT_PORT))
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
        self.sk_list = (self.sk_ext, self.sk_int)
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
        self.stats[ip] = {
            'DNS': [],      # IP of DNS servers requested
            'NTP': [],      # IP of NTP servers requested
            'resolved': [], # domain name resolved
            'ICMP': [],     # ICMP endpoint (IP) contacted
            'TCP': [],      # TCP endpoint (IP, port) contacted
            'UDP': [],      # UDP endpoint (IP, port) contacted
            'alien': [],    # other protocol endpoint contacted
            }
    
    def stop(self):
        # stop ARP resolver
        self.arpd.stop()
        # stop local GTPU handler
        if self._listening:
            self._listening = False
            sleep(self.SELECT_TO * 2)
            try:
                # unset promiscuous mode
                set_promisc(self.sk_ext, self.EXT_IF, 0)
                # closing sockets
                self.sk_int.close()
                self.sk_ext.close()
            except Exception as err:
                self._log('ERR', 'socket error: %s' % err)
    
    def listen(self):
        # select() until we receive something on 1 side
        while self._listening:
            r = select(self.sk_list, [], [], self.SELECT_TO)[0]
            # read ext and int sockets until they are empty
            for sk in r:
                if sk != self.sk_int:
                    # sk == self.sk_ext
                    try:
                        buf = sk.recvfrom(self.BUFLEN)[0]
                    #except timeout:
                    #    # nothing to read anymore
                    #    buf = b''
                    except Exception as err:
                        self._log('ERR', 'external network IF error (recvfrom): %s' % err)
                        #buf = b''
                    else:
                        if len(buf) >= 34 and \
                        buf[:6] == self.GGSN_MAC_BUF and \
                        buf[12:14] == b'\x08\0' and \
                        buf[16:20] in self._mobiles_ip:
                            # transferring over GTP-U after removing the Ethernet header
                            self.transfer_to_int(buf[14:])
                            #threadit(self.transfer_to_int, buf[14:])
                else:
                    # sk == self.int_sk
                    try:
                        buf = sk.recv(self.BUFLEN)
                    #except timeout:
                    #    # nothing to read anymore
                    #    buf = b''
                    except Exception as err:
                        self._log('ERR', 'internal network IF error (recv): %s' % err)
                        #buf = b''
                    else:
                        self.transfer_to_ext(buf)
                        #threadit(self.transfer_to_ext, buf)
        #
        self._log('INF', 'GTPU handler stopped')
    
    def transfer_to_ext(self, buf):
        # if GTP-U TEID in self._mobiles_teid, just forward...
        # in this direction, there is no reason to filter
        # except to avoid IP spoofing from malicious mobile 
        # (damned ! Would it be possible ?!?)
        #
        # extract the GTP header
        try:
            flags, msgtype, msglen, teid_from_ran = unpack('>BBHI', buf[:8])
        except:
            self._log('WNG', 'invalid GTP packet from RAN')
            return
        #
        # in case GTP TEID is not correct, drop it
        try:
            mobile_ip = self._mobiles_teid[teid_from_ran]
        except:
            self._log('WNG', 'unknown GTP TEID from RAN: 0x%.8x' % teid_from_ran)
            return
        #
        # in case GTP does not contain UP data, drop it
        if msgtype != 0xff:
            self._log('WNG', 'unsupported GTP type from RAN: 0x%.2x' % msgtype)
            return
        #
        # get the IP packet: use the length in GTPv1 header to cut the buffer
        if flags & 0x04:
            # GTP header extended
            msglen -= 4
        ipbuf = buf[-msglen:]
        #
        # drop dummy IP packets
        if len(ipbuf) < 24:
            self._log('WNG', 'dummy packet from mobile dropped: %s' % hexlify(ipbuf).decode('ascii'))
            return
        #
        # drop packet other than IPv4
        ipver = ord(ipbuf[0:1]) >> 4
        if ipver != 4:
            self._log('WNG', 'unsupported IPv%i packet from UE' % ipver)
            return
        #
        # drop spoofed IP packet
        if self.DROP_SPOOF and ipbuf[12:16] != mobile_ip:
            self._log('WNG', 'spoofed IPv4 source address from UE: %s' % inet_ntoa(ipbuf[12:16]))
            return
        #
        ipsrc = inet_ntoa(ipbuf[12:16])
        ipdst = inet_ntoa(ipbuf[16:20])
        #
        # analyze the packet content for statistics
        if self.DPI:
            self._analyze(ipsrc, ipbuf)
        #
        # possibly process the UL GTP-U payload within modules
        if self.MOD:
            try:
                for mod in self.MOD:
                    if mod.TYPE == 0:
                        ipbuf = mod.handle_ul(ipbuf)
                    else:
                        mod.handle_ul(ipbuf)
            except Exception as err:
                self._log('ERR', 'MOD error: %s' % err)
        #
        # resolve the dest MAC addr
        macdst = self.arpd.resolve(ipdst)
        #
        # possibly bypass blackholing rule for allowed ports
        # check if PROT / PORT is allowed in the whilelist
        if self.BLACKHOLING:
            if self.WL_ACTIVE:
                dst, prot, pay = DPI.get_ip_dst_pay(ipbuf)
                # TCP:6, UDP:17
                if prot in (6, 17) and pay:
                    port = DPI.get_port(pay)
                    if (self._prot_dict[prot], port) in self.WL_PORTS:
                        self._transfer_to_ext(macdst, ipbuf)
                    else:
                        return
                else:
                    return
            elif macdst != self.arpd.ROUTER_MAC_BUF:
                if self.BLACKHOLING & BLACKHOLE_LAN:
                    return
                else:
                    self._transfer_to_ext(macdst, ipbuf)
            else:
                if self.BLACKHOLING & BLACKHOLE_WAN:
                    return
                else:
                    self._transfer_to_ext(macdst, ipbuf)
        else:
            self._transfer_to_ext(macdst, ipbuf)
    
    def _transfer_to_ext(self, macdst, ipbuf):
        # forward to the external PF_PACKET socket, over the Gi interface
        try:
            self.ext_sk.sendto(b''.join((macdst, self.GGSN_MAC_BUF, b'\x08\0', ipbuf))
                               (self.EXT_IF, self.EXT_PROT))
        except Exception as err:
            self._log('ERR', 'external network IF error (sendto): %s' % err)
        #else:
        #    self._log('DBG', 'buffer transferred from GTPU to RAW')
    
    def transfer_to_int(self, buf):
        # from .listen():
        # buf length is guaranteed >= 20 and ipdst in self._mobiles_ip
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
        ran_ip, teid_from_ran, teid_to_ran = self._mobiles_ip[buf[16:20]]
        # prepend GTP header and forward to the RAN IP
        gtphdr = pack('>BBHI', 0x30, 0xff, len(buf), teid_to_ran)
        #
        try:
            ret = self.int_sk.sendto(gtphdr + buf, (ran_ip, self.INT_PORT))
        except Exception as err:
            self._log('ERR', 'internal network IF error (sendto): %s' % err)
        #else:
        #    self._log('DBG', '%i bytes transferred from RAW to GTPU' % ret)
    
    ###
    # Now we can add and remove (mobile_IP, TEID_from/to_RAN),
    # to configure filters and really start forwading packets over GTP
    
    def add_mobile(self, mobile_ip='192.168.1.201', ran_ip='10.1.1.1',
                         teid_from_ran=0x1, teid_to_ran=0x1):
        try:
            ip = inet_aton(mobile_ip)
        except Exception as err:
            self._log('ERR', 'mobile_ip (%r) has not the correct format: '\
                      'cannot configure the GTPU handler' % mobile_ip)
            return
        if not self.GTP_TEID_EXT:
            teid_to_ran = self.get_teid_to_ran()
        self._mobiles_ip[ip] = (ran_ip, teid_from_ran, teid_to_ran)
        self._mobiles_teid[teid_from_ran] = ip
        self._log('INF', 'setting GTP tunnel for mobile with IP %s' % mobile_ip)
        return teid_to_ran
    
    def rem_mobile(self, mobile_ip='192.168.1.201'):
        try:
            ip = inet_aton(mobile_ip)
        except Exception as err:
            self._log('ERR', 'mobile_ip (%r) has not the correct format: '\
                      'cannot configure the GTPU handler' % mobile_ip)
            return
        if ip in self._mobiles_ip:
            self._log('INF', 'unsetting GTP tunnel for mobile with IP %s' % mobile_ip)
            ran_ip, teid_from_ran, teid_to_ran = self._mobiles_ip[ip]
            del self._mobiles_ip[ip]
        if teid_from_ran in self._mobiles_teid:
            del self._mobiles_teid[teid_from_ran]
    
    def get_teid_to_ran(self):
        if self.GTP_TEID >= self.GTP_TEID_MAX:
            self.GTP_TEID = randint(0, 200000)
        self.GTP_TEID += 1
        return self.GTP_TEID
    
    def _analyze(self, ipsrc, ipbuf):
        #
        try:
            stats = self.stats[ipsrc]
        except:
            self.init_stats(ipsrc)
            stats = self.stats[ipsrc]
        #
        dst, prot, pay = DPI.get_ip_dst_pay(ipbuf)
        # UDP
        if prot == 17 and pay:
            port = DPI.get_port(pay)
            if (dst, port) not in stats['UDP']:
                stats['UDP'].append((dst, port))
            # DNS
            if port == 53:
                if dst not in stats['DNS']:
                    stats['DNS'].append(dst)
                name = DPI.get_dn_req(pay[8:])
                if name not in stats['resolved']:
                    stats['resolved'].append(name)
            elif port == 123 and dst not in stats['NTP']:
                stats['NTP'].append(dst)
        # TCP
        elif prot == 6 and pay:
            port = DPI.get_port(pay)
            if (dst, port) not in stats['TCP']:
                stats['TCP'].append((dst, port))
        # ICMP
        elif prot == 1 and pay and dst not in stats['ICMP']:
            stats['ICMP'].append(dst)
        # alien
        else:
            stats['alien'].append(hexlify(ipbuf))


class DPI:
    
    @staticmethod
    def get_ip_dst_pay(ipbuf):
        # returns a 3-tuple: dst IP, protocol, payload buffer
        # get IP header length
        l = (ord(ipbuf[0:1]) & 0x0F) * 4
        # get dst IP
        dst = inet_ntoa(ipbuf[16:20])
        # get protocol
        prot = ord(ipbuf[9:10])
        #
        return (dst, prot, ipbuf[l:])
    
    @staticmethod
    def get_port(pay):
        return unpack('!H', pay[2:4])[0]
    
    @staticmethod
    def get_dn_req(req):
        # remove fixed DNS header and Type / Class
        s = req[12:-4]
        n = []
        while len(s) > 1:
            l = ord(s[0])
            n.append( s[1:1+l] )
            s = s[1+l:]
        return b'.'.join(n)


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
    with a single or random IP address
    
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
    
    @classmethod
    def handle_ul(self, ipbuf):
        # check if we have an UDP/53 request
        ip_proto, (udpsrc, udpdst) = ord(ipbuf[9]), unpack('!HH', ipbuf[20:24])
        if ip_proto != 17:
            # not UDP
            return
        if udpdst != 53:
            # not DNS
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
        self.GTPUd.transfer_to_int(pkt.to_bytes())


class TCPSYNACK(MOD):
    '''
    This module answers to TCP SYN request incoming from UE (UL direction) with
    a TCP SYN-ACK, enabling to get the 1st TCP data packet from the UE
    
    To be used with GTPUd.BLACKHOLING capability to avoid UE getting SYN-ACK 
    from real servers in parallel
    '''
    TYPE = 1
    
    @classmethod
    def handle_ul(self, ipbuf):
        # check if we have a TCP SYN
        ip_proto, ip_pay = ord(ipbuf[9:10]), ipbuf[20:]
        if ip_proto != 6:
            # not TCP
            return
        if ip_pay[13:14] != b'\x02':
            # not SYN
            return
        
        # build the TCP SYN-ACK: invert src / dst ports, seq num (random),
        # ack num (SYN seq num + 1)
        tcpsrc, tcpdst, seq = unpack('!HHI', ip_pay[:8])
        tcp_synack = TCP(val={'seq': randint(1, 4294967295), 'ack': (1+seq)%4294967296,
                              'src':tcpdst, 'dst':tcpsrc, 
                              'SYN':1, 'ACK':1, 'win':0x1000}, hier=1)
        
        # build the IPv4 header: invert src / dst addr
        ipsrc, ipdst = inet_ntoa(ipbuf[12:16]), inet_ntoa(ipbuf[16:20])
        iphdr = IPv4(val={'src':ipdst, 'dst':ipsrc}, hier=0)
        #
        pkt = Envelope('p', GEN=(iphdr, tcp_synack))
        # send back the TCP SYN-ACK
        self.GTPUd.transfer_to_int(pkt.to_bytes())

