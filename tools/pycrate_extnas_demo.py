#!/usr/bin/env python
# -*- coding: UTF-8 -*-

#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2022. Vadim Yanitskiy
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
# * File Name : tools/pycrate_extnas_demo.py
# * Created : 2020-03-03
# * Authors : Vadim Yanitskiy
# *--------------------------------------------------------
#*/

from binascii import hexlify
import logging as log
import argparse
import socket

from pycrate_mobile.NASLTE import parse_NASLTE_MT
from pycrate_mobile import TS24301_EMM as NAS
from pycrate_mobile import TS24301_IE as IE

from pycrate_osmo.RRCTL import RRCTLMsgType, RRCTLMsgDisc
from pycrate_osmo.RRCTL import RRCTLConnEstCause
from pycrate_osmo.RRCTL import PLMNInfo
from pycrate_osmo.RRCTL import RRCTLMsg

class Connection:
    def __init__(self, path='/tmp/ue_extnas.sock'):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connected = False
        self.sock_path = path

    def connect(self):
        log.info('Connecting to \'%s\'', self.sock_path)
        self.sock.connect(self.sock_path)
        self.connected = True

    def disconnect(self):
        self.sock.close()
        self.connected = False

class RRCTLInterface(Connection):
    def send(self, msg):
        log.debug('Tx RRCTL message: %s', msg['Hdr'])
        self.sock.send(msg.to_bytes())

    def receive(self):
        data = self.sock.recv(1024)
        if not data:
            raise IOError

        msg = RRCTLMsg()
        msg.from_bytes(data)
        log.debug('Rx RRCTL message: %s', msg['Hdr'])

        return msg

    def expect(self, msg_type, msg_disc):
        msg = self.receive()
        if not msg.match(msg_type, msg_disc):
            raise AssertionError('Rx unexpected RRCTL PDU', msg['Hdr'])
        return msg

    def reset(self):
        ''' Send Reset.Req, wait for Reset.Cnf '''
        msg = RRCTLMsg()
        msg.set_type(RRCTLMsgType.Reset)
        self.send(msg)

        # Wait for the confirmation
        self.expect(RRCTLMsgType.Reset, RRCTLMsgDisc.Cnf)

class TestCase:
    def __init__(self, iface, params):
        assert iface.connected
        self.iface = iface
        self.iface.reset()
        self.params = params

    def do_plmn_search(self):
        ''' Search for networks on the configured EARFCN '''
        msg = RRCTLMsg()
        msg.set_type(RRCTLMsgType.NetworkSearch)
        self.iface.send(msg)

        # Wait for the search results
        msg = self.iface.expect(RRCTLMsgType.NetworkSearch, RRCTLMsgDisc.Res)

        cell_num = msg['Data']['NofPLMNs'].get_val()
        cell_list = msg['Data']['PLMNs']
        if cell_num != cell_list.get_num():
            raise ValueError('PLMN list is longer / shorter than indicated')

        log.info('PLMN search completed, %u cell(s) found', cell_num)
        for idx, cell in enumerate(cell_list):
            log.info("Cell #%02d: %s", idx, cell)

        return cell_list

    def do_plmn_select(self, mcc, mnc):
        ''' Select a cell defined by a given pair of MCC/MNC '''
        msg = RRCTLMsg()
        msg.set_type(RRCTLMsgType.NetworkSelect)
        msg['Data']['MCC'].set_val(mcc)
        msg['Data']['MNC'].set_val(mnc)
        self.iface.send(msg)

        # Wait for the network selection result
        self.iface.expect(RRCTLMsgType.NetworkSelect, RRCTLMsgDisc.Cnf)

    def do_conn_establish(self, pdu, cause=RRCTLConnEstCause.MO_Signalling):
        ''' Establish connection with the previously selected network '''
        msg = RRCTLMsg()
        msg.set_type(RRCTLMsgType.ConnEstabish)
        msg['Data']['Cause'].set_val(cause)
        msg['Data']['PDU'].set_val(pdu)
        self.iface.send(msg)

        # Wait for the establishment result
        self.iface.expect(RRCTLMsgType.ConnEstabish, RRCTLMsgDisc.Cnf)

    def search_select(self):
        cell_list = self.do_plmn_search()
        if cell_list.get_num() == 0:
            raise AssertionError('No PLMNs found :/')

        # Find a cell by MCC/MNC (if specified)
        cell = None
        for c in cell_list:
            if self.params.plmn_mcc is not None:
                if self.params.plmn_mcc != c['MCC'].decode():
                    continue
            if self.params.plmn_mnc is not None:
                if self.params.plmn_mnc != c['MNC'].decode():
                    continue
            cell = c
            break
        if cell is None:
            raise AssertionError('No matching PLMN found')

        log.info('Selecting PLMN: %s', cell)
        (mcc, mnc, tac) = cell()
        self.do_plmn_select(mcc, mnc)

        log.info('PLMN has been found and selected \o/')

    def establish(self, pdu):
        log.info('Establishing MO connection to the network...')
        self.do_conn_establish(pdu)
        log.info('Connection has been established \o/')

    def test(self):
        ''' The actual test case body '''
        raise NotImplementedError

class TC_DetachRequest(TestCase):
    def test(self):
        # Search and select the network
        self.search_select()

        pdu = NAS.EMMDetachRequestMO()

        pdu['EPSDetachType'].set_IE(val = {
            'SwitchOff' : 1, # Yes
            'Type'      : self.params.detach_type,
            })

        # Oh, that looks so ugly... is there a better way?
        epsid = IE.EPSID()
        epsid.encode(IE.IDTYPE_IMSI, self.params.subscr_imsi)
        pdu['EPSID'].set_val({'V' : epsid.to_bytes()})

        log.info('Sending Detach Request:\n%s', pdu.show())
        self.establish(pdu.to_bytes())

        # Wait for any RRCTL messages
        while True:
            msg = self.iface.receive()
            if not msg.match(RRCTLMsgType.ConnData, RRCTLMsgDisc.Ind):
                log.info('Rx unexpected message %s', msg[1])

            lcid    = msg['Data']['LCID'].get_val()
            pdu_enc = msg['Data']['PDU'].get_val()
            pdu_len = len(pdu_enc)

            log.info('Rx MT NAS message (lcid=0x%08x, len=%u): %s',
                     lcid, pdu_len, hexlify(pdu_enc))
            try:
                (pdu, err) = parse_NASLTE_MT(pdu_enc)
                print(pdu.show())
            except:
                log.info('Failed to parse MT NAS PDU')
                continue
            # We're done
            break

ap = argparse.ArgumentParser(prog='pycrate_extnas_demo')

ap.add_argument('-s', '--socket-path', metavar='PATH',
                type=str, default='/tmp/ue_extnas.sock',
                help='UNIX socket patch of the RRC interface (default \'%(default)s\')')
ap.add_argument('--plmn-mcc', metavar='MCC',
                type=str, nargs='?',
                help='Mobile Country Code (select any by default)')
ap.add_argument('--plmn-mnc', metavar='MNC',
                type=str, nargs='?',
                help='Mobile Network Code (select any by default)')
ap.add_argument('--subscr-imsi', metavar='IMSI',
                type=str, default='001010000000000',
                help='IMSI to use (default \'%(default)s\')')
ap.add_argument('--detach-type', metavar='TYPE',
                type=int, default=2, choices=range(8),
                help='IMSI detach type (default %(default)s, see _EPSDetTypeMO_dict)')

log.basicConfig(format='[%(levelname)s] %(filename)s:%(lineno)d %(message)s', level=log.INFO)

if __name__ == '__main__':
    # Parse the arguments
    argv = ap.parse_args()

    # Init the RRCTL interface
    iface = RRCTLInterface(argv.socket_path)
    iface.connect()

    test_cases = list()
    test_cases.append(TC_DetachRequest(iface, argv))

    for test in test_cases:
        log.info('Starting test case \'%s\'', test.__class__.__name__)
        test.test()
        log.info('Test case \'%s\' completed', test.__class__.__name__)
