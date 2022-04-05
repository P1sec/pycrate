#!/usr/bin/env python3

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2022. Benoit Michau. P1sec
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
# * File Name : tools/pycrate_gtp_type_info.py
# * Created : 2022-12-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import sys
import argparse

from pycrate_mobile.TS29060_GTP     import * # GTPv1-C
from pycrate_mobile.TS29274_GTPC    import * # GTPv2-C
from pycrate_mobile.TS29281_GTPU    import * # GTP-U


def _print_msgtype_info(cls):
    Msg = cls()
    Msg[1].init_ies(wopt=True, wpriv=True)
    print('  ' + Msg.show().replace('\n', '\n  '))
    #
    if isinstance(Msg[1].MAND, set):
        # GTPv1-C
        print('\n  mandatory IE(s): %s' % ', '.join(Msg[1].MAND))
    else:
        # GTPv2-C
        print('\n  mandatory IE(s): %s' % ', '.join(['%s (%i, %i)' % (v[1], k[0], k[1]) for k, v in Msg[1].MAND.items()]))


GTPv1CCtxt = {
    'Path'  : 'path management',
    'Tun'   : 'tunnel management',
    'Loc'   : 'location management',
    'Mob'   : 'mobility management',
    'MB_UE' : 'UE-related MBMS management',
    'MB_Serv' : 'MBMS service management',
    'MSInfo'  : 'MS-related charging notification',
    'GTPp'    : 'charging with GTP\''
    }


def _print_msgctxt_info(vers, typ):
    prot, inf = [], []
    if vers == 1:
        if typ in GTPDispatcherSGSN:
            prot.append('GTPv1-C')
        if typ in GTPUDispatcher:
            prot.append('GTP-U')
    else:
        if typ in GTPCDispatcher:
            prot.append('GTPv2-C')
        if typ in GTPUDispatcher:
            prot.append('GTP-U')
    print('  Message used in %s' % ' and '.join(prot))
    #
    if 'GTPv1-C' in prot:
        # transactional ctxt
        for ctxt, ctxt_dict in GTPReqResp.items():
            for ini, dst in ctxt_dict.items():
                if ini[0] == typ:
                    if ini[1] == 'SGSN':
                        disp_ini, disp_resp = GTPDispatcherGGSN, GTPDispatcherSGSN
                    else:
                        disp_ini, disp_resp = GTPDispatcherSGSN, GTPDispatcherGGSN
                    inf.append('%s (type %i) initiated by %s, sent to %s and responded with %s (type %s), used for %s'\
                        % (disp_ini[ini[0]].__name__, ini[0], ini[1], dst[1], disp_resp[dst[0]].__name__ if dst[0] else 'None', dst[0], GTPv1CCtxt[ctxt]))
                elif dst[0] == typ:
                    if dst[1] == 'SGSN':
                        disp_ini, disp_resp = GTPDispatcherSGSN, GTPDispatcherGGSN
                    else:
                        disp_ini, disp_resp = GTPDispatcherGGSN, GTPDispatcherSGSN
                    inf.append('%s (type %i) initiated by %s, sent to %s in response to %s (type %s), used for %s'\
                        % (disp_ini[dst[0]].__name__, dst[0], dst[1], ini[1], disp_resp[ini[0]].__name__, ini[0], GTPv1CCtxt[ctxt]))
        if inf:
            print('  - ' + '\n  - '.join(inf))
    #
    elif 'GTPv2-C' in prot:
        # transactional ctxt
        for req, resps in GTPCReqResp.items():
            if req == typ:
                inf.append('%s (type %i), responded with' % (GTPCDispatcher[req].__name__, req))
                if resps[0] is not None:
                    inf[-1] += ' %s (type %s) for success' % (GTPCDispatcher[resps[0]].__name__, resps[0])
                else:
                    inf[-1] += ' None for success'
                if len(resps) > 1:
                    inf[-1] += ', %s (type %s) for error' % (GTPCDispatcher[resps[1]].__name__, resps[1])
            elif resps[0] == typ:
                # success
                inf.append('%s (type %i) in successful response to %s (type %i)'\
                    % (GTPCDispatcher[resps[0]].__name__, resps[0], GTPCDispatcher[req].__name__, req)) 
            elif len(resps) > 1 and resps[1] == typ:
                # error
                inf.append('%s (type %i) in error response to %s (type %i)'\
                    % (GTPCDispatcher[resps[1]].__name__, resps[1], GTPCDispatcher[req].__name__, req))
        if inf:
            print('  ' + '\n  '.join(inf))
        #
        ift = []
        for ifn, ifts in GTPC_IF_ALL.items():
            if typ in ifts:
                ift.append(ifn)
        print('  Used in interfaces: %s' % ', '.join(ift))


# the entry for the app is the protocol version (V1 or V2) and the message type

def print_msgtype_infos(vers, typ):
    if vers == 1:
        if typ is None:
            # list all GTPv1-C messages
            for t in GTPDispatcherSGSN:
                if t in {18, 19}:
                    print('- %3i: %s' % (t, GTPDispatcherSGSN[t].__name__))
                    print('- %3i: %s' % (t, GTPDispatcherGGSN[t].__name__))
                else:
                    print('- %3i: %s' % (t, GTPDispatcherSGSN[t].__name__))
        else:
            for t in typ:
                if t not in GTPDispatcherSGSN:
                    if t in GTPUDispatcher:
                        cls = GTPUDispatcher(t)
                        print('- %3i: %s\n' % (t, cls.__name__))
                        _print_msgctxt_info(vers, t)
                        print('')
                        print('  ' + cls().show().replace('\n', '\n  '))
                        print('')
                    else:
                        # non-existent message
                        print('- %3i: type does not exist for GTPv1\n' % t)
                elif t in {18, 19}:
                    # can be both SGSN and GGSN-initiated, with different struct
                    cls = GTPDispatcherSGSN[t]
                    print('- %3i: %s\n' % (t, cls.__name__))
                    _print_msgctxt_info(vers, t)
                    print('')
                    _print_msgtype_info(cls)
                    print('')
                    #
                    cls = GTPDispatcherGGSN[t]
                    print('- %3i: %s\n' % (t, cls.__name__))
                    _print_msgtype_info(cls)
                    print('')
                else:
                    # get the msg
                    cls = GTPDispatcherSGSN[t]
                    print('- %3i: %s\n' % (t, cls.__name__))
                    _print_msgctxt_info(vers, t)
                    print('')
                    _print_msgtype_info(cls)
                    print('')
    #
    elif vers == 2:
        if typ is None:
            # list all GTPv2-C messages
            for t in GTPCDispatcher:
                print('- %3i: %s' % (t, GTPCDispatcher[t].__name__))
        else:
            for t in typ:
                if t not in GTPCDispatcher:
                    print('- %3i: type does not exist for GTPv2\n' % t)
                else:
                    # get the msg
                    cls = GTPCDispatcher[t]
                    print('- %3i: %s\n' % (t, cls.__name__))
                    _print_msgctxt_info(vers, t)
                    print('')
                    _print_msgtype_info(cls)
                    print('')


def main():
    parser = argparse.ArgumentParser(description='print information related to GTP-C '\
        'messages structure and context')
    parser.add_argument('-v2', action='store_true', help='GTPv2 (TS 29.274, 29.276 and 29.280) instead of GTPv1 (TS 29.060 and TS 32.295)')
    parser.add_argument('-t', type=int, nargs='+', help='GTP-C message type (0..255)')
    args = parser.parse_args()
    #
    if args.v2:
        vers = 2
    else:
        vers = 1
    #
    print_msgtype_infos(vers, args.t)
    #
    return 0


if __name__ == '__main__':
    sys.exit(main())

