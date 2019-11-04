# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate
# * Version : 0.4.0
# *
# * Copyright © 2019. Benoit Michau. P1sec.
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
# * File Name : pycrate_mobile/TS29002_MAPAppCtx.py
# * Created : 2019-01-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
#
# MAP application context functions
#

# making use of the almighty MAPv2v3 module
from pycrate_int_asn1dir.TCAP_MAPv2v3 import *

Operations      = GLOBAL.MOD['MAPv2v3-Protocol']['Supported-MAP-Operations']
OperationPkgs   = GLOBAL.MOD['MAPv2v3-Application']['Supported-MAP-OperationPackages']
ApplicationCtxs = GLOBAL.MOD['MAPv2v3-Application']['Supported-MAP-ApplicationContexts']


def get_operation(opcode):
    """returns the list of defined MAP operations for the given opcode
    There is a single MAP operation per opcode per MAP version (v1, v2, v3)
    """
    t, op = Operations.get('operationCode', ('local', opcode))
    if t == 'M':
        # several operation / version
        return op
    elif t == 'U':
        # single operation for all versions
        return [op]
    else:
        # no operation for this opcode
        return []


def list_operation_pkg_names():
    """returns the list of names of defined MAP operation-packages
    """
    names = []
    for name in GLOBAL.MOD['MAPv2v3-Application']['_val_']:
        if name.split('-')[-2][-7:] == 'Package':
            names.append(name)
    return names


def list_application_ctx_names():
    """returns the list of names of defined MAP application-contexts
    """
    names = []
    for name in GLOBAL.MOD['MAPv2v3-Application']['_val_']:
        if name.split('-')[-2][-7:] == 'Context':
            names.append(name)
    return names


def get_operation_pkgs(opcode, mode='S'):
    """returns the list of defined MAP operation-packages that include the MAP
    operation(s) for the given opcode
    
    mode:  'S' for Supplier (initiator) or 'C' for Consumer (responder)
    """
    ret = {}
    key = 'Supplier' if mode in ('s', 'S') else 'Consumer' 
    for opname in list_operation_pkg_names():
        opval = GLOBAL.MOD['MAPv2v3-Application'][opname]._val
        if key not in opval:
            continue
        for oval in opval[key].getv():
            if oval['operationCode'] == ('local', opcode):
                if opname in ret:
                    assert(ret[opname] == opval)
                    pass
                else:
                    ret[opname] = opval
    return ret


def get_application_ctx(oid):
    """returns the defined MAP application-context for the given OID
    """
    t, ac = ApplicationCtxs.get('code', oid)
    if t == 'M':
        assert()
    elif t == 'U':
        return ac
    else:
        assert( t == 'N' )
        return None


def get_application_ctxs(opcode, mode='I'):
    """returns the list of defined MAP application-contexts that include the MAP
    operation(s) for the given opcode
    
    mode: 'I' for Initiator or 'R' for Responder
    """
    ret    = {}
    key    = ('Symmetric', 'InitiatorConsumerOf') if mode in ('I', 'i') else ('Symmetric', 'ResponderConsumerOf')
    keyrev = ('Symmetric', 'ResponderConsumerOf') if mode in ('I', 'i') else ('Symmetric', 'InitiatorConsumerOf') 
    for acname in list_application_ctx_names():
        acval = GLOBAL.MOD['MAPv2v3-Application'][acname]._val
        # looking at Supplier within the Initiator potential operation-package
        for k in key:
            if k in acval:
                for opval in acval[k].getv():
                    # here, we look at "Supplier" within the operation-package
                    if 'Supplier' in opval:
                        for oval in opval['Supplier'].getv():
                            if oval['operationCode'] == ('local', opcode):
                                if acname in ret:
                                    assert(ret[acname] == acval)
                                else:
                                    ret[acname] = acval
        #
        # looking at Consumer within the Responder potential operation-package
        for k in keyrev:
            if k in acval:
                for opval in acval[k].getv():
                    if 'Consumer' in opval:
                        for oval in opval['Consumer'].getv():
                            if oval['operationCode'] == ('local', opcode):
                                if acname in ret:
                                    assert(ret[acname] == acval)
                                else:
                                    ret[acname] = acval
    #
    return ret

