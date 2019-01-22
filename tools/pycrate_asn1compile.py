#!/usr/bin/env python

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_asn1compile.py
# * Created : 2017-02-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import os
import sys
import argparse

from pycrate_asn1c.proc import compile_text, compile_spec, compile_all, \
     generate_modules, PycrateGenerator, JSONDepGraphGenerator, ASN_SPECS


# inputs:
# compile any single file
# compile all .asn or .asn1 files into a directory
#   -> take load_mod.txt into account
# compile a given spec (by shortname)
# compile all specs from asndir

# -fautotags: force AUTOMATIC TAGS behaviour for all modules
# -fextimpl: force EXTENSIBILITY IMPLIED behaviour for all modules
# -fverifwarn: force warning instead of raising during the verification stage

# output:
# destination file or directory


python_version = sys.version_info[0]


def print_specnames():
    print('%s, valid specification names:' % sys.argv[0])
    for k, v in ASN_SPECS.items():
        print('    %s (%s)' % (k, v))


def get_mod_wl(fn):
    ret = []
    try:
        fd = open(fn)
    except:
        print('unable to read %s, ignoring it')
        return ret
    else:
        try:
            for l in fd.readlines():
                if len(l) > 1 and l[0] != '#':
                    ret.append(l[:-1].strip())
        except:
            print('unable to read %s, ignoring it')
            fd.close()
            return ret
        else:
            return ret


def main():
    
    parser = argparse.ArgumentParser(description='compile ASN.1 input file(s) for the pycrate ASN.1 runtime')
    #
    parser.add_argument('-i', dest='input', type=str, nargs='+',
                        help='ASN.1 input file(s) or directory')
    #parser.add_argument('-s', dest='spec', type=str,
    #                    help='provide a specification shortname, instead of ASN.1 input file(s)')
    parser.add_argument('-o', dest='output', type=str, default='out',
                        help='compiled output Python (and json) source file(s)')
    parser.add_argument('-j', dest='json', action='store_true',
                        help='output a json file with information on ASN.1 objects dependency')
    parser.add_argument('-fautotags', action='store_true',
                        help='force AUTOMATIC TAGS for all ASN.1 modules')
    parser.add_argument('-fextimpl', action='store_true',
                        help='force EXTENSIBILITY IMPLIED for all ASN.1 modules')
    parser.add_argument('-fverifwarn', action='store_true',
                        help='force warning instead of raising during the verification stage')
    #
    args = parser.parse_args()
    #
    ckw = {}
    if args.fautotags:
        ckw['autotags'] = True
    if args.fextimpl:
        ckw['extimpl'] = True
    if args.fverifwarn:
        ckw['verifwarn'] = True
    #
    try:
        ofd = open(args.output + '.py', 'w')
    except:
        print('%s, args error: unable to create output file %s' % (sys.argv[0], args.output))
        return 0
    else:
        ofd.close()
    
    #if args.spec:
    #    if args.spec not in ASN_SPECS:
    #        print('%s, args error: invalid specification name %s' % (sys.argv[0], args.spec))
    #        print_specnames()
    #        return 0
    #    compile_spec(shortname=args.spec, **ckw)
    #
    if args.input:
        files = []
        for i in args.input:
            if os.path.isdir(i):
                fn, wl = [], []
                # get all potential .asn / .asn1 / .ASN / .ASN1 files from the dir
                for f in os.listdir(i):
                    if f.split('.')[-1] in ('asn', 'asn1', 'ASN', 'ASN1'):
                        fn.append(f)
                    elif f == 'load_mod.txt':
                        wl = get_mod_wl('%s/%s' % (i, f))
                # keep only asn files specified in the load_mod.txt file
                if wl:
                    files.extend(['%s%s' % (i, f) for f in fn if f in wl])
                else:
                    files.extend(['%s%s' % (i, f) for f in fn])
            elif os.path.isfile(i):
                files.append(i)
            else:
                print('%s, args warning: invalid input %s' % (sys.argv[0], i))
        if not files:
            print('%s, args error: no ASN.1 inputs found')
            return 0
        else:
            #print(files)
            ckw['filenames'] = list(files)
        # read all file content into a single buffer
        txt = []
        for f in files:
            try:
                fd = open(f)
            except:
                print('%s, args error: unable to open input file %s' % (sys.argv[0], f))
                return 0
            else:
                try:
                    if python_version < 3:
                        txt.append( fd.read().decode('utf-8') )
                    else:
                        txt.append( fd.read() )
                except:
                    print('%s, args error: unable to read input file %s' % (sys.argv[0], f))
                    fd.close()
                    return 0
                else:
                    fd.close()
        compile_text(txt, **ckw)
    #
    else:
        print('%s, args error: missing ASN.1 input(s) or specification name' % sys.argv[0])
        return 0
    
    generate_modules(PycrateGenerator, args.output + '.py')
    if args.json:
        generate_modules(JSONDepGraphGenerator, args.output + '.json')
    return 0

if __name__ == '__main__':
    sys.exit(main())

