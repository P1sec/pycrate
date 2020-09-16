#!/usr/bin/env python3

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# * Copyright 2020. Benoit Michau. P1Sec.
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
import inspect

from pycrate_asn1c.generator import _Generator
from pycrate_asn1c.asnproc import (
    compile_text, compile_spec, compile_all, \
    generate_modules, PycrateGenerator, JSONDepGraphGenerator,
    ASN_SPECS, GLOBAL, get_spec_dir
    )


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
    parser.add_argument('-s', dest='spec', type=str,
                        help='provide a specification shortname, instead of ASN.1 input file(s)')
    parser.add_argument('-i', dest='input', type=str, nargs='+',
                        help='ASN.1 input file(s) or directory')
    parser.add_argument('-o', dest='output', type=str, default='out',
                        help='compiled output Python (and json) source file(s)')
    parser.add_argument('-g', '--generator', dest='generator_path', type=str, default=None,
                        help='provide an alternative python generator file path')
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
    generator_class = PycrateGenerator
    if args.generator_path:
        generator_class, err = import_generator_from_file(args.generator_path)
        if err:
            return 0
    #
    if args.spec:
        if args.spec not in ASN_SPECS:
            print('%s, args error: invalid specification name %s' % (sys.argv[0], args.spec))
            print_specnames()
            return 0
        # get spec name and potential flags
        specname = ASN_SPECS[args.spec]
        if isinstance(specname, (tuple, list)):
            for kw in specname[1:]:
                if kw not in ckw:
                    ckw[kw] = True
            specname = specname[0]
        specdir  = os.path.abspath(get_spec_dir(specname))
        # compile the spec
        GLOBAL.clear()
        compile_spec(name=specname, **ckw)
        # generate .txt files
        objname = specdir + os.path.sep + 'load_obj.txt'
        modname = specdir + os.path.sep + 'load_mod.txt'
        if not os.path.exists(modname):
            with open(modname, 'w') as fd:
                for m in GLOBAL.MOD:
                    if m[0] != '_':
                        fd.write('%s.asn\n' % m)
                print('%s file created' % modname)
        if not os.path.exists(objname):
            with open(objname, 'w') as fd:
                for (m, n) in GLOBAL.COMP['DONE']:
                    fd.write('%s.%s\n' % (m, n))
                print('%s file created' % objname)
        # generate python and json files
        destname = os.path.abspath(specdir + os.path.sep + '..') + os.path.sep + args.spec
        generate_modules(generator_class, destname + '.py')
        print('%s file created' % (destname + '.py', ))
        generate_modules(JSONDepGraphGenerator, destname + '.json')
        print('%s file created' % (destname + '.json', ))
        GLOBAL.clear()
    #
    elif args.input:
        #
        try:
            ofd = open(args.output + '.py', 'w')
        except:
            print('%s, args error: unable to create output file %s' % (sys.argv[0], args.output))
            return 0
        else:
            ofd.close()
        #
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
            print('%s, args error: no ASN.1 inputs found' % sys.argv[0])
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
        generate_modules(generator_class, args.output + '.py')
        if args.json:
            generate_modules(JSONDepGraphGenerator, args.output + '.json')
    #
    else:
        print('%s, args error: missing ASN.1 input(s) or specification name' % sys.argv[0])
    #
    return 0


def import_generator_from_file(path):
    if not os.path.isfile(path):
        print('%s, args error: generator must be a file, %s is not' % (sys.argv[0], path))
        return None, 1
    # set the directory of the path in the Python module path
    module_dir = os.path.dirname(path)
    sys.path.append(module_dir)
    # get the filename and strip its suffix to get the corresponding module name
    # and load it
    module_name = '.'.join(path.split(os.path.sep)[-1].split('.')[0:-1])
    python_module = __import__(module_name)
    # ensure we have an ASN.1 generator
    generator_class = find_class_in_module(python_module, mother=_Generator)
    if generator_class is None:
        print('%s, args error: generator file does not contain a _Generator class in module %s'\
               % (sys.argv[0], python_module))
        return None, 1
    return generator_class, 0


def find_class_in_module(python_module, mother=_Generator):
    # look for the 1st _Generator subclass in the module
    found_class = None
    for name, obj in inspect.getmembers(python_module, inspect.isclass):
        if obj != mother and issubclass(obj, mother):
            found_class = obj
            break
    # potentially look for a subclass of the found class
    if found_class:
        child = find_class_in_module(python_module, mother=found_class)
        if child:
            found_class = child
    return found_class


if __name__ == '__main__':
    sys.exit(main())

