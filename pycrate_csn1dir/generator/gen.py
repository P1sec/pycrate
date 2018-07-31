#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import os
import sys
import time
import importlib

from pycrate_csn1.trans import *


# local path, specifications name, python file header, python import prefix
PATH    = os.path.dirname(os.path.abspath( __file__ )) + os.sep
SPECS   = ['24008', '44018', '44060']
HEAD    = open(PATH + 'header.txt').readlines()
IMPPREF = PATH.split(os.sep)[-2]


def build_py_path(spec, objname):
    #path = (IMPPREF, spec, objname)
    path = (IMPPREF, objname)
    return '.'.join(path)


def process_file(spec, fn):       
    dbg = True
    #
    if dbg:
        print('> %s/%s' % (spec, fn))
    #
    fd = open(PATH + spec + os.sep + fn)
    lines = fd.readlines()
    fd.close()
    #
    # 1) get infos (in CSN.1 comment in the 3 1st lines)
    obj_name = lines[2][2:].strip()
    pname = pythonize_name(obj_name)
    # 2) create the header
    header = HEAD[:]
    header[-5] = header[-5][:-1] + pname + '.py' + '\n'
    header[-4] = header[-4][:-1] + time.strftime('%Y-%m-%d') + '\n'
    header.append('# specification: %s\n' % lines[0][2:].strip())
    header.append('# section: %s\n' % lines[1][2:].strip())
    header.append('# top-level object: %s\n' %  obj_name)
    #
    # 3) compile the CSN.1 text
    try:
        objs, externs, pycode = translate_text(''.join(lines[3:]))
    except Exception as exc:
        print('    [ERR] %s/%s: unable to translate' % (spec, fn))
        print('    Exception: %s' % exc)
        raise(Exception('CSN.1 object translation error'))
    #
    return ''.join(header), externs, pycode, objs


def process(specs):
    global PATH
    # dict to collect all objects and Python code generated
    Objs = {}
    for spec in specs:
        print('[o] %s: processing' % spec)
        cnt = 0
        # compile each .csn file in the spec directory
        flist = os.listdir(PATH + spec + os.sep)
        for fn in flist:
            if fn[-4:] == '.csn':
                header, externs, pycode, objs = process_file(spec, fn)
                Objs[(spec, fn[:-4])] = [header, externs, pycode, objs]
                cnt += len(objs)
        print('[o] %s: done, %i files, %i definitions' % (spec, len(flist), cnt))
    #
    # resolve all imports
    link(Objs, specs)
    #
    # try to load all generated file
    for (spec, objname) in sorted(Objs.keys()):
        load_py_file(spec, objname)


def link(Objs, specs):
     # resolve imports
    all_files = []
    for (spec, objname), (header, externs, pycode, objs) in sorted(Objs.items()):
        #
        print('[o] %s/%s' % (spec, objname))
        imp = []
        other_specs = specs[:]
        other_specs.remove(spec)
        for ref in externs:
            resolved = False
            if (spec, ref) in Objs:
                # 1) external ref, local spec, top-level obj
                imp.append('from %s import %s' % (build_py_path(spec, ref), ref))
                print('    [INF] external reference solved: %s/%s' % (spec, ref))
                resolved = True
            else:
                for other_spec in other_specs:
                    if (other_spec, ref) in Objs:
                        # 2) external ref, other spec, top-level obj
                        imp.append('from %s import %s' % (build_py_path(other_spec, ref), ref))
                        print('    [INF] external reference solved: %s/%s' % (other_spec, ref))
                        resolved = True
                        break
            if not resolved:
                # 3) external ref, non-top-level obj
                pot = []
                for (o_spec, o_objname) in sorted(Objs.keys()):
                    # prioritize local spec reference
                    if o_spec == spec:
                        o_objs = set(Objs[(o_spec, o_objname)][3].keys())
                        if ref in o_objs:
                            pot.append( (o_spec, o_objname) )
                if not pot:
                    for (o_spec, o_objname) in sorted(Objs.keys()):
                        if o_spec != spec:
                            o_objs = set(Objs[(o_spec, o_objname)][3].keys())
                            if ref in o_objs:
                                pot.append((o_spec, o_objname))
                if len(pot) == 0:
                    # reference not found
                    print('    [ERR] %s/%s: unable to resolve reference %s' % (spec, objname, ref))
                    raise(Exception('CSN.1 object reference error'))
                elif len(pot) > 1:
                    # too much references found
                    print('    [WNG] %s/%s: too much potential imports found for reference %s'\
                          % (spec, objname, ref))
                    print('    using the 1st one from %s/%s' % pot[0])
                    imp.append('from %s import %s' % (build_py_path(*pot[0]), ref))
                    print('    [INF] external reference solved: %s/%s/%s' % (pot[0][0], pot[0][1], ref))
                else:
                    imp.append('from %s import %s' % (build_py_path(*pot[0]), ref))
                    print('    [INF] solved reference: %s/%s/%s' % (pot[0][0], pot[0][1], ref))
        #
        if imp:
            imp.insert(0, '# external references')
        create_py_file(spec, objname, header, '\n'.join(imp) + '\n', pycode)


def create_py_file(spec, objname, header, imports, pycode):
    #fd = open(PATH + spec + os.sep + objname + '.py', 'w')
    l = os.listdir(PATH)
    fn = objname + '.py'
    #if fn in l:
    #    raise(Exception('file %s alredy exists' % fn))
    #
    fd = open(PATH + fn, 'w')
    fd.write(header)
    fd.write('\n')
    fd.write(imports)
    fd.write('\n')
    fd.write(pycode)
    fd.write('\n')
    fd.close()


def load_py_file(spec, objname): 
    imppath = build_py_path(spec, objname)
    try:
        importlib.import_module(imppath)
    except Exception as exc:
        print('[ERR] %s.%s: %s' % (spec, objname, exc)) 
    else:
        del sys.modules[imppath]

 
if __name__ == '__main__':
    process(SPECS)
    sys.exit(0)

