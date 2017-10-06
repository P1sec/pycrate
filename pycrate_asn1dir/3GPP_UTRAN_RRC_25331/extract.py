# -*- coding: UTF-8 -*-

# 1) convert the 25331-$release.doc files to text files in utf-8 format with MS Office
# 2) use this script to extract all 3G RRC ASN.1 modules

import codecs
import re

dirpath = './'
path = dirpath + '25331-d30.txt'

# ASN.1 modules are described within specific sections
# no extraction of ECN modules
sections = [
    '11.1	General message structure',
    '11.2	PDU definitions',
    '11.3	Information element definitions',
    '11.4	Constant definitions',
    '11.5	RRC information between network nodes',
    ]

# for RRC, this re works fine as there is no OID when a module is declared
module_def = re.compile('^([A-Z][a-zA-Z0-9\-]{0,})(\s{1,}DEFINITIONS\s{1,}[A-Z\-\s]{0,}::=)')

def main():
    
    fd = codecs.open(path, 'r', 'utf-8')
    speclines = fd.readlines()
    fd.close()
    #print(len(speclines))
    
    inside, start = False, False
    module = []
    module_name = None
    
    for line in speclines:
        if line[:-2] in sections:
            if inside:
                raise(Exception('ASN.1 extraction failed: %s' % line))
            inside, start = True, True
        elif inside and line[:-2] == 'END':
            module.append(line)
            inside = False
            print('%s.asn' % module_name)
            fd = codecs.open(dirpath + module_name + '.asn', 'w', 'utf-8')
            fd.write( ''.join(module) )
            fd.close()
            module = []
            module_name = None
        else:
            if inside:
                #print('inside')
                if start:
                    #print('start')
                    m = module_def.match(line)
                    if m:
                        module_name = m.group(1)
                        start = False
                        start = False
                        #print(module_name)
                    elif not re.match('^\s{1,}$', line) and not line[:2] == '--':
                        start = False
                # inside a module: storing the line
                module.append(line)
    
    print('> extraction done')
    return 0

if __name__ == '__main__':
    main()

