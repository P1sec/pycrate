# -*- coding: UTF-8 -*-

# 1) convert all 36XYZ-$release.doc files to text files in utf-8 format with MS Office
# 2) use this script to extract all ASN.1 modules

import codecs
import re

dirpath = './'
path = dirpath + '36355-f50.txt'

# it is not possible to catch modules' name as an OID is declared on multiple lines
module_def = re.compile('DEFINITIONS\s{1,}[A-Z\-\s]{0,}::=')

module_names = {
    0 : 'LPP-PDU-Definitions'
    }

def main():
    
    fd = codecs.open(path, 'r', 'utf-8')
    speclines = fd.readlines()
    fd.close()
    #print(len(speclines))
    
    # every ASN.1 textual definition starts with "-- ASN1START"
    # and ends with "-- ASN1STOP"
    
    inside, start = False, False
    module, cnt = [], 0
    
    for line in speclines:
        if line[:12] == '-- ASN1START':
            if inside:
                raise(Exception('ASN.1 extraction failed: %s' % line))
            inside, start = True, True
            #print('-- ASN1START')
        elif inside and line[:11] == '-- ASN1STOP':
            inside = False
        else:
            if inside:
                #print('inside')
                if start:
                    #print('start')
                    m = module_def.search(line)
                    if m:
                        # new module starting
                        if module:
                            # write the current one into an .asn file
                            if cnt in module_names:
                                module_name = module_names[cnt]
                            else:
                                module_name = '%i' % cnt
                            print('%s.asn' % module_name)
                            fd = codecs.open(dirpath + module_name + '.asn', 'w', 'utf-8')
                            fd.write( ''.join(module) )
                            fd.close()
                            module = []
                            cnt += 1
                        start = False
                        #print(module_name)
                    elif not re.match('^\s{1,}$', line):
                        start = False
                # inside a module: storing the line
                module.append(line)
    #
    # write the last module into an .asn file
    if module:
        if cnt in module_names:
            module_name = module_names[cnt]
        else:
            module_name = '%i' % cnt
        print('%s.asn' % module_name)
        fd = codecs.open(dirpath + module_name + '.asn', 'w', 'utf-8')
        fd.write( ''.join(module) )
        fd.close()
    
    print('> extraction done')
    return 0

if __name__ == '__main__':
    main()

