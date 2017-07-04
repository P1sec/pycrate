# -*- coding: UTF-8 -*-

# 1) convert the 29002-$release.doc file to a text file in utf-8 format with MS Office
# 2) use this script to extract all ASN.1 modules

import sys

dirpath = './'
path = dirpath + '29002-d40.txt'

def main():
    
    if sys.version_info[0] < 3:
        fd = open(path, 'r')
    else:
        fd = open(path, 'r', encoding='utf-8')
    speclines = fd.readlines()
    fd.close()

    inside = False
    module = []

    for line in speclines:
        if line[:6] == '.$MAP-':
            if inside:
                raise(Exception('ASN.1 extraction failed: %s' % line))
            inside = True
            name = line[2:-1].strip()
            if name[-1] == '{':
                name = name[:-1].strip()
            module.append(line[2:])
        elif line[:5] == '.#END':
            if not inside:
                raise(Exception('ASN.1 extraction failed: %s' % line))
            module.append(line[2:])
            # write module to a new file in dirpath
            print('%s.asn' % name)
            fd = open(dirpath + name + '.asn', 'w')
            fd.write( ''.join(module) )
            fd.close()
            #
            module = []
            inside = False
        elif inside:
            module.append(line)

    print('> extraction done')
    return 0

if __name__ == '__main__':
    main()
