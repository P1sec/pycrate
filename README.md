What is pycrate
===============

Pycrate is a french word for qualifying bad wine.
The present software library has nothing to do with bad wine, it is simply a
Python library for manipulating various digital formats in an easy way.
It is the glorious successor of [libmich](https://github.com/mitshell/libmich), 
which was started 8 years ago and served well.


Installation
============

Operating systems and Python version
------------------------------------

The library is designed to work with both Python 2 (2.7) and Python 3 (3.4, 3.5 and greater), 
from the official Python implementation [CPython](https://www.python.org/).
It is also supporting alternative Python engine such as [pypy](http://pypy.org/) or
[nuitka](http://nuitka.net/).
It is regularly tested both on Linux and Windows, and should actually work on any
operating system which has [r|d]ecent Python support (as in 2017).


Dependencies
------------

Currently none. Only the Python builtins and few internal modules of Python 
(e.g. os, system, re) are required.


Automatic installation
----------------------

An installation script is available.
It installs the library within your Python package directory:

```
python setup.py install
```

It is also possible to test the library before installing it
(this will create two local directories *./test_asn/* and *./pycrate.egg-info/* that
you can just delete afterwards):

```
python setup.py test
```

Or to build the library without installing it in the system:

```
python setup.py build
```

It is also possible to recompile all ASN.1 modules, this will take few minutes
(but if I did not do any mistake, all ASN.1 modules provided in *./pycrate_asn1dir/*
should have been compiled with the latest version of the compiler):

```
python -m pycrate_asn1c.proc
```


License
=======

The whole library is licensed under GPLv2 and is compatible with more recent version
of the GPL: all licensed files have an header making it self-explanatory.


Contact and support
==================

As the unique developper of the library, I am the only person to contact:
michau \[dot\] benoit \[at\] gmail \[dot\] com


Extending the library
=====================

If you are willing to extend the library, do not hesitate to contact me by
email or through the github service. Any patch or submission is very welcome!
Moreover, in case you are using this library in any of your project and you
find it useful, do not hesitate to drop me an email.
It is always a pleasure to know where code provided on the Internet can end 
up...


Components
==========

Pycrate is actually more a software suite than a single library. It is composed
of several subdirectories, each providing specific services.


pycrate_core
------------

The core of the library.
* *utils* provides basics functions to manipulate integers, bytes and bits
* *charpy* provides the Charpy class to handle easily the consumption of a bit-stream
* *elt* and *base* are providing several classes to help when building complex
   data structures
* *repr* provides simple functions to help with the representation of instances
   from the *elt* and *base* modules

Some of the most useful features are provided by the *pack_val()* functions from 
the *utils* module and the *Charpy* class from the *charpy* module.
They help to deal easily with packing and unpacking bytes and integers 
(signed / unsigned, little / big endian) in an aligned and unaligned way.
All lengths of fields are provided in bits, hence facilitating the handling of 
unaligned structures.


pycrate_ether
-------------

The modules provided here implement Ethernet and IP-oriented protocols and formats.
* *Ethernet* with structures for Ethernet and VLAN headers
* *ARP* simply providing the structure for ARP
* *IP* with structures for IPv4, IPv6, ICMP, UDP and TCP
* *PCAP* with structures for the PCAP global header and the record header


pycrate_media
-------------

The modules here implement various multimedia formats.
* *JPEG* with detailed structures used in the JPEG format
* *GIF* with detailed structures used in the GIF format
* *TIFF* with detailed structures used in the TIFF format
* *BMP* with structures used in the BMP format
* *PNG* with the basic structure used in the PNG format
* *MPEG4* with the basic structure used in the MPEG4 file format
* *MP3* with detailed structures used in the MP3 format, including ID3v1 and ID3v2 tags

Most of the classes here implement a complete recipe to parse all of those format in a 
single shot, by using their *from_char()* method.


pycrate_asn1c
-------------

All the modules here serve the sole purpose of compiling ASN.1 specifications.
The most important ones are:
* *asnobj* which is the almighty class when parsing any ASN.1 definition
* *generator* which provides two distinct generators to produce source files from
   the ASN.1 objects processed in Python: *PycrateGenerator* which produces source 
   file to be used with the pycrate ASN.1 runtime (in *pycrate_asn1rt*), 
   and *JSONDepGraphGenerator* which produces json file listing object dependencies 
   (which then can be browsed dynamically thanks to D3).
* *proc* which is the top-level module for the compiler, it contains for example 
   the *compile_text()* function which compiles a serie of ASN.1 modules into
   Python objects
   
This compiler support most of the ASN.1 language features, including parameterization and
class objects and sets (especially useful when working with table constraints).
It has however few restrictions, the biggest being the need for the left part of the ASN.1
assignment *::=* being on a single line. Also, old-school ASN.1 macros are not supported ;
hence, the compiler cannot parse SNMP MIBs. 


pycrate_asn1dir
---------------

This subdirectory contains several ASN.1 specifications that are supported and 
precompiled for pycrate. Very few specifications have been changed in order to
work with pycrate :
* Q.775, in which the terrible *AllPackagesAS* is commented out
* Q.773 and Q.775, in which the *TCInvokeIdSet* constraint is modified to be easier
   used as a set of values
That's all !


pycrate_asn1rt
--------------

This subdirectory contains the ASN.1 runtime, that is loaded and used by the ASN.1 
specifications compiled with the compiler in *pycrate_asn1c*. It supports 
the PER encoding rules (aligned and not, canonical also), and the BER, CER and 
DER encoding rules.


pycrate_csn1
------------

This subdirectory contains a CSN.1 to Python translater in the file *trans.py*,
and a CSN.1 runtime in the file *csnobj.py*, in order to encode and decode CSN.1 
structures translated to Python objects.


pycrate_csn1dir
---------------

This dubdirectory contains some CSN.1 structures extracted from 3GPP specifications
(in the .csn files), and translated into Python objects.


pycrate_mobile
--------------

This subdirectory implements several 3GPP NAS protocol formats:
* *GSMTAP* with the gsmtap header format
* *MCC_MNC* with dictionnaries for MCC and MNC look-ups
* *TS24007* with basic formats from the TS 24.007 specification
* *TS24008_IE* with formats supporting many information elements from TS 24.008
* *TS24008_MM* with formats for encoding / decoding mobility management messages from TS 24.008
* *TS24008_GMM* with formats for encoding / decoding GPRS mobility management messages from TS 24.008
* *TS24301_IE* with formats supporting some information elements from TS 24.301


Usage
=====

Most of the modules have doc strings. I try also to write readable sources and to
comment them as much as possible for understanding them easily (and to allow also
myself to understand my own code years after...).
In a near future, a wiki may be provided to bring examples and methods on how to
use the different modules (any contribution on this would be very welcomed, too).
Finally, the code provided in the *test/* subdirectory is also representative on
how to use the different modules.


ASN.1 usage
===========

When a Python module from *pycrate_asn1dir/* is loaded, it creates Python classes
corresponding to ASN.1 module (all dash characters are converted to underscore).
Each ASN.1 object has a corresponding Python instance, exposing the following methods:
* from_asn1() / to_asn1(), which converts ASN.1 textual value to Python value and back
* from_aper() / to_aper(), which converts aligned PER encoded value to Python value and back
* from_uper() / to_uper(), which converts unaligned PER
* from_ber() / to_ber(), which converts BER
* from_cer() / to_cer(), which converts CER
* from_der() / to_der(), which converts DER

All the methods useful for working with ASN.1 objects at runtime can be found in 
the file *pycrate_asn1rt/asnobj.py*.


Tools
=====

Three different tools are provided (yet):
* *pycrate_showmedia.py* parses some media files (jpg, bmp, gif, mp3, png, 
   tiff, mpeg4) and pretty print the file structure on the standard output.
* *pycrate_asn1compile.py* compiles ASN.1 source file(s) and produce a Python
   source file that makes use of the ASN.1 runtime. This source file is then
   usable to encode / decode any ASN.1 object from the compiled ASN.1 
   specification.
* *pycrate_berdecode.py* parses any BER/CER/DER encoded binary value of ASN.1 
   objects and prints the corresponding structure.


Examples
========

It is possible to test the *pycrate_showmedia.py* tool with media test files 
provided in *./test/res/*, or any other supported media file.

```console
$ ./tools/pycrate_showmedia.py --help
usage: pycrate_showmedia.py [-h] [-bl BL] [-wt] input

print the internal structure of the input media file,supported formats are:
BMP, GIF, JPEG, MP3, MPEG4, PNG, TIFF

positional arguments:
  input       input media file

optional arguments:
  -h, --help  show this help message and exit
  -bl BL      maximum length for buffer representation
  -wt         show also absent / transparent fields

$ ./tools/pycrate_showmedia.py ./test/res/xkcd_wireless_signal.png 
### PNG ###
 <sig [PNG signature] : '\x89PNG\r\n\x1a\n'>
     ### PNGBody ###
      ### PNGChunk ###
       <len [chunk length] : 13>
       <type [chunk type] : 'IHDR'>
       ### IHDR ###
        <width : 238>
        <height : 415>
        <depth [bit depth] : 8>
        <color [color type] : 0>
        <comp [compression method] : 0>
        <filter [filter method] : 0>
        <interlace [interlace method] : 0>
       <crc [chunk CRC32] : 0x7d8cb12e>
      ### PNGChunk ###
       <len [chunk length] : 9>
       <type [chunk type] : 'pHYs'>
       <data [chunk data] :
        00 00 0c 4e 00 00 0c 4e 01                      | '\x00\x00\x0cN\x00\x00\x0cN\x01'>
       <crc [chunk CRC32] : 0x7f778c23>
      ### PNGChunk ###
       <len [chunk length] : 792>
       <type [chunk type] : 'iCCP'>
       <data [chunk data] :
        50 68 6f 74 6f 73 68 6f 70 20 49 43 43 20 70 72 | 'Photoshop ICC pr'
        6f 66 69 6c 65 00 00 78 da 63 60 60 9e e0 e8 e2 | 'ofile\x00\x00x\xdac``\x9e\xe0\xe8\xe2'
        e4 ca 24 c0 c0 50 50 54 52 e4 1e e4 18 19 11 19 | '\xe4\xca$\xc0\xc0PPTR\xe4\x1e\xe4\x18\x19\x11\x19'
        a5 c0 7e 9e 81 8d 81 99 81 81 81 81 81 21 31 b9 | '\xa5\xc0~\x9e\x81\x8d\x81\x99\x81\x81\x81\x81\x81!1\xb9'
        b8 c0 31 20 c0 87 81 81 81 21 2f 3f 2f 95 01 15 | '\xb8\xc01 \xc0\x87\x81\x81\x81!/?/\x95\x01\x15'
        30 32 30 7c bb c6 c0 c8 c0 c0 c0 70 59 d7 d1 c5 | '020|\xbb\xc6\xc0\xc8\xc0\xc0\xc0pY\xd7\xd1\xc5'
        c9 95 81 34 c0 9a 5c 50 54 c2 c0 c0 70 80 81 81 | '\xc9\x95\x814\xc0\x9a\\PT\xc2\xc0\xc0p\x80\x81\x81'
        c1 28 25 b5 38 99 81 81 e1 0b 03 03 43 7a 79 49 | '\xc1(%\xb58\x99\x81\x81\xe1\x0b\x03\x03CzyI'
        41 09 03 03 63 0c 03 03 83 48 52 76 41 09 03 03 | 'A\t\x03\x03c\x0c\x03\x03\x83HRvA\t\x03\x03'
        63 01 03 03 83 48 76 48 90 33 03 03 63 0b 03 03 | 'c\x01\x03\x03\x83HvH\x903\x03\x03c\x0b\x03\x03'
        13 4f 49 6a 45 09 03 03 03 83 73 7e 41 65 51 66 | '\x13OIjE\t\x03\x03\x03\x83s~AeQf'
        7a 46 89 82 a1 a5 a5 a5 82 63 4a 7e 52 aa 42 70 | 'zF\x89\x82\xa1\xa5\xa5\xa5\x82cJ~R\xaaBp'
        65 71 49 6a 6e b1 82 67 5e 72 7e 51 41 7e 51 62 | 'eqIjn\xb1\x82g^r~QA~Qb'
        49 6a 0a 03 03 03 d4 0e 06 06 06 06 5e 97 fc 12 | 'Ij\n\x03\x03\x03\xd4\x0e\x06\x06\x06\x06^\x97\xfc\x12'
        05 f7 c4 cc 3c 05 23 03 55 06 2a 83 88 c8 28 05 | '\x05\xf7\xc4\xcc<\x05#\x03U\x06*\x83\x88\xc8(\x05'
        08 0b 11 3e 08 31 04 48 2e 2d 2a 83 07 25 03 83 | '\x08\x0b\x11>\x081\x04H.-*\x83\x07%\x03\x83'
        00 83 02 83 01 83 03 43 00 43 22 43 3d c3 02 86 | '\x00\x83\x02\x83\x01\x83\x03C\x00C"C=\xc3\x02\x86'
        a3 0c 6f 18 c5 19 5d 18 4b 19 57 30 de 63 12 63 | '\xa3\x0co\x18\xc5\x19]\x18K\x19W0\xdec\x12c'
        0a 62 9a c0 74 81 59 98 39 92 79 21 f3 1b 16 4b | '\nb\x9a\xc0t\x81Y\x989\x92y!\xf3\x1b\x16K'
        96 0e 96 5b ac 7a ac ad ac f7 d8 2c d9 a6 b1 7d | '\x96\x0e\x96[\xacz\xac\xad\xac\xf7\xd8,\xd9\xa6\xb1}'
        63 0f 67 df cd a1 c4 d1 c5 f1 85 33 91 f3 02 97 | 'c\x0fg\xdf\xcd\xa1\xc4\xd1\xc5\xf1\x853\x91\xf3\x02\x97'
        23 d7 16 6e 4d ee 05 3c 52 3c 53 79 85 78 27 f1 | "#\xd7\x16nM\xee\x05<R<Sy\x85x'\xf1"
        09 f3 4d e3 97 e1 5f 2c a0 23 b0 43 d0 55 f0 8a | '\t\xf3M\xe3\x97\xe1_,\xa0#\xb0C\xd0U\xf0\x8a'
        50 aa d0 0f e1 5e 11 15 91 bd a2 e1 a2 5f c4 26 | 'P\xaa\xd0\x0f\xe1^\x11\x15\x91\xbd\xa2\xe1\xa2_\xc4&'
        89 1b 89 5f 91 a8 90 94 93 3c 26 95 2f 2d 2d 7d | '\x89\x1b\x89_\x91\xa8\x90\x94\x93<&\x95/--}'
        42 a6 4c 56 5d f6 96 5c 9f bc 8b fc 1f 85 ad 8a | 'B\xa6LV]\xf6\x96\\\x9f\xbc\x8b\xfc\x1f\x85\xad\x8a'
        85 4a 7a 4a 6f 95 d7 aa 14 a8 9a a8 fe 54 3b a8 | '\x85JzJo\x95\xd7\xaa\x14\xa8\x9a\xa8\xfeT;\xa8'
        de a5 11 aa a9 a4 f9 41 eb 80 f6 24 9d 54 5d 2b | '\xde\xa5\x11\xaa\xa9\xa4\xf9A\xeb\x80\xf6$\x9dT]+'
        3d 41 bd 57 fa 47 0c 16 18 d6 1a c5 18 db 9a c8 | '=A\xbdW\xfaG\x0c\x16\x18\xd6\x1a\xc5\x18\xdb\x9a\xc8'
        9b 32 9b be 34 bb 60 be d3 62 89 e5 04 ab 3a eb | '\x9b2\x9b\xbe4\xbb`\xbe\xd3b\x89\xe5\x04\xab:\xeb'
        5c 9b 38 db 40 3b 57 7b 6b 07 63 47 1d 27 35 67 | "\\\x9b8\xdb@;W{k\x07cG\x1d'5g"
        25 17 05 57 79 37 05 77 65 0f 75 4f 5d 2f 13 6f | '%\x17\x05Wy7\x05we\x0fuO]/\x13o'
        1b 1f 77 df 60 bf 04 ff fc 80 fa c0 89 41 4b 83 | '\x1b\x1fw\xdf`\xbf\x04\xff\xfc\x80\xfa\xc0\x89AK\x83'
        77 85 5c 0c 7d 19 ce 14 21 17 69 15 15 11 5d 11 | 'w\x85\\\x0c}\x19\xce\x14!\x17i\x15\x15\x11]\x11'
        33 33 76 4f dc 83 04 b6 44 dd a4 b0 e4 86 94 35 | '33vO\xdc\x83\x04\xb6D\xdd\xa4\xb0\xe4\x86\x945'
        a9 37 d3 39 32 2c 32 33 b3 e6 66 5f cc 65 cf b3 | '\xa97\xd392,23\xb3\xe6f_\xcce\xcf\xb3'
        cf af 28 d8 54 f8 ae 58 bb 24 ab 74 55 d9 9b 0a | '\xcf\xaf(\xd8T\xf8\xaeX\xbb$\xabtU\xd9\x9b\n'
        fd ca 92 aa 5d 35 8c b5 5e 75 53 eb 1f 36 ea 35 | '\xfd\xca\x92\xaa]5\x8c\xb5^uS\xeb\x1f6\xea5'
        d5 34 9f 6d 95 6b 2b 6c 3f da 29 dd 55 d4 7d ba | '\xd54\x9fm\x95k+l?\xda)\xddU\xd4}\xba'
        57 b5 af b1 ff ee 44 9b 49 b3 27 ff 9d 1a 3f ed | "W\xb5\xaf\xb1\xff\xeeD\x9bI\xb3'\xff\x9d\x1a?\xed"
        f0 0c 8d 99 fd b3 be cf 49 98 7b 7a be f9 82 a5 | '\xf0\x0c\x8d\x99\xfd\xb3\xbe\xcfI\x98{z\xbe\xf9\x82\xa5'
        8b 44 16 b7 2e f9 b6 2c 73 f9 bd 95 21 ab 4e af | '\x8bD\x16\xb7.\xf9\xb6,s\xf9\xbd\x95!\xabN\xaf'
        71 59 bb 6f bd e5 86 6d 9b 4c 36 6f d9 6a b2 6d | 'qY\xbbo\xbd\xe5\x86m\x9bL6o\xd9j\xb2m'
        fb 0e ab 9d fb 77 bb ee 39 bb 2f 6c ff 83 83 39 | '\xfb\x0e\xab\x9d\xfbw\xbb\xee9\xbb/l\xff\x83\x839'
        87 7e 1e 69 3f 26 7e 7c c5 49 eb 53 e7 ce 24 9f | '\x87~\x1ei?&~|\xc5I\xebS\xe7\xce$\x9f'
        fd 75 7e d2 45 ed 4b 47 af 24 5e fd 77 7d ce 4d | '\xfdu~\xd2E\xedKG\xaf$^\xfdw}\xceM'
        9b 5b 77 ef d4 df 53 be 7f e2 61 de 63 b1 27 fb | "\x9b[w\xef\xd4\xdfS\xbe\x7f\xe2a\xdec\xb1'\xfb"
        9f 65 be 10 79 79 f0 75 fe 5b f9 77 17 3e 34 7d | '\x9fe\xbe\x10yy\xf0u\xfe[\xf9w\x17>4}'
        32 fd fc ea eb 82 ef e1 3f 05 7e 9d fa d3 fa cf | '2\xfd\xfc\xea\xeb\x82\xef\xe1?\x05~\x9d\xfa\xd3\xfa\xcf'
        f1 ff 7f 00 0d 00 0f 34                         | '\xf1\xff\x7f\x00\r\x00\x0f4'>
       <crc [chunk CRC32] : 0xfa96f15d>
      ### PNGChunk ###
       <len [chunk length] : 32>
       <type [chunk type] : 'cHRM'>
       <data [chunk data] :
        00 00 6e 27 00 00 73 af 00 00 df f2 00 00 83 30 | "\x00\x00n'\x00\x00s\xaf\x00\x00\xdf\xf2\x00\x00\x830"
        00 00 77 43 00 00 c8 0a 00 00 34 95 00 00 2e dc | '\x00\x00wC\x00\x00\xc8\n\x00\x004\x95\x00\x00.\xdc'>
       <crc [chunk CRC32] : 0x20bf171a>
      ### PNGChunk ###
       <len [chunk length] : 21130>
       <type [chunk type] : 'IDAT'>
       <data [chunk data] :
        78 da ed bd 79 50 8d fd 1f ff ff bc ce 39 73 4e | 'x\xda\xed\xbdyP\x8d\xfd\x1f\xff\xff\xbc\xce9sN'
        db b4 37 95 32 b4 19 94 06 2d 7e 11 26 b2 fc 10 | '\xdb\xb47\x952\xb4\x19\x94\x06-~\x11&\xb2\xfc\x10'
        46 22 23 61 90 65 ec 3f 64 f9 d9 bf c8 32 f6 41 | 'F"#a\x90e\xec?d\xf9\xd9\xbf\xc82\xf6A'
        dc 8d 7d 90 65 ec 83 dc 8c fd 77 13 19 b2 0c 92 | '\xdc\x8d}\x90e\xec\x83\xdc\x8c\xfdw\x13\x19\xb2\x0c\x92'
        26 a9 a6 bd 69 3d 73 ce 79 fe fe b8 ae 93 4a e9 | '&\xa9\xa6\xbdi=s\xcey\xfe\xfe\xb8\xae\x93J\xe9'
        94 ea be ef cf ed fd 8f e3 5c 57 d7 b9 1e d7 f5 | '\x94\xea\xbe\xef\xcf\xed\xfd\x8f\xe3\\W\xd7\xb9\x1e\xd7\xf5'
        5e 5e fb 1b 81 f8 0f b5 ff 0b 90 59 fd 67 9a 1c | '^^\xfb\x1b\x81\xf8\x0f\xb5\xff\x0b\x90Y\xfdg\x9a\x1c'
        80 2b ff 33 cd e7 37 ee 6f dc df b8 bf 71 7f e3 | '\x80+\xff3\xcd\xe77\xeeo\xdc\xdf\xb8\xbfq\x7f\xe3'
        fe c6 fd 8d fb 1b f7 37 6e cb e2 ae 8b fc f1 bb | '\xfe\xc6\xfd\x8d\xfb\x1b\xf77n\xcb\xe2\xae\x8b\xfc\xf1\xbb'
        0b f3 35 35 fe 5f 7a 78 42 77 af be 1b 72 ea be | '\x0b\xf355\xfe_zxBw\xaf\xbe\x1br\xea\xbe'
        42 f9 eb fa 7f 38 f7 c5 b7 9f dd 57 f6 e5 93 8f | 'B\xf9\xeb\xfa\x7f8\xf7\xc5\xb7\x9f\xddW\xf6\xe5\x93\x8f'
        b4 35 bf 7a a5 23 c9 a2 c4 94 ea bf 3f f7 64 f5 | '\xb45\xbfz\xa5#\xc9\xa2\xc4\x94\xea\xbf?\xf7d\xf5'
        53 34 b7 2a aa 3e 67 cc 5e 5a d4 18 5c 77 73 5d | 'S4\xb7*\xaa>g\xcc^Z\xd4\x18\\ws]'
        81 f8 a9 e4 40 ae f8 e1 8b b5 7d 25 49 26 38 f8 | '\x81\xf8\xa9\xe4@\xae\xf8\xe1\x8b\xb5}%I&8\xf8'
        a6 90 e4 05 7b 98 f9 06 39 a1 7b e2 c6 b9 a3 7b | '\xa6\x90\xe4\x05{\x98\xf9\x069\xa1{\xe2\xc6\xb9\xa3{'
        74 71 73 0c ac ac 7e 85 85 f2 37 f5 d0 3c ed 21 | 'tqs\x0c\xac\xac~\x85\x85\xf27\xf5\xd0<\xed!'
        00 d6 53 8b 2a 4a d3 9e 9c db b9 68 e2 83 ea 07 | '\x00\xd6S\x8b*J\xd3\x9e\x9c\xdb\xb9h\xe2\x83\xea\x07'
        af 0d 2e de 61 04 c0 29 56 47 92 7c 7d 54 47 f2 | '\xaf\r.\xdea\x04\xc0)VG\x92|}TG\xf2'
        1c 0e 90 19 11 4a a0 4f f6 f7 eb 00 63 4b 48 6e | '\x1c\x0e\x90\x19\x11J\xa0O\xf6\xf7\xeb\x00cKHn'
        b2 7f 4f 92 fb 71 49 7f 24 b3 2d 30 b5 61 5c 9f | '\xb2\x7fO\x92\xfbqI\x7f$\xb3-0\xb5a\\\x9f'
        39 fa 4f f6 ed f6 20 93 24 57 7a 62 26 49 b2 c2 | '9\xfaO\xf6\xed\xf6 \x93$Wzb&I\xb2\xc2'
        1f 27 49 32 cf d2 18 3d 75 64 92 bc eb 0d 35 a9 | "\x1f'I2\xcf\xd2\x18=ud\x92\xbc\xeb\r5\xa9"
        0d 81 00 58 74 ec e2 21 1f 52 fd 52 09 f2 ee 9a | '\r\x81\x00Xt\xec\xe2!\x1fR\xfdR\t\xf2\xee\x9a'
        d2 62 92 e4 7e cf 7c 52 d7 7b b5 74 e4 b1 a9 e9 | '\xd2b\x92\xe4~\xcf|R\xd7{\xb5t\xe4\xb1\xa9\xe9'
        f4 5d cb 83 6d 57 98 88 6a 99 ca ca ba ff cd aa | '\xf4]\xcb\x83mW\x98\x88j\x99\xca\xca\xba\xff\xcd\xaa'
        bf 9b 82 38 93 5e f7 92 0e 79 60 5c c5 e1 10 5d | '\xbf\x9b\x828\x93^\xf7\x92\x0ey`\\\xc5\xe1\x10]'
        91 2d d6 92 0c 43 3a 1f da 08 43 76 4e c0 a0 2a | '\x91-\xd6\x92\x0cC:\x1f\xda\x08CvN\xc0\xa0*'
        26 2f 00 fd 4b c9 de 88 24 c9 65 b8 af 3f 34 04 | '&/\x00\xfdK\xc9\xde\x88$\xc9e\xb8\xaf?4\x04'
        ab bd 15 99 0d e2 76 74 d4 7f 32 ee 7a 08 7f 92 | '\xab\xbd\x15\x99\r\xe2vt\xd4\x7f2\xeez\x08\x7f\x92'
        64 90 51 77 ac 21 c9 09 88 22 49 ae c0 91 d9 b8 | 'd\x90Qw\xac!\xc9\t\x88"I\xae\xc0\x91\xd9\xb8'
        40 ae c1 61 92 d4 f9 2a 4d c7 56 90 a4 d8 3f b3 | '@\xae\xc1a\x92\xd4\xf9*M\xc7V\x90\xa4\xd8?\xb3'
        c2 1e 93 64 7e 3b c5 bd f1 4a 58 44 15 52 6d af | '\xc2\x1e\x93d~;\xc5\xbd\xf1JXD\x15Rm\xaf'
        fa 4c aa db 59 a9 49 92 5a 4f e5 13 92 e4 84 9e | '\xfaL\xaa\xdbY\xa9I\x92ZO\xe5\x13\x92\xe4\x84\x9e'
        53 30 ea d2 8b fc ee 42 5f 15 76 50 e3 b3 9b 24 | 'S0\xea\xd2\x8b\xfc\xeeB_\x15vP\xe3\xb3\x9b$'
        fd 6d a6 0a 2f 48 96 8f c7 a6 70 05 af 00 e6 c5 | '\xfdm\xa6\n/H\x96\x8f\xc7\xa6p\x05\xaf\x00\xe6\xc5'
        a4 87 3d 13 4d 4c 2f 93 5c 85 f7 e2 1d 6a 7b 63 | '\xa4\x87=\x13ML/\x93\\\x85\xf7\xe2\x1dj{c'
        e3 3d 17 84 91 6e 50 66 93 0c c3 17 e9 e6 2f 63 | '\xe3=\x17\x84\x91nPf\x93\x0c\xc3\x17\xe9\xe6/c'
        84 ee 20 76 34 88 1b 8d 97 e2 87 62 04 5d c5 31 | '\x84\xee v4\x88\x1b\x8d\x97\xe2\x87b\x04]\xc51'
        92 8c 44 4a 7b 4c d1 70 17 fa 57 92 64 a5 95 ab | '\x92\x8cDJ{L\xd1p\x17\xfaW\x92d\xa5\x95\xab'
        36 cb bc ab 8e c9 d8 48 92 eb 10 81 b9 d5 2e f1 | '6\xcb\xbc\xab\x8e\xc9\xd8H\x92\xeb\x10\x81\xb9\xd5.\xf1'
        cc d4 e4 15 c9 49 58 ef 0f a7 80 1e f0 2d 4f c5 | '\xcc\xd4\xe4\x15\xc9IX\xef\x0f\xa7\x80\x1e\xf0-O\xc5'
        78 92 1c 2f 5d fb 1a 96 49 63 8d 89 d8 45 de c7 | 'x\x92\x1c/]\xfb\x1a\x96Ic\x8d\x89\xd8E\xde\xc7'
        0c be 75 56 a5 e5 41 95 4a d2 aa cf 72 64 91 a4 | '\x0c\xbeuV\xa5\xe5A\x95J\xd2\xaa\xcfrd\x91\xa4'
        d6 a5 fd 78 68 f6 23 0c fb 49 74 2b 70 36 be 4f | '\xd6\xa5\xfdxh\xf6#\x0c\xfbIt+p6\xbeO'
        92 da 27 d2 0f 5d c2 44 b2 a2 07 4e b1 ad 80 18 | "\x92\xda'\xd2\x0f]\xc2D\xb2\xa2\x07N\xb1\xad\x80\x18"
        92 5e 32 fd 78 ef 23 4f 65 a1 79 97 06 71 6f 60 | '\x92^2\xfdx\xef#Oe\xa1y\x97\x06qo`'
        8f f8 a1 08 41 4f b0 9d 24 17 21 35 cd 1b 63 1f | '\x8f\xf8\xa1\x08AO\xb0\x9d$\x17!5\xcd\x1bc\x1f'
        c9 dd c4 b1 7c 1b ab c9 45 b8 c1 74 2c ce ca 7c | '\xc9\xdd\xc4\xb1|\x1b\xab\xc9E\xb8\xc1t,\xce\xca|'
        30 01 1d 92 b0 aa fa 35 ee c8 ba ea 78 11 fd 0e | '0\x01\x1d\x92\xb0\xaa\xfa5\xee\xc8\xba\xeax\x11\xfd\x0e'
        62 b9 86 9c 8e f5 27 70 8e 24 63 c4 7f b8 0b d7 | "b\xb9\x86\x9c\x8e\xf5'p\x8e$c\xc4\x7f\xb8\x0b\xd7"
        c8 37 09 ef 49 26 62 1b b9 08 2f c8 eb 58 92 09 | '\xc87\t\xefI&b\x1b\xb9\x08/\xc8\xebX\x92\t'
        4c 23 35 18 b3 1d e2 24 17 89 49 c8 da 85 7b 16 | 'L#5\x18\xb3\x1d\xe2$\x17\x89I\xc8\xda\x85{\x16'
        7e a4 cc 37 0a 27 6a de 7c 98 2c 8b 64 aa 85 53 | "~\xa4\xcc7\n'j\xde|\x98,\x8bd\xaa\x85S"
        99 9d 97 6d 47 92 ae d6 fa 79 4a 18 4c 72 38 52 | '\x99\x9d\x97mG\x92\xae\xd6\xfayJ\x18Lr8R'
        1a c2 cd c2 24 e9 c9 c3 27 11 9b 49 72 0d 12 59 | "\x1a\xc2\xcd\xc2$\xe9\xc9\xc3'\x11\x9bIr\r\x12Y"
        d2 07 2a e3 57 e2 91 55 78 40 be 17 86 32 1f 32 | '\xd2\x07*\xe3W\xe2\x91Ux@\xbe\x17\x862\x1f2'
        00 e8 9d 96 04 6b 57 e7 80 8f 55 17 99 8d 83 a9 | '\x00\xe8\x9d\x96\x04kW\xe7\x80\x8fU\x17\x99\x8d\x83\xa9'
        76 36 e9 43 8c cb 49 56 d8 76 5c 85 4f 24 79 56 | 'v6\xe9C\x8c\xcbIV\xd8v\\\x85O$yV'
        ec 0d 4c 44 f7 ad 5d 00 0c cc e7 43 ec 22 bb 38 | '\xec\rLD\xf7\xad]\x00\x0c\xcc\xe7C\xec"\xbb8'
        68 5e fc b1 d9 d8 3d 05 96 b2 97 ac 44 d4 51 5c | 'h^\xfc\xb1\xd9\xd8=\x05\x96\xb2\x97\xacD\xd4Q\\'
        23 49 46 21 0c 1f 62 91 38 19 89 b4 73 56 05 d5 | '#IF!\x0c\x1fb\x918\x19\x89\xb4sV\x05\xd5'
        ba 79 3b 5f 8a f7 77 d4 ca 67 1e fe 22 15 ee d2 | '\xbay;_\x8a\xf7w\xd4\xcag\x1e\xfe"\x15\xee\xd2'
        91 a3 d8 5b fc e1 cb 51 fd ab fb c9 cc ec ee 21 | '\x91\xa3\xd8[\xfc\xe1\xcbQ\xfd\xab\xfb\xc9\xcc\xec\xee!'
        7d 70 6e f3 18 ce c1 c1 6d 8c 81 44 32 cf 51 ba | '}pn\xf3\x18\xce\xc1\xc1m\x8c\x81D2\xcfQ\xba'
        ...>
       <crc [chunk CRC32] : 0xa9fbdd38>
      ### PNGChunk ###
       <len [chunk length] : 0>
       <type [chunk type] : 'IEND'>
       <data [chunk data] : >
       <crc [chunk CRC32] : 0xae426082>
```

It is possible to test the *pycrate_asn1compile.py* tool with some test ASN.1 
specification from *./test/res/*, or any other valid ASN.1 specification of your
choice.

```console
$ ./tools/pycrate_asn1compile.py --help
usage: pycrate_asn1compile.py [-h] [-i INPUT [INPUT ...]] [-o OUTPUT]
                              [-fautotags] [-fextimpl] [-fverifwarn]

compile ASN.1 input file(s) for the pycrate ASN.1 runtime

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT [INPUT ...]  ASN.1 input file(s) or directory
  -o OUTPUT             compiled output Python source file
  -fautotags            force AUTOMATIC TAGS for all ASN.1 modules
  -fextimpl             force EXTENSIBILITY IMPLIED for all ASN.1 modules
  -fverifwarn           force warning instead of raising during the
                        verification stage
```

After compiling a module, it is possible to load it in Python and use it for
encoding / decoding any objects defined in it.

```python
Python 3.4.3 (default, Nov 17 2016, 01:08:31) 
[GCC 4.8.4] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> HardcoreSyntax # this is the only ASN.1 module provided in Hardcore.asn
<class 'Hardcore.HardcoreSyntax'>
>>> Final = HardcoreSyntax.Final # this is the Final object defined at line 115
>>> Final
<Final (SEQUENCE)>
>>> Final.get_proto() # warning: this does not show optional or extended component
{
w1: {
 r10: {
  low: 'INTEGER',
  high: 'INTEGER',
  bool: 'BOOLEAN',
  null: 'NULL'
  },
 r90: {
  low: 'INTEGER',
  high: 'INTEGER',
  bool: 'BOOLEAN',
  null: 'NULL'
  }
 },
w2: {
 r10: {
  low: 'INTEGER',
  high: 'INTEGER',
  bool: 'BOOLEAN',
  null: 'NULL'
  },
 r90: {
  low: 'INTEGER',
  high: 'INTEGER',
  bool: 'BOOLEAN',
  null: 'NULL'
  }
 },
bool: 'BOOLEAN'
}
>>> V = { \
... 'w1':{'r10':{'low':5, 'high':50, 'bool':False}, 'r90':{'low':50, 'high':95, 'bool':False, 'null':0}}, \
... 'w2':{'r10':{'low':1, 'high':10, 'bool':False}, 'r90':{'low':90, 'high':100, 'bool':True}}, \
... 'bool': True})
>>> Final.set_val(V)
>>> print(Final.to_asn1()) # .to_asn1() returns a printable ASN.1 representation of the value
{
  w1 {
    r10 {
      low 5,
      high 50,
      bool FALSE
    },
    r90 {
      low 50,
      high 95,
      bool FALSE,
      null NULL
    }
  },
  w2 {
    r10 {
      low 1,
      high 10,
      bool FALSE
    },
    r90 {
      low 90,
      high 100,
      bool TRUE
    }
  },
  bool TRUE
}
>>> Final.to_aper() # aligned PER
b'*\x85\x92\x80@\x01\x00\x08\x02\xd5`'
>>> Final.to_uper() # unaligned PER
b'*\x85\x92\x80@@\x02\x00\xb5X'
>>> Final.to_ber()
b'05\xa0\x18\xa0\t\x80\x01\x05\x81\x012\x82\x01\x00\xa1\x0b\x80\x012\x81\x01_\x82\x01\x00\x83\x00\xa1\x16\xa0\t\x80\x01\x01\x81\x01\n\x82\x01\x00\xa1\t\x80\x01Z\x81\x01d\x82\x01\xff\x82\x01\xff'
>>> Final.to_cer()
b'0\x80\xa0\x80\xa0\x80\x80\x01\x05\x81\x012\x82\x01\x00\x00\x00\xa1\x80\x80\x012\x81\x01_\x82\x01\x00\x83\x00\x00\x00\x00\x00\xa1\x80\xa0\x80\x80\x01\x01\x81\x01\n\x82\x01\x00\x00\x00\xa1\x80\x80\x01Z\x81\x01d\x82\x01\xff\x00\x00\x00\x00\x82\x01\xff\x00\x00'
>>> Final.to_der()
b'05\xa0\x18\xa0\t\x80\x01\x05\x81\x012\x82\x01\x00\xa1\x0b\x80\x012\x81\x01_\x82\x01\x00\x83\x00\xa1\x16\xa0\t\x80\x01\x01\x81\x01\n\x82\x01\x00\xa1\t\x80\x01Z\x81\x01d\x82\x01\xff\x82\x01\xff'
>>> Final.from_ber( Final.to_ber() )
>>> Final() == V # or Final._val == V
True
```

For more information about the API exposed for each ASN.1 object, you can check
the docstrings of all ASN.1 objects, and also read the source file *pycrate_asn1rt/asnobj.py*.

