What is pycrate
===============

Pycrate is a french word for qualifying bad wine (when it's close to vinegar !).
The present software library has nothing to do with wine (except it is developped in France), 
it is simply a Python library for manipulating various digital formats in an easy way,
with a funny name.
It is the glorious successor of [libmich](https://github.com/mitshell/libmich), 
which was started back in 2009, served well and retired in 2017.

It provides basically a runtime for encoding and decoding data structures, including
CSN.1 and ASN.1. Additionally, it features a 3G and LTE mobile core network.


License
=======

The whole library is licensed under LGPL v2.1 and is compatible with more recent 
version of the LGPL: all licensed files have an header making it self-explanatory.
For more details, please report to the 
[license.txt](https://github.com/P1sec/pycrate/blob/master/license.txt) file.


Wiki
====

Pycrate has a growing [wiki](https://github.com/p1sec/pycrate/wiki/The-pycrate-wiki).
Use it as much as possible before opening an issue.
Feel free also to propose some additional content.


Installation
============

Operating systems and Python version
------------------------------------

The library is designed to work with both Python 2 (2.7) and Python 3 (3.4, 3.5 and greater), 
from the official Python implementation [CPython](https://www.python.org/).
It is also supporting alternative Python engine such as [pypy](http://pypy.org/),
[nuitka](http://nuitka.net/) or [Cython](https://cython.org/).
It is regularly tested both on Linux and Windows, and should actually work on any
operating system which has [r|d]ecent Python support (as in 2017, 2018 and more...).


Dependencies
------------

Currently none. Only the Python builtins and few internal modules of Python 
(e.g. os, system, re, struct, datetime) are required for most of the features. 
The json internal module is required for supporting the JSON API.
If you want to run pycrate in Python2 (which is bad !), you will however need to
install the [enum34](https://pypi.org/project/enum34/) package.

The _pycrate\_ether/SCTP_ module can optionally use the external 
[crc32c](https://pypi.org/project/crc32c/) module from ICRAR.

The _pycrate\_mobile/TS24301\_EMM_ and _pycrate\_mobile/TS24501\_FGMM_ modules use 
[CryptoMobile](https://github.com/p1sec/CryptoMobile) as optional dependency to 
encrypt and decrypt LTE and 5G NAS messages.

The _pycrate\_corenet_ part requires also [pysctp](https://pypi.org/project/pysctp/) 
and [CryptoMobile](https://github.com/p1sec/CryptoMobile) to run.

The _pycrate\_diameter/parse\_iana\_diameter\_xml.py_ file uses 
[lxml](https://pypi.org/project/lxml/) to translate xml files from IANA to Python 
dictionnaries ; this is however not required for standard runtime.

The _pycrate\_osmo/SEDebugMux.py_ module relies on the [crcmod](https://pypi.org/project/crcmod/)
to compute CRC in the frame format.


Automatic installation
----------------------

An installation script is available.
As soon as you have cloned or downloaded the repository, you can use it to install
the library within your Python package directory:

```
python setup.py install
```

Run it as superuser for a system-wide install, or as-is for a user home-directory 
level install. You can also run _develop_ instead of _install_ if you want a 
developer-friendly installation.

It is also possible to test the library before installing it
(this will create two local directories *./test_asn/* and *./pycrate.egg-info/* that
you can just delete afterwards):

```
python -m unittest test.test_pycrate
```

Or to build the library without installing it in the system:

```
python setup.py build
```

It is also possible to recompile all ASN.1 modules, this will take few minutes
(but if I did not do any mistake, all ASN.1 modules provided in *./pycrate_asn1dir/*
should have been compiled with the latest version of the compiler):

```
python -m pycrate_asn1c.asnproc
```

More generally, installation is not required, and simply having all _pycrate\_*_ 
subdirectories into the PYTHONPATH enables to use the entire library.


Installation with pip
---------------------

Alternatively, you can install the library with the `pip` command:
```
pip install pycrate
```

The install package is available on [pypi](https://pypi.org/project/pycrate/).
It contains the library from the last tagged release on github.


Contributing
============

Contact and support
-------------------

This library is free software, and you are free to use it (or not to use it). 
In case you encounter a problem with it, first read this readme completely and 
check the wiki ; moreover many classes, methods and functions are documented with 
docstrings, and finally you can have a look at the source code.

If after all those steps, you still have a question or you think you found a bug,
please open an issue (see below). Specific support requires time and may not be always 
possible. In case you require such support, please consider also contributing in one 
way or another (see below, too).

In case you are using this library in any of your project and you find it useful,
do not hesitate to send me an email. It is always a pleasure to know where 
code provided on the Internet can end up...


Filling an issue
---------------

When filling an issue, please provide precise and contextual information about 
your case and the error you potentially encounter:
- indicate the version (or commit-level) of pycrate your are using, together with 
the version of Python.
- provide a code snippet that leads to the error you are facing, so that it can be
reproduced.
- provide the eventual stacktrace you are getting from Python
- provide additional and contextual information as needed (e.g. a specific ASN.1 
specification being used...)

This is the bare minimum if you want to get help.
And when you consider your issue has been addressed, please close it: "A good issue
is a closed one !" as would have said my great grandmother.


Extending the library
---------------------

If you are willing to extend the library, do not hesitate to contact me by
email or preferably through the github service (ideally, open a pull request).
For important changes, please elaborate about your need and provide some justification.
Any patch or submission is always very welcome!


Other contributions
-------------------

In case you do not want to deep dive in the code, you can still contribute in many ways:
* highlighting specific issues in the inner-working of the library,
and opening an issue with concrete debugging information 
* writing new test cases for more coverage (have a look at the *test/* directory)
* sending captures / real-world data that can be used for writing new test cases
* writing new parts of the wiki (have a look at the 
[pycrate wiki](https://github.com/p1sec/pycrate/wiki/The-pycrate-wiki))

Getting contributions is extremely important to encourage the continuous development
of the library, and to confirm the choice made to open-source it.


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
* *MPLS* with structures for MPLS label and header
* *Ethernet* with structures for Ethernet and VLAN headers
* *ARP* simply providing the structure for ARP
* *IP* with structures for IPv4, IPv6, ICMP, UDP and TCP
* *SCTP* with structures for SCTP headers and various chunks
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
* *asnproc* which is the top-level module for the compiler, it contains for example 
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
* Q.773 and Q.775, in which the *TCInvokeIdSet* constraint is modified to be
   used as a set of values
That's all !


pycrate_asn1rt
--------------

This subdirectory contains the ASN.1 runtime, that is loaded and used by the ASN.1 
specifications compiled with the compiler in *pycrate_asn1c*. It supports 
the PER encoding rules (aligned and not, canonical also), and the BER, CER, DER 
and JER encoding rules.


pycrate_csn1
------------

This subdirectory contains a CSN.1 to Python translater in the file *trans.py*,
and a CSN.1 runtime in the file *csnobj.py*, in order to encode and decode CSN.1 
structures translated to Python objects.


pycrate_csn1dir
---------------

This subdirectory contains CSN.1 structures extracted from 3GPP specifications
(in the .csn files), and translated into Python objects. The following specifications
have been used: TS 44.018, TS 44.060 and TS 24.008.


pycrate_mobile
--------------

This subdirectory implements most of the 3GPP NAS protocol formats:
* *GSMTAP*: gsmtap header format
* *MCC_MNC*: dictionnaries for MCC and MNC look-up
* *NAS*: provides two functions to parse any uplink and downlink mobile NAS messages
* *NASLTE*: provides two functions to parse LTE uplink and downlink NAS messages
* *NAS5G*: provides one function to parse 5G uplink and downlink mobile NAS messages
* *PPP*: structures for NCP and LCP protocols used for PPP connection estabishment
* *SCCP*: structures for SCCP user-data and management messages
* *SIGTRAN*: structures for SIGTRAN (mostly M2PA and M3UA) messages
* *TS102225*: structures for SIM card's Secured Packets from ETSI TS 102.225
* *TS23038*: structures and routines for SMS encoding from TS 23.038
* *TS23040_SMS*: structures for the SMS transport protocol from TS 23.040
* *TS23041_CBS*: structures for the Cell Broadcast Service protocol from TS 23.041
* *TS24007*: basic structures from the TS 24.007 specification, reused in most of the NAS protocols
* *TS24008_CC* : structures for call control messages from TS 24.008
* *TS24008_GMM*: structures for GPRS mobility management messages from TS 24.008
* *TS24008_IE*: structures for many information elements from TS 24.008
* *TS24008_MM*: structures for mobility management messages from TS 24.008
* *TS24008_SM*: structures for GPRS session management messages from TS 24.008
* *TS24011_PPSMS*: structures for the SMS point-to-point protocol from TS 24.011
* *TS24080_SS*: structures for the Supplementary Services protocol from TS 24.080, wrapping some MAP ASN.1 objects
* *TS24301_EMM*: structures for the EPS mobility management messages from TS 24.301
* *TS24301_ESM*: structures for the EPS session management messages from TS 24.301
* *TS24301_IE*: structures for many information elements from TS 24.301
* *TS24501_FGMM*: structures for the 5G mobility management messages from TS 24.501
* *TS24501_FGSM*: structures for the 5G session management messages from TS 24.501
* *TS24501_IE*: structures for many information elements from TS 24.501
* *TS24501_UEPOL*, *TS24526_UEPOL* and *TS24588_UEPOL*: structures for the 5G UE policy protocol from TS 24.501, 526 and 588
* *TS29002_MAPAppCtx*: functions that relies on the Pycrate_TCAP_MAPv2v3 ASN.1 module, dealing mostly with MAP application-contexts
* *TS29002_MAPIE*: structure for the MAP AddressString object from TS 29.002
* *TS29244_PFCP*: structure for PFCP messages from TS 29.244
* *TS29274_GTPC*: structures for LTE/EPC GTP-C messages from TS 29.274
* *TS29281_GTPU*: structures for LTE/EPC GTP-U messages from TS 29.281
* *TS31111_SAT*: basic structures and dict for the SIM application toolkit from TS 31.111
* *TS31115*: structures for SIM card's Secured Packets over SMS from TS 31.115
* *TS38415_PDUSess*: structure used in 5G user-place traffic (i.e. GTP-U) from TS 38.415
* *TS44018_GTTP*: structure for the single GSM GTTP message from TS 44.018
* *TS44018_IE*: structures for many information elements from TS 44.018
* *TS44018_RR*: structures for the GSM and GPRS radio ressources messages from TS 44.018


pycrate_diameter
----------------

This subdirectory contains the following modules:
* *parse_iana_diameter_xml*: to translate XML Diameter structures from IANA to Python
* *iana_diameter_dicts.py*: that is automatically created by the former, containing Diameter Python dicts
* *Diameter*: a generic Diameter module which implements DiameterGeneric and AVPGeneric structures
* *DiameterIETF*: a Diameter module which relies on AVP types provided in all IETF RFC
* *Diameter3GPP*: a Diameter module which relies on AVP types provided in all 3GPP TS


pycrate_osmo
------------

This subdirectory contains the following modules:
* *L1CTL*: structures used by osmocom-bb to communicate with the embedded stack from the host
* *SEDebugMux*: structure used by Sony-Ericsson SoC and basebands to wrap logs


pycrate_corenet
---------------

This subdirectory implements a signaling server that supports IuCS and IuPS over Iuh interfaces
(including HNBAP and RUA/RANAP) for interfacing with 3G femtocells, and S1 interfaces 
(including S1AP) for interfacing with LTE eNodeBs.
It handles many procedures to drive femtocells, eNodeBs and mobile terminals connecting
through them. In terms of services, it mostly support short messages and data connectivity.
It does not handle call services, neither active mobility procedures (handovers).

It can be easily (common, running a mobile core network is not *that* easy) 
configured and used thanks to the [corenet](https://github.com/mitshell/corenet/) project, 
also open-source.


Usage
=====

Most of the modules have doc strings. I try also to write readable sources and to
comment them as much as possible for understanding them easily (and to allow also
myself to understand my own code years after...).
A [wiki](https://github.com/p1sec/pycrate/wiki/The-pycrate-wiki) is provided 
and extended from time to time, to bring examples and methods on how to use the 
different modules (any contribution on this would be very welcome, too).
Finally, the code provided in the *test/* subdirectory is also representative on
how to use the different modules.

Basically, a pycrate's object exposes the following methods:
* set_val() / get_val(), which sets and gets a value into the object
* from_bytes() / to_bytes(), which converts a buffer into values according to the internal structure of the object, and back
* from_json() / to_json(), for working with JSON-encoded values
* hex() / bin(), for getting hexadecimal and binary representation of the serialized obect's value
* repr() / show(), for providing nice python's internal representation, and printable representation of the object's value


ASN.1 usage
===========

When a Python module from *pycrate_asn1dir/* is loaded, it creates Python classes
corresponding to ASN.1 modules (all dash characters are converted to underscore).
Each ASN.1 object has a corresponding Python instance, exposing the following methods:
* from_asn1() / to_asn1(), which converts ASN.1 textual value to Python value and back
* from_aper() / to_aper(), which converts aligned PER encoded value to Python value and back
* from_uper() / to_uper(), which converts unaligned PER
* from_ber() / to_ber(), which converts BER
* from_cer() / to_cer(), which converts CER
* from_der() / to_der(), which converts DER
* from_jer() / to_jer(), which converts JER
* set_val() / get_val(), to set and get Python's values into the ASN.1 object
* get_proto(), to return to internal structure of the ASN.1 object

All the methods useful for working with ASN.1 objects at runtime can be found in 
the file *pycrate_asn1rt/asnobj.py*.


Tools
=====

Four different tools are provided (yet):
* *pycrate_showmedia.py* parses some media files (jpg, bmp, gif, mp3, png, 
   tiff, mpeg4) and pretty print the file structure on the standard output.
* *pycrate_asn1compile.py* compiles ASN.1 source file(s) and produce a Python
   source file that makes use of the ASN.1 runtime. This source file is then
   usable to encode / decode any ASN.1 object from the compiled ASN.1 
   specification.
* *pycrate_berdecode.py* parses any BER/CER/DER encoded binary value of ASN.1 
   objects and prints the corresponding structure.
* *pycrate_map_op_info.py* prints prototypes and various information related to
   TCAP-MAP (Mobile Application Part) and CAMEL operations and application-contexts.


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
       <len : 13>
       <type : 'IHDR'>
       ### IHDR ###
        <width : 238>
        <height : 415>
        <depth [bit depth] : 8>
        <color [color type] : 0 (Greyscale)>
        <comp [compression method] : 0 (inflate/deflate with sliding window)>
        <filter [filter method] : 0 (no interlace)>
        <interlace [interlace method] : 0 (no interlace)>
       <crc : 0x7d8cb12e>
      ### PNGChunk ###
       <len : 9>
       <type : 'pHYs'>
       <data :
        00 00 0c 4e 00 00 0c 4e 01                      | '\x00\x00\x0cN\x00\x00\x0cN\x01'>
       <crc : 0x7f778c23>
      ### PNGChunk ###
       <len : 792>
       <type : 'iCCP'>
       <data :
        50 68 6f 74 6f 73 68 6f 70 20 49 43 43 20 70 72 | 'Photoshop ICC pr'
        6f 66 69 6c 65 00 00 78 da 63 60 60 9e e0 e8 e2 | 'ofile\x00\x00x\xdac``\x9e\xe0\xe8\xe2'
        [...]
        32 fd fc ea eb 82 ef e1 3f 05 7e 9d fa d3 fa cf | '2\xfd\xfc\xea\xeb\x82\xef\xe1?\x05~\x9d\xfa\xd3\xfa\xcf'
        f1 ff 7f 00 0d 00 0f 34                         | '\xf1\xff\x7f\x00\r\x00\x0f4'>
       <crc : 0xfa96f15d>
      ### PNGChunk ###
       <len : 32>
       <type : 'cHRM'>
       <data :
        00 00 6e 27 00 00 73 af 00 00 df f2 00 00 83 30 | "\x00\x00n'\x00\x00s\xaf\x00\x00\xdf\xf2\x00\x00\x830"
        00 00 77 43 00 00 c8 0a 00 00 34 95 00 00 2e dc | '\x00\x00wC\x00\x00\xc8\n\x00\x004\x95\x00\x00.\xdc'>
       <crc : 0x20bf171a>
      ### PNGChunk ###
       <len : 21130>
       <type : 'IDAT'>
       <data :
        78 da ed bd 79 50 8d fd 1f ff ff bc ce 39 73 4e | 'x\xda\xed\xbdyP\x8d\xfd\x1f\xff\xff\xbc\xce9sN'
        db b4 37 95 32 b4 19 94 06 2d 7e 11 26 b2 fc 10 | '\xdb\xb47\x952\xb4\x19\x94\x06-~\x11&\xb2\xfc\x10'
        [...]
        91 a3 d8 5b fc e1 cb 51 fd ab fb c9 cc ec ee 21 | '\x91\xa3\xd8[\xfc\xe1\xcbQ\xfd\xab\xfb\xc9\xcc\xec\xee!'
        7d 70 6e f3 18 ce c1 c1 6d 8c 81 44 32 cf 51 ba | '}pn\xf3\x18\xce\xc1\xc1m\x8c\x81D2\xcfQ\xba'
        ...>
       <crc : 0xa9fbdd38>
      ### PNGChunk ###
       <len : 0>
       <type : 'IEND'>
       <data : >
       <crc : 0xae426082>
```

It is possible to test the *pycrate_asn1compile.py* tool with some test ASN.1 
specification from *./test/res/*, or any other valid ASN.1 specification of your
choice.

```console
$ ./tools/pycrate_asn1compile.py --help
usage: pycrate_asn1compile.py [-h] [-s SPEC] [-i INPUT [INPUT ...]] [-o OUTPUT] [-g GENERATOR_PATH] [-j] [-fautotags] [-fextimpl] [-fverifwarn]

compile ASN.1 input file(s) for the pycrate ASN.1 runtime

optional arguments:
  -h, --help            show this help message and exit
  -s SPEC               provide a specification shortname, instead of ASN.1 input file(s)
  -i INPUT [INPUT ...]  ASN.1 input file(s) or directory
  -o OUTPUT             compiled output Python (and json) source file(s)
  -g GENERATOR_PATH, --generator GENERATOR_PATH
                        provide an alternative python generator file path
  -j                    output a json file with information on ASN.1 objects dependency
  -fautotags            force AUTOMATIC TAGS for all ASN.1 modules
  -fextimpl             force EXTENSIBILITY IMPLIED for all ASN.1 modules
  -fverifwarn           force warning instead of raising during the verification stage

$ ./tools/pycrate_asn1compile.py -i ./test/res/Hardcore.asn -o Hardcore
[proc] [./test/res/Hardcore.asn] module HardcoreSyntax (oid: []): 116 ASN.1 assignments found
--- compilation cycle ---
--- compilation cycle ---
--- compilation cycle ---
--- verifications ---
[proc] ASN.1 modules processed: ['HardcoreSyntax']
[proc] ASN.1 objects compiled: 75 types, 3 sets, 37 values
[proc] done
```

After compiling a module, it is possible to load it in Python and use it for
encoding / decoding any objects defined in it.

```python
Python 3.8.5 (default, Jul 28 2020, 12:59:40) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Hardcore import HardcoreSyntax
>>> HardcoreSyntax # this is the only ASN.1 module provided in Hardcore.asn
<class 'Hardcore.HardcoreSyntax'>
>>> Final = HardcoreSyntax.Final # this is the Final object defined at line 115
>>> Final
<Final (SEQUENCE)>
>>> Final.get_proto() # warning: this can return very laaaaaaarge definitions
('SEQUENCE', {
w1: ('SEQUENCE', {
 r10: ('SEQUENCE', {
  low: 'INTEGER',
  high: 'INTEGER',
  bool: 'BOOLEAN',
  null (OPT): 'NULL'
  }),
 r90: ('SEQUENCE', {
  low: 'INTEGER',
  high: 'INTEGER',
  bool: 'BOOLEAN',
  null (OPT): 'NULL'
  })
 }),
w2: ('SEQUENCE', {
 r10: ('SEQUENCE', {
  low: 'INTEGER',
  high: 'INTEGER',
  bool: 'BOOLEAN',
  null (OPT): 'NULL'
  }),
 r90: ('SEQUENCE', {
  low: 'INTEGER',
  high: 'INTEGER',
  bool: 'BOOLEAN',
  null (OPT): 'NULL'
  })
 }),
bool: 'BOOLEAN'
})
>>> V = {
... 'w1':{'r10':{'low':5, 'high':50, 'bool':False}, 'r90':{'low':50, 'high':95, 'bool':False, 'null':0}},
... 'w2':{'r10':{'low':1, 'high':10, 'bool':False}, 'r90':{'low':90, 'high':100, 'bool':True}},
... 'bool': True}
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
Do not forget to have a look at the [wiki](https://github.com/p1sec/pycrate/wiki/The-pycrate-wiki), too!
