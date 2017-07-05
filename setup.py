# −*− coding: UTF−8 −*−

from setuptools import setup, find_packages

setup(
    name="pycrate",
    version="0.1.0",
    
    #packages=find_packages(),
    packages=["pycrate_core",
              "pycrate_ether",
              "pycrate_media",
              "pycrate_asn1c",
              "pycrate_asn1dir",
              "pycrate_asn1rt"],
    
    test_suite="test.test_pycrate",
    
    scripts=["tools/pycrate_asn1compile.py",
             "tools/pycrate_showmedia.py",
             #"tools/pycrate_stripmedia.py",
             ],
    
    # no dependency yet
    install_requires=[],
    
    # dirs with .asn and .txt files are not installed, like .json files 
    # only compiled .py modules are installed by default
    package_data={
        #'pycrate_asn1dir': ['*.asn', '*.json'],
        },
    #include_package_data=False,
    
    author="Benoit Michau",
    author_email="michau.benoit@gmail.com",
    description="A software suite to handle various data formats",
    long_description=open("README.md", "r").read(),
    url="https://github.com/mitshell/pycrate/",
    keywords="protocol format asn1 compiler  encoder decoder",
    license="GPLv2+",
    )
