from distutils.core import setup, Extension
import shutil
import sys

CLASSIFIERS = filter(None, map(str.strip,
"""
Intended Audience :: Developers
License :: Private :: All Rights Reserved!
Programming Language :: Python
Topic :: Database
Topic :: Software Development :: Libraries :: Python Modules
""".splitlines()))
    
libs = []

if sys.platform != "win32":
    libs.append("stdc++")
    
if sys.platform == "win32":
    libs.append("ws2_32")


module1 = Extension('amysql',
                sources = ["./amysql.c" ],
                include_dirs = [ "./"],
                library_dirs = [ "./"],
                libraries=libs,
                define_macros=[('WIN32_LEAN_AND_MEAN', None), ('DEBUG', None)])

setup (name = 'amysql',
       version = "2.5",
       description = "Async MySQL driver for Python",
       ext_modules = [module1],
       extra_compile_args=["-O0"],
       extra_link_args=["-O0"],
       author="Abael Heyijun",
       author_email="hyjdyx@gmail.com",
       license="BSD License",
       platforms=['any'],	   
	   url="http://www.abael.com",
       classifiers=CLASSIFIERS,
	   )       
