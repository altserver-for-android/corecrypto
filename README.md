<!-- Copyright (c) (2010,2012,2014-2021) Apple Inc. All rights reserved.

 corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 is contained in the License.txt file distributed with corecrypto) and only to
 people who accept that license. IMPORTANT:  Any license rights granted to you by
 Apple Inc. (if any) are limited to internal use within your organization only on
 devices and computers you own or control, for the sole purpose of verifying the
 security characteristics and correct functioning of the Apple Software.  You may
 not, directly or indirectly, redistribute the Apple Software or any portions thereof.
-->

The corecrypto (cc) project
===========================

The main goal is to provide low level fast math routines and crypto APIs which
can be used in various environments (Kernel, bootloader, userspace, etc.).  It
is an explicit goal to minimize dependancies between modules and functions so
that clients of this library only end up with the routines they need and
nothing more.

Corecrypto compiles under all Apple OSs, Windows and Linux.

Corecrypto Modules
------------------

Each module has the following subdirectories:

* `corecrypto`:     headers for this module
* `src`:            sources for this module
* `doc`:            documentation, references, etc.
* `crypto_tests`:   sources for executable tests for this module
* `test_vectors`:   test vectors for this module
* `tools`:          sources for random helper tools.

Windows
-------
corecrypto compiles under Windows using Visual Studio 2015 and Clang with Microsoft CodeGen. The corecrypto Solution contains three projects:

1. `corecrypto`: This projects compiles corecrypto, and produces a static library in 32 and 64 bit modes.
2. `corecrypto_test`: This project compiles corecrypto test files and links statically with the corecrypto debug library.
3. `corecrypto_perf`: This project compiles corecrypto performance measurement files and links statically with the corecrypto release library.
4. `corecrypto_wintest`: This project contains a simple code that links to the corecrypto.lib and complies in c++ using the Visul C++ compiler. This project created to
   make sure corecrypto library can linked to c++ software that are compiled with the Microsoft Compiler.

Linux
-----
The corecrypto library, `corecrypto_test` and `corecrypto_perf` compile under Linux and are built using cmake. See Cmake section for more details.
The Linux implementation does not use ASM implementations due to differences between assemblers on Darwin and Linux.

CMake
-----
The corecrypto library, 'corecrypto_test' and 'corecrypto_perf' can also be built using cmake in macOS and Linux.

To compile using cmake, run the usual cmake commands:
```
  $ cd <srcdir>
  $ mkdir build && cd build
  $ CC=clang CXX=clang++ cmake ..
  $ make
```
where `<srcdir>` is the path to the directory containing the sources.

To install, type `make install` from the build directory (will require root privileges).
