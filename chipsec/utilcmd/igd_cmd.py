#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2017, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#



"""
The igd command allows memory read/write operations using igd dma.
"""

import time

import chipsec_util
from chipsec.hal import igd
from chipsec.command import BaseCommand
from argparse import ArgumentParser

from chipsec.logger import *
import chipsec.file

# Port I/O
class IgdCommand(BaseCommand):
    """
    >>> chipsec_util igd 
    >>> chipsec_util igd dmaread <address> [width] [file_name]
    >>> chipsec_util igd dmawrite <address> <width> <value|file_name>

    Examples:

    >>> chipsec_util igd dmaread 0x20000000 4
    >>> chipsec_util igd dmawrite 0x2217F1000 0x4 deadbeef
    """

    def requires_driver(self):
        parser = ArgumentParser(usage=IgdCommand.__doc__)
        subparsers = parser.add_subparsers()

        parser_dmaread = subparsers.add_parser('dmaread')
        parser_dmaread.add_argument("phys_address",type=lambda sz: int(sz,0),help="physical address to read")
        parser_dmaread.add_argument("size",type=lambda sz: int(sz,0), nargs='?', default=0x100,help="number of bytes to read")
        parser_dmaread.add_argument("file",nargs='?',help="output file name. place read bytes here")
        parser_dmaread.set_defaults(func=self.dmaread)

        parser_dmawrite = subparsers.add_parser('dmawrite')
        parser_dmawrite.add_argument("phys_address",type=lambda sz: int(sz,0),help="physical address to write")
        parser_dmawrite.add_argument("size",type=lambda sz: int(sz,0),help="number of bytes to write")
        parser_dmawrite.add_argument("value",help="value to write, either hex value or file containing hex value")
        parser_dmawrite.set_defaults(func=self.dmawrite)


        parser.parse_args(self.argv[2:],namespace=self)
        if hasattr(self, 'func'):
            return True
        else:
            return False


    def dmaread(self):
        self.logger.log('[CHIPSEC] reading buffer from memory: PA = 0x{:016X}, len = 0x{:X}..'.format(self.phys_address, self.size))

        buffer = self.cs.igd.gfx_aperture_dma_read_write( self.phys_address, self.size )
        if self.file:
            chipsec.file.write_file(self.file, buffer)
        else:
            print_buffer(buffer)
    

    def dmawrite(self):
        if not os.path.exists(self.value): # if value isnt a file, assume hex string
            try:
                buffer = bytearray.fromhex(self.value)
            except ValueError as e:
                self.logger.error( "incorrect <value> specified: '{}'".format(self.value) )
                self.logger.error( str(e) )
                return
            self.logger.log("[CHIPSEC] read 0x{:X} hex bytes from command-line: {}'".format(len(buffer), self.value))
        else:
            buffer = chipsec.file.read_file(self.value)
            self.logger.log("[CHIPSEC] read 0x{:X} bytes from file '{}'".format(len(buffer), self.value))
        if len(buffer) < self.size:
            self.logger.error("number of bytes read (0x{:X}) is less than the specified <length> (0x{:X})".format(len(buffer),self.size))
            return
        self.logger.log( '[CHIPSEC] writing buffer to memory: PA = 0x{:016X}, len = 0x{:X}..'.format(self.phys_address, self.size) )
        self.cs.igd.gfx_aperture_dma_read_write(self.phys_address,self.size,buffer)
    
    def run(self):
        if not self.cs.igd.is_device_enabled():
            self.logger.log( '[CHIPSEC] Looks like internal graphics device is not enabled' )
            return
        t = time.time()
        self.func()
        self.logger.log( "[CHIPSEC] (mem) time elapsed {:.3f}".format(time.time()-t) )

commands = { 'igd': IgdCommand }


