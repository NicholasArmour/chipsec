#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2018, Intel Corporation
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
The uefi command provides access to UEFI variables, both on the live system and in a SPI flash image file.
"""

import os
import shutil
import glob
import time

import chipsec_util

from chipsec.logger     import *
from chipsec.file       import *

from chipsec.hal.uefi          import *
from chipsec.hal.spi_uefi      import *

from chipsec.command    import BaseCommand
import json
json_objs = []
def read_json(json_obj):
    json_objs.append(json_obj)
    if 'children' in json_obj:
        for c in json_obj['children']:
            read_json(c)

    
# Unified Extensible Firmware Interface (UEFI)
class UEFICommand(BaseCommand):
    """
    >>> chipsec_util uefi types
    >>> chipsec_util uefi var-list
    >>> chipsec_util uefi var-find <name>|<GUID>
    >>> chipsec_util uefi var-read|var-write|var-delete <name> <GUID> <efi_variable_file>
    >>> chipsec_util uefi decode <rom_file> [fwtype]
    >>> chipsec_util uefi decode <rom_file> [fwtype]
    >>> chipsec_util uefi nvram[-auth] <rom_file> [fwtype]
    >>> chipsec_util uefi keys <keyvar_file>
    >>> chipsec_util uefi tables
    >>> chipsec_util uefi s3bootscript [script_address]
    >>> chipsec_util uefi assemble <GUID> freeform none|lzma|tiano <raw_file> <uefi_file>
    >>> chipsec_util uefi insert_before|insert_after|replace|remove <GUID> <rom> <new_rom> <uefi_file>
    
    Examples:

    >>> chipsec_util uefi types
    >>> chipsec_util uefi var-list
    >>> chipsec_util uefi var-find PK
    >>> chipsec_util uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
    >>> chipsec_util uefi var-write db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
    >>> chipsec_util uefi var-delete db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
    >>> chipsec_util uefi decode uefi.rom
    >>> chipsec_util uefi nvram uefi.rom vss_auth
    >>> chipsec_util uefi keys db.bin
    >>> chipsec_util uefi tables
    >>> chipsec_util uefi s3bootscript
    >>> chipsec_util uefi assemble AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE freeform lzma uefi.raw mydriver.efi
    >>> chipsec_util uefi replace  AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE bios.bin new_bios.bin mydriver.efi
    """

    def requires_driver(self):
        return False
        # No driver required when printing the util documentation
        if len(self.argv) < 3:
            return False
        # Always load the driver unless native mode is requested
        load_driver = True
        if '-n' in self.argv:
            self.argv.remove('-n')
            load_driver = False
        # Driver is always required for these specific commands to run
        if len(self.argv) >= 3 and self.argv[2] in ('tables','s3bootscript'):
            load_driver = True
        return load_driver

    def run(self):
        _uefi = UEFI( self.cs )
        if len(self.argv) < 3:
            print (UEFICommand.__doc__)
            return
        
        op       = self.argv[2]
        t        = time.time()
        filename = None

        if ( 'types' == op ):
            self.logger.log( "<fwtype> should be in [ %s ]" % (" | ".join( ["%s" % tp for tp in fw_types])) )

        elif ( 'var-read' == op ):
            if (4 < len(self.argv)):
                name = self.argv[3]
                guid = self.argv[4]
            if (5 < len(self.argv)):
                filename = self.argv[5]
            self.logger.log( "[CHIPSEC] Reading EFI variable Name='{}' GUID={{{}}} to '{}' via Variable API..".format(name, guid, filename) )
            var = _uefi.get_EFI_variable( name, guid, filename )

        elif ( 'var-write' == op ):

            if (5 < len(self.argv)):
                name = self.argv[3]
                guid = self.argv[4]
                filename = self.argv[5]
            else:
                print (UEFICommand.__doc__)
                return
            self.logger.log( "[CHIPSEC] writing EFI variable Name='{}' GUID={{{}}} from '{}' via Variable API..".format(name, guid, filename) )
            status = _uefi.set_EFI_variable_from_file( name, guid, filename )
            self.logger.log("[CHIPSEC] status: {}".format(chipsec.hal.uefi_common.EFI_STATUS_DICT[status]))
            if status == 0:
                self.logger.log( "[CHIPSEC] writing EFI variable was successful" )
            else:
                self.logger.error( "writing EFI variable failed" )

        elif ( 'var-delete' == op ):

            if (4 < len(self.argv)):
                name = self.argv[3]
                guid = self.argv[4]
            else:
                print( UEFICommand.__doc__)
                return
            self.logger.log( "[CHIPSEC] Deleting EFI variable Name='{}' GUID={{{}}} via Variable API..".format(name, guid) )
            status = _uefi.delete_EFI_variable( name, guid )
            self.logger.log("Returned {}".format(chipsec.hal.uefi_common.EFI_STATUS_DICT[status]))
            if status == 0: self.logger.log( "[CHIPSEC] deleting EFI variable was successful" )
            else: self.logger.error( "deleting EFI variable failed" )

        elif ( 'var-list' == op ):

            #infcls = 2
            #if (3 < len(self.argv)): filename = self.argv[3]
            #if (4 < len(self.argv)): infcls = int(self.argv[4],16)
            self.logger.log( "[CHIPSEC] Enumerating all EFI variables via OS specific EFI Variable API.." )
            efi_vars = _uefi.list_EFI_variables()
            if efi_vars is None:
                self.logger.log( "[CHIPSEC] Could not enumerate EFI Variables (Legacy OS?). Exit.." )
                return

            self.logger.log( "[CHIPSEC] Decoding EFI Variables.." )
            _orig_logname = self.logger.LOG_FILE_NAME
            self.logger.set_log_file( 'efi_variables.lst' )
            #print_sorted_EFI_variables( efi_vars )
            nvram_pth = 'efi_variables.dir'
            if not os.path.exists( nvram_pth ): os.makedirs( nvram_pth )
            decode_EFI_variables( efi_vars, nvram_pth )
            self.logger.set_log_file( _orig_logname )

            #efi_vars = _uefi.list_EFI_variables( infcls, filename )
            #_orig_logname = self.logger.LOG_FILE_NAME
            #self.logger.set_log_file( (filename + '.nv.lst') )
            #_uefi.parse_EFI_variables( filename, efi_vars, False, FWType.EFI_FW_TYPE_WIN )
            #self.logger.set_log_file( _orig_logname )

            self.logger.log( "[CHIPSEC] Variables are in efi_variables.lst log and efi_variables.dir directory" )

        elif ( 'var-find' == op ):

            _vars = _uefi.list_EFI_variables()
            if _vars is None:
                self.logger.log_warning( 'Could not enumerate UEFI variables (non-UEFI OS?)' )
                return

            _input_var = self.argv[3]
            if ('-' in _input_var):
                self.logger.log( "[*] Searching for UEFI variable with GUID {{{}}}..".format(_input_var) )
                for name in _vars:
                    n = 0
                    for (off, buf, hdr, data, guid, attrs) in _vars[name]:
                        if _input_var == guid:
                            var_fname = '{}_{}_{}_{:d}.bin'.format(name,guid,get_attr_string(attrs).strip(),n)
                            self.logger.log_good( "Found UEFI variable {}:{}. Dumped to '{}'".format(guid,name,var_fname) )
                            write_file( var_fname, data )
                        n += 1
            else:
                self.logger.log( "[*] Searching for UEFI variable with name {}..".format(_input_var) )
                name = _input_var
                if name in list(_vars.keys()):
                    n = 0
                    for (off, buf, hdr, data, guid, attrs) in _vars[name]:
                        var_fname = '{}_{}_{}_{:d}.bin'.format(name,guid,get_attr_string(attrs).strip(),n)
                        self.logger.log_good( "Found UEFI variable {}:{}. Dumped to '{}'".format(guid,name,var_fname) )
                        write_file( var_fname, data )
                        n += 1

        elif ( 'nvram' == op or 'nvram-auth' == op ):

            authvars = ('nvram-auth' == op)
            if len(self.argv) == 3:
                self.logger.log( "<fw_type> should be in [ %s ]\n" % (" | ".join( ["%s" % tp for tp in fw_types])) )
                return

            romfilename = self.argv[3]
            fwtype      = self.argv[4] if len(self.argv) == 5 else None
            self.logger.log( "[CHIPSEC] Extracting EFI Variables from ROM file '{}'".format(romfilename) )
            if not os.path.exists( romfilename ):
                self.logger.error( "Could not find file '{}'".format(romfilename) )
                return

            rom = read_file( romfilename )
            if fwtype is None:
                fwtype = identify_EFI_NVRAM( rom )
                if fwtype is None:
                    self.logger.error( "Could not automatically identify EFI NVRAM type" )
                    return
            elif fwtype not in fw_types:
                self.logger.error( "Unrecognized EFI NVRAM type '{}'".format(fwtype) )
                return

            _orig_logname = self.logger.LOG_FILE_NAME
            self.logger.set_log_file( (romfilename + '.nv.lst') )
            _uefi.parse_EFI_variables( romfilename, rom, authvars, fwtype )
            self.logger.set_log_file( _orig_logname )

        elif ( 'decode' == op ):

            if len(self.argv) < 4:
                print (UEFICommand.__doc__)
                return

            filename = self.argv[3]
            fwtype   = self.argv[4] if len(self.argv) > 4 else None
            if not os.path.exists( filename ):
                self.logger.error( "Could not find file '{}'".format(filename) )
                return

            _orig_logname = self.logger.LOG_FILE_NAME
            self.logger.set_log_file( filename + '.UEFI.lst' )
            cur_dir = self.cs.helper.getcwd()
            if not os.path.exists(os.path.join(cur_dir,filename + '.dir')):
                self.logger.log( "[CHIPSEC] Parsing EFI volumes from '{}'..".format(filename) )
                decode_uefi_region(_uefi, cur_dir, filename, fwtype)
                self.logger.set_log_file( _orig_logname )
            else:
                print("Decompression results already found for {}, delete the {}.dir to re-decompress".format(filename,filename))

           

            # >>> chipsec_util uefi decode <rom_file> [fwtype] [out_dir] [binary_type] [GUID] [binary_name]
            if len(self.argv) > 5:
                 # read all the json objects
                f = open(filename + '.UEFI.json')
                jsonf = json.load(f)
                for j in jsonf:
                    read_json(j)
                import uuid
                
                MODULE_TYPES_DICT = {'DXE_DRIVER': 0x7,'DXE_SMM_DRIVER': 0xA, 'PEI_CORE': 0x4, 'PEIM': 0x6}
                # make output directory
                out_dir = self.argv[5]
                if not os.path.exists(out_dir):
                    os.makedirs(out_dir)
                if os.name == 'nt':
                    splitstr = "\\"
                else:
                    splitstr = "/"
                for arg in self.argv[6:]:
                    if arg  == 'EFI_FILE': # get all binaries
                        for j in json_objs:
                            if 'class' in j and j['class'] == 'EFI_FILE' and 'ui_string' in j:
                                try:
                                    last_dir = glob.glob(os.path.join(j['file_path'] + '.dir','*.dir'))[0].split(splitstr)[-1]
                                    srcfile = os.path.join(j['file_path'] + '.dir',last_dir,j['ui_string'] + '.efi')
                                except IndexError:
                                    srcfile = os.path.join(j['file_path'] + '.dir',j['ui_string'] + '.efi')

                                try:
                                    shutil.copy(srcfile,out_dir)
                                except FileNotFoundError:
                                    continue


                    elif arg in MODULE_TYPES_DICT:
                        # find all binaries of arg type
                        file_type = MODULE_TYPES_DICT[arg]
                        print("Finding all {}, type = {}".format(arg,file_type))

                        for j in json_objs:
                            if 'Type' in j and j['Type'] == file_type and 'class' in j and j['class'] == 'EFI_FILE' and 'ui_string' in j:
                                try:
                                    last_dir = glob.glob(os.path.join(j['file_path'] + '.dir','*.dir'))[0].split(splitstr)[-1]
                                    srcfile = os.path.join(j['file_path'] + '.dir',last_dir,j['ui_string'] + '.efi')
                                except IndexError:
                                    srcfile = os.path.join(j['file_path'] + '.dir',j['ui_string'] + '.efi')
                                shutil.copy(srcfile,out_dir)
                    else:
                        try:
                            guid = str(uuid.UUID(arg))
                            for j in json_objs:
                                if 'Guid' in j and j['Guid'].casefold() == guid.casefold():
                                    try:
                                        last_dir = glob.glob(os.path.join(j['file_path'] + '.dir','*.dir'))[0].split(splitstr)[-1]
                                        srcfile = os.path.join(j['file_path'] + '.dir',last_dir,j['ui_string'] + '.efi')
                                    except IndexError:
                                        srcfile = os.path.join(j['file_path'] + '.dir',j['ui_string'] + '.efi')
                                    shutil.copy(srcfile,out_dir)

                        except ValueError:
                            # if its not a MODULE_TYPE, or a GUID, assume its the name of a binary
                            for j in json_objs:
                                if 'ui_string' in j and j['ui_string'].casefold() == arg.casefold():
                                    try:
                                        last_dir = glob.glob(os.path.join(j['file_path'] + '.dir','*.dir'))[0].split(splitstr)[-1]
                                        srcfile = os.path.join(j['file_path'] + '.dir',last_dir,j['ui_string'] + '.efi')
                                    except IndexError:
                                        srcfile = os.path.join(j['file_path'] + '.dir',j['ui_string'] + '.efi')
                                    shutil.copy(srcfile,out_dir)

        elif ( 'keys' == op ):

            if (3 < len(self.argv)):
                var_filename = self.argv[3]
                if not os.path.exists( var_filename ):
                    self.logger.error( "Could not find file '{}'".format(var_filename) )
                    return
            else:
                print (UEFICommand.__doc__)
                self.logger.log( "<keyvar_file> should contain one of the following EFI variables\n[ %s ]" % (" | ".join( ["%s" % var for var in SECURE_BOOT_KEY_VARIABLES]))  )
                return

            self.logger.log( "[CHIPSEC] Parsing EFI variable from '{}'..".format(var_filename) )
            parse_efivar_file( var_filename )

        elif ( 'tables' == op ):
            self.logger.log( "[CHIPSEC] Searching memory for and dumping EFI tables (this may take a minute)..\n" )
            _uefi.dump_EFI_tables()

        elif ( 's3bootscript' == op ):
            self.logger.log( "[CHIPSEC] Searching for and parsing S3 resume bootscripts.." )
            if len(self.argv) > 3:
                bootscript_pa = int(self.argv[3],16)
                self.logger.log( '[*] Reading S3 boot-script from memory at 0x{:016X}..'.format(bootscript_pa) )
                script_all = self.cs.mem.read_physical_mem( bootscript_pa, 0x100000 )
                self.logger.log( '[*] Decoding S3 boot-script opcodes..' )
                script_entries = chipsec.hal.uefi.parse_script( script_all, True )               
            else:
                (bootscript_PAs,parsed_scripts) = _uefi.get_s3_bootscript( True )

        elif op in ['insert_before', 'insert_after', 'replace']:

            if len(self.argv) < 7:
                print (UEFICommand.__doc__)
                return

            (guid, rom_file, new_file, efi_file) = self.argv[3:7]

            commands = {
                'insert_before' :  CMD_UEFI_FILE_INSERT_BEFORE,
                'insert_after'  :  CMD_UEFI_FILE_INSERT_AFTER,
                'replace'       :  CMD_UEFI_FILE_REPLACE
            }

            if get_guid_bin(guid) == '':
                print ('*** Error *** Invalid GUID: {}'.format(guid))
                return

            if not os.path.isfile(rom_file):
                print ('*** Error *** File doesn\'t exist: {}'.format(rom_file))
                return

            if not os.path.isfile(efi_file):
                print ('*** Error *** File doesn\'t exist: {}'.format(efi_file))
                return

            rom_image = chipsec.file.read_file(rom_file)
            efi_image = chipsec.file.read_file(efi_file)
            new_image = modify_uefi_region(rom_image, commands[op], guid, efi_image)
            chipsec.file.write_file(new_file, new_image)

        elif op == 'remove':

            if len(self.argv) < 6:
                print (UEFICommand.__doc__)
                return

            (guid, rom_file, new_file) = self.argv[3:6]

            if get_guid_bin(guid) == '':
                print ('*** Error *** Invalid GUID: {}'.format(guid))
                return

            if not os.path.isfile(rom_file):
                print ('*** Error *** File doesn\'t exist: {}'.format(rom_file))
                return

            rom_image = chipsec.file.read_file(rom_file)
            new_image = modify_uefi_region(rom_image, CMD_UEFI_FILE_REMOVE, guid)
            chipsec.file.write_file(new_file, new_image)

        elif op == 'assemble':

            compression = {'none': 0, 'tiano': 1, 'lzma': 2}

            if len(self.argv) < 8:
                print (UEFICommand.__doc__)
                return

            (guid, file_type, comp, raw_file, efi_file) = self.argv[3:8]

            if get_guid_bin(guid) == '':
                print ('*** Error *** Invalid GUID: {}'.format(guid))
                return

            if not os.path.isfile(raw_file):
                print ('*** Error *** File doesn\'t exist: {}'.format(raw_file))
                return

            if comp not in compression:
                print ('*** Error *** Unknown compression: {}'.format(comp))
                return

            compression_type = compression[comp]

            if file_type == 'freeform':
                raw_image  = chipsec.file.read_file(raw_file)
                wrap_image = assemble_uefi_raw(raw_image)
                if compression_type > 0:
                    comp_image = compress_image(_uefi, wrap_image, compression_type)
                    wrap_image = assemble_uefi_section(comp_image, len(wrap_image), compression_type)
                uefi_image = assemble_uefi_file(guid, wrap_image)
                chipsec.file.write_file(efi_file, uefi_image)
            else:
                print ('*** Error *** Unknow file type: {}'.format(file_type))
                return

            self.logger.log( "[CHIPSEC]  UEFI file was successfully assembled! Binary file size: {:d}, compressed UEFI file size: {:d}".format(len(raw_image), len(uefi_image)) )

        else:
            self.logger.error( "Unknown uefi command '{}'".format(op) )
            print (UEFICommand.__doc__)
            return

        self.logger.log( "[CHIPSEC] (uefi) time elapsed {:.3f}".format(time.time()-t) )


commands = { 'uefi': UEFICommand }

