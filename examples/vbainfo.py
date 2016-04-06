#!/usr/bin/env python
"""
pyvba example: parse VBA information

currently support files in following format:
* ole format
* openxml format
* mhtml format
* base64 encoded mhtml format
"""

import os
import re
import sys
import time
import zlib
import shutil
import base64
import zipfile
import hashlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pyvba import *

def vba_info(filename):

    try:
        vbafile = VBAFile(filename)
        
        if vbafile.PROJECT != None:
            print '###### VBA Project Properties ######\n'
             
            print '[Project Property]'
            for key, value in vbafile.PROJECT.Property.iteritems():
                print key + ' = ' + value

            print '\n[Host Extenders]'
            for key, value in vbafile.PROJECT.HostExtenders.iteritems():
                print key + ' = ' + value

            print '\n[Workspace]'
            for key, value in vbafile.PROJECT.Workspace.iteritems():
                print key + ' = ' + value

        print '\n###### VBA Project Records ######\n'

        print '[Information Record]'
        SysKind = vbafile.dir.InformationRecord.SysKindRecord.SysKind
        if SysKind == 0x00:
            print 'SysKind: ' + str(hex(SysKind)) + ' (16-bit Windows Platforms)'
        elif SysKind == 0x01:
            print 'SysKind: ' + str(hex(SysKind)) + ' (32-bit Windows Platforms)'
        elif SysKind == 0x02:
            print 'SysKind: ' + str(hex(SysKind)) + ' (Macintosh Platforms)'
        elif SysKind == 0x03:
            print 'SysKind: ' + str(hex(SysKind)) + ' (64-bit Windows Platforms)'
        print 'CodePage: ' + str(hex(vbafile.dir.InformationRecord.CodePageRecord.CodePage))
        print 'ProjectName: ' + vbafile.dir.InformationRecord.NameRecord.ProjectName
        print 'DocString: ' + vbafile.dir.InformationRecord.DocStringRecord.DocString
        print 'HelpFilePath1: ' + vbafile.dir.InformationRecord.HelpFilePathRecord.HelpFile1
        print 'HelpFilePath2: ' + vbafile.dir.InformationRecord.HelpFilePathRecord.HelpFile2
        print 'HelpContext: ' + str(hex(vbafile.dir.InformationRecord.HelpContextRecord.HelpContext))
        print 'MajorVersion: ' + str(hex(vbafile.dir.InformationRecord.VersionRecord.MajorVersion))
        print 'MinorVersion: ' + str(hex(vbafile.dir.InformationRecord.VersionRecord.MinorVersion))
        print 'Constants: ' + vbafile.dir.InformationRecord.ConstantsRecord.Constants

        print '\n[Reference Record]'
        for ReferenceRecord in vbafile.dir.ReferencesRecord.ReferenceArray:
            
            if ReferenceRecord[0] is not None:
                print 'Name: ' + ReferenceRecord[0].Name

            if isinstance(ReferenceRecord[1], ReferenceControlRecord):
                print 'Type: ControlRecord' 
            elif isinstance(ReferenceRecord[1], ReferenceRegisteredRecord):
                print 'Type: RegisteredRecord'
                print 'Libid: ' + ReferenceRecord[1].Libid
            elif isinstance(ReferenceRecord[1], ReferenceProjectRecord):
                print 'Type: ProjectRecord'
                print 'LibidAbsolute: ' + ReferenceRecord[1].LibidAbsolute
                print 'LibidRelative: ' + ReferenceRecord[1].LibidRelative
                print 'MajorVersion: ' + str(hex(ReferenceRecord[1].MajorVersion))
                print 'MinorVersion: ' + str(hex(ReferenceRecord[1].MinorVersion))
            else:
                print 'Unknown reference record type.'
            print '-------------------------'
        

        print '\n[Module Record]'
        print 'ModuleCookie: ' + str(hex(vbafile.dir.ModulesRecord.CookieRecord.Cookie))
        for ModuleRecord in vbafile.dir.ModulesRecord.ModuleArray:
            print '-------------------------'
            print 'ModuleName: ' + ModuleRecord.NameRecord.ModuleName
            print 'SizeOfModuleName: ' + str(hex(ModuleRecord.NameRecord.SizeOfModuleName))
            print 'ModuleNameUnicode: ' + ModuleRecord.NameUnicodeRecord.ModuleNameUnicode
            print 'SizeOfModuleNameUnicode: ' + str(hex(ModuleRecord.NameUnicodeRecord.SizeOfModuleNameUnicode))
            print 'StreamName: ' + ModuleRecord.StreamNameRecord.StreamName
            print 'DocString: ' + ModuleRecord.DocStringRecord.DocString
            print 'TextOffset: ' + str(hex(ModuleRecord.OffsetRecord.TextOffset))
            print 'HelpContext: ' + str(hex(ModuleRecord.HelpContextRecord.HelpContext))
            print 'Cookie: ' + str(hex(ModuleRecord.CookieRecord.Cookie))
            print 'Type: ' + str(hex(ModuleRecord.TypeRecord.Id))
            if ModuleRecord.ReadOnlyRecord is not None:
                print 'ReadOnly: True'
            if ModuleRecord.PrivateRecord is not None:
                print 'Private: True'
            codepage = 'cp' + str(vbafile.dir.InformationRecord.CodePageRecord.CodePage)
            if codepage == 'cp10000':
                modulename = ModuleRecord.NameRecord.ModuleName.decode('mac_roman')
            else:
                modulename = ModuleRecord.NameRecord.ModuleName.decode(codepage)
            moduledata = vbafile.OLE.find_object_by_name(modulename)
            if moduledata is not None:  
                if len(moduledata) > ModuleRecord.OffsetRecord.TextOffset:
                    code = moduledata[ModuleRecord.OffsetRecord.TextOffset:]
                    print 'SourceCodeSize:', str(hex(len(code)))
                    code = vbafile._decompress(code)
                    print 'SourceCode:'
                    print code
                else:
                    print 'No source code available in module: ' + modulename
            else:
                print 'Can not find module: ' + modulename
            
    except Exception as e:
        print e
    
    return False


def parse_file(filename):

    if False == os.path.isfile(filename):
        print 'Invalid file: ' + filename
        return

    print 'File: ' + os.path.basename(filename)
    ole_file = extract_ole_file(filename)
    if ole_file is not None:
        vba_info(ole_file)
        if ole_file[0x00:0x07] == 'tmpole_':
            print 'Extract OLE file: ' + ole_file
    

def extract_ole_file(filename):

    data = open(filename, 'rb').read()
    tmp_file = 'tmpole_' + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))

    if data[0x00:0x08] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
        print 'Type: OLE'
        return filename
    
    if data[0x00:0x04] == '\x50\x4b\x03\x04':
        try:
            zf = zipfile.ZipFile(filename, 'r')
            for name in zf.namelist():
                if name[-14:] == 'vbaProject.bin':
                    data = zf.read(name)
                    open(tmp_file, 'wb').write(data)
                    print 'Type: OpenXml'
                    return tmp_file
            print filename + ': No vbaProject.bin found in zip arachive.'
        except Exception as e:
            print filename + ': ' + str(e)

    if data[0x00:0x08] == 'IE1JTUUt':
        m = re.search('IE1JTU[0-9a-zA-Z/+=\x0d\x0a]{1000,}', data)
        if m is not None:
            b64data = m.group(0)
            data = base64.b64decode(b64data)

    if data.find('MIME-Version') != -1 or \
       data.find('<?mso-application progid="Word.Document"?>') != -1:
        m = re.search('Q[\x0d\x0a]*W[\x0d\x0a]*N[\x0d\x0a]*0[\x0d\x0a]*a[\x0d\x0a]*X[0-9a-zA-Z/+=\x0d\x0a\x20]{1000,}', data)
        if m is not None:
            b64data = m.group(0)
            data = base64.b64decode(b64data)
            try:
                data = zlib.decompress(data[0x32:])
                open(tmp_file, 'wb').write(data)
                print 'Type: MHTML'
                return tmp_file
            except Exception as e:
                print filename + ': ' + str(e)

    return None


if __name__ == '__main__':
    
    if len(sys.argv) >= 2 and len(sys.argv) <= 3:
        debug = False
        if len(sys.argv) == 3:
            if sys.argv[2] == 'debug':
                debug = True
            else:
                print 'Usage: ' + os.path.basename(sys.argv[0]) + ' filename [debug]'
                exit(0)
        init_logging(debug)
        if os.path.isfile(sys.argv[1]):
            parse_file(sys.argv[1])
        else:
            print 'Invalid file: ' + sys.argv[1]
    else:
        print 'Usage: ' + os.path.basename(sys.argv[0]) + ' filename [debug]'
        