#!/usr/bin/env python
"""
pyvba example: file classification based on file format

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
            code = vbafile.OLE.find_object_by_name(ModuleRecord.NameRecord.ModuleName.decode(codepage))[ModuleRecord.OffsetRecord.TextOffset:]
            print 'SourceCodeSize:', str(hex(len(code)))
            code = vbafile._decompress(code)
            print 'SourceCode:'
            print code
            
    except Exception as e:
        print e
    
    return False


def find_unique_vba(file_list):
    vba_list = list()
    vba_hash_list = list()
    cookie_list = list()

    for filename in file_list:
        ole_file = extract_ole_file(filename)
        if ole_file is not None:
            try:
                ole_hash = hashlib.md5(open(ole_file, 'rb').read()).hexdigest()
                if ole_hash not in vba_hash_list:
                    vba_hash_list.append(ole_hash)
                    vbafile = VBAFile(ole_file)
                    cookie = str(vbafile.dir.ModulesRecord.CookieRecord.Cookie)
                    if cookie not in cookie_list:
                        cookie_list.append(cookie)
                        vba_list.append(filename)
            except Exception as e:
                print filename + ': ' + str(e)

            if ole_file[0x00:0x07] == 'tmpole_':
                os.remove(ole_file)
    
    return vba_list


def parse_vba_info(file_list):
    vba_list = find_unique_vba(file_list)
    print 'Unique VBA: ' + str(len(vba_list))
    
    i = 0
    for filename in vba_list:
        print '<---------- VBA #' + str(i) + ' ---------->'
        print 'File: ' + filename + '\n'
        ole_file = extract_ole_file(filename)
        if ole_file is not None:
            vba_info(ole_file)
            if ole_file[0x00:0x07] == 'tmpole_':
                os.remove(ole_file)
        else:
            print 'Unsupport file format.'
        i += 1


def classify_files(filedir):
    file_lists = dict()
    ole_list = list()
    openxml_list = list()
    mhtml_list = list()
    base64_list = list()
    other_list = list()

    for root, dirs, files in os.walk(filedir):
        for file in files:
            filename = os.path.join(root, file)
            data = open(filename, 'rb').read()
            
            if data[0x00:0x08] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                ole_list.append(filename)
                continue
    
            if data[0x00:0x04] == '\x50\x4b\x03\x04':
                openxml_list.append(filename)
                continue

            if data[0x00:0x08] == 'IE1JTUUt':
               base64_list.append(filename)
               continue

            if data.find('MIME-Version') != -1:
                mhtml_list.append(filename)
                continue

            other_list.append(filename)

    file_lists['ole'] = ole_list
    file_lists['openxml'] = openxml_list
    file_lists['base64'] = base64_list
    file_lists['mhtml'] = mhtml_list
    file_lists['other'] = other_list

    return file_lists


def parse_files(filedir, action, vbainfo):

    file_lists = classify_files(filedir)

    if action:
        out_dir = 'classified_' + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))
    
    if len(file_lists['ole']) > 0:
        print '######################################'
        print 'Files in OLE format:'
        print '######################################'
        for filename in file_lists['ole']:
            name = os.path.basename(filename)
            print name
        print 'Totle number: ' + str(len(file_lists['ole']))
        if vbainfo:
            parse_vba_info(file_lists['ole'])
        if action:
            ole_dir = os.path.join(out_dir, 'ole')
            os.makedirs(ole_dir)
            for filename in file_lists['ole']:
                name = os.path.basename(filename)
                newfile = os.path.join(ole_dir, name)
                if 1 == action:
                    shutil.copy2(filename, newfile)
                elif 2 == action:
                    shutil.move(filename, newfile)
    
    if len(file_lists['openxml']) > 0:
        print '######################################'
        print 'Files in OPEN XML format:'
        print '######################################'
        for filename in file_lists['openxml']:
            name = os.path.basename(filename)
            print name
        print 'Totle number: ' + str(len(file_lists['openxml']))
        if vbainfo:
            parse_vba_info(file_lists['openxml'])
        if action:
            openxml_dir = os.path.join(out_dir, 'openxml')
            os.makedirs(openxml_dir)
            for filename in file_lists['openxml']:
                name = os.path.basename(filename)
                newfile = os.path.join(openxml_dir, name)
                if 1 == action:
                    shutil.copy2(filename, newfile)
                elif 2 == action:
                    shutil.move(filename, newfile)
    
    if len(file_lists['mhtml']) > 0:
        print '######################################'
        print 'Files in MHTML format:'
        print '######################################'
        for filename in file_lists['mhtml']:
            name = os.path.basename(filename)
            print name
        print 'Totle number: ' + str(len(file_lists['mhtml']))
        if vbainfo:
            parse_vba_info(file_lists['mhtml'])
        if action:
            mhtml_dir = os.path.join(out_dir, 'mhtml')
            os.makedirs(mhtml_dir)
            for filename in file_lists['mhtml']:
                name = os.path.basename(filename)
                newfile = os.path.join(mhtml_dir, name)
                if 1 == action:
                    shutil.copy2(filename, newfile)
                elif 2 == action:
                    shutil.move(filename, newfile)

    if len(file_lists['base64']) > 0:
        print '######################################'
        print 'Files in base64 encoded MHTML format:'
        print '######################################'
        for filename in file_lists['base64']:
            name = os.path.basename(filename)
            print name
        print 'Totle number: ' + str(len(file_lists['base64']))
        if vbainfo:
            parse_vba_info(file_lists['base64'])
        if action:
            b64mhtml_dir = os.path.join(out_dir, 'b64mhtml')
            os.makedirs(b64mhtml_dir)
            for filename in file_lists['base64']:
                name = os.path.basename(filename)
                newfile = os.path.join(b64mhtml_dir, name)
                if 1 == action:
                    shutil.copy2(filename, newfile)
                elif 2 == action:
                    shutil.move(filename, newfile)

    if len(file_lists['other']) > 0:
        print '######################################'
        print 'Files in unsupport file format:'
        print '######################################'
        for filename in file_lists['other']:
            name = os.path.basename(filename)
            print name
        print 'Totle number: ' + str(len(file_lists['other']))
        if action:
            other_dir = os.path.join(out_dir, 'other')
            os.makedirs(other_dir)
            for filename in file_lists['other']:
                name = os.path.basename(filename)
                newfile = os.path.join(other_dir, name)
                if 1 == action:  
                    shutil.copy2(filename, newfile)
                elif 2 == action:
                    shutil.move(filename, newfile)
    
    if action:
        print '######################################'
        if 1 == action:  
            print 'The classified files are copied to: ' + out_dir
        elif 2 == action:
            print 'The classified files are moved to: ' + out_dir


def extract_ole_file(filename):

    data = open(filename, 'rb').read()
    tmp_file = 'tmpole_' + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))

    if data[0x00:0x08] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
        return filename
    
    if data[0x00:0x04] == '\x50\x4b\x03\x04':
        try:
            zf = zipfile.ZipFile(filename, 'r')
            for name in zf.namelist():
                if name[-14:] == 'vbaProject.bin':
                    data = zf.read(name)
                    open(tmp_file, 'wb').write(data)
                    return tmp_file
            print filename + ': No vbaProject.bin found in zip arachive.'
        except Exception as e:
            print filename + ': ' + str(e)

    if data[0x00:0x08] == 'IE1JTUUt':
        m = re.search('IE1JTU[0-9a-zA-Z/+=\x0d\x0a]{1000,}', data)
        if m is not None:
            b64data = m.group(0)
            data = base64.b64decode(b64data)

    if data.find('MIME-Version') != -1:
        m = re.search('QWN0aX[0-9a-zA-Z/+=\x0d\x0a]{1000,}', data)
        if m is not None:
            b64data = m.group(0)
            data = base64.b64decode(b64data)
            try:
                data = zlib.decompress(data[0x32:])
                open(tmp_file, 'wb').write(data)
                return tmp_file
            except Exception as e:
                print filename + ': ' + str(e)

    return None


if __name__ == '__main__':

    init_logging(False)
    
    if len(sys.argv) >= 2 and len(sys.argv) <= 4:
        action = 0
        vbainfo = False
        if len(sys.argv) >= 3:
            if sys.argv[2] == '-copy' and action == 0:
                action = 1
            elif sys.argv[2] == '-move' and action == 0:
                action = 2
            elif sys.argv[2] == '-vba' and vbainfo == False:
                vbainfo = True
            else:
                print 'Usage: ' + sys.argv[0] + ' directory [-vba] [-copy/-move]'
                exit(0)
        if len(sys.argv) == 4:
            if sys.argv[3] == '-copy' and action == 0:
                action = 1
            elif sys.argv[3] == '-move' and action == 0:
                action = 2
            elif sys.argv[3] == '-vba' and vbainfo == False:
                vbainfo = True
            else:
                print 'Usage: ' + sys.argv[0] + ' directory [-vba] [-copy/-move]'
                exit(0)
        if os.path.isdir(sys.argv[1]):
            parse_files(sys.argv[1], action, vbainfo)
        else:
            print 'Invalid directory: ' + sys.argv[1]
    else:
        print 'Usage: ' + sys.argv[0] + ' directory [-vba] [-copy/-move]'
        