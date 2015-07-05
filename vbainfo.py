# pyvba example: show vba project information

import os
import sys
from pyvba import *


def vba_info(filename):

    try:
        vbafile = VBAFile(filename)

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

    except Exception as e:
        print e


if __name__ == '__main__':

    if len(sys.argv) == 3:
        if sys.argv[1] == '-f':
            if os.path.isfile(sys.argv[2]):
                vba_info(sys.argv[2])
            else:
                print 'Invalid file name.'
        elif sys.argv[1] == '-d':
            if os.path.isfile(sys.argv[2]):
                pass
            else:
                print 'Invalid file name.'
        else:
            print 'Invalid option.'
    else:
        print 'Usage: ' + sys.argv[0] + ' -[f/d] [file/directory]'