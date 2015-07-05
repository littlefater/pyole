# A VAB parser based on pyole

from pyole import *


class VBABase(OLEBase):

    def _decompress(self, data):

        CompressedCurrent = 0
        DecompressedCurrent = 0
        CompressedRecordEnd = len(data)
        DecompressedBuffer = ''

        SignatureByte = ord(data[CompressedCurrent])
        if SignatureByte != 0x01:
            self.ole_logger.debug('CompressedContainer.SignatureByte has an abnormal value.')
            return None

        CompressedCurrent += 1
        i = 0

        while CompressedCurrent < CompressedRecordEnd:

            CompressedChunkStart = CompressedCurrent
            CompressedChunkHeader = struct.unpack('<H', data[CompressedChunkStart:CompressedChunkStart+0x02])[0]
            
            CompressedChunkSize = (CompressedChunkHeader & 0x0FFF) + 0x03
            self.ole_logger.debug('CompressedChunk[' + str(i) + '].Size: ' + str(hex(CompressedChunkSize)))
            if CompressedChunkSize < 3 or CompressedChunkSize > 4098:
                self.ole_logger.debug('CompressedChunk[' + str(i) + '].Size has an abnormal value.')
                return None
            
            CompressedChunkFlag = (CompressedChunkHeader >> 15)
            self.ole_logger.debug('CompressedChunk[' + str(i) + '].Flag: ' + str(hex(CompressedChunkFlag)))

            if (CompressedChunkStart + CompressedChunkSize) > CompressedRecordEnd:
                CompressedEnd = CompressedRecordEnd
            else:
                CompressedEnd = CompressedChunkStart + CompressedChunkSize

            DecompressedChunkStart = DecompressedCurrent
            CompressedCurrent = CompressedChunkStart + 0x02

            if CompressedChunkFlag == 0x01:
                
                while CompressedCurrent < CompressedEnd:

                    FlagByte = ord(data[CompressedCurrent])
                    self.ole_logger.debug('CompressedChunk[' + str(i) + '].Token.FlagByte: ' + str(hex(FlagByte)))

                    CompressedCurrent += 1

                    for j in range(0, 8):
                        if CompressedCurrent < CompressedEnd:
                            FlagBit = (FlagByte >> j) & 0x01
                            self.ole_logger.debug('CompressedChunk[' + str(i) + '].Token[' + str(j) + '].FlagBit: ' + str(hex(FlagBit)))

                            if FlagBit == 0x00:
                                DecompressedBuffer += data[CompressedCurrent]
                                DecompressedCurrent = len(DecompressedBuffer)
                                CompressedCurrent += 1
                            else:
                                CopyToken = struct.unpack('<H', data[CompressedCurrent:CompressedCurrent+0x02])[0]
                                self.ole_logger.debug('CompressedChunk[' + str(i) + '].Token[' + str(j) + '].CopyToken: ' + str(hex(CopyToken)))
                                difference = DecompressedCurrent - DecompressedChunkStart
                                for bitcount in range(1, 13):
                                    if (2 ** bitcount) >= difference:
                                        break
                                if bitcount < 4:
                                    bitcount = 4
                                lengthmask = (0xFFFF >> bitcount)
                                offsetmask = (~lengthmask & 0xFFFF)
                                length = (CopyToken & lengthmask) + 3
                                self.ole_logger.debug('CompressedChunk[' + str(i) + '].Token[' + str(j) + '].Lenght: ' + str(hex(length)))
                                offset = ((CopyToken & offsetmask) >> (16 - bitcount)) + 1
                                self.ole_logger.debug('CompressedChunk[' + str(i) + '].Token[' + str(j) + '].Offset: ' + str(hex(offset)))
                                srcoffset = DecompressedCurrent - offset
                                for index in range(0, length):
                                    DecompressedBuffer += DecompressedBuffer[srcoffset+index]
                                DecompressedCurrent = len(DecompressedBuffer)
                                CompressedCurrent += 2
            else:
                DecompressedBuffer += data[CompressedCurrent:CompressedCurrent+4096]
                DecompressedCurrent = len(DecompressedBuffer)
                CompressedCurrent += 4096
                
            i += 1

        return DecompressedBuffer
            
        
class ProjectStream(VBABase):

    Property = dict()
    HostExtenders = dict()
    Workspace = dict()

    def __init__(self, data):

        self.Property = dict()
        self.HostExtenders = dict()
        self.Workspace = dict()
        
        self.ole_logger.debug('######## VBAProjectProperties ########')
        
        items = data.split('\r\n\r\n')
        
        self.Property = self._parse_property(items[0])
        self.HostExtenders = self._parse_property(items[1])
        self.Workspace = self._parse_property(items[2])

    
    def _parse_property(self, data):

        property = dict()

        items = data.split('\r\n')
        for item in items:
            self.ole_logger.debug(item)
            if -1 != item.find('='):
                key, value = item.split('=')
                if False == property.has_key(key):
                    property[key] = value
                else:
                    property[key] = property[key] + ',' + value

        return property
                

class Projectwm(VBABase):

    NameMap = list()

    def __init__(self, data):

        self.NameMap = list()

        self.ole_logger.debug('######## PROJECTwmStream ########')

        if len(data) > 0x02 and data[-2:] == '\x00\x00':

            namemaps = data.split('\x00\x00\x00')
            for i in range(0, len(namemaps)-1):
                index = namemaps[i].find('\x00')
                if -1 != index:
                    namemap_mbcs = namemaps[i][0:index]
                    self.ole_logger.debug('PROJECTwm.NameMap[' + str(i) + '].MBCS: ' + namemap_mbcs)
                    namemap_utf16 = (namemaps[i][index+1:]+'\x00').decode('utf16')
                    self.ole_logger.debug('PROJECTwm.NameMap[' + str(i) + '].UTF16: ' + namemap_utf16)
                    if namemap_mbcs == namemap_utf16:
                        self.NameMap.append(namemap_mbcs)
                    else:
                        self._raise_exception('PROJECTwm.NameMap[' + str(i) + '] has an mismatch values.')
                else:
                    self._raise_exception('PROJECTwm.NameMap[' + str(i) + '] has an abnormal values.')
        else:
            self._raise_exception('PROJECTwm stream contains abnormal values.')


class VBAProject(VBABase):

    Reserved1 = 0
    Version = 0
    Reserved2 = 0
    Reserved3 = 0
    PerformanceCache = ''
    

    def __init__(self, data):

        self.Reserved1 = 0
        self.Version = 0
        self.Reserved2 = 0
        self.Reserved3 = 0
        self.PerformanceCache = ''

        self.ole_logger.debug('######## _VBA_PROJECTStream ########')

        self.Reserved1 = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('_VBA_PROJECT.Reserved1: ' + str(hex(self.Reserved1)))
        if self.Reserved1 != 0x61CC:
            self._raise_exception('_VBA_PROJECT.Reserved1 has an abnormal values.')

        self.Version = struct.unpack('<H', data[0x02:0x04])[0]
        self.ole_logger.debug('_VBA_PROJECT.Version: ' + str(hex(self.Version)))

        self.Reserved2 = ord(data[0x04])
        self.ole_logger.debug('_VBA_PROJECT.Reserved2: ' + str(hex(self.Reserved2)))
        if self.Reserved2 != 0x00:
            self._raise_exception('_VBA_PROJECT.Reserved2 has an abnormal values.')

        self.Reserved3 = struct.unpack('<H', data[0x05:0x07])[0]
        self.ole_logger.debug('_VBA_PROJECT.Reserved3: ' + str(hex(self.Reserved3)))

        self.PerformanceCache = data[0x07:]


class ProjectSysKindRecord(VBABase):

    Id = 0
    Size = 0
    SysKind = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.SysKind = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectSysKindRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x01:
            self._raise_exception('ProjectSysKindRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectSysKindRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('ProjectSysKindRecord.Size has an abnormal value.')

        self.SysKind = struct.unpack('<I', data[0x06:0x0A])[0]
        if self.SysKind == 0x00:
            self.ole_logger.debug('ProjectSysKindRecord.SysKind: ' + str(hex(self.SysKind)) + ' (16-bit Windows Platforms)')
        elif self.SysKind == 0x01:
            self.ole_logger.debug('ProjectSysKindRecord.SysKind: ' + str(hex(self.SysKind)) + ' (32-bit Windows Platforms)')
        elif self.SysKind == 0x02:
            self.ole_logger.debug('ProjectSysKindRecord.SysKind: ' + str(hex(self.SysKind)) + ' (Macintosh Platforms)')
        elif self.SysKind == 0x03:
            self.ole_logger.debug('ProjectSysKindRecord.SysKind: ' + str(hex(self.SysKind)) + ' (64-bit Windows Platforms)')
        else:
            self._raise_exception('ProjectSysKindRecord.SysKind has an abnormal value.')


class ProjectLcidRecord(VBABase):
    
    Id = 0
    Size = 0
    Lcid = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.Lcid = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectLcidRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x02:
            self._raise_exception('ProjectLcidRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectLcidRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('ProjectLcidRecord.Size has an abnormal value.')

        self.Lcid = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('ProjectLcidRecord.Lcid: ' + str(hex(self.Lcid)))
        if self.Lcid != 0x409:
            self._raise_exception('ProjectLcidRecord.Lcid has an abnormal value.')


class ProjectLcidInvokeRecord(VBABase):
    
    Id = 0
    Size = 0
    LcidInvoke = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.LcidInvoke = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectLcidInvokeRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x14:
            self._raise_exception('ProjectLcidInvokeRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectLcidInvokeRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('ProjectLcidInvokeRecord.Size has an abnormal value.')

        self.LcidInvoke = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('ProjectLcidInvokeRecord.LcidInvoke: ' + str(hex(self.LcidInvoke)))
        if self.LcidInvoke != 0x409:
            self._raise_exception('ProjectLcidInvokeRecord.LcidInvoke has an abnormal value.')


class ProjectCodePageRecord(VBABase):
    
    Id = 0
    Size = 0
    CodePage = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.CodePage = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectCodePageRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x03:
            self._raise_exception('ProjectCodePageRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectCodePageRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x02:
            self._raise_exception('ProjectCodePageRecord.Size has an abnormal value.')

        self.CodePage = struct.unpack('<H', data[0x06:0x08])[0]
        self.ole_logger.debug('ProjectCodePageRecord.CodePage: ' + str(hex(self.CodePage)))


class ProjectNameRecord(VBABase):
    
    Id = 0
    Size = 0
    ProjectName = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.ProjectName = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectNameRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x04:
            self._raise_exception('ProjectNameRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectNameRecord.Size: ' + str(hex(self.Size)))
        if self.Size < 0x01 or self.Size > 0x80:
            self._raise_exception('ProjectNameRecord.Size has an abnormal value.')

        self.ProjectName = data[0x06:0x06+self.Size]
        self.ole_logger.debug('ProjectNameRecord.ProjectName: ' + self.ProjectName)


class ProjectDocStringRecord(VBABase):
    
    Id = 0
    SizeOfDocString = 0
    DocString = ''
    Reserved = 0
    SizeOfDocStringUnicode = 0
    DocStringUnicode = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfDocString = 0
        self.DocString = ''
        self.Reserved = 0
        self.SizeOfDocStringUnicode = 0
        self.DocStringUnicode = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectDocStringRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x05:
            self._raise_exception('ProjectDocStringRecord.Id has an abnormal value.')

        self.SizeOfDocString = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectDocStringRecord.SizeOfDocString: ' + str(hex(self.SizeOfDocString)))
        if self.SizeOfDocString > 2000:
            self._raise_exception('ProjectDocStringRecord.SizeOfDocString has an abnormal value.')

        self.DocString = data[0x06:0x06+self.SizeOfDocString]
        self.ole_logger.debug('ProjectDocStringRecord.DocString: ' + self.DocString)

        current = 0x06 + self.SizeOfDocString
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ProjectDocStringRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x40:
            self._raise_exception('ProjectDocStringRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfDocStringUnicode = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ProjectDocStringRecord.SizeOfDocStringUnicode: ' + str(hex(self.SizeOfDocStringUnicode)))
        if self.SizeOfDocStringUnicode > 2000*2:
            self._raise_exception('ProjectDocStringRecord.SizeOfDocStringUnicode has an abnormal value.')

        current = current + 0x04
        self.DocStringUnicode = data[current:current+self.SizeOfDocStringUnicode].decode('utf16')
        self.ole_logger.debug('ProjectDocStringRecord.DocStringUnicode: ' + self.DocStringUnicode)
        if self.DocStringUnicode != self.DocString:
            self._raise_exception('ProjectDocStringRecord.DocStringUnicode and DocStringRecord.DocString are mismatch.')


class ProjectHelpFilePathRecord(VBABase):
    
    Id = 0
    SizeOfHelpFile1 = 0
    HelpFile1 = ''
    Reserved = 0
    SizeOfHelpFile2 = 0
    HelpFile2 = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfHelpFile1 = 0
        self.HelpFile1 = ''
        self.Reserved = 0
        self.SizeOfHelpFile2 = 0
        self.HelpFile2 = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectHelpFilePathRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x06:
            self._raise_exception('ProjectHelpFilePathRecord.Id has an abnormal value.')

        self.SizeOfHelpFile1 = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectHelpFilePathRecord.SizeOfHelpFile1: ' + str(hex(self.SizeOfHelpFile1)))
        if self.SizeOfHelpFile1 > 260:
            self._raise_exception('ProjectHelpFilePathRecord.SizeOfHelpFile1 has an abnormal value.')

        self.HelpFile1 = data[0x06:0x06+self.SizeOfHelpFile1]
        self.ole_logger.debug('ProjectHelpFilePathRecord.HelpFile1: ' + self.HelpFile1)

        current = 0x06 + self.SizeOfHelpFile1
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ProjectHelpFilePathRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x3D:
            self._raise_exception('ProjectHelpFilePathRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfHelpFile2 = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ProjectHelpFilePathRecord.SizeOfHelpFile2: ' + str(hex(self.SizeOfHelpFile2)))
        if self.SizeOfHelpFile2 > 260:
            self._raise_exception('ProjectHelpFilePathRecord.SizeOfHelpFile2 has an abnormal value.')

        current = current + 0x04
        self.HelpFile2 = data[current:current+self.SizeOfHelpFile2]
        self.ole_logger.debug('ProjectHelpFilePathRecord.HelpFile2: ' + self.HelpFile2)


class ProjectHelpContextRecord(VBABase):
    
    Id = 0
    Size = 0
    HelpContext = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.HelpContext = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectHelpContextRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x07:
            self._raise_exception('ProjectHelpContextRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectHelpContextRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('ProjectHelpContextRecord.Size has an abnormal value.')

        self.HelpContext = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('ProjectHelpContextRecord.HelpContext: ' + str(hex(self.HelpContext)))


class ProjectLibFlagsRecord(VBABase):
    
    Id = 0
    Size = 0
    LibFlags = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.LibFlags = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectLibFlagsRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x8:
            self._raise_exception('ProjectLibFlagsRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectLibFlagsRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('ProjectLibFlagsRecord.Size has an abnormal value.')

        self.LibFlags = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('ProjectLibFlagsRecord.LibFlags: ' + str(hex(self.LibFlags)))
        if self.LibFlags != 0x00:
            self._raise_exception('ProjectLibFlagsRecord.LibFlags has an abnormal value.')


class ProjectVersionRecord(VBABase):
    
    Id = 0
    Size = 0
    MajorVersion = 0
    MinorVersion = 0

    def __init__(self, data):

        self.Id = 0
        self.Reserved = 0
        self.MajorVersion = 0
        self.MinorVersion = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectVersionRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x9:
            self._raise_exception('ProjectVersionRecord.Id has an abnormal value.')

        self.Reserved = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectVersionRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x04:
            self._raise_exception('ProjectVersionRecord.Reserved has an abnormal value.')

        self.MajorVersion = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('ProjectVersionRecord.MajorVersion: ' + str(hex(self.MajorVersion)))

        self.MinorVersion = struct.unpack('<H', data[0x0A:0x0C])[0]
        self.ole_logger.debug('ProjectVersionRecord.MinorVersion: ' + str(hex(self.MinorVersion)))


class ProjectConstantsRecord(VBABase):
    
    Id = 0
    SizeOfConstants = 0
    Constants = ''
    Reserved = 0
    SizeOfConstantsUnicode = 0
    ConstantsUnicode = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfConstants = 0
        self.Constants = ''
        self.Reserved = 0
        self.SizeOfConstantsUnicode = 0
        self.ConstantsUnicode = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectConstantsRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x0C:
            self._raise_exception('ProjectConstantsRecord.Id has an abnormal value.')

        self.SizeOfConstants = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectConstantsRecord.SizeOfConstants: ' + str(hex(self.SizeOfConstants)))
        if self.SizeOfConstants > 1015:
            self._raise_exception('ProjectConstantsRecord.SizeOfConstants has an abnormal value.')

        self.Constants = data[0x06:0x06+self.SizeOfConstants]
        self.ole_logger.debug('ProjectConstantsRecord.Constants: ' + self.Constants)

        current = 0x06 + self.SizeOfConstants
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ProjectConstantsRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x3C:
            self._raise_exception('ProjectConstantsRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfConstantsUnicode = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ProjectConstantsRecord.SizeOfConstantsUnicode: ' + str(hex(self.SizeOfConstantsUnicode)))
        if self.SizeOfConstantsUnicode > 1015*2:
            self._raise_exception('ProjectConstantsRecord.SizeOfConstantsUnicode has an abnormal value.')

        current = current + 0x04
        self.ConstantsUnicode = data[current:current+self.SizeOfConstantsUnicode].decode('utf16')
        self.ole_logger.debug('ProjectConstantsRecord.ConstantsUnicode: ' + self.ConstantsUnicode)
        if self.ConstantsUnicode != self.Constants:
            self._raise_exception('ProjectConstantsRecord.ConstantsUnicode and ConstantsRecord.Constants are mismatch.')


class ProjectInformationRecord(VBABase):

    SysKindRecord = None
    LcidRecord = None
    LcidInvokeRecord = None
    CodePageRecord = None
    NameRecord = None
    DocStringRecord = None
    HelpFilePathRecord = None
    HelpContextRecord = None
    LibFlagsRecord = None
    VersionRecord = None
    ConstantsRecord = None
    Size = 0

    def __init__(self, data):

        self.SysKindRecord = None
        self.LcidRecord = None
        self.LcidInvokeRecord = None
        self.NameRecord = None
        self.DocStringRecord = None
        self.HelpFilePathRecord = None
        self.HelpContextRecord = None
        self.LibFlagsRecord = None
        self.VersionRecord = None
        self.ConstantsRecord = None
        self.Size = 0

        self.SysKindRecord = ProjectSysKindRecord(data[0x00:0x0A])
        
        self.LcidRecord = ProjectLcidRecord(data[0x0A:0x14])
        
        self.LcidInvokeRecord = ProjectLcidInvokeRecord(data[0x14:0x1E])
        
        self.CodePageRecord = ProjectCodePageRecord(data[0x1E:0x26])
        
        self.NameRecord = ProjectNameRecord(data[0x26:])

        current = 0x26 + 0x06 + self.NameRecord.Size
        self.DocStringRecord = ProjectDocStringRecord(data[current:])

        current = current + 0x0C + self.DocStringRecord.SizeOfDocString + self.DocStringRecord.SizeOfDocStringUnicode
        self.HelpFilePathRecord = ProjectHelpFilePathRecord(data[current:])

        current = current + 0x0C + self.HelpFilePathRecord.SizeOfHelpFile1 + self.HelpFilePathRecord.SizeOfHelpFile2
        self.HelpContextRecord = ProjectHelpContextRecord(data[current:])

        current = current + 0x0A
        self.LibFlagsRecord = ProjectLibFlagsRecord(data[current:])

        current = current + 0x0A
        self.VersionRecord = ProjectVersionRecord(data[current:])

        current = current + 0x0C
        self.ConstantsRecord = ProjectConstantsRecord(data[current:])

        self.Size = current + 0x0C + self.ConstantsRecord.SizeOfConstants + self.ConstantsRecord.SizeOfConstantsUnicode


class ReferenceNameRecord(VBABase):

    Id = 0
    SizeOfName = 0
    Name = ''
    Reserved = 0
    SizeOfNameUnicode = 0
    NameUnicode = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfName = 0
        self.Name = ''
        self.Reserved = 0
        self.SizeOfNameUnicode = 0
        self.NameUnicode = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ReferenceNameRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x16:
            self._raise_exception('ReferenceNameRecord.Id has an abnormal value.')

        self.SizeOfName = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ReferenceNameRecord.SizeOfName: ' + str(hex(self.SizeOfName)))

        self.Name = data[0x06:0x06+self.SizeOfName]
        self.ole_logger.debug('ReferenceNameRecord.Name: ' + self.Name)

        current = 0x06 + self.SizeOfName
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceNameRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x3E:
            self._raise_exception('ReferenceNameRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfNameUnicode = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceNameRecord.SizeOfNameUnicode: ' + str(hex(self.SizeOfNameUnicode)))

        current = current + 0x04
        self.NameUnicode = data[current:current+self.SizeOfNameUnicode].decode('utf16')
        self.ole_logger.debug('ReferenceNameRecord.NameUnicode: ' + self.NameUnicode)
        if self.NameUnicode != self.Name:
            self._raise_exception('ReferenceNameRecord.NameUnicode and RefenceNameRecord.Name are mismatch.')


class ReferenceOriginalRecord(VBABase):

    Id = 0
    SizeOfLibidOriginal = 0
    LibidOriginal = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfLibidOriginal = 0
        self.LibidOriginal = ''

        self.id = struct.unpack('<H', data[0x00:0x02])[0]
        if self.id != 0x33:
            self._raise_exception('ReferenceOriginalRecord.Id has an abnormal value.')

        self.SizeOfLibidOriginal = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ReferenceOriginalRecord.SizeOfLibidOriginal: ' + str(hex(self.SizeOfLibidOriginal)))

        self.LibidOriginal = data[0x06:0x06+self.SizeOfLibidOriginal]
        self.ole_logger.debug('ReferenceOriginalRecord.LibidOriginal: ' + self.LibidOriginal)


class ReferenceControlRecord(VBABase):

    OriginalRecord = None
    Id = 0
    SizeTwiddled = 0
    SizeOfLibidTwiddled = 0
    LibidTwiddled = ''
    Reserved1 = 0
    Reserved2 = 0
    NameRecordExtended = None
    Reserved3 = 0
    SizeExtended = 0
    SizeOfLibidExtended = 0
    LibidExtended = ''
    Reserved4 = 0
    Reserved5 = 0
    OriginalTypeLib = ''
    Cookie = 0
    Size = 0

    def __init__(self, data):

        self.OriginalRecord = None
        self.Id = 0
        self.SizeTwiddled = 0
        self.SizeOfLibidTwiddled = 0
        self.LibidTwiddled = ''
        self.Reserved1 = 0
        self.Reserved2 = 0
        self.NameRecordExtended = None
        self.Reserved3 = 0
        self.SizeExtended = 0
        self.SizeOfLibidExtended = 0
        self.LibidExtended = ''
        self.Reserved4 = 0
        self.Reserved5 = 0
        self.OriginalTypeLib = ''
        self.Cookie = 0
        self.Size = 0

        current = 0

        id = struct.unpack('<H', data[current:current+0x02])[0]
        if id == 0x33:
            self.OriginalRecord = RefenceOriginalRecord(data)
            current = current + 0x06 + self.OriginalRecord.SizeOfLibidOriginal

        self.Id = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceControlRecord.Id: ' + str(hex(self.Id)))
        if self.id != 0x2F:
            self._raise_exception('ReferenceControlRecord.Id has an abnormal value.')

        current = current + 0x02
        self.SizeTwiddled = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceControlRecord.SizeTwiddled: ' + str(hex(self.SizeTwiddled)))

        current = current + 0x04
        self.SizeOfLibidTwiddled = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceControlRecord.SizeOfLibidTwiddled: ' + str(hex(self.SizeOfLibidTwiddled)))

        current = current + 0x04   
        self.LibidTwiddled = data[current:current+self.SizeTwiddled]
        self.ole_logger.debug('ReferenceControlRecord.LibidTwiddled: ' + self.LibidTwiddled)

        current = current + self.SizeTwiddled
        self.Reserved1 = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceControlRecord.Reserved1: ' + str(hex(self.Reserved1)))
        if self.Reserved1 != 0x00:
            self._raise_exception('ReferenceControlRecord.Reserved1 has an abnormal value.')

        current = current + 0x04
        self.Reserved2 = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceControlRecord.Reserved2: ' + str(hex(self.Reserved2)))
        if self.Reserved2 != 0x00:
            self._raise_exception('ReferenceControlRecord.Reserved2 has an abnormal value.')

        current = current + 0x02
        id = struct.unpack('<H', data[current:current+0x02])[0]
        if id == 0x16:
            self.NameRecordExtended = ReferenceNameRecord(data[current:])
            current = current + 0x0C + self.NameRecord.SizeOfName + self.NameRecord.SizeOfNameUnicode

        self.Reserved3 = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceControlRecord.Reserved3: ' + str(hex(self.Reserved3)))
        if self.Reserved3 != 0x00:
            self._raise_exception('ReferenceControlRecord.Reserved3 has an abnormal value.')

        current = current + 0x02
        self.SizeExtended = struct.unpack('<H', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceControlRecord.SizeExtended: ' + str(hex(self.SizeExtended)))

        current = current + 0x04
        self.SizeOfLibidExtended = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceControlRecord.SizeOfLibidExtended: ' + str(hex(self.SizeOfLibidExtended)))

        current = current + 0x04
        self.LibidExtended = data[current:current+self.SizeOfLibidExtended]
        self.ole_logger.debug('ReferenceControlRecord.LibidExtended: ' + self.LibidExtended)

        current = current + self.SizeOfLibidExtended
        self.Reserved4 = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceControlRecord.Reserved4: ' + str(hex(self.Reserved4)))
        if self.Reserved4 != 0x00:
            self._raise_exception('ReferenceControlRecord.Reserved4 has an abnormal value.')

        current = current + 0x04
        self.Reserved5 = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceControlRecord.Reserved5: ' + str(hex(self.Reserved5)))
        if self.Reserved5 != 0x00:
            self._raise_exception('ReferenceControlRecord.Reserved5 has an abnormal value.')

        current = current + 0x02
        self.OriginalTypeLib = data[current:current+0x10]
        self.ole_logger.debug('ReferenceControlRecord.OriginalTypeLib: ' + self.OriginalTypeLib.encode('hex'))

        current = current + 0x10
        self.Cookie = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceControlRecord.Cookie: ' + str(hex(self.Cookie)))

        self.Size = current + 0x04


class ReferenceRegisteredRecord(VBABase):

    Id = 0
    Size = 0
    SizeOfLibid = 0
    Libid = ''
    Reserved1 = 0
    Reserved2 = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.SizeOfLibid = 0
        self.Libid = ''
        self.Reserved1 = 0
        self.Reserved2 = 0

        current = 0
        self.Id = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceRegisteredRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x0D:
            self._raise_exception('ReferenceRegisteredRecord.Id has an abnormal value.')

        current = current + 0x02
        self.Size = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceRegisteredRecord.Size: ' + str(hex(self.Size)))

        current = current + 0x04
        self.SizeOfLibid = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceRegisteredRecord.SizeOfLibid: ' + str(hex(self.SizeOfLibid)))

        current = current + 0x04   
        self.Libid = data[current:current+self.SizeOfLibid]
        self.ole_logger.debug('ReferenceRegisteredRecord.Libid: ' + self.Libid)

        current = current + self.SizeOfLibid
        self.Reserved1 = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceRegisteredRecord.Reserved1: ' + str(hex(self.Reserved1)))
        if self.Reserved1 != 0x00:
            self._raise_exception('ReferenceRegisteredRecord.Reserved1 has an abnormal value.')

        current = current + 0x04
        self.Reserved2 = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceRegisteredRecord.Reserved2: ' + str(hex(self.Reserved2)))
        if self.Reserved2 != 0x00:
            self._raise_exception('ReferenceRegisteredRecord.Reserved2 has an abnormal value.')


class ReferenceProjectRecord(VBABase):

    Id = 0
    Size = 0
    SizeOfLibidAbsolute = 0
    LibidAbsolute = ''
    SizeOfLibidRelative = 0
    LibidRelative = ''
    MajorVersion = 0
    MinorVersion = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.SizeOfLibidAbsolute = 0
        self.LibidAbsolute = ''
        self.SizeOfLibidRelative = 0
        self.LibidRelative = ''
        self.MajorVersion = 0
        self.MinorVersion = 0

        current = 0
        self.Id = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceProjectRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x0E:
            self._raise_exception('ReferenceProjectRecord.Id has an abnormal value.')

        current = current + 0x02
        self.Size = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceProjectRecord.Size: ' + str(hex(self.Size)))

        current = current + 0x04
        self.SizeOfLibidAbsolute = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceProjectRecord.SizeOfLibidAbsolute: ' + str(hex(self.SizeOfLibidAbsolute)))

        current = current + 0x04   
        self.LibidAbsolute = data[current:current+self.SizeOfLibidAbsolute]
        self.ole_logger.debug('ReferenceProjectRecord.LibidAbsolute: ' + self.LibidAbsolute)

        current = current + self.SizeOfLibidAbsolute
        self.SizeOfLibidRelative = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceProjectRecord.SizeOfLibidRelative: ' + str(hex(self.SizeOfLibidRelative)))

        current = current + 0x04   
        self.LibidRelative = data[current:current+self.SizeOfLibidRelative]
        self.ole_logger.debug('ReferenceProjectRecord.LibidRelative: ' + self.LibidRelative)

        current = current + self.SizeOfLibidRelative
        self.MajorVersion = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ReferenceProjectRecord.MajorVersion: ' + str(hex(self.MajorVersion)))

        current = current + 0x04
        self.MinorVersion = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ReferenceProjectRecord.MinorVersion: ' + str(hex(self.MinorVersion)))


class ProjectReferencesRecord(VBABase):

    ReferenceArray = list()
    Size = 0

    def __init__(self, data):

        self.ReferenceArray = list()
        self.Size = 0

        current = 0
        NameRecord = None
        ControlRecord = None
        RegisteredRecord = None
        ProjectRecord = None

        while True:

            id = struct.unpack('<H', data[current:current+2])[0]

            if id == 0x0F:
                self.Size = current
                break

            elif id == 0x16:
                NameRecord = ReferenceNameRecord(data[current:])
                current = current + 0x0C + NameRecord.SizeOfName + NameRecord.SizeOfNameUnicode

                id = struct.unpack('<H', data[current:current+2])[0]

                if id == 0x2F or id == 0x33:
                    ControlRecord = ReferenceControlRecord(data[current:])
                    current = current + ControlRecord.Size
                    self.ReferenceArray.append([NameRecord, ControlRecord])

                elif id == 0x0D:
                    RegisteredRecord = ReferenceRegisteredRecord(data[current:])
                    current = current + 0x06 + RegisteredRecord.Size
                    self.ReferenceArray.append([NameRecord, RegisteredRecord])

                elif id == 0x0E:
                    ProjectRecord = ReferenceProjectRecord(data[current:])
                    current = current + 0x06 + ProjectRecord.Size
                    self.ReferenceArray.append([NameRecord, ProjectRecord])
                
                else:
                    self._raise_exception('ReferencesRecord.Id has an abnormal value.')

            elif id == 0x2F or id == 0x33:
                ControlRecord = ReferenceControlRecord(data[current:])
                current = current + ControlRecord.Size
                self.ReferenceArray.append([None, ControlRecord])

            elif id == 0x0D:
                RegisteredRecord = ReferenceRegisteredRecord(data[current:])
                current = current + 0x06 + RegisteredRecord.Size
                self.ReferenceArray.append([None, RegisteredRecord])

            elif id == 0x0E:
                ProjectRecord = ReferenceProjectRecord(data[current:])
                current = current + 0x06 + ProjectRecord.Size
                self.ReferenceArray.append([None, ProjectRecord])
            
            else:
                self._raise_exception('ReferencesRecord.Id has an abnormal value.')


class ProjectCookieRecord(VBABase):
    
    Id = 0
    Size = 0
    Cookie = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.CodePage = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ProjectCookieRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x13:
            self._raise_exception('ProjectCookieRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ProjectCookieRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x02:
            self._raise_exception('ProjectCookieRecord.Size has an abnormal value.')

        self.Cookie = struct.unpack('<H', data[0x06:0x08])[0]
        self.ole_logger.debug('ProjectCookieRecord.Cookie: ' + str(hex(self.Cookie)))


class ModuleNameRecord(VBABase):

    Id = 0
    SizeOfModuleName = 0
    ModuleName = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfModuleName = 0
        self.ModuleName = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleNameRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x19:
            self._raise_exception('ModuleNameRecord.Id has an abnormal value.')

        self.SizeOfModuleName = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleNameRecord.Size: ' + str(hex(self.SizeOfModuleName)))

        self.ModuleName = data[0x06:0x06+self.SizeOfModuleName]
        self.ole_logger.debug('ModuleNameRecord.ModuleName: ' + self.ModuleName)


class ModuleNameUnicodeRecord(VBABase):

    Id = 0
    SizeOfModuleNameUnicode = 0
    ModuleNameUnicode = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfModuleName = 0
        self.ModuleNameUnicode = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleNameUnicodeRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x47:
            self._raise_exception('ModuleNameUnicodeRecord.Id has an abnormal value.')

        self.SizeOfModuleNameUnicode = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleNameUnicodeRecord.SizeOfModuleNameUnicode: ' + str(hex(self.SizeOfModuleNameUnicode)))

        self.ModuleNameUnicode = data[0x06:0x06+self.SizeOfModuleNameUnicode].decode('utf-16')
        self.ole_logger.debug('ModuleNameUnicodeRecord.ModuleName: ' + self.ModuleNameUnicode)


class ModuleStreamNameRecord(VBABase):
    
    Id = 0
    SizeOfStreamName = 0
    StreamName = ''
    Reserved = 0
    SizeOfStreamNameUnicode = 0
    StreamNameUnicode = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfStreamName = 0
        self.StreamName = ''
        self.Reserved = 0
        self.SizeOfStreamNameUnicode = 0
        self.StreamNameUnicode = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleStreamNameRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x1A:
            self._raise_exception('ModuleStreamNameRecord.Id has an abnormal value.')

        self.SizeOfStreamName = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleStreamNameRecord.SizeOfStreamName: ' + str(hex(self.SizeOfStreamName)))

        self.StreamName = data[0x06:0x06+self.SizeOfStreamName]
        self.ole_logger.debug('ModuleStreamNameRecord.StreamName: ' + self.StreamName)

        current = 0x06 + self.SizeOfStreamName
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ModuleStreamNameRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x32:
            self._raise_exception('ModuleStreamNameRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfStreamNameUnicode = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ModuleStreamNameRecord.SizeOfStreamNameUnicode: ' + str(hex(self.SizeOfStreamNameUnicode)))

        current = current + 0x04
        self.StreamNameUnicode = data[current:current+self.SizeOfStreamNameUnicode].decode('utf16')
        self.ole_logger.debug('ModuleStreamNameRecord.StreamNameUnicode: ' + self.StreamNameUnicode)
        if self.StreamNameUnicode != self.StreamName:
            self._raise_exception('ModuleStreamNameRecord.StreamNameUnicode and ModuleStreamNameRecord.StreamName are mismatch.')


class ModuleDocStringRecord(VBABase):
    
    Id = 0
    SizeOfDocString = 0
    DocString = ''
    Reserved = 0
    SizeOfDocStringUnicode = 0
    DocStringUnicode = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfDocString = 0
        self.DocString = ''
        self.Reserved = 0
        self.SizeOfDocStringUnicode = 0
        self.DocStringUnicode = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleDocStringRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x1C:
            self._raise_exception('ModuleDocStringRecord.Id has an abnormal value.')

        self.SizeOfDocString = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleDocStringRecord.SizeOfDocString: ' + str(hex(self.SizeOfDocString)))

        self.DocString = data[0x06:0x06+self.SizeOfDocString]
        self.ole_logger.debug('ModuleDocStringRecord.DocString: ' + self.DocString)

        current = 0x06 + self.SizeOfDocString
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ModuleDocStringRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x48:
            self._raise_exception('ModuleDocStringRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfDocStringUnicode = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ModuleDocStringRecord.SizeOfDocStringUnicode: ' + str(hex(self.SizeOfDocStringUnicode)))

        current = current + 0x04
        self.DocStringUnicode = data[current:current+self.SizeOfDocStringUnicode].decode('utf16')
        self.ole_logger.debug('ModuleDocStringRecord.DocStringUnicode: ' + self.DocStringUnicode)
        if self.DocStringUnicode != self.DocString:
            self._raise_exception('ModuleDocStringRecord.DocStringUnicode and ModuleDocStringRecord.DocString are mismatch.')    


class ModuleOffsetRecord(VBABase):
    
    Id = 0
    Size = 0
    TextOffset = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.TextOffset = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleOffsetRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x31:
            self._raise_exception('ModuleOffsetRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleOffsetRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('ModuleOffsetRecord.Size has an abnormal value.')

        self.TextOffset = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('ModuleOffsetRecord.TextOffset: ' + str(hex(self.TextOffset)))    


class ModuleHelpContextRecord(VBABase):
    
    Id = 0
    Size = 0
    HelpContext = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.HelpContext = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleHelpContextRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x1E:
            self._raise_exception('ModuleHelpContextRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleHelpContextRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('ModuleHelpContextRecord.Size has an abnormal value.')

        self.HelpContext = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('ModuleHelpContextRecord.HelpContext: ' + str(hex(self.HelpContext)))    


class ModuleCookieRecord(VBABase):
    
    Id = 0
    Size = 0
    Cookie = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.Cookie = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleCookieRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x2C:
            self._raise_exception('ModuleCookieRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleCookieRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x02:
            self._raise_exception('ModuleCookieRecord.Size has an abnormal value.')

        self.Cookie = struct.unpack('<H', data[0x06:0x08])[0]
        self.ole_logger.debug('ModuleCookieRecord.Cookie: ' + str(hex(self.Cookie)))      


class ModuleTypeRecord(VBABase):
    
    Id = 0
    Reserved = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleTypeRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x21 and self.Id != 0x22:
            self._raise_exception('ModuleTypeRecord.Id has an abnormal value.')

        self.Reserved = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleTypeRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x00:
            self._raise_exception('ModuleTypeRecord.Reserved has an abnormal value.')


class ModuleReadOnlyRecord(VBABase):
    
    Id = 0
    Reserved = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModuleReadOnlyRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x25:
            self._raise_exception('ModuleReadOnlyRecord.Id has an abnormal value.')

        self.Reserved = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModuleReadOnlyRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x00:
            self._raise_exception('ModuleReadOnlyRecord.Reserved has an abnormal value.')


class ModulePrivateRecord(VBABase):
    
    Id = 0
    Reserved = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModulePrivateRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x28:
            self._raise_exception('ModulePrivateRecord.Id has an abnormal value.')

        self.Reserved = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModulePrivateRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x00:
            self._raise_exception('ModulePrivateRecord.Reserved has an abnormal value.')


class ModuleRecord(VBABase):

    NameRecord = None
    NameUnicodeRecord = None
    StreamNameRecord = None
    DocStringRecord = None
    OffsetRecord = None
    HelpContextRecord = None
    CookieRecord = None
    TypeRecord = None
    ReadOnlyRecord = None
    PrivateRecord = None
    Terminator = 0
    Reserved = 0
    Size = 0
    

    def __init__(self, data):

        self.NameRecord = None
        self.NameUnicodeRecord = None
        self.StreamNameRecord = None
        self.DocStringRecord = None
        self.OffsetRecord = None
        self.HelpContextRecord = None
        self.CookieRecord = None
        self.TypeRecord = None
        self.ReadOnlyRecord = None
        self.PrivateRecord = None
        self.Terminator = 0
        self.Reserved = 0
        self.Size = 0

        current = 0
        self.NameRecord = ModuleNameRecord(data)

        current = current + 0x06 + self.NameRecord.SizeOfModuleName
        self.NameUnicodeRecord = ModuleNameUnicodeRecord(data[current:])
        if self.NameUnicodeRecord.ModuleNameUnicode != self.NameRecord.ModuleName:
            self._raise_exception('ModuleRecord.ModuleNameUnicode and ModuleRecord.ModuleName are mismatch.')

        current = current + 0x06 + self.NameUnicodeRecord.SizeOfModuleNameUnicode
        self.StreamNameRecord = ModuleStreamNameRecord(data[current:])

        current = current + 0x0C + self.StreamNameRecord.SizeOfStreamName + self.StreamNameRecord.SizeOfStreamNameUnicode
        self.DocStringRecord = ModuleDocStringRecord(data[current:])

        current = current + 0x0C + self.DocStringRecord.SizeOfDocString + self.DocStringRecord.SizeOfDocStringUnicode
        self.OffsetRecord = ModuleOffsetRecord(data[current:current+0x0A])

        current = current + 0x0A
        self.HelpContextRecord = ModuleHelpContextRecord(data[current:current+0x0A])

        current = current + 0x0A
        self.CookieRecord = ModuleCookieRecord(data[current:current+0x08])

        current = current + 0x08
        self.TypeRecord = ModuleTypeRecord(data[current:current+0x06])

        while True:
            current = current + 0x06
            id = struct.unpack('<H', data[current:current+0x02])[0]

            if id == 0x25:
                self.ReadOnlyRecord = ModuleReadOnlyRecord(data[current:current+0x06])
            elif id == 0x28:
                self.PrivateRecord = ModulePrivateRecord(data[current:current+0x06])
            elif id == 0x2B:
                self.Terminator = struct.unpack('<H', data[current:current+0x02])[0]
                break
            else:
                self._raise_exception('ModuleRecord contains an abnormal record id.')

        current = current + 0x02
        self.Reserved = struct.unpack('<I', data[current:current+0x04])[0]
        if self.Size != 0x00:
            self._raise_exception('ModuleRecord.Reserved has an abnormal value.')
        
        self.Size = current + 0x04


class ProjectModulesRecord(VBABase):

    Id = 0
    Size = 0
    Count = 0
    CookieRecord = None
    ModuleArray = list()

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.Count = 0
        self.CookieRecord = None
        self.ModuleArray = list()

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ModulesRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x0F:
            self._raise_exception('ModulesRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ModulesRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x02:
            self._raise_exception('ModulesRecord.Size has an abnormal value.')
            
        self.Count = struct.unpack('<H', data[0x06:0x08])[0]
        self.ole_logger.debug('ModulesRecord.Count: ' + str(hex(self.Count)))

        self.CookieRecord = ProjectCookieRecord(data[0x08:0x10])

        current = 0x10
        for i in range(0, self.Count):
            Module = ModuleRecord(data[current:])
            self.ModuleArray.append(Module)
            current = current + Module.Size
        
        
class DirStream(VBABase):

    InformationRecord = None
    ReferencesRecord = None
    ModulesRecord = None

    def __init__(self, data):

        self.InformationRecord = None
        self.ReferencesRecord = None
        self.ModulesRecord = None
    
        self.ole_logger.debug('######## dirStream ########')
        
        data = self._decompress(data)

        self.InformationRecord = ProjectInformationRecord(data)

        current = self.InformationRecord.Size
        self.ReferencesRecord = ProjectReferencesRecord(data[current:])

        current = current + self.ReferencesRecord.Size
        self.ModulesRecord = ProjectModulesRecord(data[current:])


class VBAFile(VBABase):

    OLE = None
    PROJECT = None
    PROJECTwm = None
    VBA_PROJECT = None
    dir = None

    def __init__(self, filename):

        self.OLE = None
        self.PROJECT = None
        self.PROJECTwm = None
        self.VBA_PROJECT = None
        self.dir = None

        self.OLE = OLEFile(filename)

        project_data = self.OLE.find_object_by_name('PROJECT')
        if project_data is not None:
            self.PROJECT = ProjectStream(project_data)
        else:
            self._raise_exception('VBA project does not contain the PROJECT stream.')
            
        projectwm_data = self.OLE.find_object_by_name('PROJECTwm')
        if projectwm_data is not None:
            self.PROJECTwm = Projectwm(projectwm_data)
            
        vba_project_data = self.OLE.find_object_by_name('_VBA_PROJECT')
        if vba_project_data is not None:
            self.VBA_PROJECT = VBAProject(vba_project_data)
        else:
            self._raise_exception('VBA project does not contain the _VBA_PROJECT stream.')

        dir_data = self.OLE.find_object_by_name('dir')
        if dir_data is not None:
            self.dir = DirStream(dir_data)
        else:
            self._raise_exception('VBA project does not contain the dir stream.')


if __name__ == '__main__':

    init_logging(True)
    #init_logging(False)

    try:
        vba = VBAFile('oletest1.doc')
    except Exception as e:
        print e