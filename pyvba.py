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
                                offset = (((CopyToken & offsetmask) >> (16 - bitcount))) + 1
                                self.ole_logger.debug('CompressedChunk[' + str(i) + '].Token[' + str(j) + '].Offset: ' + str(hex(offset)))
                                srcoffset = DecompressedCurrent - offset
                                DecompressedBuffer += DecompressedBuffer[srcoffset:srcoffset+length]
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


class SysKindRecord(VBABase):

    Id = 0
    Size = 0
    SysKind = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.SysKind = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('SysKindRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x01:
            self._raise_exception('SysKindRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('SysKindRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('SysKindRecord.Size has an abnormal value.')

        self.SysKind = struct.unpack('<I', data[0x06:0x0A])[0]
        if self.SysKind == 0x00:
            self.ole_logger.debug('SysKindRecord.SysKind: ' + str(hex(self.SysKind)) + ' (16-bit Windows Platforms)')
        elif self.SysKind == 0x01:
            self.ole_logger.debug('SysKindRecord.SysKind: ' + str(hex(self.SysKind)) + ' (32-bit Windows Platforms)')
        elif self.SysKind == 0x02:
            self.ole_logger.debug('SysKindRecord.SysKind: ' + str(hex(self.SysKind)) + ' (Macintosh Platforms)')
        elif self.SysKind == 0x03:
            self.ole_logger.debug('SysKindRecord.SysKind: ' + str(hex(self.SysKind)) + ' (64-bit Windows Platforms)')
        else:
            self._raise_exception('SysKindRecord.SysKind has an abnormal value.')


class LcidRecord(VBABase):
    
    Id = 0
    Size = 0
    Lcid = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.Lcid = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('LcidRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x02:
            self._raise_exception('LcidRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('LcidRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('LcidRecord.Size has an abnormal value.')

        self.Lcid = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('LcidRecord.Lcid: ' + str(hex(self.Lcid)))
        if self.Lcid != 0x409:
            self._raise_exception('LcidRecord.Lcid has an abnormal value.')


class LcidInvokeRecord(VBABase):
    
    Id = 0
    Size = 0
    LcidInvoke = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.LcidInvoke = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('LcidInvokeRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x14:
            self._raise_exception('LcidInvokeRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('LcidInvokeRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('LcidInvokeRecord.Size has an abnormal value.')

        self.LcidInvoke = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('LcidInvokeRecord.LcidInvoke: ' + str(hex(self.LcidInvoke)))
        if self.LcidInvoke != 0x409:
            self._raise_exception('LcidInvokeRecord.LcidInvoke has an abnormal value.')


class CodePageRecord(VBABase):
    
    Id = 0
    Size = 0
    CodePage = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.CodePage = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('CodePageRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x03:
            self._raise_exception('CodePageRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('CodePageRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x02:
            self._raise_exception('CodePageRecord.Size has an abnormal value.')

        self.CodePage = struct.unpack('<H', data[0x06:0x08])[0]
        self.ole_logger.debug('CodePageRecord.CodePage: ' + str(hex(self.CodePage)))


class NameRecord(VBABase):
    
    Id = 0
    Size = 0
    ProjectName = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.ProjectName = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('NameRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x04:
            self._raise_exception('NameRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('NameRecord.Size: ' + str(hex(self.Size)))
        if self.Size < 0x01 or self.Size > 0x80:
            self._raise_exception('NameRecord.Size has an abnormal value.')

        self.ProjectName = data[0x06:0x06+self.Size]
        self.ole_logger.debug('NameRecord.ProjectName: ' + self.ProjectName)


class DocStringRecord(VBABase):
    
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
        self.ole_logger.debug('DocStringRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x05:
            self._raise_exception('DocStringRecord.Id has an abnormal value.')

        self.SizeOfDocString = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('DocStringRecord.SizeOfDocString: ' + str(hex(self.SizeOfDocString)))
        if self.SizeOfDocString > 2000:
            self._raise_exception('DocStringRecord.SizeOfDocString has an abnormal value.')

        self.DocString = data[0x06:0x06+self.SizeOfDocString]
        self.ole_logger.debug('DocStringRecord.DocString: ' + self.DocString)

        current = 0x06 + self.SizeOfDocString
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('DocStringRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x40:
            self._raise_exception('DocStringRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfDocStringUnicode = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('DocStringRecord.SizeOfDocStringUnicode: ' + str(hex(self.SizeOfDocStringUnicode)))
        if self.SizeOfDocStringUnicode > 2000*2:
            self._raise_exception('DocStringRecord.SizeOfDocStringUnicode has an abnormal value.')

        current = current + 0x04
        self.DocStringUnicode = data[current:current+self.SizeOfDocStringUnicode].decode('utf16')
        self.ole_logger.debug('DocStringRecord.DocStringUnicode: ' + self.DocStringUnicode)
        if self.DocStringUnicode != self.DocString:
            self._raise_exception('DocStringRecord.DocStringUnicode and DocStringRecord.DocString are mismatch.')


class HelpFilePathRecord(VBABase):
    
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
        self.ole_logger.debug('HelpFilePathRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x06:
            self._raise_exception('HelpFilePathRecord.Id has an abnormal value.')

        self.SizeOfHelpFile1 = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('HelpFilePathRecord.SizeOfHelpFile1: ' + str(hex(self.SizeOfHelpFile1)))
        if self.SizeOfHelpFile1 > 260:
            self._raise_exception('HelpFilePathRecord.SizeOfHelpFile1 has an abnormal value.')

        self.HelpFile1 = data[0x06:0x06+self.SizeOfHelpFile1]
        self.ole_logger.debug('HelpFilePathRecord.HelpFile1: ' + self.HelpFile1)

        current = 0x06 + self.SizeOfHelpFile1
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('HelpFilePathRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x3D:
            self._raise_exception('HelpFilePathRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfHelpFile2 = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('HelpFilePathRecord.SizeOfHelpFile2: ' + str(hex(self.SizeOfHelpFile2)))
        if self.SizeOfHelpFile2 > 260:
            self._raise_exception('HelpFilePathRecord.SizeOfHelpFile2 has an abnormal value.')

        current = current + 0x04
        self.HelpFile2 = data[current:current+self.SizeOfHelpFile2]
        self.ole_logger.debug('HelpFilePathRecord.HelpFile2: ' + self.HelpFile2)


class HelpContextRecord(VBABase):
    
    Id = 0
    Size = 0
    HelpContext = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.HelpContext = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('HelpContextRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x07:
            self._raise_exception('HelpContextRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('HelpContextRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('HelpContextRecord.Size has an abnormal value.')

        self.HelpContext = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('HelpContextRecord.HelpContext: ' + str(hex(self.HelpContext)))


class LibFlagsRecord(VBABase):
    
    Id = 0
    Size = 0
    LibFlags = 0

    def __init__(self, data):

        self.Id = 0
        self.Size = 0
        self.LibFlags = 0

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('LibFlagsRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x8:
            self._raise_exception('LibFlagsRecord.Id has an abnormal value.')

        self.Size = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('LibFlagsRecord.Size: ' + str(hex(self.Size)))
        if self.Size != 0x04:
            self._raise_exception('LibFlagsRecord.Size has an abnormal value.')

        self.LibFlags = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('LibFlagsRecord.LibFlags: ' + str(hex(self.LibFlags)))
        if self.LibFlags != 0x00:
            self._raise_exception('LibFlagsRecord.LibFlags has an abnormal value.')


class VersionRecord(VBABase):
    
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
        self.ole_logger.debug('VersionRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x9:
            self._raise_exception('VersionRecord.Id has an abnormal value.')

        self.Reserved = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('VersionRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x04:
            self._raise_exception('VersionRecord.Reserved has an abnormal value.')

        self.MajorVersion = struct.unpack('<I', data[0x06:0x0A])[0]
        self.ole_logger.debug('VersionRecord.MajorVersion: ' + str(hex(self.MajorVersion)))

        self.MinorVersion = struct.unpack('<H', data[0x0A:0x0C])[0]
        self.ole_logger.debug('VersionRecord.MinorVersion: ' + str(hex(self.MinorVersion)))


class ConstantsRecord(VBABase):
    
    Id = 0
    SizeOfConstants = 0
    Constants = ''
    Reserved = 0
    SizeOfConstantsUnicode = 0
    ConstantsUnicode = ''

    def __init__(self, data):

        self.Id = 0
        self.SizeOfHelpFile1 = 0
        self.Constants = ''
        self.Reserved = 0
        self.SizeOfHelpFile2 = 0
        self.HelpFile2 = ''

        self.Id = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('ConstantsRecord.Id: ' + str(hex(self.Id)))
        if self.Id != 0x0C:
            self._raise_exception('ConstantsRecord.Id has an abnormal value.')

        self.SizeOfConstants = struct.unpack('<I', data[0x02:0x06])[0]
        self.ole_logger.debug('ConstantsRecord.SizeOfConstants: ' + str(hex(self.SizeOfConstants)))
        if self.SizeOfConstants > 1015:
            self._raise_exception('ConstantsRecord.SizeOfConstants has an abnormal value.')

        self.Constants = data[0x06:0x06+self.SizeOfConstants]
        self.ole_logger.debug('ConstantsRecord.Constants: ' + self.Constants)

        current = 0x06 + self.SizeOfConstants
        self.Reserved = struct.unpack('<H', data[current:current+0x02])[0]
        self.ole_logger.debug('ConstantsRecord.Reserved: ' + str(hex(self.Reserved)))
        if self.Reserved != 0x3C:
            self._raise_exception('ConstantsRecord.Reserved has an abnormal value.')

        current = current + 0x02
        self.SizeOfConstantsUnicode = struct.unpack('<I', data[current:current+0x04])[0]
        self.ole_logger.debug('ConstantsRecord.SizeOfConstantsUnicode: ' + str(hex(self.SizeOfConstantsUnicode)))
        if self.SizeOfConstantsUnicode > 1015*2:
            self._raise_exception('ConstantsRecord.SizeOfConstantsUnicode has an abnormal value.')

        current = current + 0x04
        self.ConstantsUnicode = data[current:current+self.SizeOfConstantsUnicode].decode('utf16')
        self.ole_logger.debug('ConstantsRecord.ConstantsUnicode: ' + self.ConstantsUnicode)
        if self.ConstantsUnicode != self.Constants:
            self._raise_exception('ConstantsRecord.ConstantsUnicode and ConstantsRecord.Constants are mismatch.')


class ProjectInformation(VBABase):

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

        self.SysKindRecord = SysKindRecord(data[0x00:0x0A])
        
        self.LcidRecord = LcidRecord(data[0x0A:0x14])
        
        self.LcidInvokeRecord = LcidInvokeRecord(data[0x14:0x1E])
        
        self.CodePageRecord = CodePageRecord(data[0x1E:0x26])
        
        self.NameRecord = NameRecord(data[0x26:])

        current = 0x26 + 0x06 + self.NameRecord.Size
        self.DocStringRecord = DocStringRecord(data[current:])

        current = current + 0x0C + self.DocStringRecord.SizeOfDocString + self.DocStringRecord.SizeOfDocStringUnicode
        self.HelpFilePathRecord = HelpFilePathRecord(data[current:])

        current = current + 0x0C + self.HelpFilePathRecord.SizeOfHelpFile1 + self.HelpFilePathRecord.SizeOfHelpFile2
        self.HelpContextRecord = HelpContextRecord(data[current:])

        current = current + 0x0A
        self.LibFlagsRecord = LibFlagsRecord(data[current:])

        current = current + 0x0A
        self.VersionRecord = VersionRecord(data[current:])

        current = current + 0x0C
        self.ConstantsRecord = ConstantsRecord(data[current:])

        self.Size = current + 0x0C + self.ConstantsRecord.SizeOfConstants + self.ConstantsRecord.SizeOfConstantsUnicode


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
        #print data

        self.InformationRecord = ProjectInformation(data)


class VBA(VBABase):

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
        vba = VBA('oletest1.doc')
    except Exception as e:
        print e