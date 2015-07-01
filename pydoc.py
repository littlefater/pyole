# A simple DOC file parser based on pyole

import os
import struct
import logging
import datetime
from pyole import *


class FIBBase(OLEBase):

    wIdent = 0
    nFib = 0
    unused = 0
    lid = 0
    pnNext = 0
    Flags1 = 0
    fDot = 0
    fGlsy = 0
    fComplex = 0
    fHasPic = 0
    cQuickSaves = 0
    fEncrypted = 0
    fWhichTblStm = 0
    fReadOnlyRecommended = 0
    fWriteReservation = 0
    fExtChar = 0
    fLoadOverride = 0
    fFarEast = 0
    fObfuscated = 0
    nFibBack  = 0
    lKey = 0
    envr = 0
    Flag2 = 0
    fMac = 0
    fEmptySpecial = 0
    fLoadOverridePage = 0
    reserved1 = 0
    reserved2 = 0
    fSpare0 = 0
    reserved3 = 0
    reserved4 = 0
    reserved5 = 0
    reserved6 = 0

    def __init__(self, data):

        self.wIdent  = 0
        self.nFib = 0
        self.unused = 0
        self.pnNext = 0
        self.Flags1 = 0
        self.fDot = 0
        self.fGlsy = 0
        self.fComplex = 0
        self.fHasPic = 0
        self.cQuickSaves = 0
        self.fEncrypted = 0
        self.fWhichTblStm = 0
        self.fReadOnlyRecommended = 0
        self.fWriteReservation = 0
        self.fExtChar = 0
        self.fLoadOverride = 0
        self.fFarEast = 0
        self.fObfuscated = 0
        self.nFibBack  = 0
        self.lKey = 0
        self.envr = 0
        self.Flag2 = 0
        self.fMac = 0
        self.fEmptySpecial = 0
        self.fLoadOverridePage = 0
        self.reserved1 = 0
        self.reserved2 = 0
        self.fSpare0 = 0
        self.reserved3 = 0
        self.reserved4 = 0
        self.reserved5 = 0
        self.reserved6 = 0
        
        self.wIdent = struct.unpack('<H', data[0x00:0x02])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.wIdent: ' + str(hex(self.wIdent)))
        if self.wIdent != 0xA5EC:
            self._raise_exception('DOC.FIB.FIBBase.wIdent has an abnormal value.')

        self.nFib = struct.unpack('<H', data[0x02:0x04])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.nFib: ' + str(hex(self.nFib)))
        if self.nFib != 0x00C1:
            self._raise_exception('DOC.FIB.FIBBase.nFib has an abnormal value.')
        
        self.unused  = struct.unpack('<H', data[0x04:0x06])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.unused: ' + str(hex(self.unused)))
        #if self.unused != 0:
        #    self.ole_logger.warning('DOC.FIB.FIBBase.unused is not zero.')

        self.lid = struct.unpack('<H', data[0x06:0x08])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.lid: ' + str(hex(self.lid)))

        self.pnNext  = struct.unpack('<H', data[0x08:0x0A])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.pnNext: ' + str(hex(self.pnNext)))
        if self.pnNext != 0:
            self.ole_logger.warning('DOC.FIB.FIBBase.pnNext is not zero.')

        self.Flags1 = struct.unpack('<H', data[0x0A:0x0C])[0]
        self.fDot = self.Flags1 & 0x0001
        self.ole_logger.debug('DOC.FIB.FIBBase.fDot: ' + str(self.fDot))
        self.fGlsy = (self.Flags1 & 0x0002) >> 1
        self.ole_logger.debug('DOC.FIB.FIBBase.fGlsy: ' + str(self.fGlsy))
        self.fComplex = (self.Flags1 & 0x0004) >> 2
        self.ole_logger.debug('DOC.FIB.FIBBase.fComplex: ' + str(self.fComplex))
        self.fHasPic = (self.Flags1 & 0x0008) >> 3
        self.ole_logger.debug('DOC.FIB.FIBBase.fHasPic: ' + str(self.fHasPic))
        self.cQuickSaves = (self.Flags1 & 0x00F0) >> 4
        self.ole_logger.debug('DOC.FIB.FIBBase.cQuickSaves: ' + str(self.cQuickSaves))
        self.fEncrypted = (self.Flags1 & 0x0100) >> 8
        self.ole_logger.debug('DOC.FIB.FIBBase.fEncrypted: ' + str(self.fEncrypted))
        if self.fEncrypted == 1:
            self.ole_logger.warning('File is encrypted.')
        self.fWhichTblStm = (self.Flags1 & 0x0200) >> 9
        self.ole_logger.debug('DOC.FIB.FIBBase.fWhichTblStm: ' + str(self.fWhichTblStm))
        self.fReadOnlyRecommended = (self.Flags1 & 0x0400) >> 10
        self.ole_logger.debug('DOC.FIB.FIBBase.fReadOnlyRecommended: ' + str(self.fReadOnlyRecommended))
        self.fWriteReservation = (self.Flags1 & 0x0800) >> 11
        self.ole_logger.debug('DOC.FIB.FIBBase.fWriteReservation: ' + str(self.fWriteReservation))
        self.fExtChar = (self.Flags1 & 0x1000) >> 12
        self.ole_logger.debug('DOC.FIB.FIBBase.fExtChar: ' + str(self.fExtChar))
        if (self.Flags1 & 0x1000) >> 12 != 1:
            self._raise_exception('DOC.FIB.FIBBase.fExtChar has an abnormal value.')
        self.fLoadOverride = (self.Flags1 & 0x2000) >> 13
        self.ole_logger.debug('DOC.FIB.FIBBase.fLoadOverride: ' + str(self.fLoadOverride))
        self.fFarEast = (self.Flags1 & 0x4000) >> 14
        self.ole_logger.debug('DOC.FIB.FIBBase.fFarEast: ' + str(self.fFarEast))
        if self.fFarEast == 1:
            self.ole_logger.warning('The installation language of the application that created the document was an East Asian language.')
        self.fObfuscated = (self.Flags1 & 0x8000) >> 15
        self.ole_logger.debug('DOC.FIB.FIBBase.fObfuscated: ' + str(self.fObfuscated))
        if self.fObfuscated == 1:
            if self.fEncrypted == 1:
                self.ole_logger.warning('File is obfuscated by using XOR obfuscation.')
                
        self.nFibBack = struct.unpack('<H', data[0x0C:0x0E])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.nFibBack: ' + str(hex(self.nFibBack)))
        if self.nFibBack != 0x00BF and self.nFibBack != 0x00C1:
            self._raise_exception('DOC.FIB.FIBBase.nFibBack has an abnormal value.')

        self.lKey = struct.unpack('<I', data[0x0E:0x12])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.lKey: ' + str(hex(self.lKey)))
        if self.fEncrypted == 1:
            if self.fObfuscated == 1:
                self.ole_logger.info('The XOR obfuscation key is: ' + str(hex(self.lKey)))
        else:
            if self.lKey != 0:
                self._raise_exception('DOC.FIB.FIBBase.lKey has an abnormal value.')

        self.envr = ord(data[0x12])
        self.ole_logger.debug('DOC.FIB.FIBBase.envr: ' + str(hex(self.envr)))
        if self.envr != 0:
            self._raise_exception('DOC.FIB.FIBBase.envr has an abnormal value.')

        self.Flag2 = ord(data[0x13])
        self.fMac = self.Flag2 & 0x01
        self.ole_logger.debug('DOC.FIB.FIBBase.fMac: ' + str(hex(self.fMac)))
        if self.fMac != 0:
            self._raise_exception('DOC.FIB.FIBBase.fMac has an abnormal value.')
        self.fEmptySpecial = (self.Flag2 & 0x02) >> 1
        self.ole_logger.debug('DOC.FIB.FIBBase.fEmptySpecial: ' + str(hex(self.fEmptySpecial)))
        if self.fEmptySpecial != 0:
            self.ole_logger.warning('DOC.FIB.FIBBase.fEmptySpecial is not zero.')
        self.fLoadOverridePage = (self.Flag2 & 0x04) >> 2
        self.ole_logger.debug('DOC.FIB.FIBBase.fLoadOverridePage: ' + str(hex(self.fLoadOverridePage)))
        self.reserved1 = (self.Flag2 & 0x08) >> 3
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved1: ' + str(hex(self.reserved1)))
        self.reserved2 = (self.Flag2 & 0x10) >> 4
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved2: ' + str(hex(self.reserved2)))
        self.fSpare0 = (self.Flag2 & 0xE0) >> 5
        self.ole_logger.debug('DOC.FIB.FIBBase.fSpare0: ' + str(hex(self.fSpare0)))

        self.reserved3 = struct.unpack('<H', data[0x14:0x16])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved3: ' + str(hex(self.reserved3)))
        self.reserved4 = struct.unpack('<H', data[0x16:0x18])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved4: ' + str(hex(self.reserved4)))
        self.reserved5 = struct.unpack('<I', data[0x18:0x1C])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved5: ' + str(hex(self.reserved5)))
        self.reserved6 = struct.unpack('<I', data[0x1C:0x20])[0]
        self.ole_logger.debug('DOC.FIB.FIBBase.reserved6: ' + str(hex(self.reserved6)))


class FibRgFcLcb(OLEBase):

    fcSttbfAssoc  = 0
    lcbSttbfAssoc  = 0
    fcSttbfRMark  = 0
    lcbSttbfRMark = 0
    fcSttbSavedBy = 0
    lcbSttbSavedBy = 0
    dwLowDateTime = 0
    dwHighDateTime  = 0

    def __init__(self, data):

        self.fcSttbfAssoc  = 0
        self.lcbSttbfAssoc  = 0
        self.fcSttbfRMark  = 0
        self.lcbSttbfRMark = 0
        self.fcSttbSavedBy = 0
        self.lcbSttbSavedBy = 0
        self.dwLowDateTime = 0
        self.dwHighDateTime = 0

        self.fcSttbfAssoc = struct.unpack('<I', data[0x100:0x104])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.fcSttbfAssoc: ' + str(hex(self.fcSttbfAssoc)))
        self.lcbSttbfAssoc = struct.unpack('<I', data[0x104:0x108])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.lcbSttbfAssoc: ' + str(hex(self.lcbSttbfAssoc)))

        self.fcSttbfRMark = struct.unpack('<I', data[0x198:0x19C])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.fcSttbfRMark: ' + str(hex(self.fcSttbfRMark)))
        self.lcbSttbfRMark = struct.unpack('<I', data[0x19C:0x1A0])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.lcbSttbfRMark: ' + str(hex(self.lcbSttbfRMark)))

        self.fcSttbSavedBy = struct.unpack('<I', data[0x238:0x23C])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.fcSttbSavedBy: ' + str(hex(self.fcSttbSavedBy)))
        self.lcbSttbSavedBy = struct.unpack('<I', data[0x23C:0x240])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.lcbSttbSavedBy: ' + str(hex(self.lcbSttbSavedBy)))

        self.dwLowDateTime = struct.unpack('<I', data[0x2B8:0x2BC])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.dwLowDateTime: ' + str(hex(self.dwLowDateTime)))
        self.dwHighDateTime = struct.unpack('<I', data[0x2BC:0x2C0])[0]
        self.ole_logger.debug('DOC.FIB.FibRgFcLcb.dwHighDateTime: ' + str(hex(self.dwHighDateTime)))


class FIB(OLEBase):

    FIBBase = None
    csw = 0
    fibRgW = ''
    cslw = 0
    fibRgLw = ''
    cbRgFcLcb = 0
    fibRgFcLcbBlob = ''
    cswNew = 0

    def __init__(self, data):
        
        self.FIBBase = None
        self.csw = 0
        self.fibRgW = ''
        self.cslw = 0
        self.fibRgLw = ''
        self.cbRgFcLcb = 0
        self.fibRgFcLcbBlob = ''
        self.cswNew = 0

        self.ole_logger.debug('######## FIB ########')
        
        self.FIBBase = FIBBase(data[0:0x20])
        
        self.csw = struct.unpack('<H', data[0x20:0x22])[0]
        self.ole_logger.debug('DOC.FIB.csw: ' + str(hex(self.csw)))
        if self.csw != 0x000E:
            self._raise_exception('DOC.FIB.csw has an abnormal value.')

        self.fibRgW = data[0x22:0x3E]
        
        self.cslw = struct.unpack('<H', data[0x3E:0x40])[0]
        self.ole_logger.debug('DOC.FIB.cslw: ' + str(hex(self.cslw)))
        if self.cslw != 0x0016:
            self._raise_exception('DOC.FIB.cslw has an abnormal value.')
        
        self.fibRgLw = data[0x40:0x98]

        self.cbRgFcLcb = struct.unpack('<H', data[0x98:0x9A])[0]
        self.ole_logger.debug('DOC.FIB.cbRgFcLcb: ' + str(hex(self.cbRgFcLcb)))
        '''
        if self.FIBBase.nFib == 0x00C1 and self.cbRgFcLcb != 0x005D:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        if self.FIBBase.nFib == 0x00D9 and self.cbRgFcLcb != 0x006C:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        if self.FIBBase.nFib == 0x0101 and self.cbRgFcLcb != 0x0088:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        if self.FIBBase.nFib == 0x010C and self.cbRgFcLcb != 0x00A4:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        if self.FIBBase.nFib == 0x0112 and self.cbRgFcLcb != 0x00B7:
            self._raise_exception('DOC.FIB.cbRgFcLcb has an abnormal value.')
        '''

        self.fibRgFcLcbBlob = FibRgFcLcb(data[0x9A:0x9A+self.cbRgFcLcb*8])

        self.cswNew = struct.unpack('<H', data[0x9A+self.cbRgFcLcb*8:0x9A+self.cbRgFcLcb*8+0x02])[0]
        self.ole_logger.debug('DOC.FIB.cswNew: ' + str(hex(self.cswNew)))


class DOCFile(OLEBase):

    OLE = None
    FIB = None
    SummaryInfo = None
    DocumentSummaryInfo = None

    def __init__(self, filename):
        self.OLE = None
        self.FIB = None
        self.SummaryInfo = None
        self.DocumentSummaryInfo = None

        if os.path.isfile(filename) == False:
            self._raise_exception('Invalid file: ' + filename)

        self.OLE = OLEFile(filename)

        self.ole_logger.debug('***** Parse Word Document *****')
        self.FIB = FIB(self.OLE.find_object_by_name('WordDocument'))

    def show_rmark_authors(self):
        if self.FIB.fibRgFcLcbBlob.fcSttbfRMark != 0:
            table_stream = ''
            if self.FIB.FIBBase.fWhichTblStm == 1:
                table_stream = self.OLE.find_object_by_name('1Table')
            elif self.FIB.FIBBase.fWhichTblStm == 1:
                table_stream = self.OLE.find_object_by_name('0Table')
            else:
                print 'DOC.FIB.FIBBase.fWhichTblStm has an abnormal value.'
                return
                
            if len(table_stream) > 0:
                #print table_stream
                offset = self.FIB.fibRgFcLcbBlob.fcSttbfRMark
                length = self.FIB.fibRgFcLcbBlob.lcbSttbfRMark
                SttbfRMark = table_stream[offset:offset+length]
                fExtend = struct.unpack('<H', SttbfRMark[0x00:0x02])[0]
                if fExtend != 0xFFFF:
                    print 'fExtend has an abnormal value.'
                    return
                cbExtra = struct.unpack('<H', SttbfRMark[0x04:0x06])[0]
                if cbExtra != 0:
                    print 'cbExtra has an abnormal value.'
                    return
                cData = struct.unpack('<H', SttbfRMark[0x02:0x04])[0]
                offset = 0
                for i in range(0, cData):
                    cchData = struct.unpack('<H', SttbfRMark[0x06+offset:0x08+offset])[0]
                    Data = SttbfRMark[0x06+offset+0x02:0x08+offset+cchData*2]
                    print Data.decode('utf-16')
                    offset = offset + 0x02 + cchData*2
            else:
                print 'Failed to read the Table Stream.'
        else:
            print 'No revision marks or comments author information.'
            

if __name__ == '__main__':

    init_logging(True)
    
    try:
        docfile = DOCFile('oletest.doc')
        docfile.show_rmark_authors()
    except Exception as e:
        print e
    