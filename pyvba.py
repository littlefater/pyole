from pyole import *


class ProjectStream(OLEBase):

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
                

class VBA(OLEBase):

    OLE = None
    Project = None

    def __init__(self, filename):

        self.OLE = None
        self.Project = None

        self.OLE = OLEFile(filename)

        self.Project = ProjectStream(self.OLE.find_object_by_name('PROJECT'))


if __name__ == '__main__':

    init_logging(True)
    #init_logging(False)

    try:
        vba = VBA('oletest1.doc')
    except Exception as e:
        print e