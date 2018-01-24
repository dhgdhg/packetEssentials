import time
from drivers import Drivers

pParser = Drivers()

class Unify(object):
    """This class acts a singular point of contact for tracking purposes"""

    def __init__(self, iwDriver):
        ## Set the driver
        self.iwDriver = iwDriver
        
        ## Notate driver offset
        self.driver = Drivers()
        self.offset = self.driver.drivers(self.iwDriver)


    def times(self):
        """Timestamp function"""
        ### This converts to Wireshark style
        #int(wepCrypto.endSwap('0x' + p.byteRip(f.notdecoded[8:], qty = 8, compress = True)), 16)
        epoch = int(time.time())
        lDate = time.strftime('%Y%m%d', time.localtime())
        lTime = time.strftime('%H:%M:%S', time.localtime())
        return epoch, lDate, lTime
