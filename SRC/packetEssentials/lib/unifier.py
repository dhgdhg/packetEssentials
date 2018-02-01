import time
from drivers import Drivers
from chan_freq import ChanFreq
from scapy.utils import hexstr

### Not sure if this is needed here
pParser = Drivers()

class Unify(object):
    """This class acts a singular point of contact for tracking purposes"""

    def __init__(self, iwDriver):
        ## Set the driver
        self.iwDriver = iwDriver
        
        ## Notate driver offset
        self.driver = Drivers()
        self.chanFreq = ChanFreq()
        self.offset = self.driver.drivers(self.iwDriver)


    def times(self):
        """Timestamp function"""
        ### This converts to Wireshark style
        #int(wepCrypto.endSwap('0x' + p.byteRip(f.notdecoded[8:], qty = 8, compress = True)), 16)
        epoch = int(time.time())
        lDate = time.strftime('%Y%m%d', time.localtime())
        lTime = time.strftime('%H:%M:%S', time.localtime())
        return epoch, lDate, lTime


    def getStats(self, pkt):
        """Returns statistics for a given packet based upon the driver in use
        
        Currently this function supports the following:
          - Channel
          - Frequency
          - RSSI
          
        If you think that this function should added to, submit a PR via github
        """
        notDecoded = hexstr(str(pkt.notdecoded), onlyhex=1).split(' ')
        try:
            chan = self.chanFreq.twoFour(int(notDecoded[self.offset] + notDecoded[self.offset - 1], 16))
        except:
            chan = -256
        try:
            freq = int(notDecoded[self.offset] + notDecoded[self.offset - 1], 16)
        except:
            freq = -256
        try:
            rssi = -(256 - int(notDecoded[self.offset + 3], 16))
        except:
            rssi = -256

        return {'chan': chan,
                'freq': freq,
                'rssi': rssi}
