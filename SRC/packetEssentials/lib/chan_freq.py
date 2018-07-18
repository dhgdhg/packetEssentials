class ChanFreq(object):
    """This class is for channel/frequency specific tasks"""
    
    def twoFour(self, val):
        """Frequency to Channel converter for 2.4 ghz"""
        typeDict = {2412: '1',
                    2417: '2',
                    2422: '3',
                    2427: '4',
                    2432: '5',
                    2437: '6',
                    2442: '7',
                    2447: '8',
                    2452: '9',
                    2457: '10',
                    2462: '11',
                    2467: '12',
                    2472: '13',
                    2484: '14'}
        return typeDict.get(val)


    def fiveEight(self, val):
        """Frequency to Channel converter for 5.8 ghz"""
        typeDict = {5180: '36',
                    5200: '40',
                    5210: '42',
                    5220: '44',
                    5240: '48',
                    5250: '50',
                    5260: '52',
                    5290: '58',
                    5300: '60',
                    5320: '64',
                    5745: '149',
                    5760: '152',
                    5765: '153',
                    5785: '157',
                    5800: '160',
                    5805: '161',
                    5825: '165'}
        return typeDict.get(val)

