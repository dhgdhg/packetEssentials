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
