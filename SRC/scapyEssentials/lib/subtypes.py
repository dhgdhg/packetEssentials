class Subtypes(object):
    """This class is for naming of subtypes where symStrings doesn't work"""

    def mgmtSubtype(self, val):
            """Management Frame Subtypes"""
            subDict = {4: 'Probe request',
                       5: 'Probe response',
                       8: 'Beacon'}
            return subDict.get(val)


    def ctrlSubtype(self, val):
        """Control Frame Subtypes"""
        subDict = {8: 'Block Ack Req',
                   9: 'Block Ack',
                   11: 'RTS',
                   12: 'CTS',
                   13: 'Acknowledgement'}
        return subDict.get(val)


    def dataSubtype(self, val):
        """Data Frame Subtypes"""
        subDict = {0: 'Data',
                   4: 'Null',
                   8: 'QoS Data',
                   12: 'QoS Null'}
