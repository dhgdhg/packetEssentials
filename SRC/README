# packetEssentials
An essential set of modules for working with packets using the Scapy Library in Python.  Highly geared around 802.11, but still useful for Ethernet.

## Brief module descriptions
### chanFreq
Import for lib/chan_freq.py
This class is for channel/frequency specific tasks
* twoFour(val)
    ````python
    """"Converts the 2.4GHz frequency to its decimal-based counterpart"""
    print chanFreq.twoFour(2412)
    ````

### conv
Import for lib/converter.py
Class for simple conversions
* symString(packet, field)
    ````python
    """Shows the symblic string for a given field"""
    for i in range(200):
        p[0].FCfield = i
        print str(i) + '--' + conv.symString(p[0][Dot11], 'FCfield')
    ````

### drv
Import for lib/drivers.py
This class identifies the given offsets for drivers
* drivers(val)
    ````python
    """Returns the numeric driver offset for a given driver"""
    print drv.drivers('ath9k')
    ````

### sType
Import for lib/subtypes.py
This class is for naming of subtypes where symStrings doesn't work
* mgmtSubtype
    ````python
    """Returns Management Frame Subtypes"""
    print sType.mgmtSubtype(5)
    ````
* ctrlSubtype
    ````python
    """Returns Control Frame Subtypes"""
    print sType.ctrlSubtype(11)
    ````
* dataSubtype
    ````python
    """Returns Data Frame Subtypes"""
    print sType.dataSubtype(8)
    ````


### pt
Import for lib/utils.py
Class to deal with packet specific options
* byteRip
  * Needs example
* endSwap
    ````python
    """Takes an object and reverse Endians the bytes"""
    print pt.endSwap('0xaabbcc')
    print pt.endSwap(12345)
    print pt.endSwap('aabbcc')
    ````
* fcsGen
    ````python
    """Return the FCS for a given frame"""
    ## Thus far, you have built a frame called nPkt.
    ## You have added everything to it, except for the FCS
    nPkt = nPkt/Padding(load = SE.pt.fcsGen(nPkt[Dot11], output='str'))
    ````

## Uninstantiated modules
* lib/nic.py
  * Generates a tap interface
  ````python
  """Generates a tap interface
  By default, will create tap0 unless an integer parameter is added to Tap()
  """
  ## Create interface of tap3
  import packetEssentials as PE
  nClass = PE.lib.nic
  nTap = nClass.Tap(3)
  ````
* lib/unifier.py
  * A singular point of contact for tracking purposes
  * Useful for passing around a Class with its associated objects
  ````python
  ## Keep track of wlan0mon using ath9k
  import packetEssentials as PE
  nUnify = PE.lib.unifier
  nUni = nUnify.Unify('ath9k')
  nUni.nic = 'wlan0mon'
  print nUni.offset
  print nUni.nic
  ````
