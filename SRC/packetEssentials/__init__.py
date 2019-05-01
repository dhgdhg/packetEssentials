# Copyright (C) 2017 stryngs

from .lib.chan_freq import ChanFreq
from .lib.converter import Converter
from .lib.drivers import Drivers
from .lib.subtypes import Subtypes
from .lib.unifier import Unify
from .lib.utils import Poption

## Deal with Windows
try:
    from .lib.nic import Tap
except ModuleNotFoundError:
    pass

### Instantiations
chanFreq = ChanFreq()
conv = Converter()
drv = Drivers()
sType = Subtypes()
pt = Poption()
