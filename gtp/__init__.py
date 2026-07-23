import os
import sys

# The GTP modules were written to be importable both as a package (``gtp.info``)
# and via their sub-packages as top-level names (``commons``, ``gtp_v2_core``,
# ``attacks``).  Under Python 2 the latter worked through implicit relative
# imports; under Python 3 we make it work by putting this package's directory on
# ``sys.path`` as soon as the package is imported.
_GTP_DIR = os.path.dirname(os.path.abspath(__file__))
if _GTP_DIR not in sys.path:
    sys.path.insert(0, _GTP_DIR)
