from importlib.metadata import version

from . import main

__package__ = "cpe_lookup"
__name__ = "cpe_lookup"
__version__ = version(__name__)


app = main.create_app(__name__, __version__)
