#!flask/bin/python
# -*- coding: utf-8 -*-

from app import app
import sys
from config import *
import os
import importlib
import logging
import logging.config

importlib.reload(sys)


# logging.config.fileConfig("logging.conf")

def main():
    LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
    logging.basicConfig(level=LOGLEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if sys.version[0] == '2':
        from imp import reload

        reload(sys)
        sys.setdefaultencoding("utf-8")

    debug = False

    if 'DEBUG' in os.environ and os.environ['DEBUG'] == "1":
        debug = True

    app.run(debug=debug, host='0.0.0.0', port=8080)


main()
