#!/usr/bin/env python3
"""Run FortiGate Config Doctor: python doctor.py backup.conf"""

import sys

from fcdoctor.cli import main

if __name__ == "__main__":
    sys.exit(main())
