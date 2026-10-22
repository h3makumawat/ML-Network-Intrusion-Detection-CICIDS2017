#!/usr/bin/env python3
"""
Entrypoint wrapper matching the literal template pattern `YourName_ProjectName.py`
in addition to `YourName_NetworkIntrusionDetection.py`.
Both files execute the exact same ML Network Intrusion Detection pipeline.
"""
import sys
from YourName_NetworkIntrusionDetection import main

if __name__ == "__main__":
    sys.exit(main())
