import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
VULNERABLE_DIR = os.path.join(FIXTURES, "vulnerable")
SAFE_DIR = os.path.join(FIXTURES, "safe")
VULNERABLE_FILE = os.path.join(VULNERABLE_DIR, "claude_desktop_config.json")
SAFE_FILE = os.path.join(SAFE_DIR, "claude_desktop_config.json")

# The fake secret planted in the vulnerable fixture. It must never
# appear in any report, finding detail, or CLI output.
FAKE_SECRET = "FAKE-SECRET-DO-NOT-LEAK-987654321"
