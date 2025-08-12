# This script defines a beep() function that triggers the ASCII bell character (\a)
# to produce a terminal beep sound. It writes the bell character directly to stdout
# and flushes the output, which may cause the system to play its default alert tone
# if the terminal bell is enabled.

import sys

def beep():
    sys.stdout.write("\a")
    sys.stdout.flush()
