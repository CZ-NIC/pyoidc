"""fnl.core.memory module
 
Trivial, but working code to get the memory usage of the current process
where the pid is retrieved using os.getpid() and the memory usage is read
from the unix command ps.    
"""

import os

__version__ = "1.0"
__author__ = "Florian Leitner"

def mem(size="rss"):
    """Generalization; memory sizes: rss, rsz, vsz."""
    return int(os.popen('ps -p %d -o %s | tail -1' %
                        (os.getpid(), size)).read())

def rss():
    """Return ps -o rss (resident) memory in kB."""
    return mem("rss")

def rsz():
    """Return ps -o rsz (resident + text) memory in kB."""
    return mem("rsz")

def vsz():
    """Return ps -o vsz (virtual) memory in kB."""
    return mem("vsz")