"""Map inherited CDP descriptors after subprocess closes unrelated descriptors."""
import json
import os
import sys

from cnt_supervisor import remap_pipes

if __name__ == '__main__':
    remap_pipes(json.loads(sys.argv[1]))
    os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
