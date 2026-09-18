"""Fetch the public Linux/amd64 diagnostic binary; verify before any execution."""
import argparse
import hashlib
import os
from pathlib import Path
import tempfile
from urllib.request import urlopen
from tools.gateway_probe import BINARY_SHA256

URL = 'https://github.com/agentgateway/agentgateway/releases/download/v1.5.0/agentgateway-linux-amd64'
MAX_BYTES = 100 * 1024 * 1024


def fetch(destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            digest = hashlib.sha256()
            total = 0
            with urlopen(URL, timeout=60) as response:
                while chunk := response.read(65536):
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise ValueError('oversize release asset')
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != BINARY_SHA256:
                raise ValueError('release binary checksum mismatch')
        temporary.chmod(0o755)
        os.replace(temporary, destination)
        print(f'verified sha256:{BINARY_SHA256} -> {destination}')
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fetch(args.output)
