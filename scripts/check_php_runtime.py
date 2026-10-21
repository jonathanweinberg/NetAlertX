#!/usr/bin/env python3
"""Reject container builds with affected or inconsistent PHP runtimes."""

import argparse
import json
import re
import subprocess
import sys


# Minimum upstream releases fixing CVE-2026-109618 and CVE-2026-109619.
FIXED_RELEASES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
REQUIRED_EXTENSIONS = {'curl', 'session', 'sqlite3'}


def parse_version(output):
    """Extract a stable PHP release from a native version banner."""
    match = re.search(r'^PHP (\d+)\.(\d+)\.(\d+)(?=\s|$)', output, re.MULTILINE)
    if not match:
        raise ValueError('PHP did not report a stable release version')
    return tuple(int(part) for part in match.groups())


def require_patched(version):
    """Reject unsupported branches and releases below the security floor."""
    minimum = FIXED_RELEASES.get(version[:2])
    if minimum is None:
        raise ValueError('PHP branch has no reviewed security floor')
    if version[2] < minimum:
        actual = '.'.join(str(part) for part in version)
        raise ValueError(f'PHP {actual} is below fixed release {version[0]}.{version[1]}.{minimum}')


def command_output(arguments):
    """Run a bounded PHP inspection and reject startup diagnostics."""
    result = subprocess.run(arguments, capture_output=True, text=True, check=True, timeout=15)
    if result.stderr.strip():
        raise ValueError(f'{arguments[0]} emitted startup diagnostics')
    return result.stdout


def check_runtime(cli, servers):
    """Verify the CLI, serving binaries and required configured extensions."""
    cli_version = parse_version(command_output([cli, '-n', '-v']))
    require_patched(cli_version)
    for server in servers:
        server_version = parse_version(command_output([server, '-n', '-v']))
        require_patched(server_version)
        if server_version != cli_version:
            raise ValueError(f'{server} does not match the CLI PHP release')
    extensions = json.loads(command_output([cli, '-r', 'echo json_encode(get_loaded_extensions());']))
    if not isinstance(extensions, list) or not all(isinstance(item, str) for item in extensions):
        raise ValueError('PHP returned an invalid extension list')
    missing = REQUIRED_EXTENSIONS - set(extensions)
    if missing:
        raise ValueError('Missing PHP extensions: ' + ', '.join(sorted(missing)))
    return cli_version


def main(argv=None):
    """Expose the shared build-time runtime guard for both Docker targets."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--server', action='append', required=True)
    args = parser.parse_args(argv)
    try:
        version = check_runtime(args.cli, args.server)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'PHP runtime security check failed: {error}', file=sys.stderr)
        return 1
    print('PHP runtime security check passed: ' + '.'.join(str(part) for part in version))
    return 0


if __name__ == '__main__':
    sys.exit(main())
