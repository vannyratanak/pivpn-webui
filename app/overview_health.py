"""Bounded read-only service probe, shared by local installs and agents."""
import os
import subprocess


def service_health():
    unit = os.environ.get('OPENVPN_UNIT', 'openvpn@server')
    try:
        result = subprocess.run(['systemctl', 'show', '--property=LoadState,ActiveState', '--', unit],
                                capture_output=True, text=True, timeout=2)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if result.returncode or values.get('LoadState') != 'loaded':
            state = 'Unknown'
        else:
            state = {'active': 'Running', 'inactive': 'Stopped', 'failed': 'Failed',
                     'activating': 'Starting', 'deactivating': 'Stopping'}.get(values.get('ActiveState'), 'Unknown')
    except (OSError, subprocess.TimeoutExpired):
        state = 'Unknown'
    return {'state': state, 'unit': unit}
