# Collects workstation configuration evidence (Windows).
#
# Encryption status and endpoint protection are read from the OS rather than
# asserted by the auditor. On a non-Windows host the collector records that the
# evidence was unavailable instead of silently passing the control.
import json
import platform
import subprocess
from ..util import save_json

PS = ['powershell', '-NoProfile', '-NonInteractive', '-Command']


def _ps(script):
    try:
        out = subprocess.run(PS + [script], capture_output=True, text=True, timeout=90)
        if out.returncode != 0 or not out.stdout.strip():
            return None
        return json.loads(out.stdout)
    except Exception:
        return None


def _volumes():
    # Get-BitLockerVolume needs elevation; manage-bde is the fallback.
    data = _ps("Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus,"
               "VolumeStatus,EncryptionPercentage | ConvertTo-Json -Compress")
    if data is None:
        return None
    if isinstance(data, dict):
        data = [data]
    out = []
    for v in data:
        status = v.get('ProtectionStatus')
        # ProtectionStatus: 0 = Off, 1 = On, 2 = Unknown
        label = {0: 'Off', 1: 'On', 2: 'Unknown'}.get(status, str(status))
        out.append({
            'mount_point': v.get('MountPoint'),
            'protection_status': label,
            'volume_status': v.get('VolumeStatus'),
            'encryption_percentage': v.get('EncryptionPercentage'),
        })
    return out


def _endpoint():
    data = _ps("$s = Get-MpComputerStatus; [PSCustomObject]@{"
               "RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled;"
               "AntivirusSignatureAge=$s.AntivirusSignatureAge;"
               "AMServiceEnabled=$s.AMServiceEnabled } | ConvertTo-Json -Compress")
    if data is None:
        return None
    return {
        'product': 'Microsoft Defender',
        'realtime_protection': bool(data.get('RealTimeProtectionEnabled')),
        'service_enabled': bool(data.get('AMServiceEnabled')),
        'signature_age_days': data.get('AntivirusSignatureAge'),
    }


def run():
    result = {
        'hostname': platform.node(),
        'platform': platform.platform(),
        'collected_by': 'itgc-toolkit workstation collector',
    }

    vols = _volumes()
    if vols is None:
        result['volumes'] = []
        result['volumes_note'] = ('Encryption status unavailable. Get-BitLockerVolume '
                                  'requires an elevated shell. Re-run this collector from '
                                  'an Administrator PowerShell to test ITGC-OP-03.')
    else:
        result['volumes'] = vols

    ep = _endpoint()
    if ep is None:
        result['endpoint_protection'] = None
        result['endpoint_note'] = ('Endpoint protection status unavailable on this host; '
                                   'ITGC-OP-04 is reported as not tested rather than passed.')
    else:
        result['endpoint_protection'] = ep

    save_json('evidence/workstation.json', result)
    return result
