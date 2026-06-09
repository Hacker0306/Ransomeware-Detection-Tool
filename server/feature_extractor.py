import pefile
import os
import numpy as np

# Replace this with your actual feature list from features.pkl
FEATURE_NAMES = [
    'Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 'MajorOSVersion',
    'ExportRVA', 'ExportSize', 'IatVRA', 'MajorLinkerVersion',
    'MinorLinkerVersion', 'NumberOfSections', 'SizeOfStackReserve',
    'DllCharacteristics', 'ResourceSize', 'BitcoinAddresses'
]

def extract_features(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    try:
        pe = pefile.PE(filepath)
        features = {
            'Machine': pe.FILE_HEADER.Machine,
            'DebugSize': getattr(pe.OPTIONAL_HEADER, 'DebugSize', 0),
            'DebugRVA': getattr(pe.OPTIONAL_HEADER, 'DebugRVA', 0),
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MajorOSVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'ExportRVA': getattr(pe.OPTIONAL_HEADER, 'ExportTable', {}).get('VirtualAddress', 0),
            'ExportSize': getattr(pe.OPTIONAL_HEADER, 'ExportTable', {}).get('Size', 0),
            'IatVRA': getattr(pe.OPTIONAL_HEADER, 'ImportAddressTable', {}).get('VirtualAddress', 0),
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'ResourceSize': _get_resource_size(pe),
            'BitcoinAddresses': 0  # Optional: Could add regex scanner later
        }

        return [features[name] for name in FEATURE_NAMES]

    except Exception as e:
        print(f"[ERROR] Failed to extract features: {e}")
        return [0]*len(FEATURE_NAMES)

def _get_resource_size(pe):
    try:
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(entry, 'directory'):
                return entry.directory.struct.Size
    except Exception:
        pass
    return 0

if __name__ == '__main__':
    test_file = 'sample.exe'  # Replace with your test binary path
    features = extract_features(test_file)
    print("Extracted features:", features)
