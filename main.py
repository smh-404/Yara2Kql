import re
from typing import List, Dict
from pathlib import Path

def parse_yara_file(filepath: str) -> Dict[str, List[str]]:
    """
    Parses a YARA .yar file containing multiple rules.
    Extracts string values, file hashes, and selected metadata for context.
    """
    yara_text = Path(filepath).read_text(encoding="utf-8", errors="ignore")

    iocs = {
        "domains": [],
        "ips": [],
        "filenames": [],
        "mutexes": [],
        "registry_keys": [],
        "command_strings": [],
        "hashes": {"md5": [], "sha1": [], "sha256": []},
        "metadata": []
    }

    # Extract quoted string values from strings section
    string_values = re.findall(r'\$[\w\d_]*\s*=\s*"([^"]+?)"(?:\s+\w+)*', yara_text)

    for s in string_values:
        lowered = s.lower()

        if re.match(r'^(http[s]?://)?([\w.-]+)\.[a-z]{2,}', s) and not lowered.endswith(('.dll', '.exe', '.pdb', '.txt')) and 'impacket.' not in lowered:
            iocs["domains"].append(s)
        elif re.match(r'\b\d+\.\d+\.\d+\.\d+\b', s):
            iocs["ips"].append(s)
        elif lowered.endswith(('.exe', '.dll', '.pdb')) or 'rundll32' in lowered:
            iocs["filenames"].append(s)
        elif re.search(r'\\', s) and 'hkey_' in lowered:
            iocs["registry_keys"].append(s)
        elif re.search(r'\\', s) and 'mutex' in lowered:
            iocs["mutexes"].append(s)
        elif lowered.startswith('global\\') or 'mutex' in lowered:
            iocs["mutexes"].append(s)
        else:
            iocs["command_strings"].append(s)

    # Extract hashes from meta section
    meta_hashes = re.findall(r'(hash\d*|sha256|sha1|md5)\s*=\s*"([a-fA-F0-9]{32,64})"', yara_text)
    for label, h in meta_hashes:
        h_lower = h.lower()
        if len(h_lower) == 64:
            iocs["hashes"]["sha256"].append(h_lower)
        elif len(h_lower) == 40:
            iocs["hashes"]["sha1"].append(h_lower)
        elif len(h_lower) == 32:
            iocs["hashes"]["md5"].append(h_lower)

    # Extract metadata fields
    meta_info = re.findall(r'(description|date|reference)\s*=\s*"([^"]+)"', yara_text)
    for key, value in meta_info:
        iocs["metadata"].append(f"{key}: {value}")

    return iocs

def build_kql_queries(iocs: Dict[str, List[str]]) -> Dict[str, List[str]]:
    main_queries = []
    hash_queries = []

    comment = " // " + " | ".join(iocs["metadata"]) if iocs["metadata"] else ""

    if iocs["filenames"]:
        files = '"' + '" , "'.join(set(iocs["filenames"])) + '"'
        main_queries.append(f"DeviceFileEvents | where FileName in ({files}){comment}")

    if iocs["domains"]:
        conditions = ' or '.join([f"RemoteUrl contains \"{d}\"" for d in set(iocs["domains"])])
        main_queries.append(f"DeviceNetworkEvents | where {conditions}{comment}")

    if iocs["ips"]:
        ip_matches = ' or '.join([f"RemoteIP == \"{ip}\"" for ip in set(iocs["ips"])])
        main_queries.append(f"DeviceNetworkEvents | where {ip_matches}{comment}")

    if iocs["mutexes"]:
        mutexes = ' or '.join([f"ProcessCommandLine contains \"{m}\"" for m in set(iocs["mutexes"])])
        main_queries.append(f"DeviceProcessEvents | where {mutexes}{comment}")

    if iocs["registry_keys"]:
        keys = ' or '.join([f"RegistryKey has \"{k}\"" for k in set(iocs["registry_keys"])])
        main_queries.append(f"DeviceRegistryEvents | where {keys}{comment}")

    if iocs["command_strings"]:
        strings = ' or '.join([f"InitiatingProcessCommandLine has \"{s}\"" for s in set(iocs["command_strings"])])
        main_queries.append(f"DeviceProcessEvents | where {strings}{comment}")

    # Hash queries
    if iocs["hashes"]["sha256"]:
        vals = '"' + '" , "'.join(set(iocs["hashes"]["sha256"])) + '"'
        hash_queries.append(f"DeviceFileEvents | where SHA256 in ({vals}){comment}")
    if iocs["hashes"]["sha1"]:
        vals = '"' + '" , "'.join(set(iocs["hashes"]["sha1"])) + '"'
        hash_queries.append(f"DeviceFileEvents | where SHA1 in ({vals}){comment}")
    if iocs["hashes"]["md5"]:
        vals = '"' + '" , "'.join(set(iocs["hashes"]["md5"])) + '"'
        hash_queries.append(f"DeviceFileEvents | where MD5 in ({vals}){comment}")

    return {"main_queries": main_queries, "hash_queries": hash_queries}


if __name__ == "__main__":
    yara_file = "test.yar"  # Replace with your YARA file path
    iocs = parse_yara_file(yara_file)
    queries = build_kql_queries(iocs)

    print("\n=== Main KQL Queries ===")
    for query in queries["main_queries"]:
        print("\n", query)

    print("\n=== Hash-based KQL Queries ===")
    for hashquery in queries["hash_queries"]:
        print("\n", hashquery)
