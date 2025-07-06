# Yara2Kql
Simple python script to convert yara rules into Kusto Query Language (KQL) queries that are ready to be used in Microsoft Defender/Sentinel


**Yara2Kql** is a Python tool that converts YARA threat detection rules into Microsoft Defender XDR-compatible [Kusto Query Language (KQL)](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview) queries. Designed for security analysts, threat hunters, and incident responders, this tool bridges the gap between static malware signatures and dynamic telemetry-based hunting.

> _"From static rules to dynamic hunts"_

---

## 🔍 Features

- ✅ Supports multi-rule `.yar` files
- ✅ Extracts domains, IPs, filenames, mutexes, registry keys, command strings, and hashes
- ✅ Maps each indicator to its correct Defender XDR schema table (`DeviceFileEvents`, `DeviceRegistryEvents`, etc.)
- ✅ Includes metadata (`description`, `date`, `reference`) as comments in KQL
- ✅ Outputs hash-based KQL queries separately for focused threat hunting
- ✅ Handles edge cases with schema-aligned parsing and 3-pass verification

---

## 📂 Input Example

Given a YARA rule:

```yara
rule FakePDF_Downloader
{
    meta:
        description = "Fake PDF downloader activity"
        reference = "https://example.com/fake-pdf"
        date = "2023-11-15"

    strings:
        $s1 = "tweakscode.com"
        $s2 = "Global\\Mutex123"
        $s3 = "HKEY_LOCAL_MACHINE\\Software\\FakeApp"

    condition:
        any of them
}
```

The tool will generate KQL such as:

```
DeviceNetworkEvents 
| where RemoteUrl contains "tweakscode.com" 
// description: Fake PDF downloader activity | reference: https://example.com/fake-pdf | date: 2023-11-15
```

```
DeviceProcessEvents 
| where ProcessCommandLine contains "Global\\Mutex123" 
// description: Fake PDF downloader activity | reference: https://example.com/fake-pdf | date: 2023-11-15
```

```
DeviceRegistryEvents 
| where RegistryKey has "HKEY_LOCAL_MACHINE\\Software\\FakeApp" 
// description: Fake PDF downloader activity | reference: https://example.com/fake-pdf | date: 2023-11-15
```


## License

This project is provided under the MIT License.

## Disclaimer

This tool can be used as a basic Yara to KQL converter, however, it may not include every yara variable or map it to every Microsoft Defender/Sentinel schema, which will require further script changes.

