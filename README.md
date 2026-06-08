# EDRUnChoker

**Fileless WMI remediation for [EDRChoker](https://github.com/TwoSevenOneT/EDRChoker)**  counters QoS abuse (`pacer.sys`) that throttles EDR agents to near-zero network bandwidth.

Registers a permanent subscription in `root\subscription` (no files on disk). A 5-second timer runs embedded VBScript that enumerates QoS policies with **WbemContext `PolicyStore`** on **ActiveStore** and **GPO:localhost** — plain WMI `ExecQuery` misses ActiveStore policies created by `New-NetQosPolicy` / EDRChoker — and removes malicious app-path throttles targeting known security products or aggressive rates (≤ 1 Mbps).

## Scripts

| Script | Purpose |
|---|---|
| `Install-EdrChokerWmiDefense.ps1` | Deploy subscription (elevated) |
| `Uninstall-EdrChokerWmiDefense.ps1` | Remove subscription |
| `Get-EdrChokerDefenseStatus.ps1` | Check subscription and policy count |

## Quick start

```powershell
.\Install-EdrChokerWmiDefense.ps1
.\Get-EdrChokerDefenseStatus.ps1
```

## SOC / event log

Each successful cleanup writes a **Warning** to the **Application** log under source **EDRChokerDefense**. One event is emitted per removed policy, useful as remediation evidence and to correlate with EDRChoker activity on the host.

<img width="2077" height="1305" alt="image" src="https://github.com/user-attachments/assets/60001ea8-c1b5-4a93-8a4e-9facea3e51d1" />


| Event ID | Meaning |
|---|---|
| 1000 | Subscription installed |
| 1001 | Subscription removed |
| 1002 | Malicious QoS policy removed |
| 1003 | Remediation failed |

**1002 example:** `action=remediate qos_policy=02zxnnzr target=elastic-endpoint.exe throttle_bps=8 tier=tier1-known-edr store=ActiveStore`

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='EDRChokerDefense' } -MaxEvents 50
```

Forward `ProviderName="EDRChokerDefense"` via WEF, Splunk UF, Elastic Agent, etc.

## Protect the subscription

Attackers may delete or modify the WMI objects in `root\subscription` to disable defense. **Baseline** the subscription after install and alert on changes.

**Sysmon** (recommended): enable and monitor:

| Sysmon ID | What to watch |
|---|---|
| **19** | `WmiEventFilter` created/modified/deleted |
| **20** | `WmiEventConsumer` created/modified/deleted |
| **21** | `WmiEventFilter` ↔ consumer binding changes |

Alert on any activity involving `EDRChokerDefense_QoSFilter`, `EDRChokerDefense_QoSConsumer`, or `EDRChokerDefense_Timer`, and on **new** `ActiveScriptEventConsumer` / `CommandLineEventConsumer` instances outside your change window.

**Periodic validation** (GPO/script): `Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object Name -like 'EDRChokerDefense*'`

## References

- [EDRChoker](https://github.com/TwoSevenOneT/EDRChoker)
- [EDRChoker research](https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html)
