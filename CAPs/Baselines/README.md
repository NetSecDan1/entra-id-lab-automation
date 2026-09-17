# Custom Conditional Access baselines

An alternative to the remote Joey Verlinden import (`Deploy-CAPs.ps1` / `CABaseline` in config). These are authored directly in this repo — deployed via `Deploy-CAPs-Custom.ps1` and the shared engine in `Helpers/CAPolicyEngine.ps1`.

| Baseline | Built on | Policies |
|---|---|---|
| `Tiered.json` | This lab's own Tier0/1/2 admin groups, PAW users, VPN users, Executives | 10 |
| `ZeroTrust.json` | Microsoft's Zero Trust / Secure Future Initiative CA guidance | 8 |
| `SCuBA.json` | CISA's M365 Secure Configuration Baseline for Entra ID (MS.AAD.3.x) | 6 |

```powershell
.\CAPs\Deploy-CAPs-Custom.ps1 -Baseline Tiered
.\CAPs\Deploy-CAPs-Custom.ps1 -Baseline ZeroTrust
.\CAPs\Deploy-CAPs-Custom.ps1 -Baseline SCuBA
```

Or set `config.CAPCustomBaseline.Baseline` and run it as the `CAPsCustom` step from the orchestrator.

**Prerequisite order**: `Deploy-Groups.ps1` → `Deploy-Users.ps1` → `Deploy-NamedLocations.ps1` → `Deploy-AuthStrengths.ps1` → `Deploy-CAPs-Custom.ps1`. Every `{{Group:...}}`, `{{User:...}}`, `{{NamedLocation:...}}`, and `{{AuthStrength:...}}` token in the baseline JSON is resolved by looking up an object that must already exist — nothing here creates those objects itself.

Deploying more than one baseline against the same tenant is fine (policy display names don't collide across baselines) but will layer their controls on top of each other — that's usually not what you want for a clean comparison. Pick one at a time, or clean up between runs via the Entra portal.
