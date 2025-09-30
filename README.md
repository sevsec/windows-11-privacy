# Windows 11 Privacy

Interactive PowerShell script to disable (or re-enable) intrusive Windows 11 features. It covers five specific areas:

1. **Telemetry** (DiagTrack, tasks, minimal firewall blocks)
2. **Ads / Recommendations** (Start menu, lock screen, Settings banners)
3. **Microsoft Account prompts** (OOBE and post-setup nudges)
4. **Defender cloud features** (MAPS, sample submission)
5. **Activity history & Location** (Timeline, global location service)

## Features
- Lets you choose **DISABLE** (harden/strip) or **ENABLE** (restore defaults).
- If in DISABLE mode, presents safety options: proceed directly, create a **snapshot backup**, create a **system restore point**, or do both.
- Prompts at each step to **apply** or **skip** the feature change.
- Prints `[OK]` or `[X]` for each action so you can track what happened.
- Supports logging via optional transcript file written to the script directory.

## Usage
1. Download `Win11_Privacy_Tuner.ps1`.
2. Open a PowerShell prompt with Administrator privileges.
3. Allow script execution for the session:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```
4. Run the script:
   ```powershell
   .\Win11_Privacy_Tuner.ps1
   ```
5. Select the features that you would like to disable/re-renable by following the script's prompts.
   
## Notes

- **Windows Defender Tamper Protection** must be turned **off** if you want to modify Defender policies. Toggle it in: *Windows Security → Virus & threat protection → Manage settings*.
- Some settings apply **per-user** (HKCU). Run the script once per account if you want the same behavior everywhere. HKLM policies are global.
- Firewall FQDN blocks don’t stop direct IP connections.
- A reboot or sign-out may be required for all changes to fully apply.
- OEM images sometimes ship with different defaults. ENABLE mode restores safe defaults, not OEM-specific ones.

## Reverting

Run the script again and choose **ENABLE** mode to undo changes and restore defaults. If you enabled safety options:
- **Snapshot backup** creates a timestamped folder with JSON and .REG exports you can inspect or re-import.
- **System Restore Point** allows rollback through Windows System Restore.

---
For inspection or customization, the script is modular: each feature has paired disable/enable functions, and all actions are isolated and logged.
