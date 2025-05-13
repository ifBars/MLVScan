# MLVScan

MLVScan is a security-focused MelonLoader plugin designed to detect and disable potentially malicious mods before they can harm your system. It scans for suspicious patterns commonly found in malware and prevents them from executing.

MLVScan was created in response to the recent uprising of malware mods being uploaded to sites like NexusMods. MLVScan aims to stop these malware mods from running before they can harm the system.

![MLVScan Example](https://raw.githubusercontent.com/ifBars/MLVScan/refs/heads/master/example.png)

## Features

- **Pre-load Scanning**: Catches malicious code before it can execute
- **Modular Detection Rules**: Identifies various malicious patterns
- **Severity Classification**: Categorizes threats by risk level (Critical, High, Medium, Low)
- **Automatic Disabling**: Prevents suspicious mods from loading
- **Detailed Reports**: Generates comprehensive scan reports with specific findings
- **Whitelisting**: Allows trusted mods to bypass scanning (Most mods pass the scan just fine, with a few that have been whitelisted due to false positives, the current whitelist system is planned to be replaced with an improved version in the future)
- **Security Guidance**: Provides actionable steps if a threat is detected

## Installation

1. Download the latest release from the [Releases page](https://github.com/ifBars/MLVScan/releases)
2. Place `MLVScan.dll` in your game's `MelonLoader/Plugins` folder
3. Launch your game

## How It Works

MLVScan analyzes all mods before they are loaded by MelonLoader. It uses static analysis to scan for suspicious code patterns without executing them. When a potentially malicious mod is detected, MLVScan:

1. Prevents the mod from loading
2. Logs detailed information about the suspicious patterns
3. Creates a report file with findings and remediation steps
4. Provides security guidance if your system might be affected

## Usage

MLVScan works automatically when your game starts. No additional configuration is required for basic protection.

### Whitelist Configuration

To whitelist trusted mods that might trigger false positives:

1. Edit `MelonPreferences.cfg` in your game directory
2. Find the `[MLVScan]` section
3. Add mod filenames to the `WhitelistedMods` setting
4. Save the file

Example:

```
[MLVScan]
WhitelistedMods = S1APILoader.dll, S1API.Mono.dll, S1API.Il2Cpp.dll, CustomTV_Mono.dll, CustomTV_IL2CPP.dll
```

⚠️ **Warning**: Only whitelist mods from trusted sources. Whitelisted mods fully bypass security checks.

## Security Report Interpretation

When MLVScan detects a suspicious finding, it will generate a report with findings categorized by severity, and disable the mod if the severity is within the configured threshold:

- **Critical**: High-risk activities like executing external processes or loading assemblies
- **High**: Potentially dangerous behaviors like loading encrypted or obfuscated data
- **Medium**: Suspicious patterns that might be legitimate in some contexts
- **Low**: Minor suspicious patterns with little to no risk

Review the details carefully before deciding to whitelist a mod.

## Roadmap / Feature Ideas

- **Hash-based Whitelist**: Verify mod authenticity using cryptographic hashes instead of filenames
- **Online Verification API**: Validate mods against a community database of known-safe mods
- **Smart Pattern Analysis**: Reduce false positives through contextual analysis
- **Behavior Monitoring**: Runtime detection of suspicious behavior
- **GUI Interface**: User-friendly interface for managing security settings
- **Mod Publisher Verification**: Support for digitally signed mods from trusted developers
- **Custom Rules Configuration**: Allow users to define custom detection rules

## Contributing

Contributions are welcome! If you'd like to improve MLVScan:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Adding a new detection rule is a simple as:

1. Creating your rule class in the `Models` folder
2. Declaring it as a public class that inherits the IScanRule interface
3. Declare your IsSuspicious(MethodReference) method
4. Declare a Description and Severity for your rule
5. Add your rule to ServiceFactory.CreateAssemblyScanner

Reference the existing rule model classes for an example.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- MelonLoader team for creating the mod loading framework
- Mono.Cecil for enabling assembly analysis

## Disclaimer

MLVScan is provided as-is without warranty. While it can detect many malicious patterns, no security tool is perfect, and cyber security is a never ending battle of cat and mouse. Always exercise caution when installing newer mods, and NEVER install mods from untrusted sources. Trusted mod sources are NexusMods and Thunderstore, however you should always be weary of new mods.
