# MLVScan

<p align="center">
  <img src="icon.png" alt="MLVScan Icon" width="128" />
</p>

**MLVScan** is a security-focused mod loader plugin that protects your game by scanning mods for malicious patterns *before* they execute.

Supports **MelonLoader** and **BepInEx 5.x**.

![MLVScan Example](example.png)

## ⚡ Quick Start

### For MelonLoader
1. **Download** the latest `MLVScan.MelonLoader.dll` from [Releases](../../releases).
2. **Install** by dropping it into your game's `Plugins` folder.
3. **Play!** MLVScan automatically scans mods on startup.

### For BepInEx 5.x
1. **Download** the latest `MLVScan.BepInEx.dll` from [Releases](../../releases).
2. **Install** by dropping it into your game's `BepInEx/patchers` folder.
3. **Play!** MLVScan automatically scans plugins before they load.

## 📚 Documentation

Detailed documentation is available in the **[MLVScan Wiki](https://github.com/ifBars/MLVScan/wiki)**:

*   **[Getting Started](https://github.com/ifBars/MLVScan/wiki/Getting-Started)** - Full installation and setup guide for both MelonLoader and BepInEx.
*   **[Whitelisting](https://github.com/ifBars/MLVScan/wiki/Whitelisting)** - How to use the SHA256 security whitelist.
*   **[Understanding Reports](https://github.com/ifBars/MLVScan/wiki/Scan-Reports)** - Interpret warnings and security levels.
*   **[Architecture](https://github.com/ifBars/MLVScan/wiki/Architecture)** - How the ecosystem works.
*   **[FAQ](https://github.com/ifBars/MLVScan/wiki/FAQ)** - Common questions and troubleshooting.

### Key Differences

**MelonLoader:**
- Runs as a plugin during the mod loading phase
- Configuration stored in `MelonPreferences.cfg`
- Reports saved to `UserData/MLVScan/Reports/`

**BepInEx:**
- Runs as a preloader patcher (scans before chainloader)
- Configuration stored in `BepInEx/config/MLVScan.json`
- Reports saved to `BepInEx/MLVScan/Reports/`

## 🛡️ Powered by MLVScan.Core

MLVScan is built on **[MLVScan.Core](https://github.com/ifBars/MLVScan.Core)**, a cross-platform malware detection engine.
The same protection is also available for web browsers via **[MLVScan.Web](https://github.com/ifBars/MLVScan.Web)**.

## 🤝 Contributing

We welcome contributions! Please see the [Contributing Guidelines](https://github.com/ifBars/MLVScan.Core/wiki/Contributing) in the Core repository for adding new detection rules.

---
*Licensed under GPL-3.0*
