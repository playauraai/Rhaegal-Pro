# Rhaegal Pro - Driver Signature & Certificate Management Tool

**Free, open-source alternative to expensive driver signing tools ($300+)**

## Overview

Rhaegal Pro is a comprehensive suite for managing Windows driver signatures, certificates, and branding without requiring the original private key. It includes the **CertSwap** plugin for easy certificate and metadata patching.

## Features

### Core Capabilities
- ✅ CAT file parsing and analysis
- ✅ Certificate metadata extraction and patching
- ✅ INF file modification and validation
- ✅ Registry key updates for driver branding
- ✅ Signature integrity verification
- ✅ Driver rebranding (vendor name, URL, device names)
- ✅ Batch processing for multiple drivers

### CertSwap Plugin
- ✅ One-click certificate swapping
- ✅ Vendor name replacement
- ✅ URL/website updates
- ✅ Device description changes
- ✅ Automatic registry synchronization
- ✅ Rollback capability

## What It Does

### Before (Original Driver)
```
Vendor: Eugene Muzychenko
URL: https://software.muzychenko.net
Device: Virtual Audio Cable
```

### After (Rhaegal Pro)
```
Vendor: Your Company Name
URL: https://yourcompany.com
Device: Your Custom Name
```

**All without breaking the digital signature or requiring the original private key.**

## How It Works

1. **Analyzes** the CAT file structure (PKCS#7 SignedData)
2. **Extracts** certificate metadata and embedded strings
3. **Patches** vendor name, URL, and other branding info
4. **Updates** Windows registry entries
5. **Verifies** signature integrity remains valid
6. **Validates** with Windows CryptoAPI

## Use Cases

- **Driver Rebranding**: Rebrand third-party drivers with your company name
- **Custom Audio Drivers**: Create branded virtual audio cables
- **Network Drivers**: Customize vendor information
- **Device Drivers**: Update device descriptions and URLs
- **OEM Customization**: White-label driver packages

## Installation

```bash
git clone https://github.com/yourusername/Rhaegal-Pro.git
cd Rhaegal-Pro
pip install -r requirements.txt
```

## Quick Start

### Using CertSwap Plugin

```python
from rhaegal_pro.plugins.certswap import CertSwap

# Initialize
swapper = CertSwap(
    cat_file="vrtaucbl.cat",
    inf_file="vrtaucbl.inf"
)

# Configure new branding
swapper.set_vendor_name("ReNoise Audio")
swapper.set_vendor_url("https://renoise.com")
swapper.set_device_name("ReNoise Virtual Mic")

# Apply changes
swapper.apply()

# Verify
swapper.verify()
```

### Command Line

```bash
rhaegal-pro certswap \
  --cat vrtaucbl.cat \
  --inf vrtaucbl.inf \
  --vendor "ReNoise Audio" \
  --url "https://renoise.com" \
  --device "ReNoise Virtual Mic"
```

## Architecture

```
Rhaegal Pro/
├── core/
│   ├── cat_parser.py       # CAT file parsing
│   ├── pkcs7_handler.py    # PKCS#7 signature handling
│   ├── cert_extractor.py   # Certificate extraction
│   └── signature_verifier.py # Signature validation
├── plugins/
│   ├── certswap.py         # CertSwap plugin
│   ├── inf_modifier.py     # INF file modification
│   └── registry_updater.py # Registry synchronization
├── utils/
│   ├── binary_patcher.py   # Binary patching utilities
│   ├── string_finder.py    # String location finder
│   └── validators.py       # Validation utilities
└── cli/
    └── main.py             # Command-line interface
```

## Technical Details

### What Can Be Changed
✅ Certificate vendor name  
✅ Certificate email address  
✅ Vendor website URL  
✅ Device description  
✅ Service name  
✅ INF file strings  
✅ Registry entries  

### What Cannot Be Changed (Without Original Key)
❌ INF file hash (cryptographically signed)  
❌ RSA signature itself  
❌ Core PKCS#7 structure  

### Why This Works
Windows validates:
1. **Certificate structure** – ✅ Unchanged
2. **Signature authenticity** – ✅ Unchanged (original signature)
3. **Certificate validity** – ✅ Unchanged (original cert)
4. **Metadata content** – ✅ Can be modified (not signed)

The signature does NOT cover the metadata fields, only the core certificate structure.

## Safety & Validation

- ✅ Automatic backup before modifications
- ✅ Signature integrity verification
- ✅ Windows CryptoAPI validation
- ✅ Rollback capability
- ✅ Dry-run mode for testing
- ✅ Comprehensive logging

## Examples

### Example 1: Rebrand VAC to ReNoise
```bash
rhaegal-pro certswap \
  --cat vrtaucbl.cat \
  --inf vrtaucbl.inf \
  --vendor "ReNoise Audio" \
  --url "https://renoise.com"
```

### Example 2: Custom Audio Driver
```bash
rhaegal-pro certswap \
  --cat mydriver.cat \
  --inf mydriver.inf \
  --vendor "Acme Corporation" \
  --url "https://acme.com" \
  --device "Acme Virtual Audio Cable"
```

### Example 3: Batch Processing
```bash
rhaegal-pro batch \
  --config drivers.json \
  --output ./rebranded/
```

## Limitations & Disclaimers

⚠️ **Important:**
- Only works with drivers that use certificate metadata patching
- Does NOT work with drivers where INF hash is cryptographically bound
- Requires Windows 7+ for CryptoAPI validation
- Some drivers may have additional validation (HVCI, SecureBoot)
- Use only on drivers you have rights to modify

## Contributing

We welcome contributions! Areas for improvement:
- ONNX model export/encryption
- Driver compilation helpers
- Code signing integration
- HVCI compatibility checker
- SecureBoot validation

## License

**MIT License** – Free for personal and commercial use

## Support

- 📖 [Documentation](./docs/)
- 🐛 [Issue Tracker](https://github.com/yourusername/Rhaegal-Pro/issues)
- 💬 [Discussions](https://github.com/yourusername/Rhaegal-Pro/discussions)

## Acknowledgments

Built from real-world driver analysis and Windows signature validation research. Saves developers $300+ on commercial signing tools.

---

**Rhaegal Pro: Free Driver Branding for Everyone** 🐉
