# Drebin Feature Extractor

## Overview
Drebin Feature Extractor is a tool that statically analyzes Android application (APK) files to extract features proposed in the Drebin paper and generate reports.

This tool is a re-implementation of the feature extraction phase described in the paper "Drebin: Effective and Explainable Detection of Android Malware in Your Pocket". It was inspired by the original implementation (by Mobile-Sandbox, based on Python 2) and has been rebuilt to run in a **Python 3.13 or higher, OpenJDK 11, and Android SDK 36** environment.

While the extracted features comply with the original paper, the internal implementation is entirely different. This tool can be used for Android malware research and static analysis of applications.

[**日本語版はこちら**](README-ja.md)


## LICENSE

As mentioned below, this implementation was inspired by the original research and implementation, which was licensed under the GPL v2 or later. Therefore, to comply with the original license terms, this project is licensed under the GNU General Public License v3.0 (GPLv3).



**Original Disclaimer**

This implementation was inspired by the following original research and implementation. The original code was subject to the following license:

```
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#########################################################################################
```





## Directory Structure

```
.
├── data/             # Data related files
├── logs/             # Log files
├── src/              # Source code
│   ├── analyzer/     # APK analysis modules
│   ├── report/       # Report generation modules
│   ├── extension/    # Extension scripts (e.g., batch processing)
│   │   └── feature_extraction_automation.py
│   ├── logger.py     # Logging configuration
│   ├── extractor.py  # Main extraction logic
│   └── unpacker.py   # APK unpacking module
└── tools/            # Tool scripts
```



## Prerequisites

- Python 3.13
   - Running in a uv environment is strongly recommended.
- OpenJDK 11
- Android SDK 36



## Installation

1. Install Android SDK:
   - Download and install Android Studio from the [official Android Studio website](https://developer.android.com/studio) and use the SDK Manager to install the required SDK Platform, Build-Tools, and Platform-Tools.

2. Install `uv` :

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   (Restart your shell or follow the instructions to add uv to your PATH after installation)

3. Clone the repository:

   ```
   git clone https://github.com/Almond-Latte/DrebinFeatureExtractor
   cd DrebinFeatureExtractor
   ```

4. Configure environment variables:

   - Copy `.env.sample` to create a `.env` file.

     ```bash
     cp .env.sample .env
     ```

   - Open the `.env` file and edit it to specify the correct path to your Android SDK installation.

5. Install dependencies:

   ```bash
   uv sync
   ```



## Usage

### Analyzing a Single APK

```bash
uv run src/extractor.py [sample_file] [report_dir] [working_dir]
```

- `[sample_file]`: Path to the target APK file.
- `[report_dir]`: Output directory for the feature report file(s).
- `[working_dir]`: Temporary working directory for unpacking the APK (will be automatically deleted).
- You can also check the usage with:
   ```bash
   uv run src/extractor.py --help
   ```



### Analyzing All APKs in a Directory

```bash
uv run src/extension/feature_extraction_automation.py [apk_dir]
```

- `[apk_dir]`: Directory containing the target APK files.



# References

- Arp, Daniel, et al. "Drebin: Effective and explainable detection of android malware in your pocket." *NDSS*. Vol. 14. 2014. 