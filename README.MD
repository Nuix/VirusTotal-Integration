VirusTotal Integration
======================

![This script was last tested in Nuix 9.0](https://img.shields.io/badge/Script%20Tested%20in%20Nuix-9.0-green.svg)

View the GitHub project [here](https://github.com/Nuix/VirusTotal-Integration) or download the latest release [here](https://github.com/Nuix/VirusTotal-Integration/releases).

# Overview

This repo contains a script and a workerside script that will search selected files against the third-party [VirusTotal](http://www.virustotal.com) API service. Should results be found, those results will be stored in custom metadata fields on the relevant items. The workerside script can also encrich the properties further with data from virus total.

For more details, refer to the [wiki](https://github.com/Nuix/VirusTotal-Integration/wiki#about-the-virustotal-integration)

**Note:** You must have an internet connection and must supply your own VirusTotal API key in the required variable.

# Getting Started
To run the script, you will require an active VirusTotal account and generate an API key, which you can get from [VirusTotal](http://www.virustotal.com). See the [wiki](https://github.com/Nuix/VirusTotal-Integration/wiki/VirusTotal-API-Key#requesting-a-new-api-key) for further instructions.
## Setup
- Begin by downloading the latest release of this code [here](https://github.com/Nuix/VirusTotal-Integration/releases).
- If you are running the standard script, extract the folder "VirusTotalIntegration.nuixscript" and its contents into your Nuix scripts directory. In Windows the script directory is likely going to be either of the following:

```
    %appdata%\Nuix\Scripts - User level script directory
    %programdata%\Nuix\Scripts - System level script directory
```

- If you are running as a worker side script, you will just require the file [VirusTotalWSS.py](https://github.com/Nuix/VirusTotal-Integration/blob/wss/Python/WSS/VirusTotalWSS.py)

- Each script will require you to edit it and enter the API key VirusTotal provided you at the relevant location. You can also adjust other options in the files as required.

See [Standard script](https://github.com/Nuix/VirusTotal-Integration/wiki/Standard-Script#preparing-the-script) or [Worker side script](https://github.com/Nuix/VirusTotal-Integration/wiki/Worker-Side-Script#preparing-the-script) on the integration wiki for full details and troubleshooting.

# License

```
Copyright 2019 Nuix

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
