VirusTotal Integration
======================

![This script was last tested in Nuix 9.0](https://img.shields.io/badge/Script%20Tested%20in%20Nuix-9.0-green.svg)

View the GitHub project [here](https://github.com/Nuix/VirusTotal-Integration) or download the latest release [here](https://github.com/Nuix/VirusTotal-Integration/releases).

# Overview

This repo contains a script and a workerside script that will search selected files against the third-party [VirusTotal](http://www.virustotal.com) API service. Should results be found, those results will be stored in custom metadata fields on the relevant items. The workerside script can also encrich the properties further with data from virus total.
**Note:** You must have an internet connection and must supply your own VirusTotal API key in the required variable.  See below for details regarding how to obtain a VirusTotal API key.

# Getting Started

## Generate VirusTotal API Key

1. Navigate to [www.virustotal.com](http://www.virustotal.com/).  **Note:** A VirusTotal account is required. If you do not already have a VirusTotal account, create an account by joining their community.
2. Sign in to your VirusTotal account.
3. Click on your username in the upper right hand corner of the page.
4. From the drop-down menu, click **API Key**.
5. Your API key displays in the middle of the screen. Copy this key for later use. Protect this API key as you would a password. (It is removed for security purposes in the following image.)  ![image](https://user-images.githubusercontent.com/3867456/106201079-d5425f80-61af-11eb-8f1a-ca27471cb6c5.png)

## Running the standard script
1. Begin by downloading the latest release of the virus total script.  Extract the contents of the archive into your Nuix scripts directory.  In Windows the script directory is likely going to be either of the following:

- `%appdata%\Nuix\Scripts` - User level script directory
- `%programdata%\Nuix\Scripts` - System level script directory

2. Open the extracted file [VirusTotalIntegration.py](https://github.com/Nuix/VirusTotal-Integration/blob/master/Python/VirusTotalIntegration.nuixscript/VirusTotalIntegration.py) in a text editor, scroll down to the apikey row, and insert your API key between the double quotes.  ![image](https://user-images.githubusercontent.com/11775738/53526965-7d1df280-3a9a-11e9-8dac-6d294278afdf.png)
3. Save the script and close Notepad.

## Run the Script

1. Select one or more items.
2. Run the script.  **Note:** With the public API, you are limited to 4 selections in the span of a minute. If you exceed the public API request rate limit, a **204 HTTP status code** is returned. Purchase a private API key in order to check more than four requests per minute. If you try to perform calls to functions for which you do not have the required privileges, an **HTTP Error 403 Forbidden** is returned.
3. When the script completes, a custom metadata field is available under the Metadata tab in the Preview pane. The custom data shows the VirusTotal hits under the Value column.  ![image](https://user-images.githubusercontent.com/11775738/53527001-9626a380-3a9a-11e9-918c-cc70589d1b6a.png)

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
