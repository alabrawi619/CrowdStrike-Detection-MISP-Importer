# CrowdStrikeDetectionMISPImporter
## Introduction
CrowdStrikeDetectionMispImporter is a Python script designed to integrate CrowdStrike's detection capabilities with MISP (Malware Information Sharing Platform & Threat Sharing). The script fetches detection data from CrowdStrike, processes it, and creates corresponding events in MISP. This allows for efficient and automated sharing of threat intelligence between CrowdStrike and MISP.

## Requirements
- Python 3
- CrowdStrike Falcon OAuth2 API credentials
- MISP instance with API access

## Dependencies
Before running the script, install the required Python libraries:

```bash
pip install -r requirements.txt
```

- Create crowdstrike-behavior MISP custom object and put crowdstrike_behavior_template.json content in it. [Instructions](https://www.misp-project.org/2021/03/17/MISP-Objects-101.html/)

- Perform the same steps and add the object under `/var/www/MISP/PyMISP/pymisp/data/misp-objects/objects/`
## Configuration
Configure the script by setting the following variables in `settings.py`:

- client_id: Your CrowdStrike Client ID.
- client_secret: Your CrowdStrike Client Secret.
- crowdstrike_url: URL to the CrowdStrike API.
- misp_url: URL to your MISP instance.
- misp_auth_key: Your MISP API key.
- crowdstrike_org_uuid: Your MISP organization uuid
- device_ids: Specific device IDs to filter detections.

## Usage
Run the script from the command line:

```bash
python3 CrowdStrikeDetectionMispImporter.py
```

The script performs the following actions:

1. Connects to CrowdStrike and fetches detection data.
2. Processes the detection data and formats it for MISP.
3. Creates events in MISP based on the processed detection data.

## Troubleshooting
- Ensure all required environment variables are set correctly.
- Check if the CrowdStrike API and MISP instance are reachable.
- For detailed error information, refer to the log output.

## Contributing
Contributions to the script are welcome!

## Author
Taha Al-Abrawi

[LinkedIn](www.linkedin.com/in/taha-al-abrawi-791029215)
