# Dorc Release Tools

Azure DevOps Pipeline task extension for creating and managing DOrc deployment requests.

## Overview

This extension provides an Azure Pipelines task that integrates with the DOrc release management system, allowing you to submit deployment requests directly from your CI/CD pipelines. It supports:

- Creating DOrc release requests with configurable components
- Real-time streaming of component deployment logs
- Support for both TFS builds and custom build URIs
- Configurable polling intervals for deployment status
- Support for pinned builds and latest versions

## Installation

Install the **Dorc Release Tools** extension from the Azure DevOps Marketplace:
1. Open your Azure DevOps organization
2. Navigate to **Marketplace** → search for "Dorc Release Tools"
3. Click **Get it free** and select your organization
4. Click **Install**

## Getting Started

### Prerequisites

- Azure DevOps organization with Pipelines enabled
- DOrc API access (base URL and IDS client secret)
- Project and environment configured in DOrc

### Using the Dorc Request Task

Add the task to your pipeline YAML:

```yaml
- task: dorcrequest@3
  inputs:
    baseurl: 'https://deploymentportal:8443/'
    dorcIDSsecret: '$(DorcSecret)'
    project: 'MyProject'
    targetenv: 'Production'
    buildtext: 'MyBuild'
    buildnum: 'latest'
    components: 'ComponentA;ComponentB'
    pollIntervalSeconds: '2'
```

### Task Inputs

| Input | Required | Description |
|-------|----------|-------------|
| baseurl | Yes | DOrc API base URL (e.g., https://deploymentportal:8443/) |
| dorcIDSsecret | Yes | Identity Server client secret for DOrc API |
| project | Yes | Project name as configured in DOrc |
| targetenv | Yes | Target environment name in DOrc |
| buildtext | No | TFS build name |
| buildnum | No | Build version or "latest" |
| components | Yes | Semicolon-delimited list of DOrc components |
| pinned | No | Use only pinned builds (boolean) |
| builduri | No | Direct build URI (for non-TFS builds) |
| vstfsUrl | No | Direct vstfs:// build URI (overrides buildtext/buildnum) |
| pollIntervalSeconds | No | Polling interval in seconds (default: 2) |

## Build and Test

This is a PowerShell-based extension. To build and package:

```powershell
# Install tfx-cli globally
npm install -g tfx-cli

# Package the extension
tfx extension create --manifest-globs vss-extension.json --output-path .
```

## Versioning

Versions follow semantic versioning:
- **Major**: Breaking changes
- **Minor**: New features
- **Patch**: Bug fixes and improvements

## Support

For issues or feature requests, contact the development team.

## License

Copyright SEFE. All rights reserved.