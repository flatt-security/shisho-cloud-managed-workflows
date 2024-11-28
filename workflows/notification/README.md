# A Collection of Notification Workflows

## Description

This directory includes Shisho Cloud workflows for notifying events in Shisho Cloud (new incidents, new triage actions, etc.) to your workspaces.

## Use manifests

Run the following command(s):

```bash
SHISHO_ORG_ID='your-shisho-org-id'
shishoctl workflow apply --org $SHISHO_ORG_ID -f ./security-ja/manifest.yaml
shishoctl workflow apply --org $SHISHO_ORG_ID -f ./project-security-ja/manifest.yaml
```
