# A Collection of Slack Notification Workflows

## Description

This directory includes Shisho Cloud workflows for notifying events in Shisho Cloud (new incidents, new triage actions, etc.) to your Slack workspaces.

## Use manifests

Run the following command(s):

```bash
SHISHO_ORG_ID='your-shisho-org-id'
shishoctl workflow apply --org $SHISHO_ORG_ID -f ./security-ja/manifest.yaml
```
