# Slack Notification Workflow for Security Events

## Description

This directory includes a Shisho Cloud workflow for notifying events in Shisho Cloud (new incidents, new triage actions, etc.) to your Slack workspaces.

## Use manifests

Run the following command(s):

```bash
SHISHO_ORG_ID='your-shisho-org-id'
shishoctl workflow apply --org $SHISHO_ORG_ID -f ./manifest.yaml
```
