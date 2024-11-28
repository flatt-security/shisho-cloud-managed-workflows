# Additional Checks for Google Cloud by Flatt Security

## Description

This directory includes a set of additional checks from Flatt Security for Google Cloud.

## Use manifests

Run the following command(s):

```bash
SHISHO_ORG_ID='your-shisho-org-id'
find . -name "manifest.yaml" | xargs -n1 shishoctl workflow apply --org $SHISHO_ORG_ID -f
```
