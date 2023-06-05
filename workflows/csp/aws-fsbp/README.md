# AWS Foundational Security Best Practices (FSBP)

## Description

This directory includes Shisho Cloud workflows to cover checks in AWS Foundational Security Best Practices (FSBP) provided by AWS SecurityHub.

## Use manifests

Run the following command(s):

```bash
SHISHO_ORG_ID='your-shisho-org-id'
find . -name "manifest.yaml" | xargs -n1 shishoctl workflow apply --org $SHISHO_ORG_ID -f
```
