# CIS AWS Foundations Benchmark v1.5.0

## Description

This directory includes Shisho Cloud workflows to cover checks in CIS AWS Foundations Benchmark v1.5.0.

## Use manifests

Run the following command(s):

```bash
SHISHO_ORG_ID='your-shisho-org-id'
find . -name "manifest.yaml" | xargs -n1 shishoctl workflow apply --org $SHISHO_ORG_ID -f
```
