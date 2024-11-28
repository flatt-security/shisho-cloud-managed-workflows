package policy.aws.ssm.document_accessibility

import data.shisho
import future.keywords

test_whether_public_access_for_ssm_documents_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ssm": {"documents": [
		{
			"metadata": {
				"id": "aws-ssm-document|ap-northeast-1|test-document-1",
				"displayName": "test-document-1",
			},
			"permission": {"accountIds": []},
		},
		{
			"metadata": {
				"id": "aws-ssm-document|ap-northeast-1|test-document-2",
				"displayName": "test-document-2",
			},
			"permission": {"accountIds": []},
		},
	]}}]}}
}

test_whether_public_access_for_ssm_documents_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ssm": {"documents": [
		{
			"metadata": {
				"id": "aws-ssm-document|ap-northeast-1|test-document-1",
				"displayName": "test-document-1",
			},
			"permission": {"accountIds": ["all"]},
		},
		{
			"metadata": {
				"id": "aws-ssm-document|ap-northeast-1|test-document-2",
				"displayName": "test-document-2",
			},
			"permission": {"accountIds": ["all"]},
		},
	]}}]}}
}
