package policy.aws.kinesis.encryption

import data.shisho
import future.keywords

test_whether_encryption_for_kinesis_streams_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"kinesis": {"streams": [
		{
			"metadata": {
				"id": "aws-kinesis-stream|ap-northeast-1|test-data-stream-1",
				"displayName": "test-data-stream-1",
			},
			"encryptionType": "KMS",
		},
		{
			"metadata": {
				"id": "aws-kinesis-stream|ap-northeast-1|test-data-stream-2",
				"displayName": "test-data-stream-2",
			},
			"encryptionType": "KMS",
		},
	]}}]}}
}

test_whether_encryption_for_kinesis_streams_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"kinesis": {"streams": [
		{
			"metadata": {
				"id": "aws-kinesis-stream|ap-northeast-1|test-data-stream-1",
				"displayName": "test-data-stream-1",
			},
			"encryptionType": "NONE",
		},
		{
			"metadata": {
				"id": "aws-kinesis-stream|ap-northeast-1|test-data-stream-2",
				"displayName": "test-data-stream-2",
			},
			"encryptionType": "NONE",
		},
	]}}]}}
}
