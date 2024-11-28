package policy.aws.sns.kms_encryption

import data.shisho
import future.keywords

test_kms_encryption_for_sns_topics_is_enabled if {
	# the KMS encryption is enabled for all SNS topics
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"sns": {"topics": [
		{
			"metadata": {
				"id": "aws-sns-topic|ap-northeast-1|test-sns-topic-1",
				"displayName": "test-sns-topic-1",
			},
			"kmsMasterKeyId": "arn:aws:kms:ap-northeast-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			"metadata": {
				"id": "aws-sns-topic|ap-northeast-1|test-sns-topic-2",
				"displayName": "test-sns-topic-2",
			},
			"kmsMasterKeyId": "arn:aws:kms:ap-northeast-1:111122223334:key/1234abcd-12ab-34cd-56ef-1234567890ac",
		},
	]}}]}}

	# the KMS encryption is not enabled for all SNS topics
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"sns": {"topics": [
		{
			"metadata": {
				"id": "aws-sns-topic|ap-northeast-1|test-sns-topic-2",
				"displayName": "test-sns-topic-2",
			},
			"kmsMasterKeyId": "",
		},
		{
			"metadata": {
				"id": "aws-sns-topic|ap-northeast-1|test-sns-topic-3.fifo",
				"displayName": "test-sns-topic-3.fifo",
			},
			"kmsMasterKeyId": "",
		},
	]}}]}}
}
