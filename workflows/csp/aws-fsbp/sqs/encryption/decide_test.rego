package policy.aws.sqs.encryption

import data.shisho
import future.keywords

test_encryption_for_sqs_queues_is_enabled if {
	# the encryption is enabled for all SQS queues
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"sqs": {"queues": [
		{
			"metadata": {
				"id": "aws-sqs-queue|ap-northeast-1|test-fifo-queue-2.fifo|1682406082",
				"displayName": "test-fifo-queue-2.fifo",
			},
			"serverSideEncryption": {"kmsConfiguration": {"masterKeyId": "alias/aws/sqs"}},
		},
		{
			"metadata": {
				"id": "aws-sqs-queue|ap-northeast-1|test-fifo-queue-3.fifo|1682397472",
				"displayName": "test-fifo-queue-3.fifo",
			},
			"serverSideEncryption": {"kmsConfiguration": {"masterKeyId": "alias/aws/sqs"}},
		},
	]}}]}}

	# the encryption is enabled for all SQS queues
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"sqs": {"queues": [
		{
			"metadata": {
				"id": "aws-sqs-queue|ap-northeast-1|test-fifo-queue-3.fifo|1682397472",
				"displayName": "test-fifo-queue-3.fifo",
			},
			"serverSideEncryption": {"kmsConfiguration": {"masterKeyId": ""}},
		},
		{
			"metadata": {
				"id": "aws-sqs-queue|ap-northeast-1|test-standard-queue-1|1682390655",
				"displayName": "test-standard-queue-1",
			},
			"serverSideEncryption": {"kmsConfiguration": null},
		},
	]}}]}}
}
