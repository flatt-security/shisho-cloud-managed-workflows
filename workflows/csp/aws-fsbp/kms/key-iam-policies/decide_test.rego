package policy.aws.kms.key_iam_policies

import data.shisho
import future.keywords

test_whether_iam_policy_for_kms_keys_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{
		"id": "7793927777777",
		"iam": {"policies": [
			{
				"metadata": {
					"id": "aws-iam-policy|ANPA3K53E7344Z77777",
					"displayName": "test-policy-1",
				},
				"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"kms:ReEncrypt*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"arn:aws:kms:*:7793927777777:key/0acef6a5-e4ff-4837-989c-06a777777777\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
				"entities": {
					"users": [{
						"id": "AIDA3K53E7342XUU67777",
						"name": "test-user-1",
					}],
					"groups": [],
					"roles": [],
				},
			},
			{
				"metadata": {
					"id": "aws-iam-policy|ANPA3K53E7344Z77778",
					"displayName": "test-policy-2",
				},
				"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"kms:ListKeys\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"arn:aws:kms:*:7793927777777:key/*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
				"entities": {
					"users": [],
					"groups": [],
					"roles": [{
						"id": "AROA3K53E7345VCOM8889",
						"name": "AmazonEMR-ServiceRole-20230724T168889",
					}],
				},
			},
			{
				"metadata": {
					"id": "aws-iam-policy|ANPA3K53E7344Z77779",
					"displayName": "test-policy-3",
				},
				"defaultVersion": {"rawDocument": "{\n   \"Version\":\"2012-10-17\",\n   \"Statement\":[\n      {\n         \"Sid\":\"statement1\",\n         \"Effect\":\"Allow\",\n         \"Action\": \"s3:GetObject\",\n         \"Resource\": \"arn:aws:s3:::elasticbeanstalk-env-resources-*/*\",\n         \"Condition\": {\n             \"StringNotLike\": {\n                 \"s3:ResourceAccount\": \"779392188153\"\n             }\n         }\n       }\n    ]\n}"},
				"entities": {
					"users": [],
					"groups": [],
					"roles": [{
						"id": "AROA3K53E7345VCOM8888",
						"name": "AmazonEMR-ServiceRole-20230724T168888",
					}],
				},
			},
		]},
	}]}}
}

test_whether_iam_policy_for_kms_keys_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{
		"id": "7793927777777",
		"iam": {"policies": [
			{
				"metadata": {
					"id": "aws-iam-policy|ANPA3K53E7344Z77777",
					"displayName": "test-policy-1",
				},
				"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"kms:ReEncrypt*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"arn:aws:kms:*:7793927777777:key/*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
				"entities": {
					"users": [{
						"id": "AIDA3K53E7342XUU67777",
						"name": "test-user-1",
					}],
					"groups": [],
					"roles": [],
				},
			},
			{
				"metadata": {
					"id": "aws-iam-policy|ANPA3K53E7344Z77778",
					"displayName": "test-policy-1",
				},
				"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"arn:aws:kms:*:7793927777777:key/*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
				"entities": {
					"users": [],
					"groups": [],
					"roles": [{
						"id": "AROA3K53E7345VCOM8888",
						"name": "AmazonEMR-ServiceRole-20230724T168888",
					}],
				},
			},
		]},
	}]}}
}
