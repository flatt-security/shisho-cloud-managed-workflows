package policy.aws.iam.administrative_policy_limitation

import data.shisho
import future.keywords

test_whether_the_policies_are_limited_properly if {
	# check if the policies are limited proplerly
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"iam": {"policies": [
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ722222"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"ec2:*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"s3:*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
		},
		{
			"metadata": {"id": "aws-iam-policy|ANPAI7XKCFMBPM3Q33333"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\"iam:*\", \n      \"organizations:DescribeAccount\", \n      \"organizations:DescribeOrganization\", \n      \"organizations:DescribeOrganizationalUnit\", \n      \"organizations:DescribePolicy\", \n      \"organizations:ListChildren\", \n      \"organizations:ListParents\", \n      \"organizations:ListPoliciesForTarget\", \n      \"organizations:ListRoots\", \n      \"organizations:ListPolicies\", \n      \"organizations:ListTargetsForPolicy\"],\n      \"Resource\": \"*\"\n    }\n  ]\n}"},
		},
	]}}]}}

	# check if the policies are not limited proplerly
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"iam": {"policies": [
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ722222"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
		},
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ733333"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
		},
	]}}]}}

	# check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"iam": {"policies": [
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ722222"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ733333"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
