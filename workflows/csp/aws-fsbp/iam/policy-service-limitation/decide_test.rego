package policy.aws.iam.policy_service_limitation

import data.shisho
import future.keywords

test_whether_service_limitation_for_iam_policies_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"policies": [
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ722222"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"ec2:Describe*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"s3:Describe*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
		},
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ711111"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"ec2:Describe*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"s3:Describe*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:Describe*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
		},
		{
			"metadata": {"id": "aws-iam-policy|ANPAI7XKCFMBPM3Q33333"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\"iam:Describe*\", \n      \"organizations:DescribeAccount\", \n      \"organizations:DescribeOrganization\", \n      \"organizations:DescribeOrganizationalUnit\", \n      \"organizations:DescribePolicy\", \n      \"organizations:ListChildren\", \n      \"organizations:ListParents\", \n      \"organizations:ListPoliciesForTarget\", \n      \"organizations:ListRoots\", \n      \"organizations:ListPolicies\", \n      \"organizations:ListTargetsForPolicy\"],\n      \"Resource\": \"*\"\n    }\n  ]\n}"},
		},
	]}}]}}
}

test_whether_service_limitation_for_iam_policies_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"iam": {"policies": [
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ722222"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"ec2:*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"s3:*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
		},
		{
			"metadata": {"id": "aws-iam-policy|ANPAI3VAJF5ZCRZ733333"},
			"defaultVersion": {"rawDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"ec2:*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"s3:*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"cloudwatch:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"autoscaling:*\",\n      \"Resource\": \"*\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"iam:CreateServiceLinkedRole\",\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"iam:AWSServiceName\": [\n            \"autoscaling.amazonaws.com\",\n            \"ec2scheduled.amazonaws.com\",\n            \"elasticloadbalancing.amazonaws.com\",\n            \"spot.amazonaws.com\",\n            \"spotfleet.amazonaws.com\",\n            \"transitgateway.amazonaws.com\"\n          ]\n        }\n      }\n    }\n  ]\n}"},
		},
	]}}]}}
}
