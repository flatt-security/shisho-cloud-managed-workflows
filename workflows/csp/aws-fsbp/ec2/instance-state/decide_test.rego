package policy.aws.ec2.instance_state

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

two_months_ago_string := date_string(time.add_date(now_ns, 0, -2, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT00:00:00Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

test_unused_duration_of_instances_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"state": {"state": "STOPPED"},
			"stateTransitedAt": today_string,
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"state": {"state": "STOPPED"},
			"stateTransitedAt": today_string,
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0633259a9098f15a8",
				"displayName": "i-0633259a9098f15a8",
			},
			"state": {"state": "RUNNING"},
			"stateTransitedAt": null,
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"state": {"state": "STOPPED"},
			"stateTransitedAt": today_string,
		},
	]}}]}}
}

test_unused_duration_of_instances_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"state": {"state": "STOPPED"},
			"stateTransitedAt": two_months_ago_string,
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"state": {"state": "STOPPED"},
			"stateTransitedAt": two_months_ago_string,
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0633259a9098f15a8",
				"displayName": "i-0633259a9098f15a8",
			},
			"state": {"state": "RUNNING"},
			"stateTransitedAt": null,
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"state": {"state": "STOPPED"},
			"stateTransitedAt": two_months_ago_string,
		},
	]}}]}}
}
