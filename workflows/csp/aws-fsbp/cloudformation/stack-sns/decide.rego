package policy.aws.cloudformation.stack_sns

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	stack := account.cloudFormation.stacks[_]

	d := shisho.decision.aws.cloudformation.stack_sns({
		"allowed": allow_if_excluded(count(stack.notificationArns) > 0, stack),
		"subject": stack.metadata.id,
		"payload": shisho.decision.aws.cloudformation.stack_sns_payload({"notification_arns": stack.notificationArns}),
	})
}

allow_if_excluded(allowed, r) {
	data.params != null

	tag := data.params.tag_exceptions[_]
	elements := split(tag, "=")

	tag_key := elements[0]
	tag_value := concat("=", array.slice(elements, 1, count(elements)))

	t := r.tags[_]
	t.key == tag_key
	t.value == tag_value
} else := allowed
