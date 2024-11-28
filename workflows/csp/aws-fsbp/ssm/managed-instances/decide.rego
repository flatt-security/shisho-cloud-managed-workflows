package policy.aws.ssm.managed_instances

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.ec2.instances[_]

	config := ssm_config(instance.state.state, instance.ssmConfiguration)

	d := shisho.decision.aws.ssm.managed_instances({
		"allowed": allow_if_excluded(config.managed_by_ssm, instance),
		"severity": custom_severity(config),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.ssm.managed_instances_payload(config),
	})
}

ssm_config(state, ssm_configuration) = {
	"association_status": ssm_configuration.associationStatus,
	"instance_state": state,
	"managed_by_ssm": true,
} {
	ssm_configuration != null
} else = {
	"association_status": "",
	"instance_state": state,
	"managed_by_ssm": false,
}

custom_severity(config) = shisho.decision.severity_medium {
	config.managed_by_ssm == false
	config.instance_state == "RUNNING"
} else = shisho.decision.severity_low {
	config.managed_by_ssm == false
	config.instance_state != "RUNNING"
} else = shisho.decision.severity_info

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
