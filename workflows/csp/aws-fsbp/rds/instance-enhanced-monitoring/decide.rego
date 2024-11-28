package policy.aws.rds.instance_enhanced_monitoring

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	d := shisho.decision.aws.rds.instance_enhanced_monitoring({
		"allowed": allow_if_excluded(instance.enhancedMonitoringResourceArn != "", instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_enhanced_monitoring_payload({
			"enhanced_monitoring_resource_arn": instance.enhancedMonitoringResourceArn,
			"monitoring_interval": instance.monitoringInterval,
		}),
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
