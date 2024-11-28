package policy.aws.autoscaling.group_instance_types

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	group := account.autoScaling.groups[_]

	types := union_instance_types(group.instances, group.mixedInstancesPolicy)

	d := shisho.decision.aws.autoscaling.group_instance_types({
		"allowed": allow_if_excluded(allowed(types), group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.autoscaling.group_instance_types_payload({
			"instance_types": types,
			"availability_zones": group.availabilityZones,
		}),
	})
}

allowed(types) {
	[
		count(types) > 1,
		contains_attribute_based(types),
	][_] == true
} else = false

contains_attribute_based(types) {
	type := types[_]
	type == "ATTRIBUTE_BASED"
} else = false

union_instance_types(instances, mixed_instances_policy) = x {
	i_types := instance_types(instances)
	x := array.concat(i_types, [o_type |
		o_types := overrides_types(mixed_instances_policy)
		o_type := o_types[_]
		i_types[_] != o_type
	])
} else = []

instance_types(instances) = ["ATTRIBUTE_BASED"] {
	instance := instances[_]
	instance.type == ""
} else = x {
	x := [instance.type |
		instance := instances[_]
		instance.type != ""
	]
} else = []

overrides_types(mixed_instances_policy) = ["ATTRIBUTE_BASED"] {
	override := mixed_instances_policy.launchTemplate.overrides[_]
	override.instanceType == ""
} else = x {
	x := [override.instanceType |
		override := mixed_instances_policy.launchTemplate.overrides[_]
		override.instanceType != ""
	]
} else = []

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
