package policy.aws.autoscaling.group_launch_template

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	group := account.autoScaling.groups[_]

	launch_templates := instance_launch_templates(group.instances)
	policy_launch_template := instance_policy_launch_template(group.mixedInstancesPolicy)

	allowed := [
		count(launch_templates) > 0,
		policy_launch_template != null,
	][_] == true

	d := shisho.decision.aws.autoscaling.group_launch_template({
		"allowed": allow_if_excluded(allowed, group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.autoscaling.group_launch_template_payload({
			"launch_templates": launch_templates,
			"launch_template_of_mixed_instances_policy": policy_launch_template,
		}),
	})
}

instance_launch_templates(instances) = x {
	x := [{"id": lt.id, "name": lt.name, "version": format_int(lt.number, 10)} |
		instance := instances[_]
		lt := instance.launchTemplate
	]
} else = []

instance_policy_launch_template(mixed_instances_policy) = {
	"id": lt.id,
	"name": lt.name,
	"version": format_int(lt.number, 10),
} {
	mixed_instances_policy.launchTemplate != null
	lt := mixed_instances_policy.launchTemplate.specification
	lt.id != ""
} else = null

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
