package policy.googlecloud.networking.vpc_flow_log

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	vpc_network := project.network.vpcNetworks[_]

	allowed := any([
		count(vpc_network.subnetworks) == 0,
		is_allowed(vpc_network.subnetworks),
	])

	d := shisho.decision.googlecloud.networking.vpc_flow_log({
		"allowed": allowed,
		"subject": vpc_network.metadata.id,
		"payload": shisho.decision.googlecloud.networking.vpc_flow_log_payload({"flow_log_enabled": allowed}),
	})
}

# if the log settings is configured properly, return true
is_allowed(subnetworks) {
	network := subnetworks[_]
	log_config := network.logConfiguration

	log_config.enable == true

	# check whether filter expression is set as empty to include all logs
	log_config.filterExpression == ""

	# check whether the interval is set as the 5-second interval 
	log_config.aggregationInterval = "INTERVAL_5_SEC"

	# check whether the flow sampling is set as 1
	log_config.flowSampling = 1

	# check whether the metadata configuration is set as `INCLUDE_ALL_METADATA` to include all metadata
	log_config.metadata == "INCLUDE_ALL_METADATA"
} else = false {
	true
}
