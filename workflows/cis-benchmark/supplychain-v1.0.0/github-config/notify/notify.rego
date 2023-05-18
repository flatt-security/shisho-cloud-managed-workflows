package policy.github.config.notify

import data.shisho

notification_groups := []

notifications[n] {
	input.running_state == shisho.job.running_state_in_queue

	ng := notification_groups[_]
	msg := concat("", ["Shisho Cloud has started to audit the GitHub configurations! See https://cloud.shisho.dev for further information."])

	n := shisho.notification.to_group(ng, msg)
}
