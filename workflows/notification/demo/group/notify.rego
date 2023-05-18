package demo.notification.group

import data.shisho

notifications[n] {
	input.running_state == shisho.job.running_state_preprocessing

	data.params.group != ""
	n := shisho.notification.to_group(
		data.params.group,
		"hello!",
	)
}
