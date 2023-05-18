package demo.notification.slack

import data.shisho
import data.shisho.notification.slack

notifications[n] {
	input.running_state == shisho.job.running_state_preprocessing

	data.params.channel != ""
	workspace_id := split(data.params.channel, ":")[0]
	channel_id := split(data.params.channel, ":")[1]

	n := shisho.notification.to_slack_channel(
		workspace_id,
		channel_id,
		{"blocks": [
			slack.text_section(
				"Hello, world!",
				{"fields": [
					slack.text_element("*:one: Field 1*"),
					slack.text_element("*:two: Field 2*"),
				]},
			),
			slack.divider_block,
			slack.context_block([slack.text_element(concat("", [":shield: *Powered by Shisho Cloud*"]))]),
			slack.divider_block,
		]},
	)
}
