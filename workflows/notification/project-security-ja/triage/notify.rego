package notification.project_security.triage

import data.shisho
import data.shisho.notification.slack

minimum_severity := severity_intl(data.params.minimum_severity) {
	data.params
	data.params.minimum_severity != ""
} else := shisho.decision.severity_critical

severity_intl(x) := shisho.decision.severity_info {
	x == "INFO"
} else := shisho.decision.severity_low {
	x == "LOW"
} else := shisho.decision.severity_medium {
	x == "MEDIUM"
} else := shisho.decision.severity_high {
	x == "HIGH"
} else := shisho.decision.severity_critical {
	x == "CRITICAL"
} else := shisho.decision.severity_low

severity_string(x) := "参考情報（info）" {
	x == shisho.decision.severity_info
} else := "低（low）" {
	x == shisho.decision.severity_low
} else := "中（medium）" {
	x == shisho.decision.severity_medium
} else := "高（high）" {
	x == shisho.decision.severity_high
} else := "緊急（critical）" {
	x == shisho.decision.severity_critical
} else := x

severity_emoji(x) := ":information_source:" {
	x == shisho.decision.severity_info
} else := ":eyes:" {
	x == shisho.decision.severity_low
} else := ":warning:" {
	x == shisho.decision.severity_medium
} else := ":rotating_light:" {
	x == shisho.decision.severity_high
} else := ":sos:" {
	x == shisho.decision.severity_critical
} else := ":memo:"

triage_status(x) := "要レビュー" {
	x == "AWAITING_REVIEW"
} else := "要対応" {
	x == "ACTION_REQUIRED"
} else := "リスク受容中" {
	x == "ACKNOWLEDGED"
} else := "セキュア" {
	x == "SECURE"
} else := "削除済" {
	x == "DELETED"
} else := x

triage_status_emoji(x) := ":eyes:" {
	x == "AWAITING_REVIEW"
} else := ":heavy_exclamation_mark:" {
	x == "ACTION_REQUIRED"
} else := ":arrow_right:" {
	x == "ACKNOWLEDGED"
} else := ":large_green_circle:" {
	x == "SECURE"
} else := ":wastebasket:" {
	x == "DELETED"
} else := ":memo:"

headline(type, status) := "*新たなポリシー違反が検出されました。*\n対応を検討しましょう。" {
	type == "CREATED"
} else := "*ポリシー違反が解決されました* :tada:" {
	type == "UPDATED"
	status == "SECURE"
} else := "*ポリシーに違反した設定の対応状況が変化しました。*\n引き続き対応を進めましょう。"

title(explanation, api_version, kind) := explanation.title {
	explanation
} else := "" {
	concat(":", [api_version, kind])
}

triage_information(target) := [
	slack.divider_block,
	slack.context_block([slack.text_element(concat("", [":mega: トリアージ者: ", target.triageInitiator.displayName]))]),
	slack.context_block([slack.text_element(concat("", [":memo: コメント: ", target.triageComment]))]),
] {
	target.triageInitiator.displayName != ""
	target.triageComment != ""
} else := [
	slack.divider_block,
	slack.context_block([slack.text_element(concat("", [":mega: トリアージ者: ", target.triageInitiator.displayName]))]),
] {
	target.triageInitiator.displayName != ""
	target.triageComment == ""
} else := []

notifications[n] {
	event := input.query.shisho.event
	event.__typename == "ShishoTriageStatusEvent"
	input.running_state == shisho.job.running_state_preprocessing

	# send a notification only if the severity of the target decision is higher than the minimum severity
	target_severity := severity_intl(event.target.severity)
	minimum_severity <= target_severity

	# send a notification to the default project notification channels
	project := event.target.subject.projectsBelongingTo[_]
	channel := project.defaultNotificationChannels[_]
	channel.__typename == "ShishoNotificationChannelSlack"

	n := shisho.notification.to_slack_channel(
		channel.workspaceId,
		channel.channelId,
		{"blocks": array.concat(
			[slack.text_section(
				headline(event.type, event.status),
				{"fields": [
					# The first row
					slack.text_element("*:memo: 違反が見られた観点*"),
					slack.text_element("*:dart: 対象リソース*"),
					slack.text_element(concat("", ["<", event.target.viewer, "|", title(event.target.explanation, event.target.apiVersion, event.target.kind), ">"])),
					slack.text_element(concat("", ["<", event.target.subject.viewer, "|", event.target.subject.displayName, ">"])),
					# The second row
					slack.text_element(concat("", [severity_emoji(target_severity), " *深刻度*"])),
					slack.text_element(concat("", [triage_status_emoji(event.status), " *対応状況*"])),
					slack.text_element(severity_string(target_severity)),
					slack.text_element(concat("", ["*", triage_status(event.status), "* に変化しました"])),
				]},
			)],
			# The footer
			array.concat(triage_information(event.target), [
				slack.divider_block,
				slack.context_block([slack.text_element(concat("", [":shield: *Powered by \"<", event.target.createdBy.viewer, "|", event.target.createdBy.name, ">\" on Shisho Cloud*"]))]),
				slack.divider_block,
			]),
		)},
	)
}
