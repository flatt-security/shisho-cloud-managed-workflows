package notification.project_security.triage

import data.shisho
import future.keywords

test_severity_selected_for_projects_successfully if {
	minimum_severity == shisho.decision.severity_high with data.params as {"minimum_severity": "HIGH"}
}

test_critical_severity_selected_as_failsafe_behavior_for_projects if {
	minimum_severity == shisho.decision.severity_critical with data.params as {}
	minimum_severity == shisho.decision.severity_critical with data.params as {"mininum_severity": ""}
}
