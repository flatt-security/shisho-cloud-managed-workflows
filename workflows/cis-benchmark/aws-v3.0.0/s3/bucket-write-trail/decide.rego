package policy.aws.s3.bucket_write_trail

import data.shisho

# Whether to allow the account CloudTrail configurations S3 object logging is limited to some buckets/objects.
allow_limited_logging := data.params.allow_limited_logging {
	data.params != null
	[true, false][_] == data.params.allow_limited_logging
} else := false

decisions[d] {
	account := input.aws.accounts[_]
	allowed := has_trail_with_s3_write(account.cloudTrail.trails)

	d := shisho.decision.aws.s3.bucket_write_trail({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_write_trail_payload({"enabled": allowed}),
	})
}

has_trail_with_s3_write(trails) {
	trail := trails[_]
	has_data_event_selector(trail)
} else = false

has_data_event_selector(trail) {
	has_basic_selector_with_s3_write(trail.eventSelectors)
} else {
	has_advanced_selector_with_s3_write(trail.eventSelectors)
} else = false

has_basic_selector_with_s3_write(selectors) {
	# Find a selector that ....
	selector := selectors[_]
	selector.__typename == "AWSCloudTrailBasicEventSelector"

	# logs all write events ...
	allowed_types := ["ALL", "WRITE_ONLY"]
	allowed_types[_] == selector.readWriteType

	# ... for S3 objects.
	resource := selector.dataResources[_]
	resource.type == "AWS::S3::Object"
	records_enough(resource)
} else = false

# Cnfirm the basic selector dataResources covers the enough range of S3 buckets.
# NOTE:
# - `values` can include more limited number of values, e.g. `arn:aws:s3:::mybucket/*`.
# - specifying `"arn:aws:s3"` in `values` selects all S3 objects in all buckets for logging targets.
# - if your organization chooses to limit the scope of logging to specific buckets, you can comment out the condition on `values` in this policy code.
records_enough(resource) {
	# if `allow_limited_logging` is true, then `values` don't have to cover all S3 buckets.
	allow_limited_logging
} else {
	# if `allow_limited_logging` is false, then `values` must cover all S3 buckets.
	value := resource.values[_]
	value == "arn:aws:s3"
}

has_advanced_selector_with_s3_write(selectors) {
	# Find an advanced selector that ....
	selector = selectors[_]
	selector.__typename == "AWSCloudTrailAdvancedEventSelector"

	# logs all write events ...
	contains_field_selector(selector.fieldSelectors, "eventCategory", "Data")
	not contains_field_selector(selector.fieldSelectors, "readOnly", "true")

	# for S3 objects ...
	contains_field_selector(selector.fieldSelectors, "resources.type", "AWS::S3::Object")

	# ... with "valid" selectors.
	records_enough_advanced(selector.fieldSelectors)
} else = false

contains_field_selector(field_selectors, field, value) {
	field_selector := field_selectors[_]
	field_selector.field == field
	eq := field_selector.equals[_]
	eq == value
} else = false

records_enough_advanced(field_selectors) {
	# if `allow_limited_logging` is true, then `values` don't have to cover all S3 buckets.
	allow_limited_logging
} else {
	# If eventName filter or resources filter exist, then the selector is not for all read events.
	not has_more_selectors(field_selectors)
}

# NOTE: Judging only with the field selector existence is not enough to determine the selector is for all read events.
# However, practically, this condition is enough to filter out most of the risky scenarios.
# Allowing false positives, this condition is used to simplify the policy code.
has_more_selectors(field_selectors) {
	field_selector := field_selectors[_]
	field_selector.field == "eventName"
} else {
	field_selector := field_selectors[_]
	field_selector.field == "resources.ARN"
} else := false
