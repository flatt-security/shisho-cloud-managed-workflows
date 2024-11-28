package policy.aws.apigateway.route_auth

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	api := account.apigateway.apis[_]

	routes := routes_with_auth_type(api.routes)
	d := shisho.decision.aws.apigateway.route_auth({
		"allowed": allow_if_excluded(is_used_authorization(routes), api),
		"subject": api.metadata.id,
		"payload": shisho.decision.aws.apigateway.route_auth_payload({"routes": routes}),
	})
}

is_used_authorization(routes) = false {
	route := routes[_]
	route.authorization_type in ["NONE", ""]
} else = true

routes_with_auth_type(routes) := x {
	x := [{"id": route.id, "route_key": route.routeKey, "authorization_type": route.authorizationType} |
		route := routes[_]
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
