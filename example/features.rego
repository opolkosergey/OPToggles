package validateClientId

default allow = false

allow {
	is_expected_client_id
	some users
	us_users[users]
	users != null
}

is_expected_client_id {
  [_, payload, _] := io.jwt.decode(bearer_token)
  payload.client_id == "customer-account-support"
}

bearer_token := t {
	v := input.request.headers.Authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}

us_users[users] {
  some user
  data.example.users[input.user].location.country == "US"
  users := user
}