package auth

// DefaultForwardAuthHeader is the HTTP header trusted hops use to name the end
// user when ForwardAuth.Header is empty.
const DefaultForwardAuthHeader = "X-Secret-Agent-User"
