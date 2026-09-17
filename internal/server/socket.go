package server

// DefaultSocket is the Nix systemd listenStreams path. dial-stdio uses it when
// -s is omitted. serve with no -s uses socket activation, not this constant.
const DefaultSocket = "/tmp/secret-agent.socket"
