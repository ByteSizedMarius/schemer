// Package schemer runs an OAuth 2.0 authorization code flow with PKCE whose
// redirect_uri is a custom URI scheme rather than a loopback URL.
//
// A program using this package must handle being launched with the callback URL
// in os.Args:
//
//	if schemer.IsCallback(os.Args, "myapp") {
//		return schemer.HandleCallback(os.Args[1])
//	}
//	token, err := flow.Run(ctx)
//
// Scheme registration is implemented on Windows only. The manual route is
// Flow.Start, Session.AuthorizeURL, Session.ParseCallback on the callback URL,
// then Session.Exchange on the code.
package schemer
