# schemer

OAuth 2.0 authorization code flow with PKCE. When a provider redirects to the app's custom URI scheme (`myapp://auth`), schemer can register that scheme on the computer and catch the callback to get a token. No dependencies.

```
go get github.com/ByteSizedMarius/schemer
```

## Usage

The OS delivers the callback by launching a second instance of your program with the callback URL as its first argument. `main` checks for it with `IsCallback` before anything else:

```go
func main() {
	if schemer.IsCallback(os.Args, "myapp") {
		if err := schemer.HandleCallback(os.Args[1]); err != nil {
			log.Fatal(err)
		}
		return
	}
	flow := schemer.Flow{
		ClientID:     "my-client-id",
		AuthorizeURL: "https://auth.example.com/oauth/authorize",
		TokenURL:     "https://auth.example.com/oauth/token",
		RedirectURI:  "myapp://auth",
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	token, err := flow.Run(ctx)
	// ...
}
```

`Run` registers the scheme for the current user, opens the browser, waits for the callback, exchanges the code and restores the previous registration. A failed restore comes back as an error alongside the token. A program killed during `Run` leaves the scheme registered until its next login.

Scheme registration is implemented on Windows only. Elsewhere `Run` returns `ErrUnsupportedOS`. The manual route is `Flow.Start`, then `Session.AuthorizeURL`, then `Session.ParseCallback` on the callback URL and `Session.Exchange` on the code it returns.
