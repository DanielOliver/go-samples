package main

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type authenticationMiddleware struct {
	ClientID string
	Provider *oidc.Provider
}

func (amw *authenticationMiddleware) Middleware(next http.Handler) http.Handler {
	var verifier = amw.Provider.Verifier(&oidc.Config{ClientID: amw.ClientID})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("Authorization")
		fmt.Printf("%+v\n", reqToken)
		splitToken := strings.Split(reqToken, "Bearer")
		if len(splitToken) != 2 {
			http.Error(w, "Token doesn't seem right", http.StatusUnauthorized)
			return
		}

		reqToken = strings.TrimSpace(splitToken[1])

		idToken, err := verifier.Verify(r.Context(), reqToken)
		if err != nil {
			http.Error(w, "Unable to verify token", http.StatusUnauthorized)
			return
		}
		fmt.Printf("%+v\n", idToken)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func httpHomePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello Home Page!")
	fmt.Println("hit home page")
}

func main() {

	provider, err := oidc.NewProvider(context.Background(), "https://yourdomainname.b2clogin.com/tfp/yourtenantid/yourUserFlow/v2.0/") //REPLACE THIS WITH YOUR VALUE
	if err != nil {
		log.Fatal(err)
	}
	amw := authenticationMiddleware{
		Provider: provider,
		ClientID: "<client id guid>", //REPLACE THIS WITH YOUR VALUE
	}

	r := mux.NewRouter()
	r.HandleFunc("/", httpHomePage)

	cors := handlers.CORS(
		handlers.AllowedHeaders([]string{"Authorization"}),
		handlers.AllowedMethods([]string{"GET"}),
		handlers.AllowedOrigins([]string{"http://localhost:4200"}),
	)

	// Apply the CORS middleware to our top-level router, with the defaults.
	log.Fatal(http.ListenAndServe(":8080", cors(amw.Middleware(r))))
}
