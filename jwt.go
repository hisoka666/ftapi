package server

import (
   "fmt"
   bc "golang.org/x/crypto/bcrypt"
   "net/http"
   "appengine"
   "appengine/datastore"
   _"encoding/json"
   "io/ioutil"
   jwt "github.com/dgrijalva/jwt-go"
   _"time"
)

type User struct {
	Username string
	Password []byte
}

//fungsi untuk registrasi user baru. fungsi ini rencananya
//akan hanya bisa diakses oleh admin.
func register(w http.ResponseWriter, r *http.Request){
    ctx := appengine.NewContext(r)
	username := r.FormValue("username")
	password := r.FormValue("password")

	bpass := []byte(password)
	//salah satu metode dari paket bcrypt
    hashed, err := bc.GenerateFromPassword(bpass, 0)
    if err != nil {
    	fmt.Fprintln(w, "Error %v", err)
    }
    stored := &User{
    	Username: username,
    	Password: hashed,
    }

    key := datastore.NewIncompleteKey(ctx, "User", nil)
    if _, err := datastore.Put(ctx, key, stored); err != nil {
    	fmt.Fprintln(w, "Failed to store %v", err)
    }

}

func login(w http.ResponseWriter, r *http.Request){
	ctx := appengine.NewContext(r)

	user := r.FormValue("username")
	pass := []byte(r.FormValue("password"))

    q := datastore.NewQuery("User").Filter("Username=", user)
    t := q.Run(ctx)
    var hashed []byte
    for {
    	var u User
    	_, err := t.Next(&u)
    	if err == datastore.Done{
    		break
    	}
    	if err != nil {
    		fmt.Fprintln(w, "Maaf username atau password salah")
    		break
    	}
    	hashed = u.Password
    }

    err := bc.CompareHashAndPassword(hashed, pass)
    if err != nil {
    	fmt.Fprintln(w, "Maaf username atau password salah")
    	return
    } else {
    	fmt.Fprintf(w, "Selamat datang %s", user)
    	fmt.Fprintln(w, "")
    	signKey, err := ioutil.ReadFile("app.rsa")
    	if err != nil {
    		fmt.Fprintf(w, "Error %v", err)
    		return
    	}
    	m := jwt.New(jwt.GetSigningMethod("RS256"))
    	
    	tokenString, err := m.SignedString(signKey)
    	if err != nil {
    		w.WriteHeader(http.StatusInternalServerError)
    		fmt.Fprintf(w, "Error Signing Token %v", err)
    		return
    	}
    	//js, err := json.Marshal(tokenString)
    	fmt.Fprintln(w, tokenString)

    }

}

func middle(next http.HandlerFunc) http.Handler{
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		//mid before

		next.ServeHTTP(w, r)
		//mid after
		})
}

func init(){
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
}