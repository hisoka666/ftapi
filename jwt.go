package server

import (
   "fmt"
   bc "golang.org/x/crypto/bcrypt"
   "net/http"
   "appengine"
   "appengine/datastore"
)

type User struct {
	Username string
	Password []byte
}

func register(w http.ResponseWriter, r *http.Request){
    ctx := appengine.NewContext(r)
	username := r.FormValue("username")
	password := r.FormValue("password")

	bpass := []byte(password)
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
    }

}
func init(){
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
}