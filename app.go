package phitbot

import (
	"github.com/codahale/charlie"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const (
	user              = "Bob"
	password          = "Allurbase"
	testCSRFHeader    = "csrf-hdr"
	testCSRFCookie    = "csrf-ck"
	testSessionHeader = "s-hdr"
	testSessionCookie = "s-ck"
	testKey           = "superdupersecret"
)

var (
	tmpl_in   = template.Must(template.ParseFiles("templates/base", "templates/head", "templates/in"))
	tmpl_out  = template.Must(template.ParseFiles("templates/base", "templates/head", "templates/out"))
	tmpl_err  = template.Must(template.ParseFiles("templates/base", "templates/head", "templates/err"))
	validPath = regexp.MustCompile(`^/(in|out|auth)?/?(.*)$`)
)

func handleLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "POST requests only", http.StatusMethodNotAllowed)
		return
	}

	//c := appengine.NewContext(r)
	ck, err := r.Cookie(testCSRFCookie)
	if err == http.ErrNoCookie {
		testuser := r.FormValue("user")
		testpswd := r.FormValue("password")
		if testuser != user || testpswd != password {
			tmpl_out.ExecuteTemplate(w, "base", map[string]interface{}{"Again": true})
		} else {
			csrf := charlie.New([]byte(testKey))
                        temp := testuser + strconv.FormatInt(time.Now().Unix(), 10)
			token := csrf.Generate(temp)
			ck := &http.Cookie{Name: testCSRFCookie, Value: token, Expires: time.Now().Add(time.Hour * 12)}
			http.SetCookie(w, ck)
			ck = &http.Cookie{Name: testSessionCookie, Value: temp, Expires: time.Now().Add(time.Hour * 12)}
			http.SetCookie(w, ck)
			tmpl_in.ExecuteTemplate(w, "base", map[string]interface{}{"Message": token})
		}
	} else {
		tmpl_in.ExecuteTemplate(w, "base", map[string]interface{}{"Message": ck.Value})
	}
	return

}

func handleLogout(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		http.Error(w, "GET requests only", http.StatusMethodNotAllowed)
		return
	}
	ck, err := r.Cookie(testCSRFCookie)
	if err == http.ErrNoCookie {
	} else {
		ck.MaxAge = -1
		http.SetCookie(w, ck)
	}
	ck, err = r.Cookie(testSessionCookie)
	if err == http.ErrNoCookie {
		tmpl_out.ExecuteTemplate(w, "base", map[string]interface{}{"Message": false, "Again": true})
	} else {
		ck.MaxAge = -1
		http.SetCookie(w, ck)
		tmpl_out.ExecuteTemplate(w, "base", map[string]interface{}{"Message": true, "Again": false})
	}
	return

}

func handleAuth(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		http.Error(w, "GET requests only", http.StatusMethodNotAllowed)
		return
	}
	ck, err := r.Cookie(testCSRFCookie)
	if err == http.ErrNoCookie {
		tmpl_out.ExecuteTemplate(w, "base", map[string]interface{}{"Message": false, "Again": true})
	} else {
	        tmpl_in.ExecuteTemplate(w, "base", map[string]interface{}{"Message": ck.Value})
	}
        return

}

func makeHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		fn(w, r) //, m[2])
	}
}

func init() {
	v := charlie.HTTPParams{
		Key:           []byte(testKey),
		CSRFHeader:    testCSRFHeader,
		CSRFCookie:    testCSRFCookie,
		SessionCookie: testSessionCookie,
		SessionHeader: testSessionHeader,
	}
	http.Handle("/auth", v.Wrap(makeHandler(handleAuth)))
	http.HandleFunc("/in", makeHandler(handleLogin))
	http.HandleFunc("/out", makeHandler(handleLogout))
}
