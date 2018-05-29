/* Package main is a JSON based HTTP ReST API that provides methods for managing users.

Author: Anthony Caruana

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY,FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"lynx/user"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

var (
	url  = "0.0.0.0:50001"
	port = 50001
)

/* The following routes and methods are supported:
   # /users/ 				=> 	GET retreives all users
   # /users/ 				=>	POST adds a specific user by name
   # /users/{username}		=> 	GET retreives a specific user by name
   # /email/{username}		=> 	PUT updates email for a specific user by name
   # /password/{username}	=> 	PUT updates password for a specific user by name
   # /login/ 				=> 	POST validates user name and password
*/
func main() {

	// subcribe to SIGINT OR SIGKILL
	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, os.Interrupt, os.Kill)

	// set up mux handler for route(s)
	mux := mux.NewRouter()
	mux.HandleFunc("/users/", usersHandler)
	mux.HandleFunc("/users/{username}", userHandler)
	mux.HandleFunc("/email/{username}", emailHandler)
	mux.HandleFunc("/password/{username}", passwordHandler)
	mux.HandleFunc("/login/", loginHandler)

	// configure and launch http server
	fmt.Printf("\n>> Server listening on [%d]", port)
	fmt.Printf("\n>> Press <Ctr-C> to quit...\n")
	srv := &http.Server{Addr: url, Handler: mux}
	go func() {
		srv.ListenAndServe()
	}()

	// wait for SIGINT OR SIGKILL
	<-stopChan
	fmt.Println("\n>> Server shutting down...")

	// shut down server in a graceful fashion
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	fmt.Println(">> Server stopped!")
	fmt.Println("")
}

func userHandler(w http.ResponseWriter, r *http.Request) {

	guid, _ := guid()
	writeResponseHeaders(w)

	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)

	switch r.Method {

	case "GET":

		// Get the name from the url: /users/{username}
		userName, ok := mux.Vars(r)["username"]

		// Check that the parameter passed is valid
		if ok == false {
			err := errors.New("Username is invalid or missing")
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// Get the user with the specified name
		result, err := user.GetUser(userName)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// OK so return the JSON user object to the caller
		fmt.Printf("\t[%v]\t%s\n", guid, "Request succesful")
		fmt.Fprint(w, result)

	default:
		fmt.Printf("\t[%v]\tERROR [405 method not allowed]\n", guid)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {

	guid, _ := guid()
	writeResponseHeaders(w)

	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)

	switch r.Method {

	case "GET":

		// Get all the available users
		result, err := user.GetUsers()
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err[0].Error())
			http.Error(w, err[0].Error(), http.StatusNotFound)
			return
		}

		// OK so return the JSON user object to the caller
		fmt.Printf("\t[%v]\t%s\n", guid, "Request succesful")
		fmt.Fprint(w, result)

	case "POST":
		newUser := &user.User{}
		defer r.Body.Close()

		// Attempt to decode the incoming data
		err := json.NewDecoder(r.Body).Decode(newUser)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Validate the incoming data according to the rules
		validErrs := newUser.Validate()
		if len(validErrs) > 0 {
			err := map[string]interface{}{"Error": validErrs}
			result, _ := json.MarshalIndent(err, "", " ")
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, string(result))
			http.Error(w, string(result), http.StatusBadRequest)
			return
		}

		// // Check if user already exists with the specified name
		exists := user.Exists(newUser.Name)
		if exists != 0 {
			err := errors.New("User: " + newUser.Name + " already exists")
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		// Proceed to save this user
		result, err := user.NewUser(newUser.Name, newUser.Password, newUser.Email)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// OK so return the JSON user object to the caller
		fmt.Printf("\t[%v]\t%s\n", guid, "Request succesful")
		fmt.Fprint(w, result)

	default:
		fmt.Printf("\t[%v]\tERROR [405 method not allowed]\n", guid)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func emailHandler(w http.ResponseWriter, r *http.Request) {

	guid, _ := guid()
	writeResponseHeaders(w)

	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)

	switch r.Method {

	case "PUT":
		newUser := &user.User{}
		defer r.Body.Close()

		// Get the name from the url: /email/{username}
		userName, ok := mux.Vars(r)["username"]

		// Check that the parameter passed is valid
		if ok == false {
			err := errors.New("Username is invalid or missing")
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// Attempt to decode the incoming data
		err := json.NewDecoder(r.Body).Decode(newUser)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Validate the incoming data according to the rules
		validErrs := newUser.ValidateEmail()
		if len(validErrs) > 0 {
			err := map[string]interface{}{"Error": validErrs}
			result, _ := json.MarshalIndent(err, "", " ")
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, string(result))
			http.Error(w, string(result), http.StatusBadRequest)
			return
		}

		// Proceed to update email address for this user
		result, err := user.ChangeEmail(userName, newUser.Email)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// OK so return the JSON user object to the caller
		fmt.Printf("\t[%v]\t%s\n", guid, "Request succesful")
		fmt.Fprint(w, result)

	default:
		fmt.Printf("\t[%v]\tERROR [405 method not allowed]\n", guid)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func passwordHandler(w http.ResponseWriter, r *http.Request) {

	guid, _ := guid()
	writeResponseHeaders(w)

	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)

	switch r.Method {

	case "PUT":
		newUser := &user.User{}
		defer r.Body.Close()

		// Get the name from the url: /password/{username}
		userName, ok := mux.Vars(r)["username"]

		// Check that the parameter passed is valid
		if ok == false {
			err := errors.New("Username is invalid or missing")
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// Attempt to decode the incoming data
		err := json.NewDecoder(r.Body).Decode(newUser)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Validate the incoming data according to the rules
		validErrs := newUser.ValidatePassword()
		if len(validErrs) > 0 {
			err := map[string]interface{}{"Error": validErrs}
			result, _ := json.MarshalIndent(err, "", " ")
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, string(result))
			http.Error(w, string(result), http.StatusBadRequest)
			return
		}

		// Proceed to update password for this user
		result, err := user.ChangePassword(userName, newUser.Password)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// OK so return the JSON user object to the caller
		fmt.Printf("\t[%v]\t%s\n", guid, "Request succesful")
		fmt.Fprint(w, result)

	default:
		fmt.Printf("\t[%v]\tERROR [405 method not allowed]\n", guid)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	guid, _ := guid()
	writeResponseHeaders(w)

	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)

	switch r.Method {

	case "POST":
		newUser := &user.User{}
		defer r.Body.Close()

		// Attempt to decode the incoming data
		err := json.NewDecoder(r.Body).Decode(newUser)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Validate the incoming data according to the rules
		validErrs := newUser.ValidateCredentials()
		if len(validErrs) > 0 {
			err := map[string]interface{}{"Error": validErrs}
			result, _ := json.MarshalIndent(err, "", " ")
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, string(result))
			http.Error(w, string(result), http.StatusBadRequest)
			return
		}

		// Attempt to login using the suplied credentials
		err = user.Login(newUser.Name, newUser.Password)
		if err != nil {
			fmt.Printf("\t[%v]\tERROR [%s]\n", guid, err.Error())
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// OK return success to the caller
		fmt.Printf("\t[%v]\t%s\n", guid, "Request succesful")

	default:
		fmt.Printf("\t[%v]\tERROR [405 method not allowed]\n", guid)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func writeResponseHeaders(w http.ResponseWriter) {

	w.Header().Set("Content-type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Transfer-Encoding", "base64")
}
func guid() (r string, e error) {

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), err
}
