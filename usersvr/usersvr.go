/* Package main is a JSON based HTTP ReST API that provides methods for managing users.

Author: Anthony Caruana

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY,FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"lynx/user"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type ipRange struct {
	start net.IP
	end   net.IP
}

var (
	url  = "0.0.0.0:50001"
	port = 50001
)

/* The following routes and methods are supported:
   # /users/                =>  GET retreives all users
   # /users/                =>  POST adds a specific user by name
   # /users/{username}      =>  sGET retreives a specific user by name
   # /email/{username}      =>  PUT updates email for a specific user by name
   # /password/{username}   =>  PUT updates password for a specific user by name
   # /login/                =>  POST validates user name and password
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

	fmt.Printf("\n>> Server listening on [%d]", port)
	fmt.Printf("\n>> Press <Ctr-C> to quit...\n")

	// configure timeouts, url + port and default router
	srv := &http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         url,
		Handler:      mux,
	}

	// launch http server
	go func() {
		srv.ListenAndServe()
	}()

	// wait for SIGINT OR SIGKILL
	<-stopChan
	fmt.Println("\n>> Server shutting down...")

	// shut down server gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cancel()
	srv.Shutdown(ctx)
	fmt.Println(">> Server stopped!")
	fmt.Println("")
}

func userHandler(w http.ResponseWriter, r *http.Request) {

	// Create request Trace ID and write common response headers
	guid, _ := guid()
	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)
	writeResponseHeaders(w)

	// Check for HMAC Authentication token
	if checkAuthorization(r) == false {
		fmt.Printf("\t[%v]\tERROR [%s]\n", guid, r.RemoteAddr+" => "+http.StatusText(http.StatusUnauthorized))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

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

	// Create request Trace ID and write common response headers
	guid, _ := guid()
	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)
	writeResponseHeaders(w)

	// Check for HMAC Authentication token
	if checkAuthorization(r) == false {
		fmt.Printf("\t[%v]\tERROR [%s]\n", guid, r.RemoteAddr+" => "+http.StatusText(http.StatusUnauthorized))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

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

	// Create request Trace ID and write common response headers
	guid, _ := guid()
	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)
	writeResponseHeaders(w)

	// Check for HMAC Authentication token
	if checkAuthorization(r) == false {
		fmt.Printf("\t[%v]\tERROR [%s]\n", guid, r.RemoteAddr+" => "+http.StatusText(http.StatusUnauthorized))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

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

	// Create request Trace ID and write common response headers
	guid, _ := guid()
	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)
	writeResponseHeaders(w)

	// Check for HMAC Authentication token
	if checkAuthorization(r) == false {
		fmt.Printf("\t[%v]\tERROR [%s]\n", guid, r.RemoteAddr+" => "+http.StatusText(http.StatusUnauthorized))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

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

	// Create request Trace ID and write common response headers
	guid, _ := guid()
	fmt.Printf("\n\t[%v]\tReceieved %s request...\n", guid, r.Method)
	writeResponseHeaders(w)

	// Check for HMAC Authentication token
	if checkAuthorization(r) == false {
		fmt.Printf("\t[%v]\tERROR [%s]\n", guid, r.RemoteAddr+" => "+http.StatusText(http.StatusUnauthorized))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

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

func checkAuthorization(r *http.Request) bool {

	// If we are NOT local we MUST have an Authorization header present
	if isLocal(r) == false && len(r.Header.Get("Authorization")) == 0 {
		return false
	}

	// If the  Authorization header present	it MUST be valid
	return true
}

func isLocal(r *http.Request) bool {

	// Check to see if request was forwarded via a proxy or load balancer
	// Otherwise just use the rmeote ip address from the request object
	remoteAddr := getForwardedAddress(r)
	if len(remoteAddr) == 0 {
		ip, _, err := parseIP(r.RemoteAddr)
		if len(ip) == 0 || err != nil {
			return false
		}
		remoteAddr = ip
	}

	if remoteAddr == "127.0.0.1" || remoteAddr == "::1" {
		return true
	}

	return false
}

func parseIP(s string) (ip string, port string, err error) {

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", errors.New("Invalid IP")
	}

	ipv4 := net.ParseIP(host)
	if ipv4 == nil {
		return "", "", errors.New("Invalid IP")
	}

	return ipv4.String(), port, nil
}

func getForwardedAddress(r *http.Request) string {

	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}
			return ip
		}
	}
	return ""
}

func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

var privateRanges = []ipRange{
	ipRange{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	ipRange{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	ipRange{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	ipRange{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	ipRange{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	ipRange{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}
