/* Package user is a thread-safe high level library that abstracts reading and writing users in REDIS.

Author: Anthony Caruana

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY,FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package user

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/mediocregopher/radix.v2/pool"
	"github.com/mediocregopher/radix.v2/util"
	"golang.org/x/crypto/pbkdf2"
)

var (
	// dbPool : Declare a global db variable to store the REDIS connection pool.
	dbPool *pool.Pool
)

const (
	userDatabaseID   = 0
	maxPoolSize      = 10
	pbkdf2Iterations = 4096
)

func init() {
	dbPool, _ = pool.New("tcp", "127.0.0.1:6379", maxPoolSize)
}

// User : In memory representation of a user object
type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email" validate:"email"`
	Password string `json:"password"`
	Salt     string `json:"salt"`
}

// Validate : Checks the user object has valid data
func (user *User) Validate() url.Values {

	errs := url.Values{}

	if len(strings.TrimSpace(user.Name)) == 0 {
		errs.Add("Name", "The name field is required")
	}

	if len(user.Password) < 8 || len(user.Password) > 12 {
		errs.Add("Password", "The password field must be between 8-12 chars")
	}

	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if len(strings.TrimSpace(user.Email)) == 0 || !re.MatchString(user.Email) {
		errs.Add("Email", "The email field is invalid or missing")
	}

	return errs
}

// ValidateEmail : Checks the user email has valid data
func (user *User) ValidateEmail() url.Values {

	errs := url.Values{}

	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if len(strings.TrimSpace(user.Email)) == 0 || !re.MatchString(user.Email) {
		errs.Add("Email", "The email field is invalid or missing")
	}

	return errs
}

// ValidatePassword : Checks the user object has valid data
func (user *User) ValidatePassword() url.Values {

	errs := url.Values{}

	if len(user.Password) < 8 || len(user.Password) > 12 {
		errs.Add("Password", "The password field must be between 8-12 chars")
	}

	return errs
}

// ValidateCredentials : Checks the user and password are valid
// Usage: Security check before attempting login
func (user *User) ValidateCredentials() url.Values {

	errs := url.Values{}

	if len(strings.TrimSpace(user.Name)) == 0 {
		errs.Add("Name", "The name field is required")
	}

	if len(user.Password) < 8 || len(user.Password) > 12 {
		errs.Add("Password", "The password field must be between 8-12 chars")
	}

	return errs
}

// Login : Retrieve single user object and validate password
func Login(name, password string) error {

	logonError := errors.New("Invalid User name or password")

	// Get user object from database
	key := "user:" + strings.Title(strings.TrimSpace(strings.ToLower(name)))
	user, err := getUser(key)
	if err != nil {
		return logonError
	}

	// Get the current password + salt
	current, _ := base64.StdEncoding.DecodeString(user.Password)
	salt, _ := base64.StdEncoding.DecodeString(user.Salt)

	// Recalculate the password and comare to original
	new := newHash([]byte(password), salt)
	isValid := compareHash(current, new)
	if isValid == false {
		return logonError
	}

	return nil
}

// GetUser : Retrieve single user object and return in JSON format
func GetUser(name string) (string, error) {

	// Get user object from database
	key := "user:" + strings.Title(strings.TrimSpace(strings.ToLower(name)))
	user, err := getUser(key)

	// Return the JSON to the caller
	result, _ := json.MarshalIndent(user, "", " ")
	return string(result), err
}

// ChangeEmail : Retrieve single user object and change email address
func ChangeEmail(name, email string) (string, error) {

	// Get user object from database
	key := "user:" + strings.Title(strings.TrimSpace(strings.ToLower(name)))
	user, err := getUser(key)

	// Assign values to fields
	user.Email = email

	// Save user object
	err = setUser(user)

	// Return the JSON to the caller
	result, _ := json.MarshalIndent(user, "", " ")
	return string(result), err
}

// ChangePassword : Retrieve single user object and recalculate password
func ChangePassword(name, password string) (string, error) {

	// Get user object from database
	key := "user:" + strings.Title(strings.TrimSpace(strings.ToLower(name)))
	user, err := getUser(key)

	salt := newSalt()
	hash := newHash([]byte(password), salt)

	// Assign values to fields
	user.Password = base64.StdEncoding.EncodeToString(hash)
	user.Salt = base64.StdEncoding.EncodeToString(salt)

	// Save user object
	err = setUser(user)

	// Return the JSON to the caller
	result, _ := json.MarshalIndent(user, "", " ")
	return string(result), err
}

// GetUsers : : Retrieve all user object and return in JSON format
func GetUsers() (string, []error) {

	// Get user object from database
	users, err := getUsers()

	// Return the JSON to the caller
	result, _ := json.MarshalIndent(users, "", " ")
	return string(result), err

}

// NewUser : Creates user object and return in JSON format
func NewUser(name, password, email string) (string, error) {

	// Create user object
	var user = new(User)
	salt := newSalt()
	hash := newHash([]byte(password), salt)

	// Assign values to fields
	user.ID = newID()
	user.Name = strings.Title(strings.TrimSpace(strings.ToLower(name)))
	user.Email = email
	user.Password = base64.StdEncoding.EncodeToString(hash)
	user.Salt = base64.StdEncoding.EncodeToString(salt)

	// Save user object in database
	err := setUser(user)

	// Return JSON to client
	result, _ := json.MarshalIndent(user, "", " ")
	return string(result), err
}

// Exists : Checks to see if user with this name already exists
func Exists(name string) int {

	// Select the correct database
	dbPool.Cmd("SELECT", userDatabaseID)

	// Does this key exist?
	key := "user:" + strings.Title(strings.TrimSpace(strings.ToLower(name)))
	resp := dbPool.Cmd("EXISTS", key)
	exists, _ := resp.Int()
	return exists
}

func getUser(key string) (*User, error) {

	// Select the correct database
	dbPool.Cmd("SELECT", userDatabaseID)

	// Does this key exist?
	resp := dbPool.Cmd("EXISTS", key)
	exists, _ := resp.Int()
	if exists == 0 {
		return nil, errors.New(key + " not found")
	}

	// Retrieve values and create user object
	reply, err := dbPool.Cmd("HGETALL", key).Map()
	if err != nil {
		return nil, err
	}

	var user = new(User)
	user.ID = reply["id"]
	user.Name = reply["name"]
	user.Email = reply["email"]
	user.Password = reply["password"]
	user.Salt = reply["salt"]

	return user, nil
}

func getUsers() ([]*User, []error) {

	var allUsers []*User
	var errors []error

	// Select the correct database
	dbPool.Cmd("SELECT", userDatabaseID)

	// Iterate over all the available keys
	dbPool.Cmd("SELECT", userDatabaseID)
	s := util.NewScanner(dbPool, util.ScanOpts{Command: "SCAN"})
	for s.HasNext() {

		// Get user object from database
		key := s.Next()
		user, err := getUser(key)

		// Check for errors before adding user object to array
		if err != nil {
			errors = append(errors, err)
		} else {
			allUsers = append(allUsers, user)
		}
	}
	return allUsers, errors
}

func setUser(user *User) (err error) {

	// Select the correct database and save user object
	dbPool.Cmd("SELECT", userDatabaseID)
	resp := dbPool.Cmd("HMSET", "user:"+user.Name, "id", user.ID, "name", user.Name, "email", user.Email, "password", user.Password, "salt", user.Salt)
	return resp.Err
}

func newSalt() (salt []byte) {

	// Generate random bytes
	salt = make([]byte, 16)
	rand.Read(salt)
	return salt
}

func newID() (id string) {

	// Generate random bytes
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func newHash(pwd, salt []byte) (hash []byte) {

	// Hash pasword mutiple times with random salt to avoid dictionary attacks
	hash = pbkdf2.Key(pwd, salt, pbkdf2Iterations, 32, sha256.New)
	return hash
}

func compareHash(current, new []byte) (isValid bool) {

	// Validate hashes are identical in constant time
	isValid = sha256.Sum256(current) == sha256.Sum256(new)
	return isValid
}
