package service

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	logging "github.com/op/go-logging"
)

var unsafeClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// Wrapper for logger.Debugf during TCP access key searches.
func debugManager(template string, val ...interface{}) {
	// This is an optimization to reduce unnecessary allocations due to an interaction
	// between Go's inlining/escape analysis and varargs functions like logger.Debugf.
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf(fmt.Sprintf("manager debug: %s", template), val)
	}
}

// default manager for outline-ss-server
var manager *Manager = NewManager()

func init() {
	// for check
	flag.Bool("build", false, "By John Xiong")
}

// SaveUser is for saving status to json file
type SaveUser struct {
	Enabled   bool      `json:"enabled"`
	Deadline  time.Time `json:"deadline"`
	DataLimit int       `json:"data_limit"`
}

// User is ...
type User struct {
	sync.Mutex   `json:"_,omitempty"`
	ID           string    `json:"id"`
	EnabledFlag  bool      `json:"enabled"`
	IP           net.IP    `json:"ip"`
	LastUsed     time.Time `json:"-,omitempty"`
	OnlineStatus bool      `json:"online,omitempty"`
	Deadline     time.Time `json:"-,omitempty"`
	DaysLeft     int       `json:"days_left,omitempty"`
	DataLimit    int       `json:"limit,omitempty"`
}

// UpdateIP is ...
func (e *User) UpdateIP(ip net.IP) {
	e.Lock()
	e.IP = ip
	e.LastUsed = time.Now()
	e.Unlock()
}

// UpdateTime is ...
func (e *User) UpdateTime() {
	e.Lock()
	e.LastUsed = time.Now()
	e.Unlock()
}

// SetDeadline is ...
func (e *User) SetDeadline(t time.Time) {
	e.Lock()
	e.Deadline = t
	e.Unlock()
}

// SetDataLimit is ...
func (e *User) SetDataLimit(n int) {
	e.Lock()
	e.DataLimit = n
	e.Unlock()
}

// Enabled is ...
func (e *User) Enabled() (ok bool) {
	e.Lock()
	ok = e.EnabledFlag
	e.Unlock()
	return
}

// Enable is ...
func (e *User) Enable() {
	e.Lock()
	e.EnabledFlag = true
	e.Unlock()
}

// Disable is ...
func (e *User) Disable() {
	e.Lock()
	e.EnabledFlag = false
	e.Unlock()
}

// GetUsage is ...
// read data transferred by shadowsocks from shadowbox
func GetUsage(url string) (map[string]uint64, error) {
	req, err := http.NewRequest(http.MethodGet, url+"/metrics/transfer", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		return nil, errors.New("status code error, code: " + strconv.Itoa(r.StatusCode))
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	type BytesTransferred struct {
		ByUserID map[string]uint64 `json:"bytesTransferredByUserId"`
	}

	used := BytesTransferred{ByUserID: make(map[string]uint64)}
	if err := json.Unmarshal(b, &used); err != nil {
		return nil, err
	}

	return used.ByUserID, nil
}

// Manager for managing multiple users on outline-ss-server
// limiting connected ip for keys
// recoding last used ip
// display key online status
type Manager struct {
	sync.Mutex
	server   http.Server
	users    map[string]*User
	filePath string
	url      string
}

// NewManager is ....
func NewManager() *Manager {
	dir := os.Getenv("SB_STATE_DIR")
	if dir == "" {
		dir = "/opt/outline/persisted-state/outline-go-manager.json"
	} else {
		dir = filepath.Join(dir, "outline-go-manager.json")
	}

	addr := "127.0.0.1:2020"
	if port := os.Getenv("SB_API_PORT"); port != "" {
		n, _ := strconv.Atoi(port)
		addr = "127.0.0.1:" + strconv.Itoa(n+1)
	}
	prefix := os.Getenv("SB_API_PREFIX")
	prefix = "/" + prefix + "/go/manager"

	mux := http.NewServeMux()
	m := &Manager{
		server: http.Server{
			Addr:    addr,
			Handler: mux,
		},
		users:    make(map[string]*User),
		filePath: dir,
		url:      "https://127.0.0.1:" + os.Getenv("SB_API_PORT") + "/" + os.Getenv("SB_API_PREFIX"),
	}
	mux.Handle(prefix, http.Handler(m))

	go func(s *http.Server) {
		if err := s.ListenAndServe(); err != nil {
			debugManager("listen server error: %v", err)
		}
	}(&m.server)

	go m.checkLoop()

	m.ReadFromFile(m.filePath)
	return m
}

func (l *Manager) checkLoop() {
	t := time.NewTicker(time.Minute * 5)
	defer t.Stop()
	for {
		now := time.Now()
		usage, err := GetUsage(l.url)
		if err != nil {
			debugManager("get usage error: %v", err)
			l.Lock()
			for _, user := range l.users {
				if now.After(user.Deadline) {
					user.Disable()
				}
			}
			l.Unlock()
			l.SaveToFile(l.filePath)
			<-t.C
			continue
		}
		l.Lock()
		for _, user := range l.users {
			if now.After(user.Deadline) {
				user.Disable()
			}
			if num, ok := usage[user.ID]; ok {
				if num > (uint64(user.DataLimit) << 30) {
					user.Disable()
				}
			}
		}
		l.Unlock()
		l.SaveToFile(l.filePath)
		<-t.C
	}
}

// SaveToFile is ...
func (l *Manager) SaveToFile(name string) {
	deadlines := make(map[string]SaveUser)
	l.Lock()
	for id, user := range l.users {
		deadlines[id] = SaveUser{
			Enabled:   user.EnabledFlag,
			Deadline:  user.Deadline,
			DataLimit: user.DataLimit,
		}
	}
	l.Unlock()
	b, err := json.Marshal(deadlines)
	if err != nil {
		debugManager("marshal deadlines error: %v", err)
		return
	}
	if err := ioutil.WriteFile(name, b, 0644); err != nil {
		debugManager("write file error: %v", err)
	}
}

// ReadFromFile is ...
func (l *Manager) ReadFromFile(name string) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		debugManager("read file error: %v", err)
		return
	}

	users := make(map[string]SaveUser)
	if err := json.Unmarshal(b, &users); err != nil {
		debugManager("unmarshal users error: %v", err)
		return
	}

	l.Lock()
	for id, user := range users {
		e, ok := l.users[id]
		if ok {
			e.SetDeadline(user.Deadline)
			if user.Enabled {
				e.Enable()
			} else {
				e.Disable()
			}
			e.SetDataLimit(user.DataLimit)
			continue
		}
		e = &User{
			ID:          id,
			EnabledFlag: user.Enabled,
			Deadline:    user.Deadline,
			DataLimit:   user.DataLimit,
		}
		l.users[id] = e
	}
	l.Unlock()
}

// get info:      GET    127.0.0.1:2020/go/manager
// switch status: PATCH  127.0.0.1:2020/go/manager?id={id}
// set deadline:  PUT    127.0.0.1:2020/go/manager?id={id}&deadline={days}
// set data limit：POST  127.0.0.1:2020/go/manager?id={id}&limit={GB}
func (l *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// get users list
		l.GetInfo(w)
		return
	case http.MethodPatch:
		// change user status
		id := r.URL.Query().Get("id")
		if id != "" {
			l.ChangeUserStatus(id)
			return
		}
	case http.MethodPut:
		// set deadline
		id := r.URL.Query().Get("id")
		deadline := r.URL.Query().Get("deadline")
		if id != "" && deadline != "" {
			l.SetDeadline(id, deadline)
			return
		}
	case http.MethodPost:
		// set data limit
		id := r.URL.Query().Get("id")
		limit := r.URL.Query().Get("limit")
		if id != "" && limit != "" {
			l.SetDataLimit(id, limit)
			return
		}
	}
	http.HandlerFunc(http.NotFound).ServeHTTP(w, r)
}

// GetInfo is ...
func (l *Manager) GetInfo(w io.Writer) {
	type Status struct {
		Status []*User `json:"status"`
	}

	now := time.Now()
	l.Lock()
	users := make([]*User, 0, len(l.users))
	for _, user := range l.users {
		if now.Sub(user.LastUsed) < time.Minute*5 {
			user.OnlineStatus = true
		} else {
			user.OnlineStatus = false
		}
		if now.After(user.Deadline) {
			user.DaysLeft = 0
		} else {
			user.DaysLeft = int(user.Deadline.Sub(now)/time.Hour/24) + 1
		}
		users = append(users, user)
	}
	l.Unlock()

	b, err := json.Marshal(Status{Status: users})
	if err != nil {
		debugManager("marshal users error: %v", err)
		return
	}
	w.Write(b)
}

// ChangeUserStatus is ...
func (l *Manager) ChangeUserStatus(id string) {
	defer l.SaveToFile(l.filePath)

	if e, ok := l.Get(id); ok {
		if e.Enabled() {
			e.Disable()
		} else {
			e.Enable()
		}
		return
	}
	l.Add(id, nil)
	e, _ := l.Get(id)
	e.Enable()
}

// SetDeadline is ...
func (l *Manager) SetDeadline(id, deadline string) {
	defer l.SaveToFile(l.filePath)

	n, err := strconv.Atoi(deadline)
	if err != nil {
		return
	}
	if e, ok := l.Get(id); ok {
		e.SetDeadline(time.Now().Add(time.Hour * 24 * time.Duration(n)))
		return
	}
	l.Add(id, nil)
	e, _ := l.Get(id)
	e.SetDeadline(time.Now().Add(time.Hour * 24 * time.Duration(n)))
}

// SetDataLimit is ...
func (l *Manager) SetDataLimit(id, num string) {
	defer l.SaveToFile(l.filePath)

	n, err := strconv.Atoi(num)
	if err != nil {
		return
	}
	if e, ok := l.Get(id); ok {
		e.SetDataLimit(n)
		return
	}
	l.Add(id, nil)
	e, _ := l.Get(id)
	e.SetDataLimit(n)
}

// Get is ...
func (l *Manager) Get(id string) (e *User, ok bool) {
	l.Lock()
	e, ok = l.users[id]
	l.Unlock()
	return
}

// Add is ...
func (l *Manager) Add(id string, ip net.IP) {
	l.Lock()
	if ip == nil {
		l.users[id] = &User{ID: id, EnabledFlag: true}
	} else {
		l.users[id] = &User{ID: id, EnabledFlag: true, IP: ip, LastUsed: time.Now()}
	}
	l.Unlock()
}

// CheckIP is ..
func (l *Manager) CheckIP(ip net.IP, id string) bool {
	e, ok := l.Get(id)
	if !ok {
		l.Add(id, ip)
		return true
	}
	if !e.Enabled() {
		return false
	}
	if ip.Equal(e.IP) {
		e.UpdateTime()
		return true
	}
	if time.Now().Sub(e.LastUsed) > 10*time.Second {
		e.UpdateIP(ip)
		return true
	}
	return false
}
