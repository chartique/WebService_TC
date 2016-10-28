package main

import (
	"log"
	"net/http"
	"io"
	"encoding/json"
	"fmt"
	"database/sql"
	"math/rand"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"time"
	"strings"
	"regexp"
	"strconv"
	"github.com/stianeikeland/go-rpio"
	"sync"
	"os"
	"bufio"
)

const (
	DEVICE string = "28-0316458ce4ff"
	ON bool = true
	OFF bool = false
)

var STATUS bool
var MAXTEMP float64 = -273

func main() {
	go setTemp()
	go func() {
		time.Sleep(5 * time.Second)
		fmt.Println("Posting auth...")

		p := map[string]string{
			"username": "admin",
			"password": "admin",
		}
		post, err := json.Marshal(p)
		if err != nil {
			log.Printf("failed test 101: %v\n", err)
		}
		resp, err := http.Post("http://localhost:8080/api/auth", "json/application", strings.NewReader(string(post)))
		if err != nil {
			log.Printf("failed test 102: %v\n", err)
		}

		b := make([]byte, resp.ContentLength)
		resp.Body.Read(b)
		var key map[string]string
		err = json.Unmarshal(b, &key)
		if err != nil {
			log.Printf("failed test 103: %v\n", err)
		}

		fmt.Printf("Resp: %s\n", key["SECRETKEY"])

		p2 := map[string]interface{}{
			"secretkey": key["SECRETKEY"],
			"datetime": time.Now().Unix(),
			"temperature": 23,
			"starttime": time.Now().Unix(),
			"duration": time.Duration(2 * time.Hour),
		}
		post2, err := json.Marshal(p2)
		if err != nil {
			log.Printf("failed test 104: %v\n", err)
		}
		resp2, err := http.Post("http://localhost:8080/api/auth", "json/application", strings.NewReader(string(post2)))
		if err != nil {
			log.Printf("failed test 105: %v\n", err)
		}

		b2 := make([]byte, resp2.ContentLength)
		resp.Body.Read(b2)

		fmt.Printf("Resp: %s\n", string(b2))


	}()

	http.Handle("/api/v1", http.HandlerFunc(incomingTraffic))
	http.Handle("/api/auth", http.HandlerFunc(authenticate))
	log.Println(http.ListenAndServe(":8080", nil))
}


func incomingTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Read incoming bytes
		inc := make([]byte, r.ContentLength)
		_, err := r.Body.Read(inc)
		if err != nil && err != io.EOF {
			log.Printf("error 201: %v\n", err)
		}

		js := make(map[string]interface{})

		err = json.Unmarshal(inc, &js)
		if err != nil {
			log.Printf("error 202: %v\n", err)
		}

		if isValidKey(js["secretkey"].(string)) {
			MAXTEMP = js["temperature"].(string)
		}
	}
}


func authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Read incoming bytes
		inc := make([]byte, r.ContentLength)
		_, err := r.Body.Read(inc)
		if err != nil && err != io.EOF {
			log.Printf("error 101: %v\n", err)
		}

		js := make(map[string]interface{})

		err = json.Unmarshal(inc, &js)
		if err != nil {
			log.Printf("error 102: %v\n", err)
		}

		if checkCredentials(js["username"].(string), js["password"].(string)) {
			if userHasValidKey(js["username"].(string)) {
				data := map[string]string{"SECRETKEY": extractValidKey(js["username"].(string))}
				res, err := json.Marshal(data)
				if err != nil {
					log.Printf("error 103: %v\n", err)
				}
				fmt.Fprint(w, string(res))
			} else {
				key := generateKey(js["username"].(string))
				insertKey(js["username"].(string), key)

				data := map[string]string{"SECRETKEY": key}
				res, err := json.Marshal(data)
				if err != nil {
					log.Printf("error 104: %v\n", err)
				}
				fmt.Fprint(w, string(res))
			}
		}
	}
}


func checkCredentials(user, pw string) bool {
	db, err := sql.Open("postgres", "user=postgres password=raspberry dbname=home host=192.168.1.99 port=5432")
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	var pw2 string
	db.QueryRow("SELECT password FROM live.user WHERE username=$1", user).Scan(&pw2)

	if err := bcrypt.CompareHashAndPassword([]byte(pw2), []byte(pw)); err != nil {
		log.Printf("error 201: %v\n", err)
		return false
	}
	return true
}


func generateKey(user string) string {
	length := 64
	can := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$^&-=+")
	rand.Seed(time.Now().UnixNano())
	r := make([]rune, length)
	for i := range r {
		r[i] = can[rand.Intn(len(can))]
	}
	return string(r)
}


func insertKey(user, key string) {
	db, err := sql.Open("postgres", "user=postgres password=raspberry dbname=home host=192.168.1.99 port=5432")
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO live.user_key(user_id, secretkey, duration) VALUES((SELECT id FROM live.user WHERE username=$1), $2, $3)",
		user, key, int64(time.Duration(24*time.Hour)))
	if err != nil {
		fmt.Printf("couldn't execute command: %v\n", err)
	}
}


func userHasValidKey(user string) bool {
	db, err := sql.Open("postgres", "user=postgres password=raspberry dbname=home host=192.168.1.99 port=5432")
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	var crdt string
	var dur int64
	err = db.QueryRow("SELECT create_dt, duration FROM live.user_key WHERE user_id=(SELECT id from live.user WHERE username=$1) ORDER BY create_dt DESC", user).Scan(&crdt, &dur)
	if err != nil {
		return false
	}

	t2, err := time.Parse("2006-01-02T15:04:05.999Z", crdt)
	if err != nil {
		return false
	}
	if time.Now().UnixNano()-t2.UnixNano() > int64(time.Duration(24*time.Hour)) {
		return false
	}

	return true
}


func extractValidKey(user string) string {
	db, err := sql.Open("postgres", "user=postgres password=raspberry dbname=home host=192.168.1.99 port=5432")
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	var key string
	err = db.QueryRow("SELECT secretkey FROM live.user_key WHERE user_id=(SELECT id from live.user WHERE username=$1)", user).Scan(&key)
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	return key
}


func isValidKey(key string) bool {
	db, err := sql.Open("postgres", "user=postgres password=raspberry dbname=home host=192.168.1.99 port=5432")
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	var crdt string
	var dur int64
	err = db.QueryRow("SELECT create_dt, duration FROM live.user_key WHERE secretkey=$1", key).Scan(&crdt, &dur)
	if err != nil {
		return false
	}

	t2, err := time.Parse("2006-01-02T15:04:05.999Z", crdt)
	if err != nil {
		return false
	}
	if time.Now().UnixNano()-t2.UnixNano() > int64(time.Duration(24*time.Hour)) {
		return false
	}

	return true
}

func setTemp() {
	for {
		c, err := getTemp(DEVICE)
		if err != nil {
			log.Printf("setTemp error 1: ", err)
		}
		if c <= MAXTEMP {
			setStatus(ON)
		} else {
			setStatus(OFF)
		}
		log.Printf("Max Temp: %f, Current Temp: %f", MAXTEMP, c)
		time.Sleep(30 * time.Second)
	}
}

func getTemp(dev string) (float64, error) {
	mtx := &sync.Mutex{}
	f := fmt.Sprintf("/sys/bus/w1/devices/%s/w1_slave", dev)
	mtx.Lock()
	defer mtx.Unlock()
	fio, err := os.Open(f)
	if err != nil {
		return -1, err
	}
	defer fio.Close()
	bio := bufio.NewReader(fio)

	bts, err := bio.Peek(1000)
	if err != nil && err != io.EOF {
		return -2, err
	}

	re := regexp.MustCompile("t=[0-9]+").FindString(string(bts))
	t, err := strconv.Atoi(strings.TrimPrefix(re, "t="))
	if err != nil {
		return -3, err
	}
	return float64(t)/1000, nil
}

func setStatus(s bool) {
	err := rpio.Open()
	if err != nil {
		log.Printf("handleSwitch err1: %v\n", err)
	}
	defer rpio.Close()

	if STATUS && s == OFF {
		pin := rpio.Pin(17)
		pin.Output()
		pin.Toggle()
		STATUS = OFF
	} else if !STATUS && s == ON {
		pin := rpio.Pin(17)
		pin.Output()
		pin.Toggle()
		STATUS = ON
	} else if STATUS && s == ON {
		STATUS = ON
	} else {
		STATUS = OFF
	}
}