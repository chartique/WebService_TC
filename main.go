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

var (
	STATUS bool
	MAXTEMP float64 = -273
	STARTTIME int64
	ENDTIME int64
)

func main() {
	log.Println("Starting up service...")
	go setTemp()

	http.Handle("/api/v1", http.HandlerFunc(incomingTraffic))
	http.Handle("/api/auth", http.HandlerFunc(authenticate))
	log.Println(http.ListenAndServe("0.0.0.0:80", nil))
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

		log.Println(
			js["secretkey"].(string),
			"",
			time.Now().Unix(),
			int64(js["starttime"].(float64)),
			int64(js["duration"].(float64)),
			js["temperature"].(float64),)

		if isValidKey(js["secretkey"].(string)) {
			data := make(map[string]string)
			if insertPost(
				js["secretkey"].(string),
				"",
				time.Now().Unix(),
				int64(js["starttime"].(float64)),
				int64(js["duration"].(float64)),
				js["temperature"].(float64),
			) {
				data = map[string]string{"status": "ok"}
			} else {
				data = map[string]string{"status": "failed"}
			}
			res, err := json.Marshal(data)
			if err != nil {
				log.Printf("error 104: %v\n", err)
			}

			fmt.Fprint(w, string(res))
		} else {
			fmt.Fprint(w, `{"status": "failed"}`)
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
				key := generateKey()
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
	db, err := sql.Open("postgres", getDbCred())
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

func generateKey() string {
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
	stmt := `
		INSERT INTO live.user_key (user_id, secretkey, duration) VALUES ((SELECT id
									  FROM live.user
									  WHERE username = $1), $2, $3)
	`

	db, err := sql.Open("postgres", getDbCred())
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	_, err = db.Exec(stmt, user, key, int64(time.Duration(24 * time.Hour).Seconds()))
	if err != nil {
		fmt.Printf("couldn't execute command: %v\n", err)
	}
}

func userHasValidKey(user string) bool {
	stmt := `
		SELECT
		  create_dt,
		  duration
		FROM live.user_key
		WHERE user_id = (SELECT id
				 FROM live.user
				 WHERE username = $1)
		ORDER BY create_dt DESC
	`

	db, err := sql.Open("postgres", getDbCred())
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	var crdt string
	var dur int64
	err = db.QueryRow(stmt, user).Scan(&crdt, &dur)
	if err != nil {
		return false
	}

	t2, err := time.Parse("2006-01-02T15:04:05.999Z", crdt)
	if err != nil {
		return false
	}
	if time.Now().Unix() - t2.Unix() > dur {
		return false
	}
	return true
}

func extractValidKey(user string) string {
	stmt := `
		SELECT secretkey
		FROM live.user_key
		WHERE user_id = (SELECT id
				 FROM live.user
				 WHERE username = $1)
	`
	db, err := sql.Open("postgres", getDbCred())
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	var key string
	err = db.QueryRow(stmt, user).Scan(&key)
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	return key
}

func isValidKey(key string) bool {
	stmt := `
		SELECT
		  create_dt,
		  duration
		FROM live.user_key
		WHERE secretkey = $1
	`
	db, err := sql.Open("postgres", getDbCred())
	if err != nil {
		log.Printf("couldn't establish connection: %v\n", err)
	}
	defer db.Close()

	var crdt string
	var dur int64
	err = db.QueryRow(stmt, key).Scan(&crdt, &dur)
	if err != nil {
		return false
	}

	t2, err := time.Parse("2006-01-02T15:04:05.999Z", crdt)
	if err != nil {
		return false
	}
	if time.Now().Unix() - t2.Unix() > dur {
		return false
	}

	return true
}

func setTemp() {
	for {
		t := time.Now().Unix()
		if t >= STARTTIME && t <= ENDTIME {
			c, err := getTemp(DEVICE)
			if err != nil {
				log.Printf("setTemp error 1: %v", err)
			}
			if c <= MAXTEMP {
				setStatus(ON)
			} else {
				setStatus(OFF)
			}
			log.Printf("Max Temp: %f, Current Temp: %f", MAXTEMP, c)
			time.Sleep(1 * time.Second)
		} else {
			setStatus(OFF)
			time.Sleep(1 * time.Second)
		}
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
	return float64(t) / 1000, nil
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

func getDbCred() string {
	mtx := &sync.Mutex{}
	f := "/var/pglogin"
	mtx.Lock()
	defer mtx.Unlock()
	fio, err := os.Open(f)
	if err != nil {
		log.Printf("dbcred 1: %v\n", err)
	}
	defer fio.Close()
	bio := bufio.NewReader(fio)

	bts, err := bio.Peek(1000)
	if err != nil && err != io.EOF {
		log.Printf("dbcred 2: %v\n", err)
	}
	return string(bts)
}

func insertPost(key, act string, now, start, dur int64, temp float64) bool {
	stmt := `
		INSERT INTO live.temperature_actions (
		  secretkey,
		  temperature,
		  unixtime,
		  starttime,
		  duration,
		  inactive
		)
		VALUES (
		  $1, $2, $3, $4, $5, $6
		)
	`

	db, err := sql.Open("postgres", getDbCred())
	if err != nil {
		log.Printf("insertPost err1: %v\n", err)
		return false
	}
	defer db.Close()

	_, err = db.Exec(stmt, key, temp, now, start, dur, act)
	if err != nil {
		fmt.Printf("insertPost err2: %v\n", err)
		return false
	}
	return true
}