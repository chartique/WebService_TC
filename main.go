package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"

	"bufio"
	"database/sql"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	_ "github.com/lib/pq"
	"github.com/stianeikeland/go-rpio"
	"golang.org/x/crypto/bcrypt"
)

const (
	DEVICE string = "28-0316458ce4ff"
	ON     bool   = true
	OFF    bool   = false
)

var (
	STATUS  bool
	MAXTEMP float64 = -273
)

func main() {
	log.Println("Starting up service...")
	go setTemp()

	http.Handle("/api/v1", http.HandlerFunc(settingTemp))
	http.Handle("/api/v1/cancel", http.HandlerFunc(cancelTemp))
	http.Handle("/api/auth", http.HandlerFunc(authenticate))
	log.Println(http.ListenAndServe("0.0.0.0:80", nil))
}

func setTemp() {
	for {
		err := cleanTempActions()
		if err != nil {
			log.Printf("error 101: %v", err)
		}
		id, err := getCurrentAction()
		if err != nil {
			log.Printf("error 102: %v", err)
		}
		MAXTEMP, err = getSetTemp(id)
		if err != nil {
			log.Printf("error 103: %v", err)
		}

		c, err := getTemp(DEVICE)
		if err != nil {
			log.Printf("error 104: %v", err)
		}

		if c <= MAXTEMP {
			if err := setStatus(ON); err != nil {
				log.Printf("error 105: %v", err)
			}
		} else {
			if err := setStatus(OFF); err != nil {
				log.Printf("error 106: %v", err)
			}
		}
		time.Sleep(3400 * time.Millisecond)
	}
}

func settingTemp(w http.ResponseWriter, r *http.Request) {
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
			js["temperature"].(float64))

		okKey, err := isValidKey(js["secretkey"].(string))
		if err != nil {
			log.Printf("error 203: %v\n", err)
		}

		if okKey {
			data := make(map[string]string)

			ip, err := insertPost(
				js["secretkey"].(string),
				"",
				time.Now().Unix(),
				int64(js["starttime"].(float64)),
				int64(js["duration"].(float64)),
				js["temperature"].(float64),
			)
			if err != nil {
				log.Printf("error 204: %v\n", err)
			}

			if ip {
				data = map[string]string{"status": "ok"}
			} else {
				data = map[string]string{"status": "failed"}
			}
			res, err := json.Marshal(data)
			if err != nil {
				log.Printf("error 205: %v\n", err)
			}

			fmt.Fprint(w, string(res))
		} else {
			fmt.Fprint(w, `{"status":"failed"}`)
		}
	}
}

func authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Read incoming bytes
		inc := make([]byte, r.ContentLength)
		_, err := r.Body.Read(inc)
		if err != nil && err != io.EOF {
			log.Printf("error 301: %v\n", err)
		}

		js := make(map[string]interface{})

		err = json.Unmarshal(inc, &js)
		if err != nil {
			log.Printf("error 302: %v\n", err)
		}

		chkOk, err := checkCredentials(js["username"].(string), js["password"].(string))
		if err != nil {
			log.Printf("error 303: %v\n", err)
		}

		if chkOk {
			okKey, err := userHasValidKey(js["username"].(string))
			if err != nil {
				log.Printf("error 304: %v\n", err)
			}

			if okKey {
				key, err := extractValidKey(js["username"].(string))
				if err != nil {
					log.Printf("error 305: %v\n", err)
				}

				data := map[string]string{"SECRETKEY": key}
				res, err := json.Marshal(data)
				if err != nil {
					log.Printf("error 306: %v\n", err)
				}
				fmt.Fprint(w, string(res))
			} else {
				key := generateKey()
				if err := insertKey(js["username"].(string), key); err != nil {
					log.Printf("error 307: %v\n", err)
				}

				data := map[string]string{"SECRETKEY": key}
				res, err := json.Marshal(data)
				if err != nil {
					log.Printf("error 308: %v\n", err)
				}
				fmt.Fprint(w, string(res))
			}
		}
	}
}

func cancelTemp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Read incoming bytes
		inc := make([]byte, r.ContentLength)
		_, err := r.Body.Read(inc)
		if err != nil && err != io.EOF {
			log.Printf("error 401: %v\n", err)
		}

		js := make(map[string]interface{})

		err = json.Unmarshal(inc, &js)
		if err != nil {
			log.Printf("error 402: %v\n", err)
		}

		log.Println(
			js["secretkey"].(string),
			js["cancel"].(bool),
		)

		okKey, err := isValidKey(js["secretkey"].(string))
		if err != nil {
			log.Printf("error 403: %v\n", err)
		}

		if okKey {
			if js["cancel"].(bool) {
				if err := cancTemp(js["secretkey"].(string)); err != nil {
					log.Printf("error 404: %v\n", err)
				}
			}
			fmt.Fprint(w, `{"status":"ok"}`)
		} else {
			fmt.Fprint(w, `{"status":"failed"}`)
		}
	}
}


func checkCredentials(user, pw string) (bool, error) {
	stmt := `
		SELECT password
		FROM live.user
		WHERE username = $1
	`
	cred, err := getDbCred()
	if err != nil {
		return false, err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return false, err
	}
	defer db.Close()

	var pw2 string
	db.QueryRow(stmt, user).Scan(&pw2)

	if err := bcrypt.CompareHashAndPassword([]byte(pw2), []byte(pw)); err != nil {
		return false, err
	}
	return true, nil
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

func insertKey(user, key string) error {
	stmt := `
		INSERT INTO live.user_key (user_id, secretkey, duration) VALUES ((SELECT id
									  FROM live.user
									  WHERE username = $1), $2, $3)
	`
	cred, err := getDbCred()
	if err != nil {
		return err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(stmt, user, key, int64(time.Duration(24*time.Hour).Seconds()))
	if err != nil {
		return err
	}
	return nil
}

func userHasValidKey(user string) (bool, error) {
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

	cred, err := getDbCred()
	if err != nil {
		return false, err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return false, err
	}
	defer db.Close()

	var crdt string
	var dur int64
	err = db.QueryRow(stmt, user).Scan(&crdt, &dur)
	if err != nil {
		return false, err
	}

	t2, err := time.Parse("2006-01-02T15:04:05.999Z", crdt)
	if err != nil {
		return false, err
	}
	if time.Now().Unix()-t2.Unix() > dur {
		return false, err
	}
	return true, nil
}

func extractValidKey(user string) (string, error) {
	stmt := `
		SELECT secretkey
		FROM live.user_key
		WHERE user_id = (SELECT id
				 FROM live.user
				 WHERE username = $1)
	`

	cred, err := getDbCred()
	if err != nil {
		return "", err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return "", err
	}
	defer db.Close()

	var key string
	err = db.QueryRow(stmt, user).Scan(&key)
	if err != nil {
		return "", err
	}
	return key, nil
}

func isValidKey(key string) (bool, error) {
	stmt := `
		SELECT
		  create_dt,
		  duration
		FROM live.user_key
		WHERE secretkey = $1
	`

	cred, err := getDbCred()
	if err != nil {
		return false, err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return false, err
	}
	defer db.Close()

	var (
		crdt string
		dur  int64
	)
	err = db.QueryRow(stmt, key).Scan(&crdt, &dur)
	if err != nil {
		return false, err
	}

	t2, err := time.Parse("2006-01-02T15:04:05.999Z", crdt)
	if err != nil {
		return false, err
	}
	if time.Now().Unix()-t2.Unix() > dur {
		return false, err
	}
	return true, nil
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

func setStatus(s bool) error {
	err := rpio.Open()
	if err != nil {
		return err
	}
	defer rpio.Close()

	if STATUS && s == OFF {
		pin := rpio.Pin(17)
		pin.Output()
		pin.Toggle()
		STATUS = OFF
		log.Printf("Status set to: %t", STATUS)
	} else if !STATUS && s == ON {
		pin := rpio.Pin(17)
		pin.Output()
		pin.Toggle()
		STATUS = ON
		log.Printf("Status set to: %t", STATUS)
	} else if STATUS && s == ON {
		STATUS = ON
	} else {
		STATUS = OFF
	}
	return nil
}

func getDbCred() (string, error) {
	mtx := &sync.Mutex{}
	f := "/var/pglogin"
	mtx.Lock()
	defer mtx.Unlock()
	fio, err := os.Open(f)
	if err != nil {
		return "", err
	}
	defer fio.Close()
	bio := bufio.NewReader(fio)

	bts, err := bio.Peek(1000)
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(bts), nil
}

func insertPost(key, act string, now, start, dur int64, temp float64) (bool, error) {
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

	cred, err := getDbCred()
	if err != nil {
		return false, err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return false, err
	}
	defer db.Close()

	_, err = db.Exec(stmt, key, temp, now, start, dur, act)
	if err != nil {
		return false, err
	}
	return true, nil
}

func cleanTempActions() error {
	stmt := `
		SELECT
		  id,
		  starttime,
		  duration
		FROM live.temperature_actions
	`

	upd := `
		UPDATE live.temperature_actions
		    SET inactive = 'Y'
		    WHERE id = $1
	`

	cred, err := getDbCred()
	if err != nil {
		return err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query(stmt)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id        int64
			starttime int64
			duration  int64
		)

		if err := rows.Scan(&id, &starttime, &duration); err != nil {
			return err
		}

		if time.Now().Unix() > starttime+duration {
			_, err = db.Exec(upd, id)
			if err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}

func getCurrentAction() (int64, error) {
	stmt := `
		SELECT
		  id,
		  unixtime,
		  starttime,
		  duration
		FROM live.temperature_actions
		WHERE inactive != 'Y'
	`

	cred, err := getDbCred()
	if err != nil {
		return -1, err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return -1, err
	}
	defer db.Close()

	rows, err := db.Query(stmt)
	if err != nil {
		return -1, err
	}
	defer rows.Close()

	var (
		lastUpd int64
		lastId  int64
	)
	for rows.Next() {
		var (
			id        int64
			unixtime  int64
			starttime int64
			duration  int64
		)

		if err := rows.Scan(&id, &unixtime, &starttime, &duration); err != nil {
			return -1, err
		}

		t := time.Now().Unix()
		if t < starttime+duration && t >= starttime {
			if unixtime > lastUpd {
				lastUpd = unixtime
				lastId = id
			}
		}
	}
	if err := rows.Err(); err != nil {
		return -1, err
	}
	return lastId, nil
}

func getSetTemp(id int64) (float64, error) {
	stmt := `
		SELECT
		  temperature
		FROM live.temperature_actions
		WHERE id=$1
	`
	var temperature float64

	if id == 0 {
		return -273, nil
	}

	cred, err := getDbCred()
	if err != nil {
		return -273, err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return -273, err
	}
	defer db.Close()
	err = db.QueryRow(stmt, id).Scan(&temperature)

	if err != nil {
		return -273, err
	}
	return temperature, nil
}

func cancTemp(key string) error {
	stmt := `
		UPDATE live.temperature_actions
		    SET inactive = 'Y'
		    WHERE secretkey = $1
	`

	cred, err := getDbCred()
	if err != nil {
		return err
	}
	db, err := sql.Open("postgres", cred)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(stmt, key)
	if err != nil {
		return err
	}
	return nil
}
