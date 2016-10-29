package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
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
