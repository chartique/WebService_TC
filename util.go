package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stianeikeland/go-rpio"
	"golang.org/x/crypto/bcrypt"
)

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
