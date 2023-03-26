package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
)

type EgaugeUnauthorizedResponse struct {
	Rlm   string `json:"rlm"`
	Nnc   string `json:"nnc"`
	Error string `json:"error"`
}

type EgaugeJWTResponse struct {
	Jwt    string   `json:"jwt"`
	Rights []string `json:"rights"`
}

func ReadEgaugeData(egaugeJwT string, deviceName string) (string, error) {
	url := fmt.Sprintf("https://%s.d.egauge.net/api/register", deviceName)

	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", egaugeJwT))
	query := req.URL.Query()
	query.Add("time", "now")
	query.Add("rate", "")
	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func EgaugeLogin(deviceName string, usr string, pwd string) (string, error) {
	url := fmt.Sprintf("https://%s.d.egauge.net/api/auth/unauthorized", deviceName)
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	fmt.Println(string(body))

	unauthorizedResponse := EgaugeUnauthorizedResponse{}
	err = json.Unmarshal(body, &unauthorizedResponse)
	if err != nil {
		return "", err
	}

	rlm := unauthorizedResponse.Rlm
	nnc := unauthorizedResponse.Nnc
	cnnc := strconv.Itoa(rand.Intn(999999999))

	HA1 := fmt.Sprintf("%x", md5.Sum([]byte(usr+":"+rlm+":"+pwd)))
	HA2 := fmt.Sprintf("%x", md5.Sum([]byte(HA1+":"+nnc+":"+cnnc)))

	loginBody := map[string]string{
		"rlm":  rlm,
		"usr":  usr,
		"cnnc": cnnc,
		"nnc":  nnc,
		"hash": HA2,
	}

	req, err = http.NewRequest("POST", fmt.Sprintf("https://%s.d.egauge.net/api/auth/login", deviceName), strings.NewReader((func() string {
		b, _ := json.Marshal(loginBody)
		return string(b)
	})()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	fmt.Println(string(body))

	jwtResponse := EgaugeJWTResponse{}
	err = json.Unmarshal(body, &jwtResponse)
	if err != nil {
		return "", err
	}
	fmt.Println(jwtResponse.Jwt)
	return jwtResponse.Jwt, nil
}

func main() {
	deviceName := "egauge67897"
	usr := "owner"
	pwd := "000000"

	jwt, err := EgaugeLogin(deviceName, usr, pwd)
	if err != nil {
		fmt.Printf("can't connect to egauge: %v\n", err)
		return
	}

	data, err := ReadEgaugeData(jwt, deviceName)
	if err != nil {
		fmt.Printf("can't get data from egauge: %v\n", err)
		return
	}

	fmt.Println(data)
}
