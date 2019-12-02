package main

import "errors"

var inMemoryDB = make(map[string]string)

func saveToDB(key, value string) {
	inMemoryDB[key] = value
}

func getFromDB(key string) (string, error) {
	v, prs := inMemoryDB[key]
	if !prs {
		return "", errors.New("not found")
	}
	return v, nil
}
