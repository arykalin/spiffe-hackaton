package main

import "errors"

var inMemoryDB = make(map[string]certRecord)

func saveToDB(key string, value certRecord) {
	inMemoryDB[key] = value
}

func getFromDB(key string) (v certRecord, err error) {
	v, prs := inMemoryDB[key]
	if !prs {
		return v, errors.New("record not found")
	}
	return v, nil
}
