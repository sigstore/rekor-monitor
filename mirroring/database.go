package mirroring

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

type Data struct {
	ID      int64
	Payload string
}

func InitTable(database *sql.DB) error {
	//sql query string (if no db)
	statement, err := database.Exec("CREATE TABLE entries (idx INTEGER PRIMARY KEY NOT NULL, payload TEXT)") 
	if err != nil {
		log.Printf("Error %s when creating product table", err)
		return err
	}
	no, _ := statement.RowsAffected()
	log.Printf("rows affected %d\n", no)
	return nil
}

func Insert(db *sql.DB, d Data) (int64, error) {
	query := "INSERT INTO entries (idx, payload) VALUES (?, ?)"
	statement, err := db.Prepare(query)
	res, err := statement.Exec(d.ID, d.Payload)
	if err != nil {
		log.Printf("Error %s when finding rows affected", err)
		return -1, err
	}
	rows, _ := res.RowsAffected()
	log.Printf("%d products created ", rows)
	return rows, nil
}

func GetLatest(database *sql.DB) (int64, string, error) {
	rows, err := database.Query("SELECT * FROM entries ORDER BY idx DESC LIMIT 1")
	if err != nil {
		log.Printf("Error %s when retrieving rows", err)
		return -1, "/0", err
	}
	var id int64
	var payload string
	for rows.Next() {
		rows.Scan(&id, &payload)
		// fmt.Println(strconv.Itoa(id) + ": " + payload)
	}
	return id, payload, nil
}

func getLatestX(database *sql.DB, x int) (*sql.Rows, error) {
	rows, err := database.Query("SELECT * FROM entries ORDER BY idx DESC LIMIT " + strconv.Itoa(x))
	if err != nil {
		log.Printf("Error %s when retrieving rows", err)
		return nil, err
		// return -1,"/0", err
	}
	var id int
	var payload string
	for rows.Next() {
		rows.Scan(&id, &payload)
		fmt.Println(strconv.Itoa(id) + ": " + payload)
	}
	return rows, err
}
