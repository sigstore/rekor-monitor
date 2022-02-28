package mirroring
import (
	"database/sql"
	"fmt"
	"log"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)
type data struct {
    ID string
    payload string
}

func initTable(database *sql.DB) error{
    statement, err := database.Exec("CREATE TABLE entries (idx INTEGER PRIMARY KEY NOT NULL, payload TEXT)") //sql query string (if no db)
    if(err != nil){
        log.Printf("Error %s when creating product table", err)
        return err
    }
    no, _ := statement.RowsAffected()
    log.Printf("rows affected %d\n", no)
    return nil
}

func insert(db *sql.DB, d data) (int64, error) {
    query := "INSERT INTO entries (idx, payload) VALUES (?, ?)"
    statement, err := db.Prepare(query)
    res, err := statement.Exec(d.ID, d.payload)
    if(err != nil){
        log.Printf("Error %s when finding rows affected", err)
        return -1, err
    }
    rows, _ := res.RowsAffected()
    log.Printf("%d products created ", rows)
    return rows, nil
}

func getLatest(database *sql.DB) (int, string, error){
    rows, err := database.Query("SELECT * FROM entries ORDER BY idx DESC LIMIT 1")
    if(err != nil){
        log.Printf("Error %s when retrieving rows", err)
        return -1,"/0", err
    }
    var id int
    var payload string
    for rows.Next() {
        rows.Scan(&id, &payload)
        fmt.Println(strconv.Itoa(id) + ": " + payload)
    }
    return id,payload, nil
}

func getLatestX(database *sql.DB, x int) (*sql.Rows, error) {
    rows, err := database.Query("SELECT * FROM entries ORDER BY idx DESC LIMIT " + strconv.Itoa(x))
    if(err != nil){
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
