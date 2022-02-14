package main

import (
    "database/sql"
    "fmt"
    "strconv"

    _ "github.com/mattn/go-sqlite3"
)

func initTable(database *sql.DB) {
    statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS people (id INTEGER PRIMARY KEY, firstname TEXT, lastname TEXT)") //sql query string (if no db)
    statement.Exec() 
}

func insert(database *sql.DB) {
    statement, _ = database.Prepare("INSERT INTO people (firstname, lastname) VALUES (?, ?)")
    statement.Exec("Kim", "K")
}

func iterate(database *sql.DB) {
    rows, _ := database.Query("SELECT id, firstname, lastname FROM people")
    var id int
    var firstname string
    var lastname string
    var numRows int
    for rows.Next() {
        rows.Scan(&id, &firstname, &lastname)
        fmt.Println(strconv.Itoa(id) + ": " + firstname + " " + lastname)
        numRows = id
    }
}

func main() {
    database, _ := sql.Open("sqlite3", "./nraboy.db") //open database
    initTable(database)
    // var num int
    // num, _ := database.Query("SELECT * FROM" + "./nraboy.db")
    // for num.Next() {
    //     fmt.Println("NUM: " + strconv.Itoa(int(num)))
    // }
    // numRows, _ := database.Query("SELECT * FROM    TABLEWHERE   ID = (SELECT MAX(ID)  FROM TABLE);") //("SELECT COUNT(*) FROM people")
    fmt.Println(numRows)

}