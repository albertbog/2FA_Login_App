import mysql.connector

myDB = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd = "Password123"
)

my_cursor = myDB.cursor()

my_cursor.execute("CREATE DATABASE BEMSI_database")

my_cursor.execute("USE bemsi_database")


my_cursor.execute("CREATE TABLE users(name varchar(20), password varchar(40))")

my_cursor.execute("SHOW DATABASES")

for db in my_cursor:
    print(db)