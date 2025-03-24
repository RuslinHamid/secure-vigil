import sqlite3

# User input (unsafe)
username = input("Enter username: ")
password = input("Enter password: ")

# Connect to the database
conn = sqlite3.connect('example.db')
cursor = conn.cursor()

# Vulnerable SQL query
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)

# Fetch result
result = cursor.fetchone()

if result:
    print("Login successful!")
else:
    print("Login failed!")
