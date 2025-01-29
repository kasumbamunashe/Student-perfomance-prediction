import psycopg2
import bcrypt
from psycopg2 import sql

# PostgreSQL connection parameters
conn_params = {
    'host': 'localhost',
    'dbname': 'student-performance-prediction',
    'user': 'postgres',
    'password': 'Munashe056'
}

# Insert a super admin account with hashed password
def insert_super_admin(conn, username, password, email):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    with conn.cursor() as cursor:
        cursor.execute("""
        INSERT INTO users (username, password, email, role)
        VALUES (%s, %s, %s, %s)
        """, (username, hashed_password, email, 'admin'))
        conn.commit()

# Main function to connect and run the script
def main():
    try:
        # Connect to the PostgreSQL database
        conn = psycopg2.connect(**conn_params)

        # Check if the super admin already exists
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", ('jimmy',))
            admin_exists = cursor.fetchone()

        if not admin_exists:
            insert_super_admin(conn, 'jimmy', 'jimmy', 'munashekasumba@gmail.com')
            print("Super admin account created successfully!")
        else:
            print("Super admin account already exists.")

    except psycopg2.Error as e:
        print(f"Error connecting to PostgreSQL: {e}")

    finally:
        # Close the database connection
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
