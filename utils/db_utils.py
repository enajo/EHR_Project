import sqlite3
from flask import current_app, g

def get_db_connection():
    """
    Get a database connection from Flask's application context.
    """
    if 'db_connection' not in g:
        g.db_connection = sqlite3.connect(current_app.config['DATABASE'])
        g.db_connection.row_factory = sqlite3.Row  # Access rows as dictionaries
    return g.db_connection


def close_db_connection(e=None):
    """
    Close the database connection if it exists.
    """
    db = g.pop('db_connection', None)

    if db is not None:
        db.close()


def execute_query(query, params=(), fetch_one=False, fetch_all=False):
    """
    Execute a SQL query and fetch results if needed.
    
    Args:
        query (str): SQL query to execute.
        params (tuple): Parameters to bind to the query.
        fetch_one (bool): Whether to fetch one result.
        fetch_all (bool): Whether to fetch all results.
    
    Returns:
        The fetched result(s) or None if no fetch is specified.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    result = None

    try:
        cursor.execute(query, params)
        conn.commit()
        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        cursor.close()

    return result


def init_db():
    """
    Initialize the database using the schema defined in `init_db.sql`.
    """
    conn = get_db_connection()
    with current_app.open_resource('init_db.sql') as f:
        conn.executescript(f.read().decode('utf-8'))
    conn.commit()
    conn.close()
