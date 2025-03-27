import sqlite3
import json
import time
from typing import List, Dict
import threading

class EventDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_table()
        self.ensure_columns_exist()
        self.lock = threading.Lock()  # Add a lock for thread safety
        self.last_vacuum_time = time.time()
        self.batch_size = 10  # Number of events to collect before bulk insert
        self.event_batch = []  # Batch of events waiting to be inserted
        
    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id TEXT,
            type TEXT,
            user TEXT,
            computer TEXT,
            source TEXT,
            description TEXT,
            details TEXT
        )''')
        # Add index on timestamp for faster retrieval
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events (timestamp)')
        self.conn.commit()
        
    def ensure_columns_exist(self):
        """Check if all required columns exist and add them if not."""
        cursor = self.conn.cursor()
        # Get existing columns
        cursor.execute("PRAGMA table_info(events)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        
        # Check for required columns
        required_columns = {
            "details": "TEXT"
        }
        
        for column, dtype in required_columns.items():
            if column not in existing_columns:
                try:
                    cursor.execute(f"ALTER TABLE events ADD COLUMN {column} {dtype}")
                    self.conn.commit()
                    print(f"Added missing column '{column}' to events table")
                except sqlite3.Error as e:
                    print(f"Error adding column {column}: {e}")

    def add_event(self, event: Dict) -> bool:
        try:
            # Convert JSON details to string if it's not already a string
            details = event.get('details', '{}')
            if isinstance(details, dict):
                details = json.dumps(details)
                
            with self.lock:  # Use thread lock for safety
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT INTO events 
                (event_id, timestamp, type, user, computer, source, description, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.get('event_id'),
                    event.get('timestamp'),
                    event.get('type'),
                    event.get('user'),
                    event.get('computer'),
                    event.get('source'),
                    event.get('description'),
                    details
                ))
                self.conn.commit()
                
                # Vacuum database periodically to prevent bloat (every hour)
                current_time = time.time()
                if current_time - self.last_vacuum_time > 3600:  # 1 hour
                    self.conn.execute("VACUUM")
                    self.last_vacuum_time = current_time
                
            return True
        except Exception as e:
            print(f"Database error: {e}")
            return False

    def get_recent_events(self, limit: int = 1000) -> List[Dict]:
        with self.lock:  # Use thread lock for safety
            cursor = self.conn.cursor()
            
            # Get existing columns to build a dynamic query
            cursor.execute("PRAGMA table_info(events)")
            existing_columns = [row[1] for row in cursor.fetchall()]
            
            # Build columns list based on what exists
            columns = ["timestamp", "event_id", "type", "user", "computer", "source", "description"]
            if "details" in existing_columns:
                columns.append("details")
                
            # Construct the query dynamically with a limit
            query = f'''
                SELECT {', '.join(columns)}
                FROM events
                ORDER BY timestamp DESC
                LIMIT ?'''
                
            cursor.execute(query, (limit,))
            
            # Get column names from cursor description
            result_columns = [col[0] for col in cursor.description]
            
            # Convert rows to dictionaries properly
            return [dict(zip(result_columns, row)) for row in cursor.fetchall()]
    
    def search_events(self, query, params):
        """Execute a custom search query against the events table."""
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        
        # Get column names from cursor description
        columns = [col[0] for col in cursor.description]
        
        # Convert rows to dictionaries
        return [dict(zip(columns, row)) for row in cursor.fetchall()]