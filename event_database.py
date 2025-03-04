import sqlite3
import json
import datetime  # Add this import
import uuid      # Add this import
import socket    # Add this import
from typing import Dict, List, Any

class EventDatabase:
    """SQLite database for storing security events in Windows Event Log style."""
    
    def __init__(self, db_path):
        """Initialize the event database."""
        self.db_path = db_path
        self.create_database()
    
    def create_database(self):
        """Create the event database if it doesn't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create events table with Windows Event Log-like structure
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,           -- Event ID (windows-style numeric identifier)
            date TEXT,               -- Date the event occurred
            time TEXT,               -- Time the event occurred
            user TEXT,               -- Username related to the event
            computer TEXT,           -- Hostname/computer name
            source TEXT,             -- Program or component that caused the event
            type TEXT,               -- Type of event (warning, error, security, etc.)
            description TEXT,        -- Full event description
            raw_data TEXT,           -- Raw JSON data for the event
            timestamp TEXT           -- ISO timestamp for sorting
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_event(self, event):
        """Add an event to the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Extract data in Windows Event Log format
            now = datetime.datetime.now()
            
            cursor.execute(
                '''
                INSERT INTO events 
                (event_id, date, time, user, computer, source, type, description, raw_data, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    event.get('event_id', str(uuid.uuid4())[:8]),
                    event.get('date', now.strftime('%Y-%m-%d')),
                    event.get('time', now.strftime('%H:%M:%S')),
                    event.get('user', event.get('details', {}).get('username', 'SYSTEM')),
                    event.get('computer', socket.gethostname()),
                    event.get('source', event.get('type', 'UNKNOWN').split('_')[0]),
                    event.get('type', 'INFORMATION'),
                    event.get('description', json.dumps(event.get('details', {}))),
                    json.dumps(event),
                    event.get('timestamp', now.isoformat())
                )
            )
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Database error: {e}")
            return False
    
    def get_recent_events(self, limit=100):
        """Get recent events from the database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            '''
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT ?
            ''',
            (limit,)
        )
        
        events = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return events
    
    def search_events(self, query, params):
        """Search events in the database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(query, params)
        
        events = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return events