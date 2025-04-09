# File: main_window.py
# Security Event Logger - Main GUI Window
# Provides graphical interface for security event monitoring and analysis
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget, QTableView,
    QStatusBar, QComboBox, QPushButton, QHBoxLayout, QFileDialog,
    QHeaderView
)
from PyQt5.QtCore import Qt, QAbstractTableModel, QSortFilterProxyModel, QTimer, QRegExp, QThreadPool, QRunnable, pyqtSlot, pyqtSignal
from PyQt5.QtGui import QColor
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt  # Ensure this is imported
import pandas as pd
import json
import time
import gc

class EventTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = pd.DataFrame(columns=[
            "timestamp", "event_id", "type", "user", "computer", "source", "description"
        ])
        self._headers = ["Timestamp", "Event ID", "Type", "User", "Computer", "Source", "Description"]
        self._colors = {
            'INFORMATION': QColor(173, 216, 230),    # LightBlue
            'WARNING': QColor(255, 255, 0),          # Yellow
            'ERROR': QColor(255, 99, 71),            # Tomato
            'SECURITY_AUDIT': QColor(220, 20, 60),   # Crimson
            'SECURITY_ALERT': QColor(255, 0, 0)      # Red
        }
        self._theme = "Dark"  # Default theme
        self._max_rows = 5000  # Limit maximum rows for performance

    def set_theme(self, theme):
        """Update the model's theme setting"""
        self._theme = theme
        # Trigger repaint of the table
        self.layoutChanged.emit()

    def rowCount(self, parent=None):
        return len(self._data)

    def columnCount(self, parent=None):
        return len(self._headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        
        row = index.row()
        col = index.column()
        
        # Check if row and column are within valid range
        if row < 0 or row >= len(self._data) or col < 0 or col >= len(self._headers):
            return None
        
        if role == Qt.DisplayRole:
            # Safely access data with try/except
            try:
                return str(self._data.iloc[row, col])
            except:
                return ""
        elif role == Qt.BackgroundRole:
            try:
                # Only color rows based on event type/level (not specific cells)
                event_level = str(self._data.iloc[row, 4]) if len(self._data) > row else ""
                
                # Map common event levels to our color scheme
                color_key = event_level.upper()
                if "INFO" in color_key:
                    color_key = "INFORMATION"
                elif "WARN" in color_key:
                    color_key = "WARNING"
                elif "ERROR" in color_key or "FAIL" in color_key:
                    color_key = "ERROR"
                elif "AUDIT" in color_key:
                    color_key = "SECURITY_AUDIT"
                elif "ALERT" in color_key:
                    color_key = "SECURITY_ALERT"
                
                # Get appropriate color with fallback based on theme
                color = self._colors.get(color_key)
                if color:
                    # If we have a matching color, return it
                    return color
                else:
                    # Otherwise return theme-appropriate default
                    return QColor(45, 45, 45) if self._theme == "Dark" else QColor(255, 255, 255)
            except Exception as e:
                print(f"Color error: {e}")
                # Return default color based on theme if there's any error
                return QColor(45, 45, 45) if self._theme == "Dark" else QColor(255, 255, 255)
        elif role == Qt.ForegroundRole:
            # Text color based on theme
            if self._theme == "Dark":
                return QColor(255, 255, 255)  # White text for dark theme
            else:
                return QColor(0, 0, 0)  # Black text for light theme
        elif role == Qt.TextAlignmentRole:
            return Qt.AlignLeft | Qt.AlignVCenter
        return None

    def headerData(self, section, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._headers[section]
        return None

    def update_data(self, new_data):
        self.beginResetModel()
        # Limit the number of rows to prevent memory issues
        if len(new_data) > self._max_rows:
            new_data = new_data.iloc[:self._max_rows]
        self._data = new_data
        self.endResetModel()

class DataRefreshWorker(QRunnable):
    """Worker thread for data refreshing to prevent UI freezes."""
    
    def __init__(self, db, callback):
        super().__init__()
        self.db = db
        self.callback = callback
    
    @pyqtSlot()
    def run(self):
        try:
            # Get only the most recent events (limit to 5000)
            events = self.db.get_recent_events(5000)
            self.callback(events)
        except Exception as e:
            print(f"Error in data refresh worker: {e}")
            # Return empty list instead of crashing
            self.callback([])

class MainWindow(QMainWindow):
    # Define the signal at the class level, not in a method
    refresh_complete = pyqtSignal(list)
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        # Connect the signal before we use it
        self.refresh_complete.connect(self.update_with_new_data)
        
        # Connect to the logger's new_event signal directly
        self.logger.new_event.connect(self.handle_new_event)
        
        self.setup_ui()
        self.setup_refresh_timer()
        self.setup_memory_management()
        self.load_initial_data()

    def handle_new_event(self, event):
        """Handle a new event received directly from the logger."""
        try:
            # Only update if visible and not in the middle of an operation
            if self.isVisible() and not self.refresh_in_progress:
                # Create a copy to avoid modifying the original
                event_copy = event.copy()
                
                # Simple column mapping - avoid complex operations
                columns = ["timestamp", "event_id", "type", "user", "computer", "source", "description"]
                new_row = {col: event_copy.get(col, "") for col in columns}
                
                # Create a temporary DataFrame
                new_df = pd.DataFrame([new_row])
                
                # Prepend to the existing data - limit size
                if len(self.model._data) >= self.model._max_rows:
                    # Remove the last row
                    self.model._data = pd.concat([new_df, self.model._data.iloc[:-1]])
                else:
                    self.model._data = pd.concat([new_df, self.model._data])
                    
                # Update model without full reset
                self.model.layoutChanged.emit()
                
                # Update filter only if needed
                current_filter = self.filter_combo.currentText()
                if current_filter != "All":
                    self.apply_filter(current_filter)
                    
        except Exception as e:
            print(f"Error handling new event: {e}")

    def setup_ui(self):
        self.setWindowTitle("Security Event Logger")
        self.setGeometry(100, 100, 1400, 900)
        
        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Control Bar
        control_layout = QHBoxLayout()
        
        # Filter
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "INFO", "WARNING", "ERROR", "SECURITY"])
        self.filter_combo.currentTextChanged.connect(self.apply_filter)  # Connect the signal
        control_layout.addWidget(self.filter_combo)
        
        # Theme Selector
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light"])
        self.theme_combo.currentTextChanged.connect(self.apply_theme)
        control_layout.addWidget(self.theme_combo)
        
        # Export Button
        self.export_btn = QPushButton("Export CSV")
        self.export_btn.clicked.connect(self.export_to_csv)
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Main Tabs
        self.tabs = QTabWidget()
        
        # Event Table Tab
        self.event_table = QTableView()
        self.event_table.setSortingEnabled(True)
        self.event_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tabs.addTab(self.event_table, "Events")
        
        # Statistics Tab
        self.stats_tab = QWidget()
        self.setup_stats_tab()
        self.tabs.addTab(self.stats_tab, "Statistics")
        
        layout.addWidget(self.tabs)
        
        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Initialize Models
        self.model = EventTableModel()
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.event_table.setModel(self.proxy_model)
        
        self.apply_theme("Dark")
        
        # Connect tab change signal
        self.tabs.currentChanged.connect(self.tab_changed)

    def tab_changed(self, index):
        # Only update stats when switching to the stats tab
        if index == 1:  # Stats tab
            self.update_stats()
        # When switching to events tab, make sure filters are applied
        elif index == 0:
            self.apply_filter(self.filter_combo.currentText())

    def apply_filter(self, filter_text):
        """Filter events based on the selected event type."""
        if filter_text == "All":
            # Clear any filter
            self.proxy_model.setFilterRegExp("")
        else:
            # Map selections to event types in the database
            filter_map = {
                "INFO": "INFORMATION",
                "WARNING": "WARNING",
                "ERROR": "ERROR",
                "SECURITY": "(SECURITY_AUDIT|SECURITY_ALERT)"
            }
            
            # Set filter on column 2 (the "type" column)
            filter_pattern = filter_map.get(filter_text, "")
            self.proxy_model.setFilterKeyColumn(2)  # "type" is column 2
            self.proxy_model.setFilterRegExp(QRegExp(filter_pattern, Qt.CaseInsensitive))
        
        # Update status bar with filtered count
        filtered_count = self.proxy_model.rowCount()
        total_count = self.model.rowCount()
        self.status_bar.showMessage(f"Showing {filtered_count} of {total_count} events", 3000)

    def apply_theme(self, theme_name):
        """Apply the selected theme to the application."""
        if theme_name not in ["Dark", "Light"]:
            theme_name = "Dark"  # Default to dark theme
        
        # Update model theme
        self.model.set_theme(theme_name)
        
        # Load theme stylesheet
        theme_file = f"/home/aman/security_event_logger/assets/themes/{theme_name.lower()}.qss"
        stylesheet = ""
        
        try:
            with open(theme_file, "r") as f:
                stylesheet = f.read()
            self.setStyleSheet(stylesheet)
        except FileNotFoundError:
            print(f"Theme file not found: {theme_file}")
        except Exception as e:
            print(f"Error loading theme: {e}")
        
        # Update status bar
        self.status_bar.showMessage(f"Applied {theme_name} theme", 3000)

    def setup_stats_tab(self):
        layout = QVBoxLayout(self.stats_tab)
        
        # Event Type Distribution
        self.type_figure = Figure(figsize=(8, 4))
        self.type_canvas = FigureCanvas(self.type_figure)
        self.type_ax = self.type_figure.add_subplot(111)
        layout.addWidget(self.type_canvas)
        
        # Timeline Chart
        self.timeline_figure = Figure(figsize=(8, 4))
        self.timeline_canvas = FigureCanvas(self.timeline_figure)
        self.timeline_ax = self.timeline_figure.add_subplot(111)
        layout.addWidget(self.timeline_canvas)

    def setup_refresh_timer(self):
        # Create a thread pool with maximum 1 concurrent thread (reduce thread contention)
        self.threadpool = QThreadPool()
        self.threadpool.setMaxThreadCount(1)
        
        # Set up refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(2000)  # Slower refresh (2 seconds instead of 500ms)
        
        # Add a throttle mechanism with longer interval
        self.last_refresh = time.time()
        self.refresh_in_progress = False

    def setup_memory_management(self):
        """Set up periodic memory cleanup"""
        self.memory_timer = QTimer()
        self.memory_timer.timeout.connect(self.cleanup_memory)
        self.memory_timer.start(60000)  # Run every minute
    
    def cleanup_memory(self):
        """Force garbage collection and clear caches"""
        try:
            gc.collect()
            # Clear matplotlib cache if it exists
            if hasattr(self, 'type_figure'):
                import matplotlib.pyplot as plt  # Local import as fallback
                plt.close('all')
        except Exception as e:
            print(f"Memory cleanup error: {e}")

    def refresh_data(self):
        # Throttle refreshes to prevent overwhelming the UI
        current_time = time.time()
        if self.refresh_in_progress or current_time - self.last_refresh < 1.5:  # Longer throttle
            return
        
        self.refresh_in_progress = True
        self.last_refresh = current_time
        
        # Show processing indicator
        self.status_bar.showMessage("Refreshing events...", 0)
        
        # Use worker thread for database operations
        worker = DataRefreshWorker(
            self.logger.db,
            lambda events: self.refresh_complete.emit(events)
        )
        self.threadpool.start(worker)

    def update_with_new_data(self, events):
        # Reset the refresh flag
        self.refresh_in_progress = False
        
        if not events:
            self.status_bar.showMessage("No events found in database", 3000)
            return
        
        try:
            # Create dataframe from events
            df = pd.DataFrame(events)
            
            # Handle details column
            if 'details' in df.columns:
                df['details'] = df['details'].apply(lambda x: x if isinstance(x, str) else str(x))
            
            # Fix timestamp formatting
            if 'timestamp' in df.columns:
                df['timestamp'] = df['timestamp'].apply(lambda x: x.split('.')[0].replace('T', ' ') if isinstance(x, str) and 'T' in x else x)
            
            # Ensure correct column order
            column_order = ["timestamp", "event_id", "type", "user", "computer", "source", "description"]
            df_ordered = pd.DataFrame(columns=column_order)
            
            # Map database columns to display columns - safely
            for col in column_order:
                if col in df.columns:
                    df_ordered[col] = df[col]
                else:
                    df_ordered[col] = ""  # Empty placeholder for missing columns
            
            # Update model with ordered data
            self.model.update_data(df_ordered)
            
            # Only update stats when tab is visible
            if self.tabs.currentIndex() == 1:
                self.update_stats()
            
            self.status_bar.showMessage(f"Loaded {len(df)} events", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"Error processing events: {str(e)}", 3000)
            print(f"Error updating data: {e}")

    def load_initial_data(self):
        events = self.logger.db.get_recent_events(1000)
        if events:
            df = pd.DataFrame(events)
            # Parse JSON details if they exist
            if 'details' in df.columns:
                try:
                    df['details'] = df['details'].apply(lambda x: json.loads(x) if isinstance(x, str) else x)
                except Exception as e:
                    self.status_bar.showMessage(f"Error parsing event details: {str(e)}", 3000)
            self.model.update_data(df)
            self.update_stats()
            self.status_bar.showMessage(f"Loaded {len(df)} events", 3000)
        else:
            self.status_bar.showMessage("No events found in database", 3000)

    def update_stats(self):
        # Get a fresh copy of the data to avoid modification issues
        df = self.model._data.copy()
        if df.empty:
            return
        
        try:
            # Clear previous plots
            self.type_ax.clear()
            self.timeline_ax.clear()
            
            # Event Type Distribution
            if 'type' in df.columns:
                try:
                    type_counts = df['type'].value_counts()
                    self.type_ax.pie(type_counts.values, labels=type_counts.index, autopct='%1.1f%%')
                    self.type_ax.set_title('Event Type Distribution')
                    self.type_canvas.draw()
                except Exception as e:
                    print(f"Error updating type chart: {e}")
            
            # Timeline Chart
            if 'timestamp' in df.columns:
                try:
                    # Convert timestamps to datetime safely
                    df['date'] = pd.to_datetime(df['timestamp'], errors='coerce')
                    
                    # Drop rows where conversion failed
                    df = df.dropna(subset=['date'])
                    
                    # Group by date and count events
                    if not df.empty:  # Check again after dropping NAs
                        timeline = df.groupby(df['date'].dt.date).size()
                        
                        # Plot the timeline
                        dates = [str(d) for d in timeline.index]
                        self.timeline_ax.bar(dates, timeline.values)
                        self.timeline_ax.set_title('Events Over Time')
                        self.timeline_ax.tick_params(axis='x', rotation=45)
                        self.timeline_ax.set_xlabel('Date')
                        self.timeline_ax.set_ylabel('Event Count')
                        self.timeline_figure.tight_layout()
                        self.timeline_canvas.draw()
                except Exception as e:
                    print(f"Error updating timeline chart: {e}")
        except Exception as e:
            print(f"Error in update_stats: {e}")

    def export_to_csv(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export to CSV", "", "CSV Files (*.csv)")
        if file_path:
            try:
                self.model._data.to_csv(file_path, index=False)
                self.status_bar.showMessage(f"Data exported to {file_path}", 3000)
            except Exception as e:
                self.status_bar.showMessage(f"Error exporting data: {str(e)}", 3000)
            
    def closeEvent(self, event):
        """Handle window close event."""
        try:
            # Stop the logger when the window is closed
            if hasattr(self.logger, 'stop'):
                self.logger.stop()
        except Exception as e:
            print(f"Error stopping logger: {e}")
        event.accept()