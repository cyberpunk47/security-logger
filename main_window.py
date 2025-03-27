import os
import json
import pandas as pd
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget, QTableView,
    QStatusBar, QComboBox, QPushButton, QHBoxLayout, QFileDialog,
    QHeaderView
)
from PyQt5.QtCore import Qt, QAbstractTableModel, QSortFilterProxyModel, QTimer, QRegExp, QThreadPool, QRunnable, pyqtSlot, pyqtSignal
from PyQt5.QtGui import QColor
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.dates as mdates
import time

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
                # Safely get the event type (column 2) with a fallback
                event_type = self._data.iloc[row, 2] if col >= 0 and len(self._data) > row and len(self._data.columns) > 2 else ""
                # Use theme-appropriate colors
                if self._theme == "Dark":
                    return self._colors.get(event_type, QColor(45, 45, 45))  # Dark gray default
                else:
                    return self._colors.get(event_type, QColor(255, 255, 255))  # White default
            except:
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
            # Fetch data in background thread
            events = self.db.get_recent_events(1000)
            # Send results back to main thread
            self.callback(events)
        except Exception as e:
            print(f"Error in worker thread: {e}")

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
        self.load_initial_data()

    def handle_new_event(self, event):
        """Handle a new event received directly from the logger."""
        try:
            # Create a copy to avoid modifying the original
            event_copy = event.copy()
            
            # Fix details format for display
            if 'details' in event_copy and isinstance(event_copy['details'], str):
                try:
                    event_copy['details'] = json.loads(event_copy['details'])
                except:
                    pass
            
            # Convert timestamp
            if 'timestamp' in event_copy:
                try:
                    event_copy['timestamp'] = pd.to_datetime(
                        event_copy['timestamp'], errors='coerce'
                    ).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
            
            # Create a single row dataframe with correct column order
            column_order = ["timestamp", "event_id", "type", "user", "computer", "source", "description"]
            new_df = pd.DataFrame([event_copy])
            
            # Ensure all columns are present in the right order
            for col in column_order:
                if col not in new_df.columns:
                    new_df[col] = None
            
            # Keep only the columns in the defined order
            new_df = new_df[column_order]
            
            # If model data is empty, just use this row
            if self.model._data.empty:
                self.model.update_data(new_df)
            else:
                # Combine and update
                combined = pd.concat([new_df, self.model._data]).reset_index(drop=True)
                self.model.update_data(combined)
            
            # Update filter
            self.apply_filter(self.filter_combo.currentText())
            
            # Scroll to show the new event
            self.event_table.scrollToTop()
            
        except Exception as e:
            self.status_bar.showMessage(f"Error handling new event: {str(e)}", 3000)
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
        # Create a thread pool with maximum 2 concurrent threads
        self.threadpool = QThreadPool()
        self.threadpool.setMaxThreadCount(2)  # Limit thread count
        
        # Set up refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(500)  # Faster refresh but with throttling
        
        # Add a throttle mechanism
        self.last_refresh = time.time()
        self.refresh_in_progress = False

    def refresh_data(self):
        # Throttle refreshes to prevent overwhelming the UI
        current_time = time.time()
        if self.refresh_in_progress or current_time - self.last_refresh < 0.4:
            return
        
        self.refresh_in_progress = True
        self.last_refresh = current_time
        
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
                df['details'] = df['details'].apply(
                    lambda x: json.loads(x) if isinstance(x, str) and x else {})
            
            # Fix timestamp formatting
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                # Format for display
                df['timestamp'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            # Ensure correct column order to match model - column mapping was incorrect
            column_order = ["timestamp", "event_id", "type", "user", "computer", "source", "description"]
            df_ordered = pd.DataFrame(columns=column_order)
            
            # Map database columns to display columns
            for col in column_order:
                if col in df.columns:
                    df_ordered[col] = df[col]
                else:
                    df_ordered[col] = None
                    
            # Update model with ordered data
            self.model.update_data(df_ordered)
            
            # Only update stats when tab is visible to save resources
            if self.tabs.currentIndex() == 1:  # Stats tab
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
        
        # Clear previous plots
        self.type_ax.clear()
        self.timeline_ax.clear()
        
        # Event Type Distribution
        if 'type' in df.columns:
            try:
                type_counts = df['type'].value_counts()
                if not type_counts.empty:
                    colors = ['#4CAF50', '#FFC107', '#F44336', '#9C27B0']
                    type_counts.plot(kind='bar', ax=self.type_ax, color=colors[:len(type_counts)])
                    self.type_ax.set_title('Event Type Distribution')
                    for tick in self.type_ax.get_xticklabels():
                        tick.set_rotation(45)
                    self.type_figure.tight_layout()
                    self.type_canvas.draw()
            except Exception as e:
                print(f"Error updating type chart: {e}")
        
        # Timeline Chart
        if 'timestamp' in df.columns:
            try:
                # Convert timestamps to datetime safely
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['timestamp'])
                
                # Only create timeline if we have data
                if not df.empty:
                    df_timeline = df.copy()  # Create a separate copy
                    df_timeline.set_index('timestamp', inplace=True)
                    
                    # Use explicit 5min for resampling to avoid deprecation warnings
                    hourly_counts = df_timeline.resample('5min').size()
                    
                    # Only plot if we have data points
                    if len(hourly_counts) > 0:
                        self.timeline_ax.plot(hourly_counts.index, hourly_counts.values, 
                                             marker='o', linestyle='-', color='#2196F3')
                        self.timeline_ax.set_title('Event Timeline (5 Minute Intervals)')
                        self.timeline_ax.set_ylabel('Number of Events')
                        self.timeline_ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
                        self.timeline_ax.grid(True, linestyle='--', alpha=0.7)
                        self.timeline_figure.tight_layout()
                        self.timeline_canvas.draw()
            except Exception as e:
                print(f"Error updating timeline chart: {e}")

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