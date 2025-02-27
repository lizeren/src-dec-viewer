import pickle
import os

# Define a settings file path
SETTINGS_FILE = "analyzer_settings.pkl"

class SettingsManager:
    @staticmethod
    def save_settings(settings):
        """Save settings to a file"""
        try:
            with open(SETTINGS_FILE, 'wb') as f:
                pickle.dump(settings, f)
            return True
        except Exception as e:
            print(f"Failed to save settings: {str(e)}")
            return False
    
    @staticmethod
    def load_settings():
        """Load settings from a file"""
        if not os.path.exists(SETTINGS_FILE):
            return {}
        
        try:
            with open(SETTINGS_FILE, 'rb') as f:
                settings = pickle.load(f)
            return settings
        except Exception as e:
            print(f"Failed to load settings: {str(e)}")
            return {} 