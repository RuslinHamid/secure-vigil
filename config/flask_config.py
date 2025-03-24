import os
from werkzeug.middleware.reloader import ReloaderMiddleware
import tempfile
from werkzeug.serving import make_server

class CustomReloader(ReloaderMiddleware):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ignored_patterns = [
            '*.tmp',
            '*.temp',
            '*.swp',
            '*.bak',
            '*.log',
            'security_reports/*',
            'uploads/*'
        ]
    
    def should_reload(self, filename):
        # Check if the file matches any ignored patterns
        for pattern in self.ignored_patterns:
            if filename.endswith(pattern.replace('*', '')):
                return False
        return super().should_reload(filename)

def create_app():
    from app import app
    
    # Configure Flask
    app.config['TEMPLATES_AUTO_RELOAD'] = False
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    
    # Create custom reloader
    reloader = CustomReloader(app)
    
    return reloader

def run_app(app, host='0.0.0.0', port=5000):
    # Use Werkzeug's make_server instead of WSGIServer
    httpd = make_server(host, port, app)
    httpd.serve_forever() 