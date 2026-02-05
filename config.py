import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Flask configuration
class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    PASSWORD = os.environ.get('PASSWORD', 'admin123')
    
    # File system
    PROJECT_DIR = BASE_DIR / 'projects'
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {
        'py', 'js', 'html', 'css', 'txt', 'md', 'json',
        'php', 'java', 'cpp', 'c', 'go', 'rs', 'ts',
        'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico',
        'pdf', 'doc', 'docx', 'xls', 'xlsx',
        'zip', 'tar', 'gz', 'rar'
    }
    
    # Server
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8000))
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Security settings
    SESSION_TIMEOUT = 3600  # 1 hour in seconds
    RATE_LIMIT = 60  # requests per minute
    ENABLE_CORS = True
    
    # Backup settings
    BACKUP_ENABLED = True
    MAX_BACKUPS = 10
    BACKUP_DIR = PROJECT_DIR / 'backups'
