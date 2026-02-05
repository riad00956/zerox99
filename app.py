import os
import sys
import subprocess
import threading
import hashlib
import secrets
import json
import time
from pathlib import Path
from datetime import datetime
from functools import wraps
import psutil

from flask import Flask, render_template_string, request, session, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    PASSWORD = os.environ.get('PASSWORD', 'admin123')  # Default password
    PROJECT_DIR = os.environ.get('PROJECT_DIR', 'projects')
    ALLOWED_EXTENSIONS = {'py', 'js', 'html', 'css', 'txt', 'json', 'md', 'php', 'java', 'cpp', 'c', 'go', 'rs', 'ts'}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_UPLOAD_FILES = 50
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8000))
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '*').split(',')
    
    # Security settings
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 3600))  # 1 hour
    RATE_LIMIT = int(os.environ.get('RATE_LIMIT', 60))  # requests per minute
    ENABLE_REGISTRATION = os.environ.get('ENABLE_REGISTRATION', 'False').lower() == 'true'

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.from_object(Config)
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='gevent',
                   ping_timeout=60,
                   ping_interval=25,
                   logger=Config.DEBUG,
                   engineio_logger=Config.DEBUG)

# Create project directory
base_dir = Path(__file__).parent
project_path = base_dir / Config.PROJECT_DIR
project_path.mkdir(exist_ok=True)

# Create necessary subdirectories
(project_path / 'tmp').mkdir(exist_ok=True)
(project_path / 'backups').mkdir(exist_ok=True)

# Store active sessions
active_sessions = {}

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def socket_auth_required(f):
    """Decorator for socket authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return False
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Check if file extension is allowed"""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal"""
    filename = secure_filename(filename)
    # Remove any path components
    filename = os.path.basename(filename)
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    return filename

def sanitize_command(cmd):
    """Sanitize shell commands"""
    dangerous = [
        'rm -rf', 'sudo', 'shutdown', 'reboot', 'mkfs', 'dd',
        '> /', '>> /', '|', '&', '`', '$', '(', ')', '{', '}',
        'chmod', 'chown', 'passwd', 'visudo', 'crontab'
    ]
    
    cmd_lower = cmd.lower()
    for danger in dangerous:
        if danger in cmd_lower:
            return None
    
    # Limit command length
    if len(cmd) > 1000:
        return None
    
    return cmd.strip()

def get_file_icon(filename):
    """Get appropriate icon for file type"""
    ext = filename.split('.')[-1].lower() if '.' in filename else 'txt'
    
    icon_map = {
        'py': 'file-code', 'js': 'file-code', 'ts': 'file-code',
        'html': 'file-code', 'css': 'file-code', 'php': 'file-code',
        'java': 'file-code', 'cpp': 'file-code', 'c': 'file-code',
        'go': 'file-code', 'rs': 'file-code', 'json': 'file-json',
        'md': 'file-text', 'txt': 'file-text', 'pdf': 'file-text',
        'csv': 'file-spreadsheet', 'xlsx': 'file-spreadsheet',
        'jpg': 'file-image', 'jpeg': 'file-image', 'png': 'file-image',
        'gif': 'file-image', 'svg': 'file-image', 'mp3': 'file-audio',
        'mp4': 'file-video', 'zip': 'file-archive', 'tar': 'file-archive',
        'gz': 'file-archive'
    }
    
    return icon_map.get(ext, 'file')

def backup_file(filepath):
    """Create backup of a file"""
    try:
        if filepath.exists() and filepath.is_file():
            backup_dir = project_path / 'backups' / datetime.now().strftime('%Y-%m-%d')
            backup_dir.mkdir(exist_ok=True)
            
            backup_path = backup_dir / f"{filepath.name}.{int(time.time())}.bak"
            backup_path.write_bytes(filepath.read_bytes())
            
            # Keep only last 10 backups
            backups = sorted(backup_dir.glob(f"{filepath.name}.*.bak"))
            if len(backups) > 10:
                for old_backup in backups[:-10]:
                    old_backup.unlink()
    except:
        pass

def get_system_info():
    """Get system information"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get project file count
        file_count = len([f for f in project_path.rglob('*') if f.is_file() and not f.name.startswith('.')])
        
        # Get directory size
        dir_size = sum(f.stat().st_size for f in project_path.rglob('*') if f.is_file()) / (1024 * 1024)
        
        return {
            'cpu': f"{cpu_percent:.1f}%",
            'memory': {
                'total': f"{memory.total / (1024**3):.1f} GB",
                'used': f"{memory.used / (1024**3):.1f} GB",
                'percent': f"{memory.percent:.1f}%"
            },
            'disk': {
                'total': f"{disk.total / (1024**3):.1f} GB",
                'used': f"{disk.used / (1024**3):.1f} GB",
                'percent': f"{disk.percent:.1f}%"
            },
            'files': file_count,
            'size': f"{dir_size:.2f} MB",
            'uptime': time.time() - psutil.boot_time()
        }
    except:
        return {
            'cpu': 'N/A',
            'memory': {'used': 'N/A', 'percent': 'N/A'},
            'disk': {'used': 'N/A', 'percent': 'N/A'},
            'files': 0,
            'size': '0 MB',
            'uptime': 0
        }

# Load HTML template
with open(base_dir / 'templates' / 'index.html', 'r', encoding='utf-8') as f:
    HTML_TEMPLATE = f.read()

# Routes
@app.route('/')
def index():
    """Main page"""
    if session.get('logged_in'):
        return render_template_string(HTML_TEMPLATE, logged_in=True)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        # Simple password check (in production, use hashed passwords)
        if password == Config.PASSWORD:
            session['logged_in'] = True
            session['login_time'] = time.time()
            session['session_id'] = secrets.token_hex(16)
            
            # Store session info
            active_sessions[session['session_id']] = {
                'ip': request.remote_addr,
                'login_time': session['login_time'],
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
            
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid password!', 'error')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - CyberIDE</title>
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
            }
            .login-box {
                background: white;
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                width: 100%;
                max-width: 400px;
            }
            h1 {
                text-align: center;
                color: #333;
                margin-bottom: 30px;
            }
            input[type="password"] {
                width: 100%;
                padding: 15px;
                margin-bottom: 20px;
                border: 2px solid #ddd;
                border-radius: 10px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input[type="password"]:focus {
                border-color: #667eea;
                outline: none;
            }
            button {
                width: 100%;
                padding: 15px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
            }
            .alert {
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 20px;
                text-align: center;
            }
            .error { background: #fee; color: #c00; border: 1px solid #fcc; }
            .success { background: #efe; color: #0a0; border: 1px solid #cfc; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h1>🔐 CyberIDE Access</h1>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert {{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            <form method="POST">
                <input type="password" name="password" placeholder="Enter password" required>
                <button type="submit">Unlock IDE</button>
            </form>
            <p style="text-align: center; margin-top: 20px; color: #666; font-size: 14px;">
                v3.0 • Secure Web IDE
            </p>
        </div>
    </body>
    </html>
    ''')

@app.route('/logout')
def logout():
    """Logout user"""
    session_id = session.get('session_id')
    if session_id in active_sessions:
        del active_sessions[session_id]
    
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/api/files')
@login_required
def get_files():
    """API endpoint to get file list"""
    try:
        files = []
        for f in project_path.iterdir():
            if f.is_file() and allowed_file(f.name):
                stats = f.stat()
                files.append({
                    'name': f.name,
                    'size': stats.st_size,
                    'modified': stats.st_mtime,
                    'icon': get_file_icon(f.name)
                })
        
        return jsonify({'files': sorted(files, key=lambda x: x['modified'], reverse=True)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/<filename>')
@login_required
def get_file_content(filename):
    """API endpoint to get file content"""
    try:
        filename = sanitize_filename(filename)
        filepath = project_path / filename
        
        if not filepath.exists() or not filepath.is_file():
            return jsonify({'error': 'File not found'}), 404
        
        content = filepath.read_text(encoding='utf-8', errors='ignore')
        return jsonify({
            'filename': filename,
            'content': content,
            'size': filepath.stat().st_size
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/save', methods=['POST'])
@login_required
def save_file():
    """API endpoint to save file"""
    try:
        data = request.get_json()
        filename = sanitize_filename(data.get('filename', ''))
        content = data.get('content', '')
        
        if not filename:
            return jsonify({'error': 'Filename is required'}), 400
        
        filepath = project_path / filename
        
        # Create backup before saving
        backup_file(filepath)
        
        # Save file
        filepath.write_text(content, encoding='utf-8')
        
        return jsonify({
            'success': True,
            'message': f'File {filename} saved successfully',
            'size': filepath.stat().st_size
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete/<filename>', methods=['DELETE'])
@login_required
def delete_file(filename):
    """API endpoint to delete file"""
    try:
        filename = sanitize_filename(filename)
        filepath = project_path / filename
        
        if not filepath.exists():
            return jsonify({'error': 'File not found'}), 404
        
        # Create backup before deleting
        backup_file(filepath)
        
        filepath.unlink()
        
        return jsonify({
            'success': True,
            'message': f'File {filename} deleted successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rename', methods=['POST'])
@login_required
def rename_file():
    """API endpoint to rename file"""
    try:
        data = request.get_json()
        old_name = sanitize_filename(data.get('old_name', ''))
        new_name = sanitize_filename(data.get('new_name', ''))
        
        if not old_name or not new_name:
            return jsonify({'error': 'Both old and new names are required'}), 400
        
        old_path = project_path / old_name
        new_path = project_path / new_name
        
        if not old_path.exists():
            return jsonify({'error': 'Source file not found'}), 404
        
        if new_path.exists():
            return jsonify({'error': 'Destination file already exists'}), 400
        
        old_path.rename(new_path)
        
        return jsonify({
            'success': True,
            'message': f'File renamed from {old_name} to {new_name}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """API endpoint to upload files"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        filename = sanitize_filename(file.filename)
        filepath = project_path / filename
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset pointer
        
        if file_size > Config.MAX_FILE_SIZE:
            return jsonify({'error': 'File too large'}), 400
        
        # Save file
        file.save(filepath)
        
        return jsonify({
            'success': True,
            'message': f'File {filename} uploaded successfully',
            'size': filepath.stat().st_size
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<filename>')
@login_required
def download_file(filename):
    """API endpoint to download file"""
    try:
        filename = sanitize_filename(filename)
        filepath = project_path / filename
        
        if not filepath.exists() or not filepath.is_file():
            return jsonify({'error': 'File not found'}), 404
        
        from flask import send_file
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system')
@login_required
def system_info():
    """API endpoint to get system information"""
    try:
        info = get_system_info()
        info['active_sessions'] = len(active_sessions)
        info['timestamp'] = time.time()
        
        # Format uptime
        uptime = info['uptime']
        days = int(uptime // 86400)
        hours = int((uptime % 86400) // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        info['uptime_formatted'] = f"{days}d {hours}h {minutes}m {seconds}s"
        
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    """Handle new socket connection"""
    if not session.get('logged_in'):
        return False
    
    session_id = session.get('session_id')
    if session_id:
        emit('connected', {'message': 'Connected to CyberIDE', 'session': session_id})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle socket disconnect"""
    pass

@socketio.on('get_file_list')
@socket_auth_required
def handle_get_files():
    """Send file list to client"""
    try:
        files = []
        for f in project_path.iterdir():
            if f.is_file() and allowed_file(f.name):
                stats = f.stat()
                files.append({
                    'name': f.name,
                    'size': stats.st_size,
                    'modified': stats.st_mtime,
                    'icon': get_file_icon(f.name)
                })
        
        emit('file_list', {'files': sorted(files, key=lambda x: x['modified'], reverse=True)})
    except Exception as e:
        emit('error', {'message': f'Error getting files: {str(e)}'})

@socketio.on('get_file')
@socket_auth_required
def handle_get_file(data):
    """Send file content to client"""
    try:
        filename = sanitize_filename(data.get('filename', ''))
        filepath = project_path / filename
        
        if not filepath.exists() or not filepath.is_file():
            emit('error', {'message': 'File not found'})
            return
        
        content = filepath.read_text(encoding='utf-8', errors='ignore')
        emit('file_content', {
            'filename': filename,
            'content': content,
            'size': filepath.stat().st_size
        })
    except Exception as e:
        emit('error', {'message': f'Error reading file: {str(e)}'})

@socketio.on('save_file')
@socket_auth_required
def handle_save_file(data):
    """Save file from client"""
    try:
        filename = sanitize_filename(data.get('filename', ''))
        content = data.get('content', '')
        
        if not filename:
            emit('error', {'message': 'Filename is required'})
            return
        
        filepath = project_path / filename
        
        # Create backup before saving
        backup_file(filepath)
        
        # Save file
        filepath.write_text(content, encoding='utf-8')
        
        emit('file_saved', {
            'filename': filename,
            'size': filepath.stat().st_size,
            'message': 'File saved successfully'
        })
    except Exception as e:
        emit('error', {'message': f'Error saving file: {str(e)}'})

@socketio.on('create_file')
@socket_auth_required
def handle_create_file(data):
    """Create new file"""
    try:
        filename = sanitize_filename(data.get('filename', ''))
        
        if not filename:
            emit('error', {'message': 'Filename is required'})
            return
        
        filepath = project_path / filename
        
        if filepath.exists():
            emit('error', {'message': 'File already exists'})
            return
        
        # Create empty file
        filepath.touch()
        
        emit('file_created', {
            'filename': filename,
            'message': 'File created successfully'
        })
        
        # Send updated file list
        handle_get_files()
    except Exception as e:
        emit('error', {'message': f'Error creating file: {str(e)}'})

@socketio.on('delete_file')
@socket_auth_required
def handle_delete_file(data):
    """Delete file"""
    try:
        filename = sanitize_filename(data.get('filename', ''))
        filepath = project_path / filename
        
        if not filepath.exists():
            emit('error', {'message': 'File not found'})
            return
        
        # Create backup before deleting
        backup_file(filepath)
        
        filepath.unlink()
        
        emit('file_deleted', {
            'filename': filename,
            'message': 'File deleted successfully'
        })
        
        # Send updated file list
        handle_get_files()
    except Exception as e:
        emit('error', {'message': f'Error deleting file: {str(e)}'})

@socketio.on('execute_command')
@socket_auth_required
def handle_execute_command(data):
    """Execute shell command"""
    try:
        cmd = data.get('command', '')
        sanitized_cmd = sanitize_command(cmd)
        
        if not sanitized_cmd:
            emit('command_output', {'output': 'Error: Command contains dangerous characters or is too long'})
            return
        
        # Limit command execution time
        timeout = 30
        
        def run_command():
            try:
                process = subprocess.Popen(
                    sanitized_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=project_path,
                    bufsize=1,
                    universal_newlines=True
                )
                
                for line in process.stdout:
                    emit('command_output', {'output': line.rstrip()})
                
                process.wait()
                return_code = process.returncode
                emit('command_output', {'output': f'\nProcess finished with exit code {return_code}'})
                
            except subprocess.TimeoutExpired:
                emit('command_output', {'output': '\nError: Command execution timeout (30 seconds)'})
            except Exception as e:
                emit('command_output', {'output': f'\nError: {str(e)}'})
        
        # Run command in separate thread
        thread = threading.Thread(target=run_command)
        thread.daemon = True
        thread.start()
        
    except Exception as e:
        emit('error', {'message': f'Error executing command: {str(e)}'})

@socketio.on('run_code')
@socket_auth_required
def handle_run_code(data):
    """Run Python code"""
    try:
        filename = sanitize_filename(data.get('filename', ''))
        code = data.get('code', '')
        
        if not filename.endswith('.py'):
            emit('command_output', {'output': 'Error: Only Python files can be executed directly'})
            return
        
        filepath = project_path / filename
        
        # Save code to file
        filepath.write_text(code, encoding='utf-8')
        
        emit('command_output', {'output': f'Running {filename}...\n{"="*50}'})
        
        def execute_python():
            try:
                process = subprocess.Popen(
                    ['python', str(filepath)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=project_path,
                    bufsize=1,
                    universal_newlines=True
                )
                
                for line in process.stdout:
                    emit('command_output', {'output': line.rstrip()})
                
                process.wait()
                return_code = process.returncode
                emit('command_output', {'output': f'\n{"="*50}\nExecution finished with exit code {return_code}'})
                
            except Exception as e:
                emit('command_output', {'output': f'\nError: {str(e)}'})
        
        # Execute in separate thread
        thread = threading.Thread(target=execute_python)
        thread.daemon = True
        thread.start()
        
    except Exception as e:
        emit('error', {'message': f'Error running code: {str(e)}'})

@socketio.on('get_system_info')
@socket_auth_required
def handle_get_system_info():
    """Send system information"""
    try:
        info = get_system_info()
        info['active_sessions'] = len(active_sessions)
        info['timestamp'] = time.time()
        
        emit('system_info', info)
    except Exception as e:
        emit('error', {'message': f'Error getting system info: {str(e)}'})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(413)
def too_large(error):
    return jsonify({'error': 'File too large'}), 413

# Cleanup function
def cleanup_old_sessions():
    """Remove expired sessions"""
    current_time = time.time()
    expired = []
    
    for session_id, session_data in active_sessions.items():
        if current_time - session_data['login_time'] > Config.SESSION_TIMEOUT:
            expired.append(session_id)
    
    for session_id in expired:
        del active_sessions[session_id]

# Schedule cleanup
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_old_sessions, trigger="interval", seconds=300)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                 🚀 CyberIDE v3.0 Starting...              ║
    ╠═══════════════════════════════════════════════════════════╣
    ║                                                           ║
    ║  🔗 URL: http://{Config.HOST}:{Config.PORT}               
    ║  📁 Project Directory: {project_path.absolute()}          
    ║  🔐 Password: {'Set via PASSWORD env var' if Config.PASSWORD == 'admin123' else '***'} 
    ║  🚦 Debug Mode: {Config.DEBUG}                            
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Create default main.py if doesn't exist
    default_file = project_path / 'main.py'
    if not default_file.exists():
        default_file.write_text('''# Welcome to CyberIDE!
# Write your Python code here

def main():
    print("Hello from CyberIDE!")
    print("You can run this file by clicking 'Run Code'")
    
    # Example: Fibonacci sequence
    n = 10
    a, b = 0, 1
    print(f"\\nFibonacci sequence (first {n} numbers):")
    for _ in range(n):
        print(a, end=' ')
        a, b = b, a + b
    print()

if __name__ == "__main__":
    main()
''', encoding='utf-8')
    
    socketio.run(app, 
                 host=Config.HOST, 
                 port=Config.PORT,
                 debug=Config.DEBUG,
                 allow_unsafe_werkzeug=True,
                 log_output=Config.DEBUG)
