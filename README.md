# CyberIDE - Web-based Python IDE

A feature-rich web-based IDE for Python development with real-time collaboration, terminal access, and file management.

## Features

- 🚀 **Web-based Interface** - Access from any browser
- 📁 **File Management** - Create, edit, delete, rename files
- 💻 **Terminal Access** - Execute shell commands safely
- 🐍 **Python Execution** - Run Python code directly
- 🔒 **Password Protection** - Secure access control
- 📱 **Responsive Design** - Works on desktop and mobile
- ⚡ **Real-time Updates** - Live terminal output
- 🔄 **Auto-save** - Automatically saves your work
- 🎨 **Syntax Highlighting** - Code editor with syntax highlighting
- 📊 **System Monitoring** - CPU, memory, disk usage

## Installation

### Method 1: Using Git

```bash
# Clone repository
git clone <repository-url>
cd my_projects

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set password (optional)
export PASSWORD=yourpassword
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Run the application
python app.py
