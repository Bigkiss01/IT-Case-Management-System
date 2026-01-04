"""
Database Backup Module
Runs daily at 2:00 AM (Bangkok time) and overwrites the previous backup
"""
import os
import subprocess
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import pytz

# Backup directory
BACKUP_DIR = os.environ.get('BACKUP_DIR', '/tmp/backups')
BACKUP_FILENAME = 'caselog_backup.sql'

def ensure_backup_dir():
    """Create backup directory if it doesn't exist"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

def run_backup():
    """Execute mysqldump to backup the database"""
    try:
        ensure_backup_dir()
        
        # Get database credentials from environment
        db_host = os.environ.get('MYSQLHOST') or os.environ.get('DB_HOST', 'localhost')
        db_port = os.environ.get('MYSQLPORT') or os.environ.get('DB_PORT', '3306')
        db_user = os.environ.get('MYSQLUSER') or os.environ.get('DB_USER', 'case_user')
        db_pass = os.environ.get('MYSQLPASSWORD') or os.environ.get('DB_PASS', 'case_pass')
        db_name = os.environ.get('MYSQLDATABASE') or os.environ.get('DB_NAME', 'caselog_db')
        
        backup_path = os.path.join(BACKUP_DIR, BACKUP_FILENAME)
        
        # Run mysqldump command
        cmd = [
            'mysqldump',
            f'--host={db_host}',
            f'--port={db_port}',
            f'--user={db_user}',
            f'--password={db_pass}',
            '--single-transaction',
            '--routines',
            '--triggers',
            db_name
        ]
        
        with open(backup_path, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            file_size = os.path.getsize(backup_path)
            print(f"[BACKUP] Success: {backup_path} ({file_size} bytes) at {datetime.now()}")
            return True, f"Backup completed: {file_size} bytes"
        else:
            print(f"[BACKUP] Failed: {result.stderr}")
            return False, result.stderr
            
    except Exception as e:
        print(f"[BACKUP] Error: {str(e)}")
        return False, str(e)

def init_backup_scheduler(app):
    """Initialize the backup scheduler"""
    # Only run scheduler in production (not in development with reloader)
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
        scheduler = BackgroundScheduler()
        
        # Bangkok timezone
        bangkok_tz = pytz.timezone('Asia/Bangkok')
        
        # Schedule backup at 2:00 AM Bangkok time every day
        scheduler.add_job(
            run_backup,
            CronTrigger(hour=2, minute=0, timezone=bangkok_tz),
            id='daily_backup',
            name='Daily Database Backup',
            replace_existing=True
        )
        
        scheduler.start()
        print("[SCHEDULER] Database backup scheduled for 2:00 AM Bangkok time daily")
        
        return scheduler
    return None
