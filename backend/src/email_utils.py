"""Email utility module for sending OTP and notifications"""
import os
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

# SMTP Configuration
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', 'IT Case Log <noreply@caselog.local>')


def generate_otp(length=6):
    """Generate a random OTP code"""
    return ''.join(random.choices(string.digits, k=length))


def send_email(to_email: str, subject: str, html_body: str) -> dict:
    """Send an email via SMTP"""
    if not SMTP_USER or not SMTP_PASS:
        # If SMTP not configured, log and return success for development
        print(f"[DEV MODE] Email would be sent to {to_email}: {subject}")
        return {'success': True, 'message': 'Email logged (SMTP not configured)'}
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = SMTP_FROM
        msg['To'] = to_email
        msg['Subject'] = subject
        
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to_email, msg.as_string())
        
        return {'success': True, 'message': 'Email sent successfully'}
    except Exception as e:
        print(f"Email error: {e}")
        return {'success': False, 'error': str(e)}


def send_otp_email(to_email: str, otp_code: str, purpose: str) -> dict:
    """Send OTP email for verification"""
    
    if purpose == 'register':
        subject = "Your Registration OTP - IT Case Log"
        title = "Email Verification"
        message = "Please use the following OTP to verify your email address:"
    elif purpose == 'reset_password':
        subject = "Password Reset OTP - IT Case Log"
        title = "Password Reset"
        message = "You have requested to reset your password. Use this OTP to continue:"
    else:
        subject = "Your OTP Code - IT Case Log"
        title = "Verification"
        message = "Your verification code:"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
            .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 20px; }}
            .header h1 {{ color: #667eea; margin: 0; }}
            .otp-box {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0; }}
            .message {{ color: #666; text-align: center; }}
            .footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 {title}</h1>
            </div>
            <p class="message">{message}</p>
            <div class="otp-box">{otp_code}</div>
            <p class="message">This code will expire in <strong>10 minutes</strong>.</p>
            <p class="message">If you did not request this, please ignore this email.</p>
            <div class="footer">
                <p>IT Case Log Management System</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(to_email, subject, html_body)
