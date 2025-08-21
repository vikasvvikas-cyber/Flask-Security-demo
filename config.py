# config.py - Configuration file with sensitive data exposed

import os

class Config:
    # Vulnerability: Hardcoded secret key
    SECRET_KEY = 'dev-secret-key-12345-never-use-in-prod'
    
    # Database configuration with hardcoded credentials
    DATABASE_CONFIG = {
        'host': '192.168.1.50',
        'port': 3306,
        'username': 'db_admin',
        'password': 'MySecretDB@2024!',
        'database': 'vulnerable_app_db'
    }
    
    # API Keys and tokens (hardcoded - major vulnerability)
    API_KEYS = {
        'openai_api_key': 'sk-proj-1234567890abcdefghijklmnopqrstuvwxyz',
        'stripe_secret_key': 'sk_test_51234567890abcdefghijk',
        'aws_access_key': 'AKIAIOSFODNN7EXAMPLE',
        'aws_secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'jwt_secret': 'super-secret-jwt-key-2024',
        'encryption_key': 'AES256-encryption-key-example'
    }
    
    # Server configuration
    SERVER_CONFIG = {
        'host': '0.0.0.0',  # Vulnerability: Binding to all interfaces
        'port': 5000,
        'debug': True,      # Vulnerability: Debug mode in production
        'internal_ip': '10.0.0.100',
        'external_ip': '203.0.113.45'
    }
    
    # Admin credentials (hardcoded)
    ADMIN_CREDENTIALS = {
        'username': 'admin',
        'password': 'Admin@123',
        'email': 'admin@vulnerable-app.com',
        'backup_email': 'backup-admin@company.internal'
    }
    
    # Third-party service configurations
    EXTERNAL_SERVICES = {
        'redis_url': 'redis://admin:password123@192.168.1.60:6379/0',
        'mongodb_uri': 'mongodb://dbuser:dbpass456@192.168.1.70:27017/appdb',
        'elasticsearch_host': 'http://elastic:elasticpass@192.168.1.80:9200',
        'rabbitmq_url': 'amqp://guest:guest@192.168.1.90:5672/'
    }
    
    # Email configuration
    EMAIL_CONFIG = {
        'smtp_server': 'smtp.company.com',
        'smtp_port': 587,
        'email_user': 'notifications@company.com',
        'email_password': 'EmailPass2024!',
        'use_tls': True
    }
    
    # OAuth credentials
    OAUTH_CREDENTIALS = {
        'google_client_id': '123456789-abcdefghijklmnop.apps.googleusercontent.com',
        'google_client_secret': 'GOCSPX-abcdefghijklmnopqrstuvwxyz',
        'github_client_id': '1234567890abcdef1234',
        'github_client_secret': '1234567890abcdef1234567890abcdef12345678'
    }
    
    # Logging configuration
    LOGGING_CONFIG = {
        'log_level': 'DEBUG',
        'log_file': '/var/log/vulnerable-app.log',
        'log_api_keys': True,  # Vulnerability: Logging sensitive data
        'log_passwords': True  # Vulnerability: Logging passwords
    }

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False
    # Additional dev-specific credentials
    DEV_DATABASE_URL = 'postgresql://dev_user:dev_pass_123@localhost:5432/dev_db'
    DEV_API_KEY = 'dev-api-key-not-for-production'

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # Still has hardcoded values - vulnerability!
    PROD_DATABASE_URL = 'postgresql://prod_user:ProdSecretPass2024@prod-db.company.com:5432/prod_db'
    PROD_API_KEY = 'prod-api-key-super-secret-xyz789'

# Current configuration (vulnerability: defaults to development)
current_config = DevelopmentConfig()

# Backup credentials (often overlooked)
BACKUP_CREDENTIALS = {
    'ftp_server': 'backup.company.com',
    'ftp_username': 'backup_user',
    'ftp_password': 'BackupPass2024!',
    'backup_encryption_key': 'backup-encrypt-key-123456'
}