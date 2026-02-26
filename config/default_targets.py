"""
Default target paths and protocol definitions for PhantomLFI.
Done by D4rk0ps
"""

# =====================================================================
# Linux Target Files
# =====================================================================

LINUX_SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/etc/group",
    "/etc/motd",
    "/etc/mysql/my.cnf",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/environment",
    "/etc/resolv.conf",
    "/etc/fstab",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/proc/self/status",
    "/proc/self/maps",
    "/proc/version",
    "/proc/net/tcp",
    "/proc/sched_debug",
]

LINUX_LOG_FILES = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/apache/access.log",
    "/var/log/apache/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/mail.log",
    "/var/log/vsftpd.log",
    "/var/log/lastlog",
    "/var/log/faillog",
    "/var/log/dpkg.log",
    "/var/log/btmp",
    "/var/log/wtmp",
]

LINUX_APACHE_PATHS = [
    "/etc/apache2/apache2.conf",
    "/etc/apache2/sites-available/000-default.conf",
    "/etc/apache2/sites-enabled/000-default.conf",
    "/etc/apache2/ports.conf",
    "/etc/apache2/envvars",
    "/etc/httpd/conf/httpd.conf",
    "/usr/local/apache2/conf/httpd.conf",
    "/usr/local/etc/apache2/httpd.conf",
    "/opt/lampp/etc/httpd.conf",
]

LINUX_NGINX_PATHS = [
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-available/default",
    "/etc/nginx/sites-enabled/default",
    "/etc/nginx/conf.d/default.conf",
    "/usr/local/nginx/conf/nginx.conf",
    "/usr/local/etc/nginx/nginx.conf",
]

LINUX_PHP_SESSION_PATHS = [
    "/var/lib/php/sessions/sess_SESSIONID",
    "/var/lib/php5/sessions/sess_SESSIONID",
    "/var/lib/php/sess_SESSIONID",
    "/tmp/sess_SESSIONID",
    "/tmp/php_sessions/sess_SESSIONID",
]

LINUX_SSH_KEYS = [
    "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/known_hosts",
    "/home/USER/.ssh/id_rsa",
    "/home/USER/.ssh/authorized_keys",
]

LINUX_WEB_CONFIG = [
    "/var/www/html/.htaccess",
    "/var/www/html/wp-config.php",
    "/var/www/html/config.php",
    "/var/www/html/.env",
    "/var/www/html/configuration.php",
    "/var/www/html/LocalSettings.php",
    "/var/www/html/includes/configure.php",
]

# =====================================================================
# Windows Target Files
# =====================================================================

WINDOWS_SENSITIVE_FILES = [
    r"C:\Windows\win.ini",
    r"C:\Windows\system.ini",
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\System32\config\SYSTEM",
    r"C:\Windows\System32\config\SECURITY",
    r"C:\Windows\debug\NetSetup.LOG",
    r"C:\Windows\repair\SAM",
    r"C:\Windows\repair\SYSTEM",
    r"C:\boot.ini",
    r"C:\inetpub\wwwroot\web.config",
    r"C:\inetpub\logs\LogFiles",
    r"C:\xampp\apache\conf\httpd.conf",
    r"C:\xampp\php\php.ini",
    r"C:\xampp\mysql\bin\my.ini",
    r"C:\xampp\passwords.txt",
    r"C:\xampp\htdocs\.env",
    r"C:\Users\Administrator\Desktop\desktop.ini",
    r"C:\Users\Administrator\NTUser.dat",
    r"C:\Program Files\MySQL\my.ini",
]

# =====================================================================
# RFI Protocols & Shells
# =====================================================================

RFI_SHELL_FILES = [
    "shell.txt",
    "shell.php",
    "cmd.php",
    "rev.php",
    "backdoor.php",
    "webshell.txt",
    "rce.txt",
    "exec.php",
]

RFI_PROTOCOLS = [
    "http://",
    "https://",
    "ftp://",
    "ftps://",
    "sftp://",
]

# =====================================================================
# PHP Wrapper Targets
# =====================================================================

PHP_WRAPPER_TARGETS = [
    "index.php",
    "config.php",
    "login.php",
    "admin.php",
    "upload.php",
    "include.php",
    "header.php",
    "footer.php",
    "functions.php",
    "db.php",
    "connect.php",
    "settings.php",
    "wp-config.php",
    "configuration.php",
]
