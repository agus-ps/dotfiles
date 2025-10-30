set -euo pipefail

TS=$(date -u +"%Y%m%dT%H%M%SZ")
# --- 1) Backups de nginx y systemd units ---
mkdir -p /root/nginx-backups
tar czf /root/nginx-backups/nginx-etc-logs-backup-$TS.tar.gz /etc/nginx /var/log/nginx || true
cp /etc/systemd/system/cordobitec.service /root/nginx-backups/cordobitec.service.$TS || true

# --- 2) Stop & disable services (Gunicorn + Nginx) ---
systemctl stop nginx.service || true
systemctl disable nginx.service || true

# preserve the gunicorn systemd unit but stop it
if systemctl list-units --full -all | grep -q cordobitec.service; then
  systemctl stop cordobitec.service || true
  systemctl disable cordobitec.service || true
fi

# --- (optional) purge nginx packages (uncomment to remove) ---
# apt-get update
# apt-get purge -y nginx nginx-core nginx-common nginx-full || true
# apt-get autoremove -y || true

# --- 3) Install Apache + mod_wsgi + tools + ModSecurity CRS packages ---
apt-get update
apt-get install -y apache2 apache2-utils libapache2-mod-wsgi-py3 python3-venv python3-pip

# Install ModSecurity (package name on Ubuntu/debian)
apt-get install -y libapache2-mod-security2 modsecurity-crs || true

# enable modules
a2enmod wsgi rewrite headers proxy proxy_http ssl
# ModSecurity module should be auto-enabled by package; ensure it's enabled:
if [ -e /etc/modsecurity/modsecurity.conf ]; then
  a2enmod security2 || true
fi

# --- 4) Prepare app directory & permissions ---
APPDIR=/var/www/cordobitec
# ensure ownership allows Apache (www-data) to access files and virtualenv
chown -R www-data:www-data $APPDIR
find $APPDIR -type d -exec chmod 2755 {} \;
find $APPDIR -type f -exec chmod 0644 {} \;

# --- 5) Create WSGI entrypoint file (app.wsgi) ---
cat > $APPDIR/app.wsgi <<'WSGI'
import sys, os
# point to project
proj = os.path.dirname(__file__)
if proj not in sys.path:
    sys.path.insert(0, proj)
# activate virtualenv (if used)
venv = os.path.join(proj, 'env')
activate = os.path.join(venv, 'bin', 'activate_this.py')
if os.path.exists(activate):
    with open(activate) as f:
        exec(f.read(), dict(__file__=activate))
from app import app as application
WSGI
chown www-data:www-data $APPDIR/app.wsgi
chmod 644 $APPDIR/app.wsgi

# --- 6) Create Apache VirtualHost for cordobitec (HTTP) ---
cat > /etc/apache2/sites-available/cordobitec.conf <<'APV'
<VirtualHost *:80>
    ServerName cordobitec
    ServerAdmin webmaster@localhost

    DocumentRoot /var/www/cordobitec

    <Directory /var/www/cordobitec>
        Require all granted
        Options FollowSymLinks
        AllowOverride All
    </Directory>

    # WSGI config using site's virtualenv
    WSGIDaemonProcess cordobitec python-home=/var/www/cordobitec/env python-path=/var/www/cordobitec
    WSGIProcessGroup cordobitec
    WSGIScriptAlias / /var/www/cordobitec/app.wsgi

    ErrorLog ${APACHE_LOG_DIR}/cordobitec-error.log
    CustomLog ${APACHE_LOG_DIR}/cordobitec-access.log combined
</VirtualHost>
APV

# enable site; disable default
a2ensite cordobitec.conf
a2dissite 000-default.conf || true

# --- 7) Configure ModSecurity minimal + OWASP CRS link (DetectionOnly) ---
# Ensure modsecurity main conf exists; set SecRuleEngine DetectionOnly
if [ -f /etc/modsecurity/modsecurity.conf ]; then
  # backup
  cp /etc/modsecurity/modsecurity.conf /etc/modsecurity/modsecurity.conf.bak.$TS
  # set DetectionOnly (replace SecRuleEngine value)
  sed -i "s/SecRuleEngine .*$/SecRuleEngine DetectionOnly/" /etc/modsecurity/modsecurity.conf || true
fi

# Deploy CRS rules if package installed (locations may vary)
if [ -d /usr/share/modsecurity-crs ]; then
  mkdir -p /etc/modsecurity/crs
  cp -r /usr/share/modsecurity-crs /etc/modsecurity/crs || true
  # activate recommended rules (path depends on package)
  # create symlink for apache include if needed
  if [ -f /etc/modsecurity/crs/crs-setup.conf.example ]; then
    cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf || true
  fi
fi

# Ensure Apache ModSecurity includes the CRS base rules (try to create include)
CRS_INCLUDE=/etc/apache2/modsecurity.d/activated_rules.conf
mkdir -p $(dirname $CRS_INCLUDE)
cat > $CRS_INCLUDE <<'CRS'
# Include OWASP CRS rules if present
# Adjust path if your distribution places CRS elsewhere
IncludeOptional /etc/modsecurity/crs/rules/*.conf
CRS

# Tell Apache to include modsecurity conf (some packages do it automatically)
if ! grep -q "IncludeOptional /etc/apache2/modsecurity.d/activated_rules.conf" /etc/apache2/apache2.conf 2>/dev/null; then
  echo "IncludeOptional /etc/apache2/modsecurity.d/activated_rules.conf" >> /etc/apache2/apache2.conf
fi

# --- 8) Restart Apache to apply config ---
systemctl reload-or-restart apache2

# --- 9) Disable old systemd gunicorn unit (optional remove) ---
if [ -f /etc/systemd/system/cordobitec.service ]; then
  mv /etc/systemd/system/cordobitec.service /root/nginx-backups/cordobitec.service.$TS || true
  systemctl daemon-reload || true
fi

# --- 10) Integrate Apache & ModSecurity logs into Wazuh agent ---
# Backup ossec.conf
OSSEC_CONF=/var/ossec/etc/ossec.conf
cp $OSSEC_CONF $OSSEC_CONF.bak.$TS

python3 - <<'PY'
from pathlib import Path
p=Path("/var/ossec/etc/ossec.conf")
txt=p.read_text()
insert = """
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/apache2/cordobitec-access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/apache2/cordobitec-error.log</location>
  </localfile>
  <localfile>
    <log_format>plain</log_format>
    <location>/var/log/apache2/modsec_audit.log</location>
  </localfile>
"""
# try to place before closing tag </ossec_config>
if "</ossec_config>" in txt:
    txt = txt.replace("</ossec_config>", insert + "\n</ossec_config>")
else:
    txt = txt + "\n" + insert
p.write_text(txt)
print("Inserted localfile blocks into /var/ossec/etc/ossec.conf (backup created).")
PY

# restart wazuh-agent to pick new config
if systemctl list-unit-files | grep -q wazuh-agent; then
  systemctl restart wazuh-agent || true
fi

# --- 11) Quick tests ---
echo "=== Apache status ==="
systemctl status apache2 --no-pager || true

echo "=== Test HTTP locally ==="
curl -I http://127.0.0.1 || true

echo "=== Tail access log (press Ctrl+C to stop) ==="
tail -n 50 /var/log/apache2/cordobitec-access.log || true

echo "=== Tail modsec audit log (if exists) ==="
ls -l /var/log/apache2/modsec_audit.log || true

echo "Done. Backups in /root/nginx-backups/"
