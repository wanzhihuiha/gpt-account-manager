#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/ctgptm-mail-assistant"
ENV_FILE="/etc/ctgptm-mail-assistant.env"
SERVICE_FILE="/etc/systemd/system/ctgptm-mail-assistant.service"
DOMAIN="${CTGPTM_DOMAIN:-example.com}"
NGINX_SITE="/etc/nginx/sites-available/${DOMAIN}"
NGINX_LINK="/etc/nginx/sites-enabled/${DOMAIN}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash deploy/install-mail-assistant.sh"
  exit 1
fi

mkdir -p "${APP_DIR}" "${APP_DIR}/.cache" "${APP_DIR}/data"
chown -R www-data:www-data "${APP_DIR}" "${APP_DIR}/.cache" "${APP_DIR}/data"

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3-socks
elif python3 -m pip --version >/dev/null 2>&1; then
  python3 -m pip install PySocks
else
  echo "WARN: PySocks is not installed. Install python3-socks or PySocks before using socks5 proxy."
fi

if command -v npm >/dev/null 2>&1; then
  npm install --omit=dev --cache /tmp/gpt-account-manager-npm-cache --no-audit --no-fund
fi

cp deploy/ctgptm-mail-assistant.service "${SERVICE_FILE}"

if [[ ! -f "${ENV_FILE}" ]]; then
  cp deploy/mail-pickup.env.example "${ENV_FILE}"
  chown root:www-data "${ENV_FILE}"
  chmod 640 "${ENV_FILE}"
  echo "Created ${ENV_FILE}. Edit it before exposing the site."
fi

sed "s/example.com/${DOMAIN}/g" deploy/nginx.example.conf > "${NGINX_SITE}"
ln -sf "${NGINX_SITE}" "${NGINX_LINK}"

systemctl daemon-reload
systemctl enable ctgptm-mail-assistant
systemctl restart ctgptm-mail-assistant

nginx -t
systemctl reload nginx

echo
echo "GPT账号管理助手 installed."
echo "Check service: systemctl status ctgptm-mail-assistant --no-pager"
echo "Local probe:   curl -I http://127.0.0.1:8765/"
