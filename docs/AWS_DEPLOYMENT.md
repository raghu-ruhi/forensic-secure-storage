# AWS EC2 Deployment Guide

Deploys the full stack (Postgres + Flask backend + React frontend) to a single
Ubuntu EC2 instance using Docker Compose, fronted by Nginx with HTTPS.

## 1. Launch the EC2 instance

1. AWS Console → EC2 → **Launch instance**
2. AMI: **Ubuntu Server 24.04 LTS**
3. Instance type: **t3.medium** or larger (t3.micro will be tight with Postgres + 2 app containers)
4. Key pair: create or select one, download the `.pem` file
5. Network settings → create/select a security group and open:
   - **22** (SSH) — your IP only
   - **80** (HTTP) — anywhere
   - **443** (HTTPS) — anywhere
   - *(5000/5173 only if you want to test containers directly before putting Nginx in front)*
6. Storage: 20 GB gp3 is plenty
7. Launch, then note the instance's **public IPv4 address**

## 2. Connect

```bash
chmod 400 your-key.pem
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

## 3. Install Docker

Copy `scripts/ec2_bootstrap.sh` to the instance (or `git clone` your repo first,
then run it from there):

```bash
scp -i your-key.pem scripts/ec2_bootstrap.sh ubuntu@YOUR_EC2_PUBLIC_IP:~
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
bash ec2_bootstrap.sh
exit   # log out so the docker group membership takes effect
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP   # log back in
```

## 4. Clone your repository

```bash
git clone https://github.com/your-username/forensic-secure-storage.git
cd forensic-secure-storage
```

## 5. Configure environment

```bash
cp .env.example .env
nano .env
```

Set at minimum:
- `SECRET_KEY`, `JWT_SECRET_KEY` — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`
- `MAIL_USERNAME`, `MAIL_PASSWORD` — a real mailbox + app password for OTP emails
- `FRONTEND_ORIGIN=http://YOUR_EC2_PUBLIC_IP` (or your domain, once you have one)
- `VITE_API_BASE_URL=http://YOUR_EC2_PUBLIC_IP/api` (goes through the Nginx reverse proxy from step 7)

## 6. Run with Docker Compose

```bash
docker compose up --build -d
docker compose ps          # confirm all 3 containers are healthy/running
docker compose logs -f backend   # watch backend logs, Ctrl+C to stop tailing
```

The stack is now reachable at `http://YOUR_EC2_PUBLIC_IP:5173` (frontend) and
`http://YOUR_EC2_PUBLIC_IP:5000/api` (backend), but for a clean production URL
without exposing raw ports, set up the reverse proxy below.

## 7. Configure Nginx reverse proxy

```bash
sudo apt-get install -y nginx
sudo cp scripts/nginx_reverse_proxy.conf /etc/nginx/sites-available/forensic-secure-storage
sudo nano /etc/nginx/sites-available/forensic-secure-storage   # replace your-domain.com
sudo ln -s /etc/nginx/sites-available/forensic-secure-storage /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

Now `http://YOUR_EC2_PUBLIC_IP` (port 80) serves the frontend, and
`http://YOUR_EC2_PUBLIC_IP/api/...` proxies to the backend. Update `.env`'s
`VITE_API_BASE_URL` to `http://YOUR_EC2_PUBLIC_IP/api` and rebuild the frontend
container (`docker compose up --build -d frontend`) since Vite bakes the API
URL in at build time.

## 8. Enable HTTPS with Let's Encrypt

Requires a real domain name pointed at your EC2 IP (an A record).

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

Certbot edits the Nginx config to add the SSL block and sets up auto-renewal.
Verify auto-renewal works:

```bash
sudo certbot renew --dry-run
```

After this, update `FRONTEND_ORIGIN` and `VITE_API_BASE_URL` in `.env` to use
`https://your-domain.com`, then `docker compose up --build -d`.

## 9. S3 storage integration

Implemented - see **[AWS_S3_EC2.md](AWS_S3_EC2.md)** (bucket setup, instance role, least-privilege IAM policy,
security groups, production compose file and verification checklist).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `docker compose up` fails on `db` health check | Postgres taking >50s to start; increase `retries` in docker-compose.yml |
| Frontend loads but API calls fail (CORS error) | `FRONTEND_ORIGIN` in backend env doesn't match the URL you're browsing from |
| OTP emails never arrive | Check `MAIL_USERNAME`/`MAIL_PASSWORD` — for Gmail, use an **App Password**, not your normal password |
| 502 from Nginx | Backend container isn't running — check `docker compose logs backend` |
| Uploaded evidence disappears after `docker compose down` | You ran `docker compose down -v` (removes volumes) instead of `docker compose down` |
