# karen
Personal / Business Website Application


#Instructions 

 

# Nginx and Python Environment Setup

This guide provides step-by-step instructions for setting up Nginx, a Python virtual environment, and configuring HTTPS for your server.

## Prerequisites
Ensure you have sudo privileges on your server.

---

## Steps

### 1. Update and Install Nginx
```bash
sudo apt update
sudo apt install -y nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

### 2. Configure Nginx
Edit the default Nginx configuration file:
```bash
sudo vi /etc/nginx/sites-available/default
```
After making changes, restart Nginx:
```bash
sudo systemctl restart nginx
```

### 3. Set Up Python Virtual Environment
```bash
sudo apt install -y python3-venv
python3 -m venv gmenv
source gmenv/bin/activate
```

### 4. Install Certbot for HTTPS
```bash
sudo apt install certbot python3-certbot-nginx
```
Allow HTTP and HTTPS traffic through the firewall:
```bash
sudo ufw allow 80/tcp   # Allows HTTP traffic on port 80
sudo ufw allow 443/tcp  # Allows HTTPS traffic on port 443
```
Generate SSL certificates using Certbot:
```bash
sudo certbot --nginx -d gamebackrooms.com -d www.gamebackrooms.com --email info@gamebackrooms.com
```

### 5. Install Git
```bash
sudo apt update
sudo apt install -y git
```

### 6. Configure and Enable Systemd Service
Create a systemd service file:
```bash
sudo vi /etc/systemd/system/athena.service
```
Reload systemd and enable the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable athena
```

---

## Notes
- Replace `gamebackrooms.com` and `info@gamebackrooms.com` with your actual domain and email.
- Ensure your Nginx configuration file is correctly set up to point to your web application.
- Test your server setup thoroughly after completing these steps.


cd ~/.ssh
ssh-keygen -t ed25519 -C "h12600653@gmail.com"
eval "$(ssh-agent -s)"
git clone git@github.com:gamebackrooms/athena.git

pip install django
pip install django-allauth
pip install django-cors-headers
pip install PyJWT
pip install openai==0.28.0
pip install Pillow
pip install lxml
pip install pandas
pip install base58
pip install pynacl
pip install social-auth-app-django
pip install djangorestframework
pip install psycopg2-binary

python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py runserver
python manage.py createsuperuser