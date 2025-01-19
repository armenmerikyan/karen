# karen
Personal \ Business \ Organizations \ AI Agents

# GameBackrooms Project Setup

This guide outlines the necessary steps to set up and configure your server and environment for the GameBackrooms project.

Before starting, make sure you have the following installed:

- Ubuntu server (or similar Linux distribution)
- A domain name pointing to your server (e.g., gamebackrooms.com)
- SSH access to your server

## 1. Install and Configure Nginx

Install Nginx and set it up to run automatically:

```bash
sudo apt install -y nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

Configure Nginx for the project:

```bash
sudo vi /etc/nginx/sites-available/default
```

Restart Nginx to apply changes:

```bash
sudo systemctl restart nginx
```

## 2. Install SSL with Certbot

Install Certbot and configure SSL for your domain:

```bash
sudo apt install certbot python3-certbot-nginx
sudo ufw allow 80/tcp   # Allows HTTP traffic on port 80
sudo ufw allow 443/tcp  # Allows HTTPS traffic on port 443
sudo certbot --nginx -d gamebackrooms.com -d www.gamebackrooms.com --email info@gamebackrooms.com
```

## 3. Set Up Python Virtual Environment

Install Python 3 and set up a virtual environment:

```bash
sudo apt install -y python3-venv
python3 -m venv gmenv
source gmenv/bin/activate
```

Update system packages and install Git:

```bash
sudo apt update
sudo apt install -y git
```

## 4. Set Up Systemd Service

Create and enable a systemd service for Athena:

```bash
sudo vi /etc/systemd/system/athena.service
sudo systemctl daemon-reload
sudo systemctl enable athena
```

## 5. Set Up SSH Keys

Generate SSH keys and configure the SSH agent:

```bash
cd ~/.ssh
ssh-keygen -t ed25519 -C "h12600653@gmail.com"
eval "$(ssh-agent -s)"
```

Clone the Athena repository:

```bash
git clone git@github.com:gamebackrooms/athena.git
```

## 6. Install Project Dependencies

Install the required Python packages:

```bash
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
```

## 7. Set Up the Django Project

Make migrations, apply them, and run the development server:

```bash
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py runserver
```

Create a superuser for the Django admin:

```bash
python manage.py createsuperuser
```

Ensure that all steps are completed for a smooth setup of the GameBackrooms project.
