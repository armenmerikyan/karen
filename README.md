# Karen

Web software for people, businesses, organizations, AI agents and much more.

- Friends/Contacts 
- Posts 
- Feeds 
- Wallets
- History 
- Admin
- Wallet Keys 
- Streaming
- Scheduling 
- Calendar public/private view
- Customers order/pay/lead cycle
- Products inventory/purchase order 
- Analytics
- Profile
- Admin Create Order
- Admin Make Payment
- Ai Agents 

# Project Setup

This guide outlines the necessary steps to set up and configure your server and environment for the Karen project.

Before starting, make sure you have the following installed:

- Ubuntu server (or similar Linux distribution)
- A domain name pointing to your server (e.g., YOURDOMANNAME.com)
- SSH access to your server
- To integrate email sending functionality into the Karen project, you'll need a SendGrid account and API key. Follow these steps to set it up:

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
```default
server {
	listen 80 default_server;
	listen [::]:80 default_server;
	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;

	server_name www.YOURDOMANNAME.com YOURDOMANNAME.com;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-CSRFToken $http_x_csrftoken;
        proxy_set_header X-CSRF-TOKEN $http_x_csrf_token;
	    proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
    }
} 
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
sudo certbot --nginx -d YOURDOMANNAME.com -d www.YOURDOMANNAME.com --email info@YOURDOMANNAME.com
```

## 3. Set Up Python Virtual Environment

Install Python 3 and set up a virtual environment:

```bash
sudo apt install -y python3-venv
python3 -m venv kenv
source kenv/bin/activate
```

Update system packages and install Git:

```bash
sudo apt update
sudo apt install -y git
```

## 4. Set Up Systemd Service

Create and enable a systemd service for Karen:

```bash
sudo vi /etc/systemd/system/karen.service
sudo systemctl daemon-reload
sudo systemctl enable karen
```

```Service
[Unit]
Description=Django Web Application
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/root/karen

Environment="ALLOWED_HOSTS=YOURDOMAINNAME.com"
Environment="EMAIL_HOST_PASSWORD=YOURAPIKEY"
Environment="DEFAULT_FROM_EMAIL=INFO@YOURDOMAINNAME.COM"
# Use the Python interpreter from the virtual environment to run the Django server
ExecStart=/root/kenv/bin/python /root/karen/manage.py runserver 127.0.0.1:8000

Restart=always

[Install]
WantedBy=multi-user.target
```

## 5. Clone the Karen repository

```bash
git clone https://github.com/armenmerikyan/karen.git

```

## 6. Install Project Dependencies

Install the required Python packages:

```bash
sudo apt update
sudo apt install sqlite3

pip install -r requirements.txt

```

## 7. Set Up the Django Project

Make migrations, apply them, and run the development server:

```bash
python3 manage.py makemigrations
python3 manage.py migrate

sudo systemctl start karen 



```

Create a superuser for the Django admin:

```bash
python3 manage.py createsuperuser
```

Ensure that all steps are completed for a smooth setup of the Karen project.

 

