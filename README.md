# The All-in-One Solution

**Karen** It’s everything you need to manage relationships, streamline processes, and grow your community effortlessly.

---

## Key Features

## Model Context Protocol (MCP) Server

Overview

- The Model Context Protocol (MCP) Server provides an API-driven approach to managing business context and support services. This server enables businesses to integrate their data with MCP-compatible formats, authenticate via custom header authentication, and manage business records efficiently.

Features

- Business Management: Create, retrieve, update, and delete business records.

- Authentication: Custom header-based API key authentication.

- Support Ticket System: Manage support tickets for businesses.

- User Authentication: Register and log in users with JWT authentication.

- Cleaning & Immigration Services: API endpoints for submitting cleaning and immigration case requests.

- Letter Management: Create and search for letters.

LIVE 

## AI MicroAgent

Check out our AI MicroAgent: [AI MicroAgent Chat](https://chatgpt.com/g/g-67d73144560c819199fae7be98138390-aimicroagent)

### Customer Relationship Management 
- Customer Relationship Management (CRM)  
- Loyalty Program Management  
- Customer Support & Helpdesk  
- Customer Life Cycles: List, Add, Edit, Visibility Settings  
- Contacts & Friends Management  
- **Q&A: Frequently Asked Questions (FAQs) & Knowledge Base Integration**  
- **Customer Feedback & Survey Management**  

### Sales, Revenue & Financial Management  
- Sales & Revenue Management  
- Order & Invoice Processing  
- Payments & Carts  
- Financial Management  
- Admin Tools: Create Orders, Make Payments  
- **Q&A: Sales Queries & Order Status Tracking**  
- **Revenue Forecasting & Financial Reporting Tools**  

### Operations & Workflow Automation  
- Operations & Workflow Automation  
- Scheduling & Calendar (Public/Private)  
- Project & Task Management  
- Compliance & Risk Management  
- **Q&A: Workflow Troubleshooting & Process Optimization**  
- **Automated Notifications & Alerts**  

### Content & Streaming  
- Streaming and Content Management  
- Posts & Feeds  
- Communication Tools  
- **Q&A: Content Moderation & User Engagement Analytics**  
- **Live Chat & Real-Time Interaction Tools**  

### Inventory & Product Management  
- Inventory & Supply Chain Management  
- Product Life Cycles: List, Add, Edit, Visibility Settings  
- Products: List, Add, Edit  
- Asset & Equipment Tracking  
- Vendor & Procurement Management  
- Point of Sale (POS) Integration  
- Product Lifecycle Management  
- **Q&A: Inventory Tracking & Stock Alerts**  
- **Vendor Performance & Procurement Analytics**  

### Marketing, Analytics & Reporting  
- Marketing Automation & Campaign Management  
- Business Intelligence & Reporting  
- Analytics Dashboard  
- **Q&A: Campaign Performance & ROI Analysis**  
- **Customer Segmentation & Targeting Tools**  

### Human Resources & Administration  
- Employee Time Tracking & Scheduling  
- Human Resources & Payroll  
- Training & Development Platforms  
- **Q&A: Employee Queries & HR Policy Clarifications**  
- **Performance Reviews & Employee Feedback Systems**  

### AI-Powered Chatbot & LLM Integration  
- **Chatbot Feature**:  
  - AI-driven chatbot powered by fine-tuned ChatGPT (LLM).  
  - Seamless integration with product data, Q&A databases, and customer interactions.  
  - Real-time responses to customer inquiries, order tracking, and support requests.  
  - Multilingual support for global user bases.  
- **Fine-Tuning Process**:  
  - Product data (e.g., inventory, product lifecycles, pricing) and Q&A data (e.g., FAQs, customer feedback) are used to train and fine-tune the ChatGPT model.  
  - Ensures the chatbot provides accurate, context-aware, and brand-specific responses.  
- **LLM as a Service**:  
  - Deploy the fine-tuned LLM as a chatbot service on your website or platform.  
  - Enables personalized customer interactions, sales assistance, and operational support.  
  - Continuously learns and improves from user interactions and feedback.  
- **Use Cases**:  
  - Customer Support: Resolve queries instantly using the knowledge base.  
  - Sales Assistance: Recommend products, provide pricing details, and process orders.  
  - Employee Assistance: Answer HR-related questions and provide training resources.  

---

## Tech Stack

- **Backend:** Django (Live Streaming), Rust (Solana Smart Contracts)  
- **Blockchain:** Solana for Wallet Integration and SPL Tokens  
- **Database:** PostgreSQL (Relational), Redis (Caching)  
- **APIs:** REST  
- **Deployment:** Docker, Kubernetes, AWS/GCP  

---

## Admin Features

- Admin Dashboard for Profiles, Tokens, Customers, Products, Life Cycles, and Orders  
- Wallet Keys Management  
- Analytics & Reporting Tools  
- AI Agents Integration  

---

## User Features

- Profile Management: Name, About, Wallet  
- Tokens: List, Add, Edit  
- Friends & Contacts  
- Posts & Feeds  
- Wallets & Transaction History  

---

## Why Choose Karen?

- **Universal Compatibility:** Perfect for any type of operation, big or small.  
- **Scalability:** Grows with your business needs.  
- **Efficiency:** Streamlines workflows to save time and reduce costs.  

---

**Ready to revolutionize how you work?**  
Check out Karen's GitHub repository and get started today!


# Project Setup

This guide outlines the necessary steps to set up and configure your server and environment for the Karen project.

Before starting, make sure you have the following installed:

- Ubuntu server (or similar Linux distribution) with SSH access to your server, you can purchase one https://www.vultr.com 
- A domain name pointing to your server (e.g., YOURDOMANNAME.com), you can purchase one at https://www.namecheap.com 
- To integrate email sending functionality into the Karen project, you'll need a SendGrid account and API key. You can purchase one at https://sendgrid.com

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
    
    location /media/product_files/ {
        deny all;
    }

    location /solana_payment/ {
        proxy_pass http://127.0.0.1:8080;  # Forward requests to the service on port 8081
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-CSRFToken $http_x_csrftoken;
        proxy_set_header X-CSRF-TOKEN $http_x_csrf_token;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        client_max_body_size 1G;
    }
        
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

## caddy

```caddy

# The Caddyfile is an easy way to configure your Caddy web server.
#
# Unless the file starts with a global options block, the first
# uncommented line is always the address of your site.
#
# To use your own domain name (with automatic HTTPS), first make
# sure your domain's A/AAAA DNS records are properly pointed to
# this machine's public IP, then replace ":80" below with your
gigahard.ai, *.gigahard.ai {
    # Block access to /media/product_files/*
    @media {
        path /media/product_files/*
    }
    respond @media 403

    # Set maximum request body size to 1G
    request_body {
        max_size 1G
    }

    # Reverse proxy for /solana_payment/*
    handle /solana_payment/* {
        reverse_proxy 127.0.0.1:8080 {
            header_up Host {host}
            header_up X-Real-IP {remote}
            header_up X-CSRFToken {http.X-CSRFToken}
            header_up X-CSRF-TOKEN {http.X-CSRF-TOKEN}
            transport http {
                read_timeout 600s
                write_timeout 600s
            }
        }
    }

    # Reverse proxy for all other requests (Django)
    handle /* {
        reverse_proxy 127.0.0.1:8000 {
            header_up Host {host}
            header_up X-Real-IP {remote}
            header_up X-CSRFToken {http.X-CSRFToken}
            header_up X-CSRF-TOKEN {http.X-CSRF-TOKEN}
            transport http {
                read_timeout 600s
                write_timeout 600s
            }
        }
    }
}
# domain name.# this machine's public IP, then replace ":80" below with your
```
## 2. Install SSL with Certbot

Install Certbot and configure SSL for your domain:

```bash
sudo apt install certbot python3-certbot-nginx
sudo ufw allow 80/tcp   # Allows HTTP traffic on port 80
sudo ufw allow 443/tcp  # Allows HTTPS traffic on port 443
sudo certbot --nginx -d YOURDOMANNAME.com -d www.YOURDOMANNAME.com --email info@YOURDOMANNAME.com
```
## 2.5 Docker install 
```bash 
sudo apt update

sudo apt install apt-transport-https ca-certificates curl software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update

sudo apt install docker-ce
sudo systemctl status docker
sudo systemctl start docker
sudo usermod -aG docker $USER
docker --version

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
cd karen 

python3 manage.py makemigrations
python3 manage.py migrate

sudo systemctl start karen 



```

Create a superuser for the Django admin:

```bash
python3 manage.py createsuperuser
```

Ensure that all steps are completed for a smooth setup of the Karen project.

 

