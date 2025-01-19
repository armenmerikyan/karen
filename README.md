# karen
Personal / Business Website Application


#Instructions 

sudo apt update
sudo apt install -y nginx
sudo systemctl start nginx
sudo systemctl enable nginx
sudo vi /etc/nginx/sites-available/default
sudo systemctl restart nginx
sudo apt install -y python3-venv
sudo apt install certbot python3-certbot-nginx
sudo ufw allow 80/tcp   # Allows HTTP traffic on port 80
sudo ufw allow 443/tcp  # Allows HTTPS traffic on port 443
sudo certbot --nginx -d gamebackrooms.com -d www.gamebackrooms.com --email info@gamebackrooms.com 
python3 -m venv gmenv
source gmenv/bin/activate
sudo apt update
sudo apt install -y git
sudo vi /etc/systemd/system/athena.service
sudo systemctl daemon-reload
sudo systemctl enable athena

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