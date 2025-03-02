from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.admin.models import LogEntry
from django.contrib.auth.models import BaseUserManager
import os
import uuid
import re
from django.core.exceptions import ValidationError

def default_uuid():
    return str(uuid.uuid4())

class UserManager(BaseUserManager):
    def get_by_natural_key(self, username):
        return self.get(username=username)
    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given email and password.
        """
        extra_fields.setdefault('is_active', True)  # Ensure the user is active
        user = self.create_user(email, password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    company_name = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    company_phone = models.CharField(max_length=255, blank=True)
    company_email_address = models.CharField(max_length=255, blank=True)
    date_joined = models.TimeField(null=True)
    billing_address_line1 = models.CharField(max_length=255, blank=True)
    billing_address_line2 = models.CharField(max_length=255, blank=True)
    billing_city = models.CharField(max_length=255, blank=True)
    billing_state = models.CharField(max_length=255, blank=True)
    billing_zipcode = models.CharField(max_length=255, blank=True)
    billing_country = models.CharField(max_length=255, blank=True)
    shipping_address_line1 = models.CharField(max_length=255, blank=True)
    shipping_address_line2 = models.CharField(max_length=255, blank=True)
    shipping_city = models.CharField(max_length=255, blank=True)
    shipping_state = models.CharField(max_length=255, blank=True)
    shipping_zipcode = models.CharField(max_length=255, blank=True)
    shipping_country = models.CharField(max_length=255, blank=True) 
    sol_wallet_address = models.CharField(max_length=255, blank=True)

    current_intent = models.CharField(max_length=255, blank=True, null=True)
    current_entity = models.CharField(max_length=255, blank=True, null=True)
    current_entity_json = models.TextField(blank=True, null=True)
    current_field = models.CharField(max_length=255, blank=True, null=True)
    current_field_help_text = models.CharField(max_length=500, blank=True, null=True)
    current_intent_is_done = models.BooleanField(default=False)
        
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']
    objects = UserManager()

def category_upload_to(instance, filename):
    name, ext = os.path.splitext(filename)
    return f"category/{instance.id}.png"

class Category(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.ImageField(upload_to=category_upload_to, null=True, blank=True)
    def __str__(self):
        return self.name


def brand_upload_to(instance, filename):
    name, ext = os.path.splitext(filename)
    return f"brand/{instance.id}.png"

class Brand(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.ImageField(upload_to=brand_upload_to, null=True, blank=True)
    website = models.URLField(max_length=200, null=True, blank=True)
    def __str__(self):
        return self.name

def product_upload_to(instance, filename):
    name, ext = os.path.splitext(filename)
    return f"product/{instance.id}.png"





class APIData(models.Model):
    data = models.JSONField(null=True)  # Store JSON data
    timestamp = models.DateTimeField(auto_now_add=True)  # Timestamp when the data was saved
    is_retrieving = models.BooleanField(default=False)  # Boolean indicating whether data is being retrieved

    def __str__(self):
        return f"API Data saved at {self.timestamp}"


class Token(models.Model):
    mint = models.CharField(max_length=100, unique=True, null=True, blank=True)
    name = models.CharField(max_length=100, null=True, blank=True)
    symbol = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    image_uri = models.URLField(null=True, blank=True)
    metadata_uri = models.URLField(null=True, blank=True)
    twitter = models.CharField(max_length=300, null=True, blank=True)
    telegram = models.CharField(max_length=100, null=True, blank=True)
    bonding_curve = models.CharField(max_length=100, null=True, blank=True)
    associated_bonding_curve = models.CharField(max_length=100, null=True, blank=True)
    creator = models.CharField(max_length=100, null=True, blank=True)
    created_timestamp = models.DateTimeField(null=True, blank=True)
    raydium_pool = models.CharField(max_length=100, null=True, blank=True)
    complete = models.BooleanField(default=False)
    virtual_sol_reserves = models.DecimalField(max_digits=20, decimal_places=10, null=True, blank=True)
    virtual_token_reserves = models.DecimalField(max_digits=20, decimal_places=10, null=True, blank=True)
    hidden = models.BooleanField(default=False)
    total_supply = models.DecimalField(max_digits=20, decimal_places=10, null=True, blank=True)
    website = models.URLField(null=True, blank=True)
    show_name = models.BooleanField(default=False)
    last_trade_timestamp = models.DateTimeField(null=True, blank=True)
    king_of_the_hill_timestamp = models.DateTimeField(null=True, blank=True)
    market_cap = models.DecimalField(max_digits=20, decimal_places=10, null=True, blank=True)
    reply_count = models.IntegerField(null=True, blank=True)
    last_reply = models.CharField(max_length=100, null=True, blank=True)
    nsfw = models.BooleanField(default=False)
    market_id = models.IntegerField(null=True, blank=True)
    market_id_two = models.IntegerField(null=True, blank=True)
    inverted = models.BooleanField(default=False)
    username = models.CharField(max_length=100, null=True, blank=True)
    profile_image = models.URLField(null=True, blank=True)
    usd_market_cap = models.DecimalField(max_digits=20, decimal_places=10, null=True, blank=True)
    ai_analysis = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.name  # or any other field you want to represent the object with

class Accesstoken(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    access_cookie = models.CharField(max_length=255)
    public_wallet_address = models.CharField(max_length=255, unique=True)
    token_balance = models.FloatField()
    is_scam_filter_on = models.BooleanField(default=False)
    bank_balance = models.IntegerField()
    def __str__(self):
        return f'{self.public_wallet_address} - {self.access_cookie}'

class RaidLink(models.Model):
    token_mint = models.CharField(max_length=100)
    url = models.URLField()
    click_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=100)

    def __str__(self):
        return f"RaidLink(token_mint={self.token_mint}, url={self.url}, click_count={self.click_count}, created_at={self.created_at}, created_by={self.created_by.username})"


class Game(models.Model):
    game_id = models.TextField(unique=True)
    session_id = models.TextField(null=True)
    deck = models.CharField(max_length=159)
    public_wallet_address = models.TextField(null=True)
    date_created = models.DateTimeField(auto_now_add=True)
    secret_key = models.TextField(unique=True)
    number_of_players = models.IntegerField()
    current_blind = models.IntegerField(default=0)
    current_player = models.IntegerField(default=0)
    pot_size = models.IntegerField(default=0)
    game_state = models.TextField(default="Pre-flop")
    last_action_play = models.TextField(default="Big Blind")
    last_action = models.TextField(default="Big Blind")
    raise_amount = models.IntegerField(default=0)
    flop = models.CharField(max_length=8)
    turn = models.CharField(max_length=2)
    river = models.CharField(max_length=2)
    winner = models.IntegerField(default=0)
    winning_hand = models.CharField(max_length=20)

    def __str__(self):
        return self.game_id  # Or any other field you want to display

    class Meta:
        verbose_name = "Game"
        verbose_name_plural = "Games"


class Hand(models.Model):
    hand_id = models.TextField(unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    game_id = models.TextField()
    player_id = models.TextField(null=True)
    player_public_key = models.TextField()
    hand = models.TextField()
    player_state_last = models.TextField()
    player_state = models.TextField()
    last_raise = models.BooleanField(default=False)
    bet_amount = models.IntegerField(default=0)

    def __str__(self):
        return self.hand_id  # Or any other field you want to display

    class Meta:
        verbose_name = "Hand"
        verbose_name_plural = "Hands"

class Player(models.Model):
    player_id = models.TextField(unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    session_id = models.TextField()
    token_balance = models.FloatField()
    player_type = models.TextField()
    def __str__(self):
        return self.hand_id  # Or any other field you want to display

    class Player:
        verbose_name = "Player"
        verbose_name_plural = "Players"

class Handhistory(models.Model):
    hand_id = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    game_id = models.TextField()
    player_id = models.TextField(null=True)
    player_public_key = models.TextField()
    hand = models.TextField()
    player_state = models.TextField()
    reasoning = models.TextField()
    game_state = models.TextField()
    player_type = models.TextField(null=True)
    token_balance = models.FloatField(null=True)

    def __str__(self):
        return self.hand_id  # Or any other field you want to display

    class Handhistory:
        verbose_name = "Handhistory"
        verbose_name_plural = "Handhistorys"

class SocialMediaHandle(models.Model):
    handle = models.CharField(max_length=255, unique=True)
    follower_count = models.PositiveIntegerField()
    is_active = models.BooleanField(default=False)  # New field for active indicator

    def __str__(self):
        return f"{self.handle} - {self.follower_count} followers"


class TokenMarketingContent(models.Model):
    marketing_content = models.TextField()
    contract_address = models.CharField(max_length=42)  # Assuming a typical length for contract addresses
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Marketing Content for {self.contract_address} at {self.timestamp}"


class Tweet(models.Model):
    content = models.TextField()  # The text content of the tweet
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the tweet was created
    is_processed = models.BooleanField(default=False)  # Indicates if the tweet has been processed
    
    def __str__(self):
        return self.content[:50]  # Display the first 50 characters of the tweet

    class Meta:
        ordering = ['-created_at']  # Sort by most recent tweets

class TwitterStatus(models.Model):
    x_user = models.CharField(max_length=100, blank=True)
    status_id = models.CharField(max_length=20, unique=True, null=False)  # Make status_id unique and not nullable
    created_by_user = models.CharField(max_length=150)  # Stores username or user identifier
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp of record creation
    processed = models.BooleanField(default=False)  # Indicates if the status has been processed

    def save(self, *args, **kwargs):
        super(TwitterStatus, self).save(*args, **kwargs)

    def __str__(self):
        return f"{self.x_user} - {self.status_id}"

class UserQuery(models.Model): 
    created_date = models.DateTimeField(auto_now_add=True)  # Timestamp of record creation
    username = models.CharField(max_length=255)
    question = models.TextField()
    reasoning = models.TextField()
    response = models.TextField()
    connanicall_action_text = models.TextField(null=True, blank=True)  # New field

    def __str__(self):
        return f"Question by {self.username} at {self.created_date}"
    

class ConvoLog(models.Model):
    created_date = models.DateTimeField(auto_now_add=True)  # Timestamp of record creation
    username = models.CharField(max_length=255)
    topic = models.CharField(max_length=1000)  # New field for topic
    from_user = models.CharField(max_length=255)  # New field for 'from'
    to_users = models.CharField(max_length=255)  # New field for 'to'
    message = models.TextField()  # New field for message
    processed = models.BooleanField(default=False)  # New field for processed status
    upvote_count = models.IntegerField(default=0) 
    def __str__(self):
        return f"Question by {self.username} at {self.created_date}"
 
class ConversationTopic(models.Model):
    title = models.CharField(max_length=1000)            # Title of the conversation topic
    created_date = models.DateTimeField(auto_now_add=True)  # Timestamp of record creation

    def __str__(self):
        return self.title    
    
class Comment(models.Model):
    wallet_id = models.CharField(max_length=255)
    token_balance = models.DecimalField(max_digits=20, decimal_places=2)
    date = models.DateTimeField(auto_now_add=True)
    comment = models.TextField()
    comment_signed = models.TextField()
    ip_address = models.GenericIPAddressField()
    convo_log_id = models.CharField(max_length=255)
    is_visible = models.BooleanField(default=True)
    upvote_count = models.IntegerField(default=0) 

    def __str__(self):
        return f"Comment by {self.wallet_id} on {self.date}"


class Room(models.Model):
    id = models.AutoField(primary_key=True)  # Default primary key
    external_id = models.CharField(max_length=255, unique=True)  # External ID field
    external_date_created = models.DateTimeField()  # External date created field
    created_at = models.DateTimeField(auto_now_add=True)  # Internal creation timestamp

    def __str__(self):
        return self.external_id

    class Meta:
        db_table = 'rooms'  # Explicitly define the table name
        ordering = ['-created_at']  # Optional: order by newest created first

class Relationship(models.Model):
    id = models.AutoField(primary_key=True)  # Default primary key
    user_a = models.CharField(max_length=255)  # Representing userA
    user_b = models.CharField(max_length=255)  # Representing userB
    status = models.CharField(max_length=50)  # Relationship status
    user_id = models.CharField(max_length=255)  # Representing userId (additional identifier)
    created_at_external = models.DateTimeField()  # External creation timestamp
    created_at = models.DateTimeField(auto_now_add=True)  # Internal creation timestamp

    def __str__(self):
        return f"{self.user_a} - {self.user_b} ({self.status})"

    class Meta:
        db_table = 'relationships'  # Explicitly define the table name
        ordering = ['-created_at']  # Optional: order by newest created first        

class Participant(models.Model):
    id = models.AutoField(primary_key=True)  # Default primary key
    user_id = models.CharField(max_length=255)  # User ID field
    room_id = models.CharField(max_length=255)  # Room ID field
    user_state = models.CharField(max_length=50)  # User state in the room
    last_message_read = models.DateTimeField(null=True, blank=True)  # Timestamp of the last message read
    created_at_external = models.DateTimeField()  # External creation timestamp
    created_at = models.DateTimeField(auto_now_add=True)  # Internal creation timestamp

    def __str__(self):
        return f"User {self.user_id} in Room {self.room_id} ({self.user_state})"

    class Meta:
        db_table = 'participants'  # Explicitly define the table name
        ordering = ['-created_at']  # Optional: order by newest created first

class Goal(models.Model):
    id = models.AutoField(primary_key=True)  # Default primary key
    user_id = models.CharField(max_length=255)  # User ID field
    name = models.CharField(max_length=255)  # Goal name
    status = models.CharField(max_length=50)  # Status of the goal
    description = models.TextField(null=True, blank=True)  # Detailed description of the goal
    room_id = models.CharField(max_length=255, null=True, blank=True)  # Associated room ID
    objectives = models.TextField(null=True, blank=True)  # Objectives in a serialized format
    created_at_external = models.DateTimeField()  # External creation timestamp
    created_at = models.DateTimeField(auto_now_add=True)  # Internal creation timestamp

    def __str__(self):
        return f"Goal: {self.name} (Status: {self.status})"

    class Meta:
        db_table = 'goals'  # Explicit table name
        ordering = ['-created_at']  # Optional: order by newest created first

class Log(models.Model):
    id = models.AutoField(primary_key=True)  # Default primary key
    user_id = models.CharField(max_length=255)  # User ID field
    body = models.TextField()  # Log content
    type = models.CharField(max_length=50)  # Log type
    room_id = models.CharField(max_length=255, null=True, blank=True)  # Associated room ID
    created_at_external = models.DateTimeField()  # External creation timestamp
    created_at = models.DateTimeField(auto_now_add=True)  # Internal creation timestamp

    def __str__(self):
        return f"Log by User {self.user_id} (Type: {self.type})"

    class Meta:
        db_table = 'logs'  # Explicit table name
        ordering = ['-created_at']  # Optional: order by newest created first


class Memory(models.Model):
    id = models.AutoField(primary_key=True)  # Default primary key
    external_id = models.CharField(max_length=255, unique=True) 
    type = models.CharField(max_length=100)  # Type of memory
    created_at_external = models.DateTimeField(auto_now_add=True)  # External creation timestamp
    created_at = models.DateTimeField(auto_now_add=True)  # Internal creation timestamp
    content = models.TextField()  # Memory content
    embedding = models.TextField(null=True, blank=True)  # Serialized embedding data
    user_id = models.CharField(max_length=255)  # User ID associated with the memory
    room_id = models.CharField(max_length=255, null=True, blank=True)  # Associated room ID
    agent_id = models.CharField(max_length=255, null=True, blank=True)  # Associated agent ID
    unique = models.BooleanField(default=False)  # Indicates if the memory is unique

    def __str__(self):
        return f"Memory {self.id} - {self.type}"

    class Meta:
        db_table = 'memories'  # Explicit table name
        ordering = ['-created_at']  # Optional: order by newest created first

        
class Account(models.Model):
    id = models.AutoField(primary_key=True)  # Default primary key
    name = models.CharField(max_length=255)  # Full name of the account holder
    username = models.CharField(max_length=150, unique=True)  # Username, must be unique
    email = models.EmailField(unique=True)  # Email address, must be unique
    avatar_url = models.URLField(max_length=500, null=True, blank=True)  # Optional URL to the avatar image
    details = models.TextField(null=True, blank=True)  # Additional details about the account
    created_at_external = models.DateTimeField()  # External creation timestamp
    created_at = models.DateTimeField(auto_now_add=True)  # Internal creation timestamp

    def __str__(self):
        return f"{self.username} ({self.email})"

    class Meta:
        db_table = 'accounts'  # Explicitly define the table name
        ordering = ['-created_at']  # Optional: order by newest created first

 
class WebsiteProfile(models.Model):
    name = models.CharField(max_length=255, help_text="The name of the website.")
    about_us = models.TextField(help_text="Information about the website.")
    wallet = models.CharField(max_length=255, help_text="The address of the Solana Wallet.")
    x_handle = models.CharField(max_length=255, help_text="The x.com handle.")
    email = models.EmailField(max_length=255, help_text="The contact email address.", blank=True, null=True)
    phone = models.CharField(max_length=20, help_text="The contact phone number.", blank=True, null=True)

    address1 = models.CharField(max_length=255, help_text="Address line 1.", blank=True, null=True)
    address2 = models.CharField(max_length=255, help_text="Address line 2 (optional).", blank=True, null=True)
    city = models.CharField(max_length=100, help_text="City.", blank=True, null=True)
    state = models.CharField(max_length=100, help_text="State/Province.", blank=True, null=True)
    zip_code = models.CharField(max_length=20, help_text="ZIP/Postal code.", blank=True, null=True)
    country = models.CharField(max_length=100, help_text="Country.", blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True, help_text="The date and time when the profile was created.")
    updated_at = models.DateTimeField(auto_now=True, help_text="The date and time when the profile was last updated.")
    terms_of_service = models.TextField(help_text="The terms of service for the website.", blank=True, null=True)
    privacy_policy = models.TextField(help_text="The privacy policy for the website.", blank=True, null=True)
    tax_rate = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        help_text="The sales tax rate as a percentage (e.g., 7.25 for 7.25%)."
    )
    stripe_publishable_key = models.CharField(
        max_length=255, 
        help_text="The Stripe publishable key for the website.", 
        blank=True, 
        null=True
    )
    stripe_secret_key = models.CharField(
        max_length=255, 
        help_text="The Stripe secret key for the website.", 
        blank=True, 
    )  
    bird_eye_api_key = models.CharField(
        max_length=255,
        help_text="The BirdEye API key for the website.",
        blank=True,
        null=True
    )   
    deepseek_api_key = models.CharField(
        max_length=255,
        help_text="The Deepseek API key for the website.",
        blank=True,
        null=True
    )   
    chatgpt_api_key = models.CharField(
        max_length=255,
        help_text="The ChatGPT API key for the website.",
        blank=True,
        null=True
    )   
    chatgpt_model_id = models.CharField(
        max_length=255,
        help_text="The ChatGPT Fine Tuned Model ID.",
        blank=True,
        null=True
    )  
    chatgpt_model_id_current = models.CharField(
        max_length=255,
        help_text="The ChatGPT Fine Tuned Model ID Currently Active.",
        blank=True,
        null=True
    )  

    def __str__(self):
        return self.name


class TokenProfile(models.Model):
    name = models.CharField(max_length=100, unique=True, help_text="Name of the token")
    description = models.TextField(blank=True, help_text="Description of the token")
    image_uri = models.URLField(max_length=500, blank=True, help_text="URI for the token's image")
    address = models.CharField(max_length=100, unique=True, help_text="Token's unique address")
    visible = models.BooleanField(default=True, help_text="Set to True if the token is visible, False if hidden")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Timestamp when the token was created")
    updated_at = models.DateTimeField(auto_now=True, help_text="Timestamp when the token was last updated")

    def __str__(self):
        return f"{self.name} ({self.address}) - {'Visible' if self.visible else 'Hidden'}" 
    

class LifecycleStage(models.Model):
    name = models.CharField(max_length=255)
    rank = models.PositiveIntegerField()  # Rank will help determine the order of stages
    description = models.TextField(blank=True, null=True)
    is_visible = models.BooleanField(default=True)  # Whether this stage should be visible in the system
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)    
    class Meta:
        ordering = ['rank']  # Ensures stages are listed in rank order

    def __str__(self):
        return self.name    

class ProductLifecycleStage(models.Model):
    name = models.CharField(max_length=255)
    rank = models.PositiveIntegerField()
    description = models.TextField(blank=True, null=True)
    is_visible = models.BooleanField(default=True)
    is_sellable = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['rank']
    
    def __str__(self):
        return f"{self.name} (Rank {self.rank})"



def customer_upload_to(instance, filename):
    # Generate a custom file name using the customer's ID
    name, ext = os.path.splitext(filename)
    return f"customer_photos/{instance.id}_{name}{ext}"

class Customer(models.Model):
    first_name = models.CharField(max_length=100, help_text="Enter the customer's first name.")
    last_name = models.CharField(max_length=100, help_text="Enter the customer's last name.")
    email = models.EmailField(unique=True, help_text="Enter a unique email address for the customer.")
    phone_number = models.CharField(max_length=15, blank=True, null=True, help_text="Enter the customer's phone number (optional).")

    # Address Details
    address1 = models.CharField(max_length=255, blank=True, null=True, help_text="Enter the primary street address.")
    address2 = models.CharField(max_length=255, blank=True, null=True, help_text="Enter an additional address line (optional).")
    city = models.CharField(max_length=100, blank=True, null=True, help_text="Enter the city name.")
    state = models.CharField(max_length=100, blank=True, null=True, help_text="Enter the state or province.")
    zip_code = models.CharField(max_length=20, blank=True, null=True, help_text="Enter the ZIP or postal code.")
    country = models.CharField(max_length=100, blank=True, null=True, help_text="Enter the country name.")

    # Social Media
    linkedin_url = models.URLField(max_length=255, blank=True, null=True, help_text="Enter the LinkedIn profile URL (optional).")
    twitter_handle = models.CharField(max_length=100, blank=True, null=True, help_text="Enter the Twitter handle (optional).")
    facebook_url = models.URLField(max_length=255, blank=True, null=True, help_text="Enter the Facebook profile URL (optional).")
    instagram_url = models.URLField(max_length=255, blank=True, null=True, help_text="Enter the Instagram profile URL (optional).")

    # Photo Field
    photo = models.ImageField(upload_to='customer_photos/', null=True, blank=True, help_text="Upload a profile photo for the customer (optional).")

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True, help_text="Timestamp when the customer record was created.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Timestamp when the customer record was last updated.")

    # Customer Lifecycle Stage
    lifecycle_stage = models.ForeignKey('LifecycleStage', on_delete=models.SET_NULL, null=True, blank=True, help_text="Select the current lifecycle stage of the customer.")

    # Notes Field
    notes = models.TextField(blank=True, null=True, help_text="Enter any additional notes about the customer (optional).")

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    
class Cart(models.Model):
    id = models.AutoField(primary_key=True)
    external_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    checked_out = models.BooleanField(default=False)
    paid = models.BooleanField(default=False)
    paid_transaction_id = models.CharField(max_length=255, blank=True)
    billing_address_line1 = models.CharField(max_length=255, blank=True)
    billing_address_line2 = models.CharField(max_length=255, blank=True)
    billing_city = models.CharField(max_length=255, blank=True)
    billing_state = models.CharField(max_length=255, blank=True)
    billing_zipcode = models.CharField(max_length=255, blank=True)
    billing_country = models.CharField(max_length=255, blank=True)
    shipping_address_line1 = models.CharField(max_length=255, blank=True)
    shipping_address_line2 = models.CharField(max_length=255, blank=True)
    shipping_city = models.CharField(max_length=255, blank=True)
    shipping_state = models.CharField(max_length=255, blank=True)
    shipping_zipcode = models.CharField(max_length=255, blank=True)
    shipping_country = models.CharField(max_length=255, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='carts', null=True, blank=True)
    customer = models.ForeignKey(Customer, on_delete=models.SET_NULL, related_name='carts', null=True, blank=True)  # Added field
    is_processed = models.BooleanField(default=False)  # Renamed processed to is_processed
    def __str__(self):
        return self.cart_id

class Payment(models.Model):
    PAYMENT_METHODS = [
        ('CC', 'Credit Card'),
        ('PP', 'PayPal'),
        ('BT', 'Bank Transfer'),
    ]

    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    # Allow customer to be null
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='payments',
        null=True,  # Allows the customer field to be null
        blank=True  # Allows it to be blank in forms
    ) 
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=2, choices=PAYMENT_METHODS)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    transaction_id = models.CharField(max_length=255, unique=True, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payment {self.id} - {self.customer} - {self.status}"

class PaymentApplication(models.Model):
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name='applications')
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='payments')
    applied_amount = models.DecimalField(max_digits=10, decimal_places=2)
    applied_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment {self.payment.id} applied to Cart {self.cart.id} - Amount: {self.applied_amount}"
    
class Product(models.Model):
    id = models.AutoField(primary_key=True)
    sku = models.CharField(max_length=255, default=default_uuid)
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    wholesale_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    your_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    source_upload = models.TextField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    product_image = models.ImageField(upload_to='product_images/', null=True, blank=True)
    display_priority = models.IntegerField(null=True, blank=True)
    quantity = models.IntegerField()
    is_labor = models.BooleanField(default=False)  # New field added

    digital_file = models.FileField(upload_to='product_files/', null=True, blank=True)  # New field for digital files

    # Foreign keys for category, brand, and lifecycle stage
    #category = models.ForeignKey('Category', on_delete=models.CASCADE)
    #brand = models.ForeignKey('Brand', on_delete=models.CASCADE)
    lifecycle_stage = models.ForeignKey(
        'ProductLifecycleStage', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True
    )
    
    wholesale_price_item_json = models.TextField(null=True)

    def __str__(self):
        return self.name
    

class CartProduct(models.Model):
    id = models.AutoField(primary_key=True)
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    tax_rate = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        help_text="The sales tax rate as a percentage (e.g., 7.25 for 7.25%)."
    )    

class TouchPointType(models.Model):
    name = models.CharField(max_length=255, unique=True)  # Name of the touchpoint type
    instructions = models.TextField()  # Instructions for AI to generate correspondence
    lifecycle_stage = models.ForeignKey('LifecycleStage', on_delete=models.CASCADE)  # Related lifecycle stage
    objective = models.TextField()  # Purpose of the touchpoint
    touchpoint_format = models.TextField()  # How the touchpoint is structured
    integration = models.TextField()  # Where and how it is implemented
    outcome = models.TextField()  # Expected results and actions
    is_visible = models.BooleanField(default=True)  # Whether this touchpoint type is visible in the system
    created_at = models.DateTimeField(auto_now_add=True)  
    updated_at = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return self.name
    
class GeneratedMessage(models.Model):
    customer = models.ForeignKey('Customer', on_delete=models.CASCADE)
    touchpoint = models.ForeignKey('TouchPointType', on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    sent_social_media = models.BooleanField(default=False)
    sent_email = models.BooleanField(default=False)
    sent_text = models.BooleanField(default=False)
    sent_linkedin = models.BooleanField(default=False)
    sent_x = models.BooleanField(default=False)
    sent_instagram = models.BooleanField(default=False)

    def __str__(self):
        return f"Message for {self.customer} - {self.touchpoint}"
    
class PDFDocument(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)  # Added description field
    file = models.FileField(upload_to='pdfs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    lifecycle_stage = models.ForeignKey(LifecycleStage, on_delete=models.SET_NULL, null=True, blank=True)
    is_visible = models.BooleanField(default=True)  # Whether this PDF should be visible

    def __str__(self):
        return self.title
    
class QuestionAnswer(models.Model):
    question = models.TextField(help_text="The question that needs to be answered.")
    answer = models.TextField(help_text="The answer to the question.")    
    is_approved = models.BooleanField(default=False)
    product = models.ForeignKey(Product, related_name='question_answers', on_delete=models.CASCADE, null=True, blank=True)
    customer = models.ForeignKey(Customer, related_name='question_answers', on_delete=models.CASCADE, null=True, blank=True)
    is_visible_user = models.BooleanField(null=True, default=True)
    is_visible_public = models.BooleanField(null=True, default=True)
    has_sensitive_data = models.BooleanField(default=False)
    is_chatgpt_answer = models.BooleanField(default=False)
    
    created_by = models.ForeignKey(User, related_name='created_question_answers', on_delete=models.SET_NULL, null=True, blank=True)
    approved_by = models.ForeignKey(User, related_name='approved_question_answers', on_delete=models.SET_NULL, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def clean(self):
        if len(self.question) < 10:  # example length constraint
            raise ValidationError("Answer should be at least 10 characters long.")
    
    def __str__(self):
        return self.question
    
class Conversation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

class Message(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name="messages") 
    role = models.CharField(max_length=10, choices=[("user", "User"), ("assistant", "Assistant")])
    content = models.TextField()
    content_update = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)


class Visitor(models.Model):
    ip_address = models.GenericIPAddressField()
    visit_count = models.PositiveIntegerField(default=1)
    time_created = models.DateTimeField(auto_now_add=True)
    last_visit = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    geo_location = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    state = models.CharField(max_length=100, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    browser_used = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"Visitor {self.ip_address} - {self.city}, {self.country}"

    class Meta:
        verbose_name = 'Visitor'
        verbose_name_plural = 'Visitors'    

class Referral(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    referred_by = models.CharField(max_length=255, blank=True, null=True)  # Changed to CharField
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name

class LandingPage(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    goal = models.TextField()
    domain_name = models.CharField(max_length=255, unique=True)
    is_activated = models.BooleanField(default=False)
    is_docker = models.BooleanField(default=False)
    docker_name = models.CharField(max_length=255, blank=True, null=True)
    content = models.TextField(blank=True, null=True)
    docker_id = models.CharField(max_length=255, blank=True, null=True, unique=True)
    visitor_count = models.PositiveIntegerField(default=0)  # Track visitors
    port = models.PositiveIntegerField(default=7500)

    def __str__(self):
        return self.name
