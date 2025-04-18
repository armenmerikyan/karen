from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.admin.models import LogEntry
from django.contrib.auth.models import BaseUserManager
import os
import uuid
import re
from django.core.exceptions import ValidationError
import random
import string

def default_uuid():
    return str(uuid.uuid4())

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        if not username:
            raise ValueError('Users must have a username')

        user = self.model(
            username=username,
            email=self.normalize_email(email),
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(username, email, password, **extra_fields)


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
    
    openai_api_key = models.CharField(max_length=255, blank=True, null=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']
    
    objects = UserManager()
    
    def get_short_name(self):
        return self.first_name or self.email  # Or any other relevant attribute
    
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

    def to_mcp_context(self):
        return {
            "mint": self.mint,
            "name": self.name,
            "symbol": self.symbol,
            "description": self.description,
            "image_uri": self.image_uri,
            "metadata_uri": self.metadata_uri,
            "website": self.website,
            "socials": {
                "twitter": self.twitter,
                "telegram": self.telegram,
            },
            "market": {
                "raydium_pool": self.raydium_pool,
                "market_id": self.market_id,
                "market_id_two": self.market_id_two,
                "market_cap": str(self.market_cap) if self.market_cap else None,
                "usd_market_cap": str(self.usd_market_cap) if self.usd_market_cap else None,
            },
            "tokenomics": {
                "total_supply": str(self.total_supply) if self.total_supply else None,
                "bonding_curve": self.bonding_curve,
                "associated_bonding_curve": self.associated_bonding_curve,
                "virtual_sol_reserves": str(self.virtual_sol_reserves) if self.virtual_sol_reserves else None,
                "virtual_token_reserves": str(self.virtual_token_reserves) if self.virtual_token_reserves else None,
            },
            "creator": {
                "wallet_address": self.creator,
                "username": self.username,
                "profile_image": self.profile_image,
            },
            "timestamps": {
                "created_timestamp": self.created_timestamp.isoformat() if self.created_timestamp else None,
                "last_trade_timestamp": self.last_trade_timestamp.isoformat() if self.last_trade_timestamp else None,
                "king_of_the_hill_timestamp": self.king_of_the_hill_timestamp.isoformat() if self.king_of_the_hill_timestamp else None,
            },
            "meta": {
                "reply_count": self.reply_count,
                "last_reply": self.last_reply,
                "ai_analysis": self.ai_analysis,
                "nsfw": self.nsfw,
                "hidden": self.hidden,
                "show_name": self.show_name,
                "inverted": self.inverted,
            },
        }

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

    dockerhub_username = models.CharField(max_length=255, help_text="The DockerHub username.", blank=True, null=True)
    dockerhub_password = models.CharField(max_length=255, help_text="The DockerHub password. Store securely!", blank=True, null=True)
 
    sendgrid_email = models.CharField(max_length=255, help_text="Send Grid Email.", blank=True, null=True)
    sendgrid_key = models.CharField(max_length=255, help_text="Send Grid API Key", blank=True, null=True)

    google_analytics_key = models.CharField(max_length=255, help_text="Google Analytics Key", blank=True, null=True)

    # New social media fields
    facebook_url = models.URLField(max_length=255, help_text="Facebook page URL.", blank=True, null=True)
    instagram_handle = models.CharField(max_length=255, help_text="Instagram handle.", blank=True, null=True)
    youtube_channel = models.URLField(max_length=255, help_text="YouTube channel URL.", blank=True, null=True)
    tiktok_handle = models.CharField(max_length=255, help_text="TikTok handle.", blank=True, null=True)
    snapchat_handle = models.CharField(max_length=255, help_text="Snapchat username.", blank=True, null=True)
    pinterest_handle = models.CharField(max_length=255, help_text="Pinterest handle.", blank=True, null=True)
    linkedin_url = models.URLField(max_length=255, help_text="LinkedIn company page URL.", blank=True, null=True)
    discord_invite = models.URLField(max_length=255, help_text="Discord server invite URL.", blank=True, null=True)
    telegram_handle = models.CharField(max_length=255, help_text="Telegram username or channel.", blank=True, null=True)
    reddit_url = models.URLField(max_length=255, help_text="Reddit community URL.", blank=True, null=True)
    github_org = models.URLField(max_length=255, help_text="GitHub organization URL.", blank=True, null=True)
    medium_handle = models.CharField(max_length=255, help_text="Medium publication handle.", blank=True, null=True)

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
    business_name = models.CharField(max_length=100, blank=True, null=True, help_text="Enter the customer's business name.")

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

    # In Product model
    user_character = models.OneToOneField('UserCharacter', on_delete=models.CASCADE, null=True, blank=True, related_name='product')
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='products'
    )

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
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    client_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    character = models.ForeignKey('UserCharacter', null=True, blank=True, on_delete=models.SET_NULL, related_name='conversations')
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
    github = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.name

class FormSubmission(models.Model):
    # Domain or hostname where the form was submitted
    domain = models.CharField(
        max_length=255,
        help_text="Domain name or hostname where the form was submitted."
    )
    
    # Stores all form fields as a JSON object
    data = models.JSONField()
    
    # Boolean flag indicating if the submission has been processed
    is_processed = models.BooleanField(
        default=False,
        help_text="Indicates whether the submission has been processed."
    )
    user_agent = models.TextField(blank=True, null=True, help_text="User agent string of the submitter's browser.")

    referer = models.URLField(
        help_text="URL of the page where the form was submitted from.",
        blank=True,
        null=True
    )
    
    origin = models.URLField(
        help_text="Origin of the request (protocol, domain, and port).",
        blank=True,
        null=True
    )

    # IP address of the user submitting the form (supports IPv4 and IPv6)
    source_ip = models.CharField(
        max_length=45,
        help_text="IP address of the submitter."
    )
    
    # Timestamp when the submission was created
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Submission {self.pk} from {self.domain} at {self.created_at}"
    

class Business(models.Model):
    """
    MCP-Compatible Business Model
    """

    # Basic Business Info
    name = models.CharField(max_length=255, blank=True, null=True, help_text="Business name.")
    owner = models.CharField(max_length=255, blank=True, null=True, help_text="Owner or primary contact.")
    email = models.EmailField(blank=True, null=True, help_text="Business contact email.")
    phone = models.CharField(max_length=20, blank=True, null=True, help_text="Business phone number.")
    website = models.URLField(blank=True, null=True, help_text="Official website URL.")
    industry = models.CharField(max_length=255, blank=True, null=True, help_text="Industry or business category.")
    established_date = models.DateField(blank=True, null=True, help_text="Date when the business was established.")
    description = models.TextField(blank=True, null=True, help_text="Brief business description.")

    # Address Details
    address_line1 = models.CharField(max_length=255, blank=True, null=True, help_text="Street address (line 1).")
    address_line2 = models.CharField(max_length=255, blank=True, null=True, help_text="Street address (line 2).")
    city = models.CharField(max_length=100, blank=True, null=True, help_text="City.")
    state = models.CharField(max_length=100, blank=True, null=True, help_text="State or province.")
    country = models.CharField(max_length=100, blank=True, null=True, help_text="Country.")
    zip_code = models.CharField(max_length=20, blank=True, null=True, help_text="Postal/ZIP code.")
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True, help_text="Geographic latitude.")
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True, help_text="Geographic longitude.")

    # Social Media Links
    facebook = models.URLField(blank=True, null=True, help_text="Facebook page URL.")
    instagram = models.URLField(blank=True, null=True, help_text="Instagram profile URL.")
    twitter = models.URLField(blank=True, null=True, help_text="Twitter (X) profile URL.")
    linkedin = models.URLField(blank=True, null=True, help_text="LinkedIn profile URL.")
    youtube = models.URLField(blank=True, null=True, help_text="YouTube channel URL.")
    tiktok = models.URLField(blank=True, null=True, help_text="TikTok profile URL.")
    snapchat = models.URLField(blank=True, null=True, help_text="Snapchat profile URL.")
    pinterest = models.URLField(blank=True, null=True, help_text="Pinterest profile URL.")
    reddit = models.URLField(blank=True, null=True, help_text="Reddit profile URL.")
    discord = models.URLField(blank=True, null=True, help_text="Discord server invite URL.")
    telegram = models.URLField(blank=True, null=True, help_text="Telegram group or profile URL.")
    github = models.URLField(blank=True, null=True, help_text="GitHub organization or repository URL.")
    medium = models.URLField(blank=True, null=True, help_text="Medium blog URL.")
    whatsapp = models.CharField(max_length=20, blank=True, null=True, help_text="WhatsApp contact number.")
    wechat = models.CharField(max_length=20, blank=True, null=True, help_text="WeChat contact number.")

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True, help_text="Record creation timestamp.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Last update timestamp.")

    # Creator 
    creator = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="businesses", help_text="User who created this business."
    )
    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name if self.name else "Unnamed Business"

    def to_mcp_context(self):
        """
        Converts the business object to an MCP-compatible dictionary.
        """
        return {
            "id": self.id,
            "name": self.name,
            "owner": self.owner,
            "email": self.email,
            "phone": self.phone,
            "website": self.website,
            "industry": self.industry,
            "established_date": self.established_date,
            "description": self.description,
            "address": {
                "line1": self.address_line1,
                "line2": self.address_line2,
                "city": self.city,
                "state": self.state,
                "country": self.country,
                "zip": self.zip_code,
                "latitude": float(self.latitude) if self.latitude else None,
                "longitude": float(self.longitude) if self.longitude else None,
            },
            "social_media": {
                "facebook": self.facebook,
                "instagram": self.instagram,
                "twitter": self.twitter,
                "linkedin": self.linkedin,
                "youtube": self.youtube,
                "tiktok": self.tiktok,
                "snapchat": self.snapchat,
                "pinterest": self.pinterest,
                "reddit": self.reddit,
                "discord": self.discord,
                "telegram": self.telegram,
                "github": self.github,
                "medium": self.medium,
                "whatsapp": self.whatsapp,
                "wechat": self.wechat,
            },
            "timestamps": {
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat(),
            },
            "creator": {
                "id": self.creator.id,
                "username": self.creator.username,
                "email": self.creator.email,
            } if self.creator else None,
        }

def ticket_photo_upload(instance, filename):
    # Generates a unique filename and organizes uploads by ticket ID.
    extension = os.path.splitext(filename)[1]
    unique_filename = f"{uuid4().hex}{extension}"
    return f"ticket_photos/{instance.id}/{unique_filename}"      

class SupportTicket(models.Model):
    """
    MCP-Compatible Support Ticket Model with photo and additional details
    """

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ]

    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('urgent', 'Urgent'),
    ]

    business = models.ForeignKey('Business', on_delete=models.CASCADE, related_name='support_tickets', help_text="Associated business.")
    title = models.CharField(max_length=255, help_text="Short summary of the issue.")
    description = models.TextField(help_text="Detailed description of the issue.")
    additional_details = models.TextField(blank=True, null=True, help_text="Additional details or context for the issue.")
    photo = models.ImageField(
        upload_to=ticket_photo_upload, 
        blank=True, 
        null=True, 
        help_text="Optional photo attachment related to the issue."
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open', help_text="Current status of the ticket.")
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium', help_text="Priority level of the ticket.")
    created_by = models.CharField(max_length=255, help_text="Name of the person who created the ticket.")
    contact_email = models.EmailField(help_text="Contact email for follow-up.")
    assigned_to = models.CharField(max_length=255, blank=True, null=True, help_text="Support agent assigned to the ticket.")
    resolution_notes = models.TextField(blank=True, null=True, help_text="Notes on how the issue was resolved.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Ticket creation timestamp.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Last update timestamp.")

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

    def to_mcp_context(self):
        """
        Converts the support ticket object to an MCP-compatible dictionary.
        """
        return {
            "id": self.id,
            "business": self.business.to_mcp_context() if self.business else None,
            "title": self.title,
            "description": self.description,
            "additional_details": self.additional_details,
            "photo_url": self.photo.url if self.photo else None,
            "status": self.status,
            "priority": self.priority,
            "created_by": self.created_by,
            "contact_email": self.contact_email,
            "assigned_to": self.assigned_to,
            "resolution_notes": self.resolution_notes,
            "timestamps": {
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat(),
            }
        }

class Review(models.Model):
    """
    Model for storing business reviews.
    """
    business = models.ForeignKey('Business', on_delete=models.CASCADE, related_name='reviews', help_text="Reviewed business.")
    reviewer_name = models.CharField(max_length=255, help_text="Name of the reviewer.")
    reviewer_email = models.EmailField(blank=True, null=True, help_text="Email of the reviewer (optional).")
    stars = models.PositiveSmallIntegerField(
        choices=[(i, str(i)) for i in range(1, 6)],
        help_text="Star rating (1-5)."
    )
    comment = models.TextField(blank=True, null=True, help_text="Review comment.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Review creation timestamp.")
    updated_at = models.DateTimeField(auto_now=True, help_text="Last update timestamp.")

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.reviewer_name} - {self.stars}⭐ for {self.business.name}"


class CleaningRequest(models.Model):
    CLEANING_TYPE_CHOICES = [
        ('home', 'Home Cleaning'),
        ('business', 'Business Cleaning'),
    ]
    CLEANING_LEVEL_CHOICES = [
        ('basic', 'Basic Cleaning'),
        ('deep', 'Deep Cleaning'),
        ('move_out', 'Move-Out Cleaning'),
        ('post_construction', 'Post-Construction Cleaning'),
        ('airbnb', 'Airbnb Cleaning'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('scheduled', 'Scheduled'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('canceled', 'Canceled'),
    ]
    
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='cleaning_requests', help_text='The user who requested the cleaning service.')
    cleaning_type = models.CharField(max_length=10, choices=CLEANING_TYPE_CHOICES, help_text='Type of cleaning requested (home or business).')
    cleaning_level = models.CharField(max_length=20, choices=CLEANING_LEVEL_CHOICES, default='basic', help_text='Level of cleaning required (basic, deep, move-out, post-construction).')
    address_line1 = models.CharField(max_length=255, help_text='Primary address line of the location to be cleaned.')
    address_line2 = models.CharField(max_length=255, blank=True, null=True, help_text='Additional address details (e.g., apartment number).')
    city = models.CharField(max_length=100, help_text='City where the cleaning service is needed.')
    state = models.CharField(max_length=50, help_text='State where the cleaning service is needed.')
    zip_code = models.CharField(max_length=10, help_text='Postal code of the cleaning location.')
    email = models.EmailField(help_text='Email address of the customer requesting the service.')
    phone = models.CharField(max_length=20, help_text='Phone number of the customer requesting the service.')
    facebook = models.URLField(blank=True, null=True, help_text="Facebook profile or page URL.")
    instagram = models.URLField(blank=True, null=True, help_text="Instagram profile URL.")
    twitter = models.URLField(blank=True, null=True, help_text="Twitter (X) profile URL.")
    linkedin = models.URLField(blank=True, null=True, help_text="LinkedIn profile or page URL.")
    youtube = models.URLField(blank=True, null=True, help_text="YouTube channel URL.")
    tiktok = models.URLField(blank=True, null=True, help_text="TikTok profile URL.")
    snapchat = models.URLField(blank=True, null=True, help_text="Snapchat profile URL.")
    pinterest = models.URLField(blank=True, null=True, help_text="Pinterest profile URL.")
    reddit = models.URLField(blank=True, null=True, help_text="Reddit profile or subreddit URL.")
    discord = models.URLField(blank=True, null=True, help_text="Discord server or profile URL.")
    telegram = models.URLField(blank=True, null=True, help_text="Telegram channel or profile URL.")
    github = models.URLField(blank=True, null=True, help_text="GitHub profile or repository URL.")
    medium = models.URLField(blank=True, null=True, help_text="Medium profile or blog URL.")
    whatsapp = models.URLField(blank=True, null=True, help_text="WhatsApp contact link URL.")
    wechat = models.URLField(blank=True, null=True, help_text="WeChat contact or profile URL.")
    scheduled_date = models.DateTimeField(help_text='Date and time scheduled for the cleaning service.')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='pending', help_text='Current status of the cleaning request.')
    special_instructions = models.TextField(blank=True, null=True, help_text='Any special instructions or notes for the cleaning service.')
    created_at = models.DateTimeField(auto_now_add=True, help_text='Timestamp when the request was created.')
    updated_at = models.DateTimeField(auto_now=True, help_text='Timestamp when the request was last updated.')
    tracking_code = models.CharField(max_length=6, unique=True, blank=True, null=True, help_text='Unique 6-digit alphanumeric tracking code.')
    
    def __str__(self):
        return f"{self.get_cleaning_type_display()} - {self.address_line1} ({self.get_status_display()})"
    
    def save(self, *args, **kwargs):
        if not self.tracking_code:
            self.tracking_code = self.generate_tracking_code()
        super().save(*args, **kwargs)

    def generate_tracking_code(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
 
    def to_mcp_context(self):
        return { 
            "customer": {
                "id": self.customer.id,
                "email": self.email,
                "phone": self.phone,
                "social_media": {
                "facebook": self.social_media.get("facebook"),
                "instagram": self.social_media.get("instagram"),
                "twitter": self.social_media.get("twitter"),
                "linkedin": self.social_media.get("linkedin"),
                "youtube": self.social_media.get("youtube"),
                "tiktok": self.social_media.get("tiktok"),
                "snapchat": self.social_media.get("snapchat"),
                "pinterest": self.social_media.get("pinterest"),
                "reddit": self.social_media.get("reddit"),
                "discord": self.social_media.get("discord"),
                "telegram": self.social_media.get("telegram"),
                "github": self.social_media.get("github"),
                "medium": self.social_media.get("medium"),
                "whatsapp": self.social_media.get("whatsapp"),
                "wechat": self.social_media.get("wechat"),
            }
            },
            "cleaning_type": self.cleaning_type,
            "address": {
                "line1": self.address_line1,
                "line2": self.address_line2,
                "city": self.city,
                "state": self.state,
                "zip_code": self.zip_code,
            },
            "scheduled_date": self.scheduled_date.isoformat(),
            "status": self.status,
            "tracking_code": self.tracking_code,
            "special_instructions": self.special_instructions,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class ImmigrationCase(models.Model):
    # Applicant Information
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.DateField()
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    country_of_birth = models.CharField(max_length=100)
    country_of_citizenship = models.CharField(max_length=100)

    # Case Details
    case_type = models.CharField(
        max_length=100,
        choices=[
            ("Asylum", "Asylum"),
            ("Green Card", "Green Card"),
            ("Citizenship", "Citizenship"),
            ("Work Visa", "Work Visa"),
            ("Family Petition", "Family Petition"),
            ("Other", "Other"),
        ]
    )
    case_status = models.CharField(
        max_length=50,
        choices=[
            ("Pending", "Pending"),
            ("Approved", "Approved"),
            ("Denied", "Denied"),
            ("In Review", "In Review"),
        ],
        default="Pending"
    )
    application_date = models.DateField()
    receipt_number = models.CharField(max_length=50, blank=True, null=True)
    uscis_office = models.CharField(max_length=100, blank=True, null=True)

    # Immigration History
    visa_type = models.CharField(max_length=50, blank=True, null=True)
    date_of_entry = models.DateField(blank=True, null=True)
    current_status = models.CharField(max_length=100, blank=True, null=True)
    previous_visa_denials = models.BooleanField(default=False)
    deportation_history = models.BooleanField(default=False)
    deportation_details = models.TextField(blank=True, null=True)

    # Legal Representation
    attorney_name = models.CharField(max_length=200, blank=True, null=True)
    law_firm_name = models.CharField(max_length=200, blank=True, null=True)
    attorney_email = models.EmailField(blank=True, null=True)
    attorney_phone = models.CharField(max_length=20, blank=True, null=True)

    # Additional Notes
    additional_notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.case_type}"

    def to_mcp_context(self):
        """Converts the model instance into a structured dictionary compliant with Model Context Protocol."""
        return {
            "applicant": {
                "first_name": self.first_name,
                "last_name": self.last_name,
                "date_of_birth": self.date_of_birth.strftime("%Y-%m-%d"),
                "email": self.email,
                "phone_number": self.phone_number,
                "country_of_birth": self.country_of_birth,
                "country_of_citizenship": self.country_of_citizenship,
            },
            "case_details": {
                "case_type": self.case_type,
                "case_status": self.case_status,
                "application_date": self.application_date.strftime("%Y-%m-%d"),
                "receipt_number": self.receipt_number,
                "uscis_office": self.uscis_office,
            },
            "immigration_history": {
                "visa_type": self.visa_type,
                "date_of_entry": self.date_of_entry.strftime("%Y-%m-%d") if self.date_of_entry else None,
                "current_status": self.current_status,
                "previous_visa_denials": self.previous_visa_denials,
                "deportation_history": self.deportation_history,
                "deportation_details": self.deportation_details,
            },
            "legal_representation": {
                "attorney_name": self.attorney_name,
                "law_firm_name": self.law_firm_name,
                "attorney_email": self.attorney_email,
                "attorney_phone": self.attorney_phone,
            },
            "additional_notes": self.additional_notes,
            "timestamps": {
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat(),
            }
        }
    
class Letter(models.Model):
    sender = models.CharField(max_length=255)  # Open text field
    recipient = models.CharField(max_length=255)  # Open text field 
    subject = models.CharField(max_length=255)
    body = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']  # Orders by latest first
        verbose_name = "Letter"
        verbose_name_plural = "Letters"

    def __str__(self):
        return f"Letter from {self.sender} to {self.recipient} - {self.subject}"

    def get_absolute_url(self):
        return reverse('letter_detail', args=[str(self.id)])

    def to_mcp_context(self):
        """
        Converts the Letter object to an MCP-compatible dictionary.
        """
        return {
            "id": self.id,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "body": self.body,
            "timestamps": {
                "created_at": self.timestamp.isoformat(),
            }
        }
    

class CarFinderResponse(models.Model):
    contact_name = models.CharField(
        max_length=255, null=True, blank=True,
        help_text="Full name of the contact person."
    )
    contact_email = models.EmailField(
        null=True, blank=True,
        help_text="Email address of the contact person."
    )
    contact_phone = models.CharField(
        max_length=20, null=True, blank=True,
        help_text="Phone number of the contact person."
    )
    contact_address = models.TextField(
        null=True, blank=True,
        help_text="Address of the contact person."
    )    
    # Budget & Financing
    budget_min = models.PositiveIntegerField(
        null=True, blank=True, 
        help_text="Minimum budget in USD (e.g., 10000 for $10,000)"
    )
    budget_max = models.PositiveIntegerField(
        null=True, blank=True, 
        help_text="Maximum budget in USD (e.g., 30000 for $30,000)"
    )
    financing = models.BooleanField(
        default=False, 
        help_text="Are you open to financing options?"
    )
    leasing = models.BooleanField(
        default=False, 
        help_text="Would you consider leasing instead of buying?"
    )

    # Vehicle Type & Purpose
    vehicle_type = models.CharField(
        max_length=50, choices=[
            ('sedan', 'Sedan'), ('suv', 'SUV'), ('truck', 'Truck'), 
            ('coupe', 'Coupe'), ('convertible', 'Convertible'), 
            ('electric', 'Electric'), ('hybrid', 'Hybrid')
        ], null=True, blank=True,
        help_text="Select the type of vehicle you are looking for."
    )
    
    primary_use = models.CharField(
        max_length=50, choices=[
            ('daily_commute', 'Daily Commute'), ('family', 'Family'), 
            ('off_road', 'Off-road'), ('business', 'Business'),
            ('luxury', 'Luxury'), ('performance', 'Performance')
        ], null=True, blank=True,
        help_text="What will you primarily use this car for?"
    )

    passengers = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="Number of passengers you need to fit comfortably."
    )

    # Fuel Efficiency & Power
    prioritize_fuel_efficiency = models.BooleanField(
        default=False, 
        help_text="Do you prioritize fuel efficiency over performance?"
    )
    prefer_electric_or_hybrid = models.BooleanField(
        default=False, 
        help_text="Are you interested in an electric or hybrid vehicle?"
    )

    # Features & Preferences
    safety_features = models.BooleanField(
        default=False, 
        help_text="Do you want advanced safety features like blind-spot monitoring or lane assist?"
    )
    tech_features = models.BooleanField(
        default=False, 
        help_text="Are modern tech features important to you (e.g., Apple CarPlay, GPS, Bluetooth)?"
    )
    luxury_features = models.BooleanField(
        default=False, 
        help_text="Do you prefer premium features like leather seats, sunroof, or heated seats?"
    )
    awd_4wd_needed = models.BooleanField(
        default=False, 
        help_text="Do you need AWD or 4WD for snow/off-road driving?"
    )

    # New vs. Used
    open_to_used = models.BooleanField(
        default=True, 
        help_text="Are you open to buying a used car?"
    )
    max_mileage = models.PositiveIntegerField(
        null=True, blank=True, 
        help_text="What is the maximum mileage you are comfortable with? (For used cars)"
    )

    # Brand & Style
    brand_preference = models.CharField(
        max_length=100, null=True, blank=True, 
        help_text="Do you have a preferred brand (e.g., Toyota, BMW, Ford)?"
    )
    preferred_style = models.CharField(
        max_length=50, choices=[
            ('sporty', 'Sporty'), ('luxury', 'Luxury'), 
            ('classic', 'Classic'), ('practical', 'Practical')
        ], null=True, blank=True,
        help_text="What style of car do you prefer?"
    )

    # Timeline & Location
    purchase_timeline = models.CharField(
        max_length=50, choices=[
            ('asap', 'ASAP'), ('1_3_months', '1-3 Months'), ('browsing', 'Just Browsing')
        ], null=True, blank=True,
        help_text="How soon are you looking to buy a car?"
    )

    local_only = models.BooleanField(
        default=True, 
        help_text="Do you want to limit your search to local dealerships only?"
    )

    created_at = models.DateTimeField(
        auto_now_add=True, 
        help_text="Timestamp when this response was submitted."
    )

    def to_mcp_context(self):
        """
        Converts the model instance into a context-compliant dictionary
        for integration with AI models, APIs, or external systems.
        """
        return {
            "contact": {
                "name": self.contact_name,
                "email": self.contact_email,
                "phone": self.contact_phone,
                "address": self.contact_address,
            },            
            "budget": {
                "min": self.budget_min,
                "max": self.budget_max,
                "financing": self.financing,
                "leasing": self.leasing,
            },
            "vehicle_preferences": {
                "type": self.vehicle_type,
                "primary_use": self.primary_use,
                "passengers": self.passengers,
            },
            "features": {
                "safety": self.safety_features,
                "tech": self.tech_features,
                "luxury": self.luxury_features,
                "awd_4wd": self.awd_4wd_needed
            },
            "new_vs_used": {
                "open_to_used": self.open_to_used,
                "max_mileage": self.max_mileage
            },
            "brand_and_style": {
                "preferred_brand": self.brand_preference,
                "preferred_style": self.preferred_style
            },
            "timeline": {
                "purchase_timeline": self.purchase_timeline,
                "local_only": self.local_only
            },
            "metadata": {
                "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        }

    def __str__(self):
        return f"Car Finder Response {self.id} - {self.created_at.strftime('%Y-%m-%d')}"


class WebsiteCreationResponse(models.Model):
    # Contact Information
    contact_name = models.CharField(
        max_length=255, null=True, blank=True,
        help_text="Full name of the person filling out this form."
    )
    contact_email = models.EmailField(
        null=True, blank=True,
        help_text="Email address of the person filling out this form."
    )
    contact_phone = models.CharField(
        max_length=20, null=True, blank=True,
        help_text="Phone number of the contact person."
    )

    # Business Information
    business_name = models.CharField(
        max_length=255, null=True, blank=True,
        help_text="Name of the business or organization."
    )
    industry = models.CharField(
        max_length=100, null=True, blank=True,
        help_text="Industry the business operates in (e.g., Retail, Tech, Healthcare)."
    )
    business_description = models.TextField(
        null=True, blank=True,
        help_text="Brief description of the business and its services/products."
    )
    target_audience = models.TextField(
        null=True, blank=True,
        help_text="Describe the target audience or customer base."
    )

    # Website Goals
    primary_goal = models.CharField(
        max_length=100, choices=[
            ('informational', 'Informational'),
            ('ecommerce', 'E-commerce'),
            ('portfolio', 'Portfolio'),
            ('blog', 'Blog'),
            ('booking', 'Booking System'),
            ('membership', 'Membership-based'),
            ('other', 'Other')
        ], null=True, blank=True,
        help_text="What is the primary goal of the website?"
    )
    other_goal_description = models.TextField(
        null=True, blank=True,
        help_text="If 'Other' is selected, describe the website goal."
    )

    # Features & Functionality
    requires_ecommerce = models.BooleanField(
        default=False, help_text="Does the website need e-commerce functionality?"
    )
    requires_booking = models.BooleanField(
        default=False, help_text="Does the website need an appointment booking system?"
    )
    requires_blog = models.BooleanField(
        default=False, help_text="Does the website need a blog?"
    )
    requires_membership = models.BooleanField(
        default=False, help_text="Will the website have a membership system?"
    )
    requires_contact_form = models.BooleanField(
        default=True, help_text="Should the website include a contact form?"
    )
    requires_live_chat = models.BooleanField(
        default=False, help_text="Does the website need a live chat feature?"
    )
    custom_features = models.TextField(
        null=True, blank=True,
        help_text="Any additional custom features needed?"
    )

    # Design Preferences
    preferred_style = models.CharField(
        max_length=50, choices=[
            ('modern', 'Modern'),
            ('minimalist', 'Minimalist'),
            ('corporate', 'Corporate'),
            ('creative', 'Creative'),
            ('classic', 'Classic')
        ], null=True, blank=True,
        help_text="Preferred design style for the website."
    )
    color_scheme = models.CharField(
        max_length=100, null=True, blank=True,
        help_text="Preferred color scheme for the website (e.g., Blue & White)."
    )
    reference_websites = models.TextField(
        null=True, blank=True,
        help_text="List any websites you like for inspiration."
    )

    # Domain & Hosting
    has_domain = models.BooleanField(
        default=False, help_text="Do you already have a domain name?"
    )
    domain_name = models.CharField(
        max_length=255, null=True, blank=True,
        help_text="Enter the domain name if available."
    )
    requires_hosting = models.BooleanField(
        default=True, help_text="Do you need web hosting services?"
    )

    # Timeline & Budget
    timeline = models.CharField(
        max_length=50, choices=[
            ('asap', 'ASAP'),
            ('1_3_months', '1-3 Months'),
            ('flexible', 'Flexible')
        ], null=True, blank=True,
        help_text="Preferred timeline for website completion."
    )
    budget_range = models.CharField(
        max_length=50, choices=[
            ('under_1000', 'Under $1,000'),
            ('1000_5000', '$1,000 - $5,000'),
            ('5000_10000', '$5,000 - $10,000'),
            ('10000_plus', 'Over $10,000')
        ], null=True, blank=True,
        help_text="What is your estimated budget for the website?"
    )

    # Additional Information
    additional_notes = models.TextField(
        null=True, blank=True,
        help_text="Any additional notes or special requirements?"
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when this response was submitted."
    )

    def __str__(self):
        return f"Website Creation Response {self.id} - {self.business_name if self.business_name else 'No Name'}"

    def to_mcp_context(self):
        """
        Converts the model instance into a structured dictionary.
        """
        return {
            "contact": {
                "name": self.contact_name,
                "email": self.contact_email,
                "phone": self.contact_phone,
            },
            "business": {
                "name": self.business_name,
                "industry": self.industry,
                "description": self.business_description,
                "target_audience": self.target_audience,
            },
            "website_goals": {
                "primary_goal": self.primary_goal,
                "other_goal": self.other_goal_description,
            },
            "features": {
                "ecommerce": self.requires_ecommerce,
                "booking": self.requires_booking,
                "blog": self.requires_blog,
                "membership": self.requires_membership,
                "contact_form": self.requires_contact_form,
                "live_chat": self.requires_live_chat,
                "custom_features": self.custom_features,
            },
            "design": {
                "style": self.preferred_style,
                "color_scheme": self.color_scheme,
                "reference_websites": self.reference_websites,
            },
            "domain_hosting": {
                "has_domain": self.has_domain,
                "domain_name": self.domain_name,
                "requires_hosting": self.requires_hosting,
            },
            "timeline_budget": {
                "timeline": self.timeline,
                "budget": self.budget_range,
            },
            "additional_info": {
                "notes": self.additional_notes,
            },
            "metadata": {
                "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }
    
 
 
class TwitterHandleChecker(models.Model):
    handle = models.CharField(
        max_length=100,
        help_text="Twitter handle to be checked (without @)",
        verbose_name="Twitter Handle"
    )
    category = models.CharField(
        max_length=100,
        help_text="Category of the handle (e.g., crypto, fashion, sports)",
        verbose_name="Category",
        default="general"
    )
    status = models.CharField(
        max_length=50,
        help_text="Current status of the handle (e.g., available, taken)",
        verbose_name="Status"
    )
    result = models.TextField(
        help_text="Detailed result or notes from the handle check",
        verbose_name="Check Result"
    )
    checked_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when the handle was checked",
        verbose_name="Checked At"
    )

    class Meta:
        verbose_name = "Twitter Handle Checker"
        verbose_name_plural = "Twitter Handle Checkers"
        ordering = ['-checked_at']

    def __str__(self):
        return f"{self.handle} - {self.status} ({self.category})"

    def to_dict(self):
        return {
            "handle": self.handle,
            "category": self.category,
            "status": self.status,
            "result": self.result,
            "checked_at": self.checked_at.isoformat(),
        }

class UserCharacter(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='characters')
    name = models.CharField(max_length=100)
    persona = models.TextField(help_text="Character personality or system prompt")
    chatgpt_model_id = models.CharField(max_length=255, blank=True, null=True)
    chatgpt_model_id_current = models.CharField(max_length=255, blank=True, null=True)
    external_id = models.CharField(max_length=255, blank=True, null=True)
    metadata = models.JSONField(blank=True, null=True, help_text="Additional context (e.g., backstory, goals)")
    created_at = models.DateTimeField(auto_now_add=True)
    is_public = models.BooleanField(default=False, help_text="Whether this character is publicly viewable")
    allow_free_sample_usage_anyone = models.BooleanField(default=False, help_text="Whether this character allows free sample usage")
    allow_free_sample_usage_users = models.BooleanField(default=False, help_text="Whether this character allows free sample usage")
    sample_usage_call_limit = models.IntegerField(default=100, help_text="The maximum number of sample usage calls allowed")
    sample_usage_call_count = models.IntegerField(default=0, help_text="The current number of sample usage calls")

    x_handle = models.CharField(max_length=255, blank=True, null=True, help_text="The x.com handle.")
    chatgpt_link = models.CharField(max_length=255, blank=True, null=True, help_text="The ChatGPT link.")

        # ✅ Add this field
    character_image = models.ImageField(upload_to='character_images/', blank=True, null=True, help_text="Optional image for the character")
    allow_memory_update = models.BooleanField(default=False, help_text="Whether memory updates are allowed for this character by other users")

    def __str__(self):
        return f"{self.name} ({self.user.username})"
    
    def to_mcp_context(self):
        return {
            "id": str(self.external_id or self.id),
            "name": self.name,
            "persona": self.persona,
            "model_id": self.chatgpt_model_id_current or self.chatgpt_model_id,
            "metadata": self.metadata or {},
            "created_at": self.created_at.isoformat(),
            "user_id": self.user.id,
            "type": "agent",
        }

class CharacterMemory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='character_memories')
    character = models.ForeignKey(UserCharacter, on_delete=models.CASCADE, related_name='memories')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    importance = models.FloatField(default=0.5)
    memory_type = models.CharField(
        max_length=50,
        choices=[
            ('observation', 'Observation'),
            ('reflection', 'Reflection'),
            ('event', 'Event'),
            ('conversation', 'Conversation'),
        ],
        default='observation'
    )
    embedding = models.JSONField(blank=True, null=True)
    source = models.CharField(max_length=255, blank=True, null=True)
    tags = models.JSONField(blank=True, null=True)
    metadata = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"Memory for {self.character.name} at {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

    def save(self, *args, **kwargs):
        if not self.user and self.character:
            self.user = self.character.user
        super().save(*args, **kwargs)
        
    def to_mcp_context(self):
        return {
            "id": str(self.id),
            "character_id": str(self.character.external_id or self.character.id),
            "user_id": self.user.id,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "importance": self.importance,
            "memory_type": self.memory_type,
            "embedding": self.embedding,
            "source": self.source,
            "tags": self.tags or [],
            "metadata": self.metadata or {},
        }
