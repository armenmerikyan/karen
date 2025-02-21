from django.contrib.auth import authenticate, login, logout, get_backends
from django.shortcuts import render, redirect, HttpResponseRedirect, get_object_or_404
from django.template import loader
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.urls import reverse
from django.http import FileResponse, Http404
from django.http import JsonResponse
from django.http import HttpResponse

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test, login_required

from django.views.generic.edit import CreateView
from django.views.generic import View


from os.path import join

from django.core.paginator import Paginator
from django import template
from urllib.parse import quote

from django.views.decorators.csrf import csrf_exempt
from django.template.context_processors import csrf

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

import os
import csv
import io
from io import BytesIO
import socket 
from django.utils.timezone import now

import urllib.request
from django.core.files.base import ContentFile

from django.db.models import Q
from django.db import models

from django.utils import timezone  # Import Django's timezone module
 
from openai import OpenAI
from openai import OpenAIError  # Import OpenAIError for exception handling

import json
from PIL import Image
import requests
import random 
import uuid
import hashlib

from django.views.decorators.csrf import csrf_exempt
from django.template.context_processors import csrf
from lxml import html
import pandas as pd


from datetime import datetime
from django.utils.dateparse import parse_datetime

from django.core.serializers import serialize

from django.views.decorators.http import require_POST


import logging

logger = logging.getLogger(__name__)

register = template.Library()
import time 
import re
import os

from .models import Accesstoken
from .models import Game
from .models import Hand
from .models import Player
from .models import Handhistory
from .models import SocialMediaHandle
from .models import TwitterStatus
from .models import UserQuery
from .models import Comment
from .models import TokenMarketingContent
from .models import Tweet 
from .models import ConvoLog
from .models import ConversationTopic
from .models import Token as PumpFunToken
from .models import RaidLink
from .models import Tweet
from .models import Room
from .models import Memory
from .models import WebsiteProfile
from .models import TokenProfile
from .models import TokenProfile
from .models import User
from .models import LifecycleStage
from .models import Customer
from .models import ProductLifecycleStage
from .models import Product
from .models import Cart
from .models import CartProduct
from .models import Payment
from .models import PaymentApplication
from .models import TouchPointType
from .models import GeneratedMessage
from .models import PDFDocument
from .models import QuestionAnswer
from .models import Conversation, Message

from .forms import SimpleAnswerForm
from .forms import QuestionAnswerForm
from .forms import CustomerPDFForm
from .forms import PDFDocumentForm
from .forms import GeneratedMessageForm
from .forms import TouchPointTypeForm
from .forms import ShippingBillingForm
from .forms import CartForm
from .forms import ProductForm
from .forms import ProductLifecycleStageForm
from .forms import CustomerForm
from .forms import LifecycleStageForm
from .forms import UserProfileUpdateForm
from .forms import TokenProfileForm
from .forms import TokenProfileForm
from .forms import TweetForm 
from .forms import TokenMarketingContentForm
from .forms import TweetForm 
from .forms import WebsiteProfileForm
from .forms import UserCreationForm  # You need to create this form

from .serializers import ConversationTopicSerializer

from .serializers import TwitterStatusSerializer
from .serializers import UserQuerySerializer
from .serializers import ConvoLogSerializer
from .serializers import MemorySerializer

from .services import MemoryService
from .services import RoomService  # Import the RoomService class


import base64
import base58

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect, get_object_or_404, render

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser

from .serializers import TwitterStatusSerializer

from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.contrib.auth import authenticate

from django.core.paginator import Paginator
from django.utils.timesince import timesince
from django.http import JsonResponse 
from functools import wraps

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from functools import wraps
from django.shortcuts import redirect


from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string 
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
 
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model


import stripe

from decimal import Decimal

pokerGPT_version = "00.00.06"
small_blind_size = 10
big_blind_size = 20
bank_default_balance = 1000
bank_default_balance_range = 350

deck = [
    "2H", "3H", "4H", "5H", "6H", "7H", "8H", "9H", "10H", "JH", "QH", "KH", "AH",
    "2D", "3D", "4D", "5D", "6D", "7D", "8D", "9D", "10D", "JD", "QD", "KD", "AD",
    "2C", "3C", "4C", "5C", "6C", "7C", "8C", "9C", "10C", "JC", "QC", "KC", "AC",
    "2S", "3S", "4S", "5S", "6S", "7S", "8S", "9S", "10S", "JS", "QS", "KS", "AS"
]
#MY_TOKEN = "TBD"
MY_TOKEN = "DF2LXZ9msqFihobc8MVMo8fL7zPfLjJbuNTR1JMCpump"
poker_player_types = [{"type": "Drunk Player", "description": "Often makes reckless bets, unpredictable, and can be aggressive."}, {"type": "Sober and Desperate", "description": "Plays cautiously but may make risky moves out of desperation."}, {"type": "Wealthy Player", "description": "Has a lot of chips to play with, may play loose and aggressive."}, {"type": "Professional Player", "description": "Highly skilled, plays strategically, and is hard to read."}, {"type": "Novice Player", "description": "Inexperienced, makes basic mistakes, and is easy to bluff."}, {"type": "Tight Player", "description": "Plays very few hands, only bets with strong cards."}, {"type": "Loose Player", "description": "Plays many hands, often makes large bets with weak hands."}, {"type": "Aggressive Player", "description": "Frequently raises and bets, often tries to intimidate opponents."}, {"type": "Passive Player", "description": "Rarely raises, often calls, and tends to fold under pressure."}, {"type": "Bluffer", "description": "Frequently bluffs, making it hard to tell when they have a good hand."}, {"type": "Calling Station", "description": "Calls almost every bet, rarely folds, and doesn't raise often."}, {"type": "Recreational Player", "description": "Plays for fun, not very skilled, and doesn't take the game too seriously."}, {"type": "Strategist", "description": "Carefully analyzes each move, often follows a calculated game plan."}, {"type": "Experienced Veteran", "description": "Has played for many years, understands the game deeply, and can adapt to different opponents."}, {"type": "Psychologist", "description": "Tries to read opponents' tells and body language to gain an advantage."}]

from django.contrib.auth import login, get_backends
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.shortcuts import render, redirect 
from django.conf import settings 


from solana.rpc.api import Client
from solders.transaction import Transaction
from solders.system_program import TransferParams, transfer
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.rpc.config import RpcSendTransactionConfig as TxOpts

from .decorators import staff_required
 
import PyPDF2

from PyPDF2 import PdfReader, PdfWriter 

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
   
import pdfminer
from pdfminer.high_level import extract_text

from pdfminer.high_level import extract_pages
from pdfminer.layout import LTTextContainer
import pdfrw


import tempfile

def register(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Deactivate user until email verification
            user.save()

            # Send email verification
            current_site = get_current_site(request)
            subject = "Verify your email address"
            
            uidb64 = quote(urlsafe_base64_encode(force_bytes(user.pk)))  # URL encode the UID
            token = quote(default_token_generator.make_token(user))  # URL encode the token

 
            message = render_to_string('email_verification.html', {
                'user': user,
                'domain': request.get_host(),
                'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),  # Pass uidb64, not uid
                'token': default_token_generator.make_token(user),
            })
            
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

            return redirect('email_verification_sent')  # Page showing verification message
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form, 'profile': profile})

def email_verification_sent(request):
    return render(request, 'email_verification_sent.html')

def email_verification_confirm(request, uidb64, token):

    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('login')  # Redirect to login after successful verification
    else:
        return render(request, 'email_verification_invalid.html')  # Show invalid link message
    
def resend_verification_email(request):
    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return render(request, 'email_not_found.html')

        # Generate token and UID for the user
        uid = urlsafe_base64_encode(user.pk.encode())
        token = default_token_generator.make_token(user)

        # Construct the email confirmation link
        current_site = get_current_site(request)
        mail_subject = 'Resend Email Verification'
        message = f'Hi {user.username}, please verify your email using this link: ' \
                  f'http://{current_site.domain}/verify-email/{uid}/{token}/'

        # Send the email
        send_mail(mail_subject, message, 'no-reply@example.com', [email])

        return redirect('verification_email_sent')

    return render(request, 'resend_verification_email.html')
    
def shop_product_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    
    # Get search term from request
    search_query = request.GET.get('search', '')
    
    # Filter products based on search query and lifecycle stage (sellable)
    if search_query:
        products = Product.objects.filter(
            Q(name__icontains=search_query) | Q(description__icontains=search_query),
            lifecycle_stage__is_sellable=True  # Only products in a sellable stage
        ).order_by('display_priority')  # Sort by display_priority
    else:
        products = Product.objects.filter(lifecycle_stage__is_sellable=True).order_by('display_priority')  # Sort by display_priority

    # Pass the products and profile to the template
    return render(request, 'products/shop_product_list.html', {'products': products, 'profile': profile})

 
 
def shop_product_detail(request, product_id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    # Fetch the specific product by its ID
    product = get_object_or_404(Product, id=product_id)
    # Pass the product to the template
    return render(request, 'products/shop_product_detail.html', {'product': product, 'profile': profile})

@login_required
def update_profile(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    if request.method == 'POST':
        form = UserProfileUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            return redirect('index')  # Redirect to profile page after update
    else:
        form = UserProfileUpdateForm(instance=request.user)
    
    return render(request, 'update_profile.html', {'form': form, 'profile': profile, 'user': request.user})

def admin_required(view_func):
    """
    Decorator to ensure the user is logged in and is a superuser.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return redirect('login')  # Redirect to your login page

        # Check if the user is a superuser
        if not request.user.is_superuser:
            return HttpResponseForbidden("You do not have permission to access this page.")

        # Proceed to the view if checks pass
        return view_func(request, *args, **kwargs)

    return _wrapped_view


def strip_non_unicode(text):
    if isinstance(text, str):
        return text.encode('ascii', 'ignore').decode('ascii')
    return None

def about_us(request):
    
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
 

    return render(request, 'about_us.html', { 'profile': profile})

def terms_of_service(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    return render(request, 'terms_of_service.html', { 'profile': profile})

def privacy_policy(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    return render(request, 'privacy_policy.html', { 'profile': profile})

def upvote_convo_log(request, log_id):
    # Get the ConvoLog object or return a 404 error if it doesn't exist
    convo_log = get_object_or_404(ConvoLog, id=log_id)
    
    # Increment the upvote count by 1
    convo_log.upvote_count += 1
    convo_log.save()  # Save the updated upvote count
    
    # Redirect back to the convo_log_detail page after the upvote
    return redirect('convo_log_detail', pk=convo_log.id)

@admin_required
def create_cart(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    if request.method == 'POST':
        form = CartForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('cart_list')  # Redirect to cart list page or anywhere you want after creating the cart
    else:
        form = CartForm()
    
    return render(request, 'create_cart.html', {'form': form, 'profile': profile})

@admin_required
def cart_create(request, customer_id):
    customer = get_object_or_404(Customer, id=customer_id)
    cart = Cart.objects.create(
        customer=customer,
        billing_address_line1=customer.address1,
        billing_address_line2=customer.address2,
        billing_city=customer.city,
        billing_state=customer.state,
        billing_zipcode=customer.zip_code,
        billing_country=customer.country,
        shipping_address_line1=customer.address1,
        shipping_address_line2=customer.address2,
        shipping_city=customer.city,
        shipping_state=customer.state,
        shipping_zipcode=customer.zip_code,
        shipping_country=customer.country, 
    )
    return redirect('cart_edit', id=cart.id)

@admin_required
def cart_edit(request, id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    cart = get_object_or_404(Cart, id=id)
    if request.method == "POST":
        form = CartForm(request.POST, instance=cart)
        if form.is_valid():
            form.save()
            return redirect('cart_detail', id=cart.id)
    else:
        form = CartForm(instance=cart)
    return render(request, 'cart_edit.html', {'form': form, 'profile': profile})


@admin_required
def cart_detail(request, id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    try:
        cart = Cart.objects.get(id=id)
        cart_products = CartProduct.objects.filter(cart=cart)

        subtotal = 0
        total_tax = 0
        total_with_tax = 0
        products = []

        for cart_product in cart_products:
            total_price = cart_product.quantity * cart_product.product.price
            product_tax = total_price * cart_product.tax_rate / 100  # Calculate tax for each product
            total_with_product = total_price + product_tax

            subtotal += total_price
            total_tax += product_tax
            total_with_tax += total_with_product

            products.append({
                'product': cart_product.product,
                'quantity': cart_product.quantity,
                'price': cart_product.product.price,
                'line_item_total': total_price,
                'tax': product_tax,
                'total_with_tax': total_with_product,
                'id': cart_product.id,
            })

        total_payments = PaymentApplication.objects.filter(cart=cart).aggregate(models.Sum('applied_amount'))['applied_amount__sum'] or 0
        balance_due = total_with_tax - total_payments

        return render(request, 'cart_detail.html', {
            'cart': cart,
            'cart_products': products,  # Use the detailed products list
            'subtotal': round(subtotal, 2),
            'total_tax': round(total_tax, 2),
            'total_with_tax': round(total_with_tax, 2),
            'total_payments': total_payments,
            'balance_due': round(balance_due, 2),
            'profile': profile,
        })
    except Cart.DoesNotExist:
        return HttpResponseBadRequest("Cart not found.")


@admin_required
def payment_form(request, cart_id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    cart = get_object_or_404(Cart, id=cart_id)

    if request.method == 'POST':
        amount = request.POST.get('amount')
        payment_method = request.POST.get('payment_method')

        if not amount or not payment_method:
            return HttpResponse("Amount and Payment Method are required.", status=400)

        payment = Payment.objects.create(
            customer=cart.customer,
            amount=amount,
            payment_method=payment_method,
            status='PENDING',
        )

        PaymentApplication.objects.create(
            payment=payment,
            cart=cart,
            applied_amount=amount,
        )

        payment.status = 'COMPLETED'
        payment.save()

        return redirect('cart_detail', id=cart.id)

    return render(request, 'payment_form.html', {'cart': cart, 'profile': profile})

@admin_required
def cart_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    
    carts = Cart.objects.order_by('-date_created')  # Fetch all carts, newest first
    paginator = Paginator(carts, 10)  # 10 carts per page
    page_number = request.GET.get('page')  # Get the current page number from query parameters
    page_obj = paginator.get_page(page_number)  # Get the page object

    return render(request, 'cart_list.html', {'page_obj': page_obj, 'profile': profile})

# View to list all products
@admin_required
def product_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    products = Product.objects.all()
    return render(request, 'product_list.html', {'products': products, 'profile': profile})

@admin_required
def product_list_shop(request, cart_id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    cart = get_object_or_404(Cart, id=cart_id)
    products = Product.objects.all()
    return render(request, 'product_list_shop.html', {'products': products, 'cart': cart, 'profile':profile})

def shop_add_to_cart(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    cart_id = request.COOKIES.get('cartId')
    logger.info(f"Cart ID: {cart_id}")
    
    if request.method == 'POST':
        quantity = request.POST.get('quantity')
        product_id = request.POST.get('product_id')
        logger.info(f"Quantity: {quantity}, Product ID: {product_id}")
        
        if not quantity or quantity == '':
            quantity = 1
        
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            logger.error(f"Invalid product ID: {product_id}")
            return JsonResponse({'status': 'error', 'message': 'Invalid product id'})

        if Cart.objects.filter(external_id=cart_id).exists():
            cart = Cart.objects.get(external_id=cart_id)
        else:
            cart = Cart.objects.create(external_id=cart_id)


        tax_rate = profile.tax_rate if not product.is_labor else 0

        CartProduct.objects.create(cart=cart, product=product, quantity=quantity, price=product.price, tax_rate=tax_rate)

        # Set the cart_id in a cookie
        response = JsonResponse({'status': 'success'})
        response.set_cookie('cartId', cart_id)
        return response
    else:
        logger.error("Invalid request method")
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
    
@admin_required
def add_to_cart(request, cart_id, product_id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    try:
        product = Product.objects.get(id=product_id)
        cart = Cart.objects.get(id=cart_id)
        quantity = int(request.POST.get('quantity', 1))  # Default to 1 if no quantity is provided
        
        if quantity < 1:
            return HttpResponseBadRequest("Quantity must be at least 1.")


        cart_products = CartProduct.objects.filter(cart=cart, product=product)
        
        if cart_products.exists():
            # If multiple CartProducts exist, we can delete them or merge
            cart_products.delete()
        
        # Check if product is not labor and get its tax rate
        tax_rate = profile.tax_rate if not product.is_labor else 0
        
        # Create a new CartProduct entry with the correct quantity and tax rate
        CartProduct.objects.create(cart=cart, product=product, quantity=quantity, price=product.price, tax_rate=tax_rate)
 

        return redirect('product_list_shop', cart_id=cart.id)
    except Product.DoesNotExist:
        return HttpResponseBadRequest("Product not found.")
    except Cart.DoesNotExist:
        return HttpResponseBadRequest("Cart not found.")
    
# View to add a new product
@admin_required
def product_add(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('product_list')  # Redirect to the product list after saving
    else:
        form = ProductForm()

    return render(request, 'product_form.html', {'form': form, 'action': 'Add', 'profile': profile})

# View to edit an existing product
@admin_required
def product_edit(request, pk):

    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    product = get_object_or_404(Product, pk=pk)
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            form.save()
            return redirect('product_list')  # Redirect to product list after saving
    else:
        form = ProductForm(instance=product)

    return render(request, 'product_form.html', {'form': form, 'action': 'Edit', 'profile': profile})

@admin_required
def customer_list(request):
    # Get all lifecycle stages for the dropdown filter
    lifecycle_stages = LifecycleStage.objects.all()

    # Get the profile info (if available)
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    # Check if a lifecycle stage filter was applied
    selected_stage = request.GET.get('lifecycle_stage')
    if selected_stage:
        # Filter customers by the selected lifecycle stage
        customers = Customer.objects.filter(lifecycle_stage_id=selected_stage)
    else:
        # Get all customers if no filter is selected
        customers = Customer.objects.all()

    return render(request, 'customer_list.html', {
        'customers': customers,
        'profile': profile,
        'lifecycle_stages': lifecycle_stages,  # Pass lifecycle stages to the template
        'selected_stage': selected_stage,  # Keep track of the selected filter
    })


# Add new customer
@admin_required 
def customer_add(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    if request.method == 'POST':
        form = CustomerForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('customer_list')
    else:
        form = CustomerForm()

    return render(request, 'customer_form.html', {'form': form, 'profile': profile})

# Edit existing customer
@admin_required
def customer_edit(request, customer_id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    customer = get_object_or_404(Customer, id=customer_id)

    if request.method == 'POST':
        form = CustomerForm(request.POST, request.FILES, instance=customer)

        if form.is_valid():
            form.save()
            return redirect('customer_list')
    else:
        form = CustomerForm(instance=customer)

    touchpoints = TouchPointType.objects.filter(
        is_visible=True, 
        lifecycle_stage=customer.lifecycle_stage
    ) if customer.lifecycle_stage else TouchPointType.objects.none()

    return render(request, 'customer_form.html', {
        'form': form,
        'profile': profile,
        'touchpoints': touchpoints
    })


# List all ProductLifecycleStages
@admin_required
def product_lifecycle_stages_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    stages = ProductLifecycleStage.objects.all()
    return render(request, 'product_lifecycle_stages/product_lifecycle_stages_list.html', {'stages': stages, 'profile': profile})

# Create a new ProductLifecycleStage
@admin_required
def product_lifecycle_stages_create(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    if request.method == 'POST':
        form = ProductLifecycleStageForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect(reverse('product_lifecycle_stages_list'))
    else:
        form = ProductLifecycleStageForm()
    return render(request, 'product_lifecycle_stages/product_lifecycle_stages_form.html', {'form': form, 'profile': profile})

# Edit an existing ProductLifecycleStage
@admin_required
def product_lifecycle_stages_edit(request, pk):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    stage = get_object_or_404(ProductLifecycleStage, pk=pk)
    if request.method == 'POST':
        form = ProductLifecycleStageForm(request.POST, instance=stage)
        if form.is_valid():
            form.save()
            return redirect(reverse('product_lifecycle_stages_list'))
    else:
        form = ProductLifecycleStageForm(instance=stage)
    return render(request, 'product_lifecycle_stages/product_lifecycle_stages_form.html', {'form': form, 'stage': stage, 'profile': profile})

@admin_required
@require_POST
def delete_conversation_topic(request, pk):
    topic = get_object_or_404(ConversationTopic, pk=pk)
    topic.delete()
    return redirect('conversation_topics')

@admin_required
def delete_convo_log(request, id):
    convo_log = get_object_or_404(ConvoLog, id=id)
    convo_log.delete()
    messages.success(request, 'Conversation log deleted successfully.')
    return redirect('index')  # Replace 'convo_log_list' with your list view name

@admin_required
def token_list(request):

    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    tokens = TokenProfile.objects.all()
    return render(request, 'tokens/token_list.html', {'tokens': tokens, 'profile': profile})

@admin_required
def toggle_visibility(request, token_id):
    if request.method == "POST":  # Ensure it's a POST request for safety
        token = get_object_or_404(TokenProfile, id=token_id)
        token.visible = not token.visible
        token.save()
        return redirect('token_list')  # Replace 'your_view_name' with the name of the view that renders the token list.
    return HttpResponseForbidden("Invalid request method")

@admin_required
def add_token(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    if request.method == 'POST':
        form = TokenProfileForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('token_list')
    else:
        form = TokenProfileForm()
    return render(request, 'tokens/add_token.html', {'form': form, 'profile': profile})


def custom_logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to the login page or any other page after logout

def conversation_topics(request):
    topics_list = ConversationTopic.objects.all().order_by('-created_date')
    paginator = Paginator(topics_list, 10)  # Show 10 topics per page
    
    page_number = request.GET.get('page')
    topics = paginator.get_page(page_number)
    
    if request.headers.get('Content-Type') == 'application/json' or request.GET.get('format') == 'json':
        # Prepare data for JSON response with elapsed time
        topics_data = [
            {
                'id': topic.id,
                'title': topic.title,
                'created_date': elapsed_time(topic.created_date),  # Use the filter here
            }
            for topic in topics
        ]
        return JsonResponse({'topics': topics_data, 'num_pages': paginator.num_pages})

    return render(request, 'conversation_topics.html', {'topics': topics})


@csrf_exempt
@admin_required 
@api_view(['POST'])
def create_conversation_topic(request):
    print("create_conversation_topic")
    if request.method == 'POST':
        serializer = ConversationTopicSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@admin_required
@api_view(['POST'])
def create_convo_log(request):
    if request.method == 'POST':
        serializer = ConvoLogSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@admin_required
@api_view(['POST'])
def create_user_query(request):
    if request.method == 'POST':
        serializer = UserQuerySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Retrieve all UserQuery records
@api_view(['GET'])
def list_user_queries(request):
    if request.method == 'GET':
        user_queries = UserQuery.objects.all()
        serializer = UserQuerySerializer(user_queries, many=True)
        return Response(serializer.data)

# Retrieve a single UserQuery record by ID
@api_view(['GET'])
def get_user_query(request, query_id):
    try:
        user_query = UserQuery.objects.get(id=query_id)
    except UserQuery.DoesNotExist:
        return Response({'error': 'User query not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = UserQuerySerializer(user_query)
        return Response(serializer.data)
 
def convo_log_detail(request, pk):
    convo_log = get_object_or_404(ConvoLog, pk=pk)
    #comments = Comment.objects.filter(convo_log_id=str(convo_log.id), is_visible=True).order_by('-date')
    comments = Comment.objects.filter(
        convo_log_id=str(convo_log.id), 
        is_visible=True
    ).order_by('-token_balance', '-date')

    for comment in comments:
        if isinstance(comment.comment, bytes):
            comment.comment = comment.comment.decode('utf-8')
    
    return render(request, 'convo_log_detail.html', {
        'convo_log': convo_log,
        'comments': comments,
        'MY_TOKEN': MY_TOKEN,
    })

def user_queries_view(request):
    # Fetch all queries from the database 
    #queries = UserQuery.objects.all().order_by('-created_date')
    queries = UserQuery.objects.all().order_by('-created_date')[:50]


    # If the request is an AJAX request, return JSON response
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        json_queries = queries.values('connanicall_action_text', 'username', 'question', 'reasoning', 'response', 'created_date')
        return JsonResponse(list(json_queries), safe=False)

    # Otherwise, return the regular HTML view
    context = {
        'user_queries': queries,
    }
    return render(request, 'user_queries.html', context)

    
@csrf_exempt
@admin_required
def processed_status(request, status_id):
        # Fetch the TwitterStatus object by status_id
    twitter_status = get_object_or_404(TwitterStatus, status_id=status_id)
    
    # Check if the processed field is False and convert it to True 
    twitter_status.processed = True
    twitter_status.save()  # Save the changes
    
    # Response data after the update
    data = {
        'message': 'Status updated successfully',
        'status_id': twitter_status.status_id,
        'processed': twitter_status.processed,
    }
    return JsonResponse(data)
    
    # If already processed, return a message
    data = {'message': 'Status is already processed', 'processed': twitter_status.processed}
    return JsonResponse(data)
    
def toggle_scam_filter(request):
    access_id = request.COOKIES.get('access_id')
    
    if not access_id:
        return JsonResponse({'error': 'Access ID not found in cookies.'}, status=400)

    access_token = get_object_or_404(Accesstoken, access_cookie=access_id)
    # Toggle the is_scam_filter_on field
    if access_token.is_scam_filter_on:
        access_token.is_scam_filter_on = False
    else:
        access_token.is_scam_filter_on = True
    access_token.save()

    return JsonResponse({'success': True, 'is_scam_filter_on': access_token.is_scam_filter_on})
    
def twitter_status_detail(request, status_id):
    # Fetch the TwitterStatus object by status_id
    print(status_id)
    twitter_status = get_object_or_404(TwitterStatus, status_id=status_id)
    
    # Prepare the data to be returned as JSON
    data = {
        'x_user': twitter_status.x_user,
        'status_id': twitter_status.status_id,
        'created_by_user': twitter_status.created_by_user,
        'created_at': twitter_status.created_at,
        'processed': twitter_status.processed,
    }
    
    return JsonResponse(data)

class TwitterStatusDetailView(View):
    def get(self, request, status_id):
        # Fetch the TwitterStatus object by status_id
        twitter_status = get_object_or_404(TwitterStatus, status_id=status_id)
        # Prepare the data to be returned as JSON or any other format
        data = {
            'x_user': twitter_status.x_user,
            'status_id': twitter_status.status_id,
            'created_by_user': twitter_status.created_by_user,
            'created_at': twitter_status.created_at,
            'processed': twitter_status.processed,
        }
        return JsonResponse(data)

def extract_twitter_info(url):
    match = re.search(r'https://x\.com/([^/]+)/status/(\d+)', url)
    if match:
        username = match.group(1)
        status_id = match.group(2)
        return username, status_id
    return None, None

# View all TwitterStatus entries (API)
@api_view(['GET'])
def list_twitter_status(request):
    if request.method == 'GET':
        statuses = TwitterStatus.objects.all()
        serializer = TwitterStatusSerializer(statuses, many=True)
        return Response(serializer.data)

@require_POST
def delete_status(request, status_id):
    status = get_object_or_404(TwitterStatus, id=status_id)
    status.delete()
    return redirect('view_twitter_status')  # Replace with the URL name for your status list view



@csrf_exempt
@admin_required
def save_twitter_status(request):
    try:
        # Load the JSON body from the request
        url = request.GET.get('url', 'got empty')   
        created_by_user = request.GET.get('created_by', 'got empty')
        print(url)
        print(created_by_user)
        username, status_id = extract_twitter_info(url)  # Ensure this function is correct
        if username and status_id:
            twitter_status = TwitterStatus(
                x_user=username,
                status_id=status_id,
                created_by_user=created_by_user
            )
            twitter_status.save()
            return JsonResponse({"message": "Twitter status saved successfully."}, status=201)
        else:
            print("Username or status ID is missing")
            return JsonResponse({"error": "Username or status ID is missing."}, status=400)

    except Exception as e:
        print(f"An error occurred: {e}")
        return JsonResponse({"error": "An unexpected error occurred."}, status=500)

 
@login_required(login_url='login')
def checkout_view(request):
    form = ShippingBillingForm()  # Default form in case cart doesn't exist
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    cart_id = request.COOKIES.get('cartId')
    try:
        cart = Cart.objects.get(external_id=cart_id)
        cart_products = CartProduct.objects.filter(cart=cart)

        # Get the current user email and check for an existing customer
        customer = None
        if request.user.is_authenticated:
            customer = Customer.objects.filter(email=request.user.email).first()

        if request.user.is_authenticated:
            cart.user = request.user
            cart.save()

        if request.method == 'POST':
            form = ShippingBillingForm(request.POST, instance=cart)
            if form.is_valid():
                form.save()
                return redirect('select_payment')
        else:
            if customer:
                # Fully override the cart data with the customer's address
                cart.shipping_address_line1 = customer.address1
                cart.shipping_address_line2 = customer.address2
                cart.shipping_city = customer.city
                cart.shipping_state = customer.state
                cart.shipping_zipcode = customer.zip_code
                cart.shipping_country = customer.country

                cart.billing_address_line1 = customer.address1
                cart.billing_address_line2 = customer.address2
                cart.billing_city = customer.city
                cart.billing_state = customer.state
                cart.billing_zipcode = customer.zip_code
                cart.billing_country = customer.country

                # Save the cart with the updated information
                cart.save()

            # Now create the form with the updated cart data
            form = ShippingBillingForm(instance=cart)

        subtotal, total_tax, total_with_tax = 0, 0, 0
        products = []

        for cart_product in cart_products:
            total_price = cart_product.quantity * cart_product.product.price
            product_tax = total_price * cart_product.tax_rate / 100
            total_with_product = total_price + product_tax

            subtotal += total_price
            total_tax += product_tax
            total_with_tax += total_with_product

            products.append({
                'product': cart_product.product,
                'quantity': cart_product.quantity,
                'price': cart_product.product.price,
                'line_item_total': total_price,
                'tax': product_tax,
                'total_with_tax': total_with_product,
                'id': cart_product.id,
            })

        total_payments = PaymentApplication.objects.filter(cart=cart).aggregate(models.Sum('applied_amount'))['applied_amount__sum'] or 0
        balance_due = total_with_tax - total_payments

        context = {
            'cart': cart,
            'products': products,
            'subtotal': subtotal,
            'total_tax': total_tax,
            'total_with_tax': total_with_tax,
            'total_payments': total_payments,
            'balance_due': balance_due,
            'profile': profile,
            'form': form,
        }

        return render(request, 'checkout_shop.html', context)
    except Cart.DoesNotExist:
        # Ensure form is still passed if cart doesn't exist
        return redirect('current_cart')  # Redirect back to the cart if something goes wrong

@login_required
def process_checkout(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
        
    cart_id = request.COOKIES.get('cartId')
    
    print('CART ID CHECK OUT')

    print(cart_id) 


    cart = get_object_or_404(Cart, external_id=cart_id)
    #cart = Cart.objects.get(external_id=cart_id) 
    #cart = Cart.objects.filter(external_id=cart_id).first()  # Use first() to get only one cart

    if cart:
        # Process the payment, update the cart, etc.
        cart.checked_out = True
        cart.save()

        cart_products = CartProduct.objects.filter(cart=cart)
        subtotal, total_tax, total_with_tax = 0, 0, 0
        products = []

        for cart_product in cart_products:
            total_price = cart_product.quantity * cart_product.product.price
            product_tax = total_price * cart_product.tax_rate / 100
            total_with_product = total_price + product_tax

            subtotal += total_price
            total_tax += product_tax
            total_with_tax += total_with_product

            products.append({
                'product': cart_product.product,
                'quantity': cart_product.quantity,
                'price': cart_product.product.price,
                'line_item_total': total_price,
                'tax': product_tax,
                'total_with_tax': total_with_product,
                'id': cart_product.id,
            })

        total_payments = PaymentApplication.objects.filter(cart=cart).aggregate(models.Sum('applied_amount'))['applied_amount__sum'] or 0
        balance_due = total_with_tax - total_payments

        context = {
            'cart': cart,
            'products': products,
            'subtotal': subtotal,
            'total_tax': total_tax,
            'total_with_tax': total_with_tax,
            'total_payments': total_payments,
            'balance_due': balance_due,
            'profile': profile, 
        }

        response = render(request, 'order_confirmation.html', context)
        response.delete_cookie('cartId')  # Remove the cookie after checkout
        return response

    return redirect('current_cart')  # Redirect back to the cart if something goes wrong


def view_twitter_status(request):
    statuses = TwitterStatus.objects.all()
    return render(request, 'twitter_status_list.html', {'statuses': statuses})

def login_view(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
        
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'index')  # Redirect to the next URL or index
            return redirect(next_url)
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials', 'profile': profile})    
    return render(request, 'login.html', {'profile': profile})

@csrf_exempt
@admin_required
def delete_tweet_by_content(request):
    content = request.GET.get('content')  # Get the content from the query string
    if not content:
        return redirect('tweet_list')  # Redirect if no content is provided

    # Retrieve all tweets that match the content
    tweets = Tweet.objects.filter(content=content)
    if not tweets.exists():
        return redirect('tweet_list')  # Redirect if no tweets are found

    # Delete all tweets with the matching content
    tweets.delete()
    return redirect('tweet_list')  # Redirect to the list after deletion


# View to delete a tweet without confirmation

@csrf_exempt
@admin_required
def delete_tweet(request, tweet_id):
    tweet = get_object_or_404(Tweet, id=tweet_id)
    tweet.delete()  # Delete the tweet immediately
    return redirect('tweet_list')  # Redirect to the list after deletion

def tweet_list(request):
    tweets = Tweet.objects.all()

    # Check if the request is for JSON format
    if request.GET.get('format') == 'json':
        tweet_data = list(tweets.values())  # Convert the QuerySet to a list of dictionaries
        return JsonResponse(tweet_data, safe=False)

    return render(request, 'tweet_list.html', {'tweets': tweets})

@method_decorator(csrf_exempt, name='dispatch')
def create_tweet_api(request):
    if request.method == 'POST':
        try:
            # Parse the JSON request body
            data = json.loads(request.body)
            tweet_url = data.get('url')
            
            # Create and save the new tweet instance
            if tweet_url:
                new_tweet = Tweet(content=tweet_url)  # Assuming you have a 'url' field in the Tweet model
                new_tweet.save()
                
                # Return a success response
                return JsonResponse({"message": "Tweet saved successfully", "id": new_tweet.id}, status=201)
            else:
                return JsonResponse({"error": "No URL provided"}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    else:
        return JsonResponse({"error": "POST request required"}, status=405)

# View to create a new tweet
# View to list all LifecycleStages
@admin_required
def lifecycle_stage_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    stages = LifecycleStage.objects.all()
    return render(request, 'lifecycle_stage_list.html', {'stages': stages, 'profile': profile})

# View to create a new LifecycleStage
@admin_required
def lifecycle_stage_create(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    if request.method == 'POST':
        form = LifecycleStageForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect(reverse('lifecycle_stage_list'))  # Redirect to the list view
    else:
        form = LifecycleStageForm()
    return render(request, 'lifecycle_stage_form.html', {'form': form, 'profile': profile})

# View to update an existing LifecycleStage
@admin_required
def lifecycle_stage_update(request, pk):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    stage = get_object_or_404(LifecycleStage, pk=pk)
    if request.method == 'POST':
        form = LifecycleStageForm(request.POST, instance=stage)
        if form.is_valid():
            form.save()
            return redirect(reverse('lifecycle_stage_list'))  # Redirect to the list view
    else:
        form = LifecycleStageForm(instance=stage)
    return render(request, 'lifecycle_stage_form.html', {'form': form, 'profile': profile})

@csrf_exempt
@admin_required
def create_tweet(request):
    if request.method == 'POST':
        form = TweetForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('tweet_list')  # Redirect to the list after saving
    else:
        form = TweetForm()
    
    return render(request, 'index.html', {'form': form})    

@csrf_exempt
@require_POST
def add_social_media_handle(request):
    try:
        data = json.loads(request.body)
        handle = data.get('handle')
        follower_count = data.get('follower_count')

        if not handle or not isinstance(follower_count, int):
            return JsonResponse({'error': 'Invalid data'}, status=400)

        # Create and save the SocialMediaHandle instance
        SocialMediaHandle.objects.create(handle=handle, follower_count=follower_count)
        return JsonResponse({'message': 'Social media handle added successfully'}, status=201)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def generate_response():
    authors = ["Mark Twain", "Jane Austen", "George Orwell", "J.K. Rowling", "Ernest Hemingway", "Virginia Woolf", "Leo Tolstoy", "F. Scott Fitzgerald", "Charles Dickens"]

    random_author = random.choice(authors)
    SECRET_KEY = os.getenv('OPENAI_SECRET_KEY')
    openai.api_key = SECRET_KEY
    model_engine = "gpt-3.5-turbo" 
    response = openai.ChatCompletion.create(
        model='gpt-3.5-turbo',
        messages=[
            {"role": "system", "content": "You are a helpful assistant " + random_author},
            {"role": "user", "content": "generate a short tweet about 80 characters long max, about me graduating Schizo University because i am cured and no longer schizo time to connect with alumni, make it positive, funny, intresting and pardoxical"},
        ])

    message_gpt = response.choices[0]['message']['content']
    print("RESPONSE FROM GPT")
    print(message_gpt)
    print("RESPONSE FROM GPT DONE")
    return message_gpt

# View to forward to x.com
def forward_to_x(request): 
    msg = generate_response()
    encoded_msg = urllib.parse.quote(msg.strip('"') + " #schizou $schizou")
    return redirect('https://x.com/intent/post?text=' + encoded_msg)


class TokenMarketingContentCreateView(View):

    def post(self, request, *args, **kwargs):
        marketing_content = request.POST.get('marketing_content')
        contract_address = request.POST.get('contract_address')
        
        if marketing_content and contract_address:
            # Create a new TokenMarketingContent object
            TokenMarketingContent.objects.create(
                marketing_content=marketing_content,
                contract_address=contract_address
            )
            # Return success response
            return JsonResponse({'message': 'Marketing content added successfully!'})
        else:
            # Return error response
            return JsonResponse({'error': 'Both marketing content and contract address are required.'}, status=400)


    def get(self, request, *args, **kwargs):
        return render(request, 'token_marketing_content_form.html')

def toggle_handle_status(request, handle_id):
    handle = get_object_or_404(SocialMediaHandle, id=handle_id)
    handle.is_active = not handle.is_active  # Toggle status
    handle.save()
    return redirect('index')  # Redirect to the list view (update the name if different)

 
def index(request):
 
    cart_id = request.COOKIES.get('cartId')
    if cart_id is None:
        cart_id = generate_id()
 
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")


    tokens = TokenProfile.objects.filter(visible=True)
 
    
    context = {
        'cart_id': cart_id,
        'profile': profile,
        'tokens': tokens, 
    }
    
    response = render(request, 'index.html', context) 
    response.set_cookie('cartId', cart_id) 

    return response


 
@admin_required
def list_and_add_website_profiles(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    
    if request.method == 'POST':
        form = WebsiteProfileForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('list_and_add_website_profiles')
    else:
        initial_data = vars(profile) if profile else {}
        form = WebsiteProfileForm(initial=initial_data)

    profiles = WebsiteProfile.objects.order_by('-created_at')
    return render(request, 'website_profiles.html', {'form': form, 'profiles': profiles, 'profile': profile})

 
@staff_required
def admin_panel(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    # Counting carts
    total_carts = Cart.objects.count()
    checked_out_count = Cart.objects.filter(checked_out=True).count()
    processed_count = Cart.objects.filter(is_processed=True).count()
    paid_count = Cart.objects.filter(paid=True).count()

    # Counting total products and customers
    total_products = Product.objects.count()
    total_customers = Customer.objects.count()  # Using Customer model

    # Initialize model information
    current_model_id = "Not Available"
    current_model_status = "Unknown"
    fallback_model_id = "Not Available"
    fallback_model_status = "Unknown"

    try:
        # OpenAI API setup 
        client = OpenAI(api_key=profile.chatgpt_api_key)

        # Retrieve current model status if model ID is available
        if profile.chatgpt_model_id_current:
            fine_tune_status_current = client.fine_tuning.jobs.retrieve(profile.chatgpt_model_id_current)
            current_model_status = fine_tune_status_current.status
            if current_model_status == 'succeeded':
                current_model_id = fine_tune_status_current.fine_tuned_model
            else:
                current_model_id = "gpt-3.5-turbo"
        else:
            current_model_id = "Not Available"
            current_model_status = "No Model ID Provided"

        # Retrieve status for fallback model if model ID is available
        if profile.chatgpt_model_id:
            fine_tune_status_fallback = client.fine_tuning.jobs.retrieve(profile.chatgpt_model_id)
            fallback_model_status = fine_tune_status_fallback.status
            if fallback_model_status == 'succeeded':
                fallback_model_id = fine_tune_status_fallback.fine_tuned_model
            else:
                fallback_model_id = "gpt-3.5-turbo"
        else:
            fallback_model_id = "Not Available"
            fallback_model_status = "No Model ID Provided"

    except OpenAIError as e:
        # Handle OpenAI API errors and log if necessary
        print(f"Error occurred while retrieving fine-tune status: {e}")
        # If there's an error, leave the values as "Not Available" or "Unknown"
        current_model_id = "Not Available"
        current_model_status = "Error"
        fallback_model_id = "Not Available"
        fallback_model_status = "Error"

    # Add all model statuses and IDs
    return render(request, 'admin.html', {
        'profile': profile,
        'total_carts': total_carts,
        'checked_out_count': checked_out_count,
        'processed_count': processed_count,
        'paid_count': paid_count,
        'total_products': total_products,
        'total_customers': total_customers,
        'current_model_id': current_model_id,
        'current_model_status': current_model_status,
        'fallback_model_id': fallback_model_id,
        'fallback_model_status': fallback_model_status
    })



def generate_id():
    return uuid.uuid4().hex

def view_game(request, game_id):
    game = get_object_or_404(Game, game_id=game_id)

    hands = Hand.objects.filter(game_id=game_id)
    handhistorys = Handhistory.objects.filter(game_id=game_id)

    all_players = Player.objects.filter(session_id=game.session_id)
    context = {
        'game': game,
        'hands': hands,  # Add the hands to the context
        'players': all_players, 
        'handhistorys' : handhistorys,
    }  

    return render(request, 'view_game.html', context)

def delete_product(request, product_id):
    cart_id = request.COOKIES.get('cartId')
    cart_product = get_object_or_404(CartProduct, id=product_id, cart__external_id=cart_id)
    cart_product.delete()
    return view_cart_detail_shop_current(request)

def view_cart_detail_shop_current(request):

    cart_id = request.COOKIES.get('cartId')

    return view_cart_detail_shop(request, cart_id)
 
 
def view_cart_detail_shop(request, cart_id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    try:
        cart = Cart.objects.get(external_id=cart_id)
    except Cart.DoesNotExist:
        # Create a new cart if it doesn't exist
        cart = Cart.objects.create(external_id=cart_id)  # Adjust the length as needed 

    cart_products = CartProduct.objects.filter(cart=cart)

    subtotal = 0
    total_tax = 0
    total_with_tax = 0
    products = []

    for cart_product in cart_products:
        total_price = cart_product.quantity * cart_product.product.price
        product_tax = total_price * cart_product.tax_rate / 100
        total_with_product = total_price + product_tax

        subtotal += total_price
        total_tax += product_tax
        total_with_tax += total_with_product

        products.append({
            'product': cart_product.product,
            'quantity': cart_product.quantity,
            'price': cart_product.product.price,
            'line_item_total': total_price,
            'tax': product_tax,
            'total_with_tax': total_with_product,
            'id': cart_product.id,
        })

    total_payments = PaymentApplication.objects.filter(cart=cart).aggregate(models.Sum('applied_amount'))['applied_amount__sum'] or 0
    balance_due = total_with_tax - total_payments

    context = {
        'cart': cart,
        'products': products,
        'subtotal': subtotal,
        'total_tax': total_tax,
        'total_with_tax': total_with_tax,
        'total_payments': total_payments,
        'balance_due': balance_due,
        'profile': profile,
    }

    return render(request, 'cart_detail_shop.html', context)

def all_games(request):
    games = Game.objects.all().order_by('-date_created')
    #games = Game.objects.filter(game_state='End of Hand').order_by('-date_created')  # Filter games with state "End of Hand"
        
    paginator = Paginator(games, 10)  # Show 10 games per page

    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {'page_obj': page_obj}
    return render(request, 'all_games.html', context)

def game_create(request):
    access_id = request.COOKIES.get('access_id')
    access_token = Accesstoken.objects.get(access_cookie=access_id)
    access_token.bank_balance = bank_default_balance
    access_token.save()

    if request.method == "POST":
        number_of_players = int(request.POST.get('number_of_players' ))

        if number_of_players != 0 and request.POST.get( 'player2_type', None) == None: 
            session_id = str(uuid.uuid4())
            players = range(1, number_of_players)
            context = {'poker_player_types': poker_player_types, 'number_of_players': number_of_players, 'poker_player_types': poker_player_types, 'players': players}
            response = render(request, 'game.html', context)
            return response
        else:    
            #[add code]
            players = range(1, number_of_players)
            
            player_types = []
            for player in range(1, number_of_players + 1):
                player_type = request.POST.get(f"player{player}_type", None)
                if player_type == 'Select one' :

                    selected_player_type = random.choice(poker_player_types)
                    player_type = selected_player_type['type']
                    player_types.append(player_type)
                else:    
                    player_types.append(player_type)

                print(f"Player {player} - Type: {player_type}")      

            session_id = str(uuid.uuid4())
            return init_game(request, 0, number_of_players, session_id, player_types)

    else:    
        context = {'poker_player_types': poker_player_types}
        response = render(request, 'game.html', context)
        return response

def init_game(request, current_blind, number_of_players, session_id, player_types):
    access_id = request.COOKIES.get('access_id')
    names = ["Alice", "Bob", "Charlie", "Diana", "Edward", "Fiona", "George", "Hannah", "Ian", "Julia", "Kevin", "Laura", "Michael", "Nina", "Oscar", "Paula", "Quincy", "Rachel", "Steven", "Tina", "Umar", "Violet", "Walter", "Xena", "Yasmine", "Zachary"]

    random.shuffle(deck)
    game_id = str(uuid.uuid4())
    secret_key = str(uuid.uuid4())
    if number_of_players == '2':
        current_player = 1
    else:
        current_player = current_blind + 3  

    # Converting the deck to a comma-separated string
    deck_string = ",".join(deck)

    flop = ",".join(deck[0:3])
    turn = deck[3]
    river = deck[4]
    
    pot_size = small_blind_size + big_blind_size
    # Save game data to Game model
    game = Game.objects.create(
        game_id=game_id,
        session_id=session_id,
        deck=deck_string,
        secret_key=secret_key,
        number_of_players=int(number_of_players),
        current_blind=current_blind,
        pot_size=pot_size,
        current_player=current_player,
        flop=flop,
        turn=turn,
        river=river
    )

    game_object = Game.objects.get(game_id=game_id)

    combined_string = deck_string + secret_key
    # Generate hash (SHA-256 example)
    hash_object = hashlib.sha256(combined_string.encode())
    generated_hash = hash_object.hexdigest()

    public_wallet_address = None
    try:
        access_token = Accesstoken.objects.get(access_cookie=access_id)
        public_wallet_address = access_token.public_wallet_address
        game_object.public_wallet_address = public_wallet_address
        game_object.save()
    except Accesstoken.DoesNotExist:
        # Handle the case where the access token is not found
        public_wallet_address = None
    all_players = Player.objects.filter(session_id=session_id)
    players = Player.objects.filter(session_id=session_id, token_balance__gt=small_blind_size)
    # Create hands for each player
    if not players:
        for i in range(int(number_of_players)):
            # Select two cards for each player (adjust your logic here)
            player_cards = deck[5 + i*2:7 + i*2]
            # Convert player cards to a string representation (adjust as needed)
            player_hand_string = ",".join(player_cards)

            # Generate hand ID for the player's hand
            hand_id = str(uuid.uuid4())
            player_type = "Me"
            bet_amount = 0
            # Determine the player_public_key
            if i == 0:
                player_public_key = "Me"
                access_token.bank_balance -= small_blind_size
                access_token.save()
                bet_amount = small_blind_size
            else:
                player_type = player_types[i-1]
                print(player_type)
                player_public_key = random.choice(names)
                names.remove(player_public_key)

            if i == current_blind:
                player_state = ''
            elif i == current_blind + 1:
                player_state = "Big Blind"
            else:
                player_state = ''

            player_id = str(uuid.uuid4())
            
            lower_bound = max(0, bank_default_balance - bank_default_balance_range)
            upper_bound = bank_default_balance + bank_default_balance_range
            random_number = random.randint(lower_bound, upper_bound)
            bank_default_balance_tmp = random_number

            bet_amount = 0
            if i == 0:
                bank_default_balance_tmp -= small_blind_size
                bet_amount = small_blind_size

            if i == 1:
                bank_default_balance_tmp -= big_blind_size
                bet_amount = big_blind_size

            Player.objects.create(
                player_id=player_id,
                session_id=session_id,
                token_balance=bank_default_balance_tmp,
                player_type=player_type
            )

            Hand.objects.create(
                hand_id=hand_id,
                game_id=game_id,
                player_id=player_id,
                player_public_key=player_public_key,
                hand=player_hand_string,
                player_state=player_state,
                bet_amount=bet_amount
            )
    else:
        print(len(players))
        for player_index, player in enumerate(players):
            player_cards = deck[5 + player_index * 2: 7 + player_index * 2]        
            # Convert player cards to a string representation (adjust as needed)
            player_hand_string = ",".join(player_cards)

            # Generate hand ID for the player's hand
            hand_id = str(uuid.uuid4())
            # Determine the player_public_key
            player_type = "Me"
            if player_index == 0:
                player_public_key = "Me"
            else:
                player_public_key = random.choice(names)
                names.remove(player_public_key)

            if player_index == current_blind:
                player.token_balance -= small_blind_size
                player.save()
                player_state = "Blind"
            elif player_index == current_blind + 1:
                player.token_balance -= big_blind_size
                player.save()
                player_state = "Big Blind"
            else:
                player_state = ''
            
            
            Hand.objects.create(
                hand_id=hand_id,
                game_id=game_id,
                player_id=player.player_id,
                player_public_key=player_public_key,
                hand=player_hand_string,
                player_state=player_state,
                player_type=player.player_type,
                token_balance=player.token_balance
            )

    hands = Hand.objects.filter(game_id=game_id)
    context = {
        'game': game_object,
        'players': all_players, 
        'generated_hash': generated_hash,
        'hands': hands,  # Add the hands to the context
        'small_blind_size': small_blind_size, 
        'big_blind_size': big_blind_size,
        'access_id': access_id, 
    }        
    response = render(request, 'game.html', context)
    return response

def extract_json_from_string(text):
    # Find the first occurrence of a JSON-like object
    pattern = r'\{(?:[^{}]|)*\}'
    match = re.search(pattern, text)
    if match:
        json_str = match.group()
        return json_str
    else:
        return None        
    
def game_next(request):
    cart_id = request.COOKIES.get('cartId')
    access_id = request.COOKIES.get('access_id')
    winning_hand = None
    access_token = Accesstoken.objects.get(access_cookie=access_id)
    poker_game_states = ["Pre-flop", "Flop", "Turn (Fourth Street)", "River (Fifth Street)", "Showdown", "End of Hand"]

    game_id = request.POST.get('game_id')  

    action = request.POST.get('action')
    raise_amount = request.POST.get('raise_amount', 0) 

    game_object = get_object_or_404(Game, game_id=game_id)

    if game_object.public_wallet_address != access_token.public_wallet_address:
        return HttpResponseForbidden("Unauthorized access")

    all_players = Player.objects.filter(session_id=game_object.session_id)
    hands = Hand.objects.filter(game_id=game_id)

    combined_string = game_object.deck + game_object.secret_key
    # Generate hash (SHA-256 example)
    hash_object = hashlib.sha256(combined_string.encode())
    generated_hash = hash_object.hexdigest()
    
    # Find the next active player
    current_player_index = game_object.current_player - 1  # Convert to zero-indexed
    if action == "Fold" or action == "Call" or action == "Raise":
        hand_object = hands[current_player_index]
        #call openai to get reason and analysis of this action 

        openai_var = os.getenv('OPENAI')
        openai.api_key = openai_var
        prompt = 'reponde with json string with fromat {"action": "", "amount": , "reasoning":  } with educational reasoning and action being Raise, Fold or Call with your next move given the following Texas Holdem poker hand ' + hand_object.hand + ' the game is in the following stage ' + game_object.game_state 
        
        if game_object.last_action_play == 'Big Blind':
            prompt += ' previous player is the Big Blind you are under the gun and big blind amount is at ' + str(big_blind_size) + ' number of players in the game ' + str(game_object.number_of_players)
        else:
            prompt += ' previous player did the following ' + game_object.last_action 
        
        prompt +=  ' your chip stack balance is ' + str(access_token.bank_balance)
        
        if game_object.last_action == "Raise":
           prompt +=  ' for the amount of ' + str(game_object.raise_amount)
        
        if game_object.game_state == poker_game_states[1] or game_object.game_state == poker_game_states[2] or game_object.game_state == poker_game_states[3]:
            prompt += ' the flop cards are the following ' + game_object.flop
        if game_object.game_state == poker_game_states[2] or game_object.game_state == poker_game_states[3]:
            prompt += ' the turn card is the following ' + game_object.turn
        if game_object.game_state == poker_game_states[3]:
            prompt += ' the river card is the following ' + game_object.river
        
        response = openai.ChatCompletion.create(
            model='gpt-3.5-turbo',
            messages=[
                {"role": "system", "content": "You are a professional poker player."},
                {"role": "user", "content": prompt},
            ])

        message_gpt = response.choices[0]['message']['content']
        print("RESPONSE FROM GPT")
        print(message_gpt)


        json_data = json.loads(extract_json_from_string(message_gpt))

        reasoning = json_data['reasoning']

        Handhistory.objects.create(
            hand_id=hand_object.hand_id,
            game_id=hand_object.game_id,
            player_id=hand_object.player_id,
            player_public_key=hand_object.player_public_key,
            player_state=action,
            reasoning=reasoning,
            game_state=game_object.game_state,
            player_type='Me'
        )            
        json_data = json.loads(extract_json_from_string(message_gpt))


    if action == "Fold":
        # Handle fold action
        print(action)    
        hand_object = hands[current_player_index]
        hand_object.player_state = "Fold"
        hand_object.save()
        game_object.last_action_play = "Fold"
        game_object.save()
  

    elif action == "Call":
        # Handle call action
        print(action)     
        access_token.bank_balance -= game_object.raise_amount - hand_object.bet_amount
        access_token.save()
        hand_object = hands[current_player_index]
        hand_object.player_state = "Call"
        hand_object.bet_amount = game_object.raise_amount
        hand_object.save()
        game_object.last_action_play = "Call"
        game_object.last_action = "Call"
        game_object.save()

    elif action == "Check":
        hand_object = hands[current_player_index]
        hand_object.player_state = "Check"
        hand_object.save()
        game_object.last_action_play = "Check"
        game_object.save()

    elif action == "Raise":
        # Handle raise action
        access_token.bank_balance -= int(raise_amount) - hand_object.bet_amount
        access_token.save()
        game_object.pot_size += int(raise_amount)  
        hand_object = hands[current_player_index]
        hand_object.player_state = "Raise"
        game_object.last_action_play = "Raise"
        game_object.last_action = "Raise"
        game_object.raise_amount = int(raise_amount)
        hand_object.save()
        game_object.save()
        game_state_manager_action(game_object, hands, all_players, current_player_index) 

    elif action == "Next":
        # Handle next action (advance to the next player)
        hand_object = hands[current_player_index]
        player = Player.objects.get(player_id=hand_object.player_id)

        openai_var = os.getenv('OPENAI')
        openai.api_key = openai_var
        prompt = 'reponde with json string with fromat {"action": "", "amount": , "reasoning":  } with reasoning and action being Raise, Fold or Call with your next move given the following Texas Holdem poker hand ' + hand_object.hand + ' the game is in the following stage ' + game_object.game_state 
        
        if game_object.last_action_play == 'Big Blind':
            prompt += ' previous player is the Big Blind you are under the gun and big blind amount is at ' + str(big_blind_size) + ' number of players in the game ' + str(game_object.number_of_players)
        else:
            prompt += ' previous player did the following ' + game_object.last_action 
        
        prompt +=  ' your chip stack balance is ' + str(player.token_balance)
        
        if game_object.last_action == "Raise":
           prompt +=  ' for the amount of ' + str(game_object.raise_amount)
        
        if game_object.game_state == poker_game_states[1] or game_object.game_state == poker_game_states[2] or game_object.game_state == poker_game_states[3]:
            prompt += ' the flop cards are the following ' + game_object.flop
        if game_object.game_state == poker_game_states[2] or game_object.game_state == poker_game_states[3]:
            prompt += ' the turn card is the following ' + game_object.turn
        if game_object.game_state == poker_game_states[3]:
            prompt += ' the river card is the following ' + game_object.river

        prompt += ' remember you are a ' + player.player_type + " poker player."    
        
        response = openai.ChatCompletion.create(
            model='gpt-3.5-turbo',
            messages=[
                {"role": "system", "content": "You are a persona of a " + player.player_type + " poker player."},
                {"role": "user", "content": prompt},
            ])

        message_gpt = response.choices[0]['message']['content']
        print("RESPONSE FROM GPT")
        print(message_gpt)
        json_data = json.loads(extract_json_from_string(message_gpt))

        if json_data:
            print("Extracted JSON:", json_data)
            print(json_data['action'])       
            action = json_data['action']

            # Now check if action is "Raise"
            if action == "Raise":
                print("Action is Raise")
                game_object.last_action_play = json_data['action']
                game_object.last_action = json_data['action']                     
                game_object.pot_size += int(json_data['amount']) - hand_object.bet_amount
                game_object.raise_amount += int(json_data['amount']) 
                game_object.save()
                player.token_balance -= game_object.raise_amount + int(json_data['amount']) - hand_object.bet_amount
                player.save()
                hand_object.bet_amount = game_object.raise_amount + game_object.raise_amount
                hand_object.save()
                game_state_manager_action(game_object, hands, all_players, current_player_index) 

                # Your code logic when action is Raise
            elif action == "Call":  
                game_object.last_action_play = json_data['action']
                game_object.last_action = json_data['action']     
                game_object.save()
                if game_object.raise_amount == 0:
                    player.token_balance -= big_blind_size
                    player.save()                  
                else:    
                    game_object.pot_size += game_object.raise_amount - hand_object.bet_amount
                    game_object.save()
                    player.token_balance -= game_object.raise_amount - hand_object.bet_amount
                    player.save()                  
                    hand_object.bet_amount = game_object.raise_amount
                    hand_object.save()
            else:
                game_object.last_action_play = json_data['action']
                print("Action is not Raise")
                #game_object.raise_amount = 0
                # Your code logic when action is not Raise

            if player.token_balance < 0: 
                hand_object.player_state = 'All In' 
            else:
                hand_object.player_state = json_data['action']   

            hand_object.save()  

            reasoning = json_data['reasoning']
            print(reasoning)    
            #ARM
            
            Handhistory.objects.create(
                hand_id=hand_object.hand_id,
                game_id=hand_object.game_id,
                player_id=hand_object.player_id,
                player_public_key=hand_object.player_public_key,
                player_state=hand_object.player_state,
                game_state=game_object.game_state,
                reasoning=reasoning,
                player_type=player.player_type
            )            
            # Now you can parse json_data using json.loads() if needed
        else:
            print("No JSON object found in the string.")


        print("RESPONSE FROM GPT DONE")



    hands = Hand.objects.filter(game_id=game_id)

    while True:
        current_player_index = (current_player_index + 1) % game_object.number_of_players
        if current_player_index >= len(hands):
            break  # Should not happen if number_of_players <= len(hands)
        
        # Check if this player's hand state is not "fold"
        if hands[current_player_index].player_state != "Fold" and hands[current_player_index].player_state != "All In" :
            game_object.current_player = current_player_index + 1  # Convert back to one-indexed
            game_object.save()
            break

    # UPDING THE STATE ENGINE MANAGER HERE 
    # NEED TO CREATE ABILITY TO RERAISE GO IN CIRCLES

    remaining_hands = Hand.objects.filter(game_id=game_id).exclude(player_state__in=['Fold', 'All In'])
    num_remaining_hands = remaining_hands.count()
    if num_remaining_hands == 1:
        game_object.game_state = poker_game_states[-1]  # Set game state to the last item in the array
        winning_hand = remaining_hands.first()
        game_object.save()

    
    no_empty_player_states = not Hand.objects.filter(game_id=game_id, player_state='').exists()

    if no_empty_player_states:
        print("There are no hands with empty player_state.")
        current_index = poker_game_states.index(game_object.game_state)
        if current_index + 1 < len(poker_game_states):
            game_object.game_state = poker_game_states[current_index+1]
            game_object.raise_amount = 0
            game_object.save()            

            if game_object.game_state == poker_game_states[-1] :
                found_winner = game_state_manager_action_find_winner(game_object, hands, all_players)
            else :    
                for index, hand in enumerate(hands):
                    if hand.player_state != "Fold" and hand.player_state != "All In":
                        hand.player_state = ''
                        hand.bet_amount = 0
                        hand.save()    
            

        else:
            game_object.game_state = poker_game_states[-1]
            game_object.save()
            found_winner = game_state_manager_action_find_winner(game_object, hands, all_players)
            #current_blind = game_object.current_blind + 1 
            #return init_game(request, current_blind, game_object.number_of_players, game_object.session_id)
    
    #game_object = game_state_manager(game_object, hands, all_players, game_object.current_player, False, False, 0, action)
    
    
    hash_object = hashlib.sha256(combined_string.encode())
    
    hands = Hand.objects.filter(game_id=game_id)
    game_object = get_object_or_404(Game, game_id=game_id)
    handhistorys = Handhistory.objects.filter(game_id=game_id)
    has_raise_or_big_blind = Hand.objects.filter(
        Q(game_id=game_id) & Q(player_state__in=['Raise', 'Big Blind'])
    ).exists()


    context = {
        'game': game_object,
        'generated_hash': generated_hash,
        'hands': hands,  # Add the hands to the context
        'players': all_players,
        'small_blind_size': small_blind_size,  
        'big_blind_size': big_blind_size,
        'access_id': access_id, 
        'winning_hand': winning_hand,
        'handhistorys' : handhistorys,
        'has_raise_or_big_blind': has_raise_or_big_blind
    }        
    
    response = render(request, 'game.html', context)
    return response

def verify_signature_game(request):
    if request.method == 'GET':
        public_key = request.GET.get('publicKey', '').strip()  # Ensure no leading/trailing spaces
        print(public_key)
        signature_base64 = request.GET.get('signature', '')
        
        print(signature_base64)
        message_or_transaction = 'Hello from Game!'
        try:

            # Decode the base64 signature into bytes
            signature_bytes = base64.b64decode(signature_base64)
            # Prepare the message as bytes
            message_bytes = message_or_transaction.encode('utf-8')

            # Decode the Solana public key from Base58 to bytes
            public_key_bytes = base58.b58decode(public_key)

            # Create a VerifyKey instance
            verify_key = VerifyKey(public_key_bytes)
            print('Made it here')
            verify_key.verify(message_bytes, signature_bytes)
            print("Signature is valid!")

            response_data = {
                'valid': True,
                'message': 'Signature is valid.'
            }
            response_tmp = JsonResponse(response_data) 
            user = request.user
            user.sol_wallet_address = public_key
            user.save()

            return response_tmp  
                    
        except BadSignatureError:
            print("Signature verification failed: Invalid signature")
            return JsonResponse({'valid': False, 'message': 'Invalid signature'})
        except Exception as e:
            print(f"Signature verification failed: {str(e)}")
            return JsonResponse({'valid': False, 'message': str(e)}, status=500)


def verify_signature(request):
    if request.method == 'GET':
        public_key = request.GET.get('publicKey', '').strip()  # Ensure no leading/trailing spaces
        print(public_key)
        signature_base64 = request.GET.get('signature', '')
        message_or_transaction = request.GET.get('message', '')
        print(message_or_transaction)
        if isinstance(message_or_transaction, bytes):
            message_or_transaction = message_or_transaction.decode('utf-8')

        convo_log_id = request.GET.get('convo_log_id', '')
        print(signature_base64)

        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip_address:
            # HTTP_X_FORWARDED_FOR may return multiple IPs if there are proxies in between;
            # the client’s IP address is the first in the list
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        
        try:
            
            # Decode the base64 signature into bytes
            signature_bytes = base64.b64decode(signature_base64)
            
            # Prepare the message as bytes
            message_bytes = message_or_transaction.encode('utf-8')

            # Decode the Solana public key from Base58 to bytes
            public_key_bytes = base58.b58decode(public_key)

            # Create a VerifyKey instance
            verify_key = VerifyKey(public_key_bytes)
            #print('Made it here')
            verify_key.verify(message_bytes, signature_bytes)
            #print("Signature is valid!")

             
            url = "https://solana-mainnet.g.alchemy.com/v2/VtqY_fIlu2ELUJF4Ea1uLKEYsW-XopF5"
            headers = {"accept": "application/json", "content-type": "application/json"}

            payload = {
                "id": 1,
                "jsonrpc": "2.0",
                "method": "getTokenAccountsByOwner",
                "params": [
                    public_key,
                    {"mint": MY_TOKEN},
                    {"encoding": "jsonParsed"},
                ],
            }


            # Request token accounts
            response = requests.post(url, json=payload, headers=headers)
            response_data = response.json()

            # Check if there is a token account in the response
            if response_data.get("result", {}).get("value"):
                token_amount_str = response_data["result"]["value"][0]["account"]["data"]["parsed"]["info"]["tokenAmount"]["uiAmount"]
                token_amount_float = float(token_amount_str)
            else:
                token_amount_float = 0  # Default to 0 if no token account is found
                print("No token account found for the given public key and token mint.")


            
            access_id = request.COOKIES.get('access_id')

            try:
                access_token = Accesstoken.objects.get(access_cookie=access_id)
                public_wallet_address = access_token.public_wallet_address
            except Accesstoken.DoesNotExist:
                # Handle the case where the access token is not found
                public_wallet_address = None

            if token_amount_float >= 0:    
                print("Token amount is greater than 1,000,000")
                access_id = generate_id()
                print(access_id)
                response_data = {
                    'valid': True,
                    'message': 'Signature is valid.'
                }
                response = JsonResponse(response_data)
                response.set_cookie('access_id', access_id)     
 
                access_token, created = Accesstoken.objects.get_or_create(
                    public_wallet_address=public_key,
                    defaults={
                        'access_cookie': access_id,
                        'token_balance': token_amount_float,
                        'bank_balance' : bank_default_balance,
                    }
                )

                # If not created, update existing access_token
                if not created:
                    access_token.access_cookie = access_id
                    access_token.token_balance = token_amount_float
                    access_token.save()

                # Optionally, you can print or log the instance for verification
                print(access_token)                
                Comment.objects.create(
                    wallet_id=public_key,
                    token_balance=token_amount_float,
                    date=timezone.now(),
                    comment=message_or_transaction,
                    comment_signed=signature_base64,
                    ip_address=ip_address,
                    convo_log_id=convo_log_id,
                    is_visible=True,
                    upvote_count=0
                )
                

                return response    
            else:
                print("Token amount is not greater than 1,000,000")
                print("Token Amount as Float:", token_amount_float)
                return JsonResponse({'valid': True, 'message': 'Signature is valid.'})
            
        except BadSignatureError:
            print("Signature verification failed: Invalid signature")
            return JsonResponse({'valid': False, 'message': 'Invalid signature'})
        except Exception as e:
            print(f"Signature verification failed: {str(e)}")
            return JsonResponse({'valid': False, 'message': str(e)}, status=500)



def game_state_manager_action(game, hands, players, current_player_index):

    for hand in hands:
        hand.last_raise = False
        hand.save()

    hand_object = hands[current_player_index]
    hand_object.last_raise = True
    hand_object.save()


    update_hands = Hand.objects.filter(
        Q(game_id=game.game_id),
        Q(player_state='Check') | Q(player_state='Call')| Q(player_state='Raise') | Q(player_state='Blind') | Q(player_state='Big Blind')
    )
    if update_hands:
        for index, hand in enumerate(update_hands): 
            if hand.last_raise != True :
                hand.player_state = ''
                hand.save() 
 
 
def game_state_manager_action_find_winner(game, hands, players):


    openai_var = os.getenv('OPENAI')
    openai.api_key = openai_var
    prompt = 'reponde with json string with fromat {"winner": "", "winning_hand": ""} with winner being the plyer number and winning_hand being the Royal Flush, Straight Flush, Four of a Kind, Full House, Flush, Straight, Three of a Kind, Two Pair, One Pair, High Card.' 
    print(prompt)
    for index, player in enumerate(players):
        hand = hands[index]
        prompt += f' player number {index + 1} has the following cards {hand.hand} last action was {hand.player_state}.\n'
        print(f"Counter: {index + 1}, Player ID: {player.id}")
    
    prompt +=  ' the following cards are the flop ' + str(game.flop)     
    prompt +=  ' the following card is the turn ' + str(game.turn)     
    prompt +=  ' the following card is the river ' + str(game.river)   
    prompt +=  ' make sure you are correct when juding the player hand and consider their last action if it is Fold do not count them as winner'     
    
    print(prompt)

    response = openai.ChatCompletion.create(
        model='gpt-3.5-turbo',
        messages=[
            {"role": "system", "content": "You are a persona of a professional poker player."},
            {"role": "user", "content": prompt},
        ])

    message_gpt = response.choices[0]['message']['content']
    print("RESPONSE FROM GPT")
    print(message_gpt)
    json_data = json.loads(extract_json_from_string(message_gpt))

    if json_data:
        print("Extracted Winner JSON:", json_data)
        print(json_data['winner'])       
        winner = json_data['winner']
        game.winner = int(winner) -1
        game.winning_hand = json_data['winning_hand']
        game.save()

@csrf_exempt
def get_count(request):
    # Get the column name and value from the request
    access_id = request.COOKIES.get('access_id')
    column_name = request.GET.get('column_name')
    value = request.GET.get('value')

    access_cookie = request.COOKIES.get('access_id')
    
    if not column_name or not value:
        return JsonResponse({'error': 'Both column_name and value must be provided.'}, status=400)

    # Check if access token exists in the database
    occurrences = PumpFunToken.objects.filter(**{column_name: value}).count()
    return JsonResponse({'column': column_name, 'value': value, 'occurrences': occurrences})



# PUMP FUN CLUB CODE 
def superuser_required(user):
    return user.is_superuser


@admin_required
def marketcap_async(request): 


    access_id = request.COOKIES.get('access_id')


    try:
        try:
            access_token = Accesstoken.objects.get(access_cookie=access_id)
            context = {'request': request, 'access_token': access_token, 'MY_TOKEN': MY_TOKEN }
            return render(request, 'marketcap_async.html', context)
        except Accesstoken.DoesNotExist:
            access_token = None
            context = {'request': request, 'access_token': access_token, 'MY_TOKEN': MY_TOKEN }
            return render(request, 'marketcap_async.html', context)

    except Exception as e:
        print("An error occurred while rendering the template:", e)
        return render(request, 'error.html', {'error_message': 'An error occurred while rendering the template.'})

def marketcap_json(request):
    tokens = None

    try:
        # Fetch the latest 30 records from the Token model
        search_name = request.GET.get('search_name')
        search_value = request.GET.get('search_value')
        
        if search_name and search_value:
            # Using **kwargs to dynamically filter by search_name and search_value
            filter_kwargs = {search_name: search_value}
            tokens = PumpFunToken.objects.filter(**filter_kwargs).order_by('-created_timestamp')[:7]
        elif search_value:
            # Perform a like search on specific fields
            tokens = PumpFunToken.objects.filter(
                Q(mint__icontains=search_value) | 
                Q(name__icontains=search_value) | 
                Q(symbol__icontains=search_value) | 
                Q(image_uri__icontains=search_value) | 
                Q(twitter__icontains=search_value) | 
                Q(telegram__icontains=search_value) | 
                Q(website__icontains=search_value)
            ).order_by('-created_timestamp')[:15]            
        else:
            tokens = PumpFunToken.objects.order_by('-created_timestamp')[:7]


        total_token_count = PumpFunToken.objects.count()
    except Exception as e:
        print("An error occurred while fetching data from the database:", e)
        return JsonResponse({'error_message': 'An error occurred while fetching data from the database.'}, status=500)

    # Create a list of dictionaries to hold token data
    token_list = []
    for token in tokens:
        token_data = {
            'id': token.id,
            'mint': token.mint,
            'name': token.name,
            'symbol': token.symbol,
            'description': token.description,
            'image_uri': token.image_uri,
            'metadata_uri': token.metadata_uri,
            'twitter': token.twitter,
            'telegram': token.telegram,
            'creator': token.creator,
            'website': token.website,
            'ai_analysis': token.ai_analysis
        }
        token_list.append(token_data)

    response_data = {
        'tokens': token_list,
        'total_token_count': total_token_count
    }

    return JsonResponse(response_data)
     
@csrf_exempt
@user_passes_test(superuser_required)
def create_token(request):
    print("create_token")
    if request.method == 'POST':
        try:
            # Extracting variables from the POST request

            print("POST Data:", request.POST)
            mint = request.POST.get('mint')
            name = request.POST.get('name')
            symbol = request.POST.get('symbol')

            name = strip_non_unicode(name)
            symbol = strip_non_unicode(symbol)

            #description = request.POST.get('description')
            description = request.POST.get('description')
            image_uri = request.POST.get('image_uri')
            metadata_uri = request.POST.get('metadata_uri')
            twitter = request.POST.get('twitter')
            telegram = request.POST.get('telegram')
            bonding_curve = request.POST.get('bonding_curve')
            associated_bonding_curve = request.POST.get('associated_bonding_curve')
            creator = request.POST.get('creator')
            raydium_pool = request.POST.get('raydium_pool')
            complete = request.POST.get('complete', 'False').lower() == 'true'
            virtual_sol_reserves = request.POST.get('virtual_sol_reserves')
            virtual_token_reserves = request.POST.get('virtual_token_reserves')
            hidden = request.POST.get('hidden', 'False').lower() == 'true'
            total_supply = request.POST.get('total_supply')
            website = request.POST.get('website', '')
            show_name = request.POST.get('show_name', 'False').lower() == 'true'
            last_trade_timestamp = request.POST.get('last_trade_timestamp')
            king_of_the_hill_timestamp = request.POST.get('king_of_the_hill_timestamp')
            market_cap = request.POST.get('market_cap')
            reply_count = request.POST.get('reply_count')
            last_reply = request.POST.get('last_reply')
            nsfw = request.POST.get('nsfw', 'False').lower() == 'true'
            market_id = request.POST.get('market_id')
            inverted = request.POST.get('inverted', 'False').lower() == 'true'
            username = request.POST.get('username')
            profile_image = request.POST.get('profile_image')
            usd_market_cap = request.POST.get('usd_market_cap')
            ai_analysis = request.POST.get('ai_analysis')
            
            # Creating and saving the Token object
            token = PumpFunToken(
                mint=mint,
                name=name,
                symbol=symbol,
                image_uri=image_uri,
                metadata_uri=metadata_uri,
                twitter=twitter,
                telegram=telegram,
                bonding_curve=bonding_curve,
                associated_bonding_curve=associated_bonding_curve,
                creator=creator,
                raydium_pool=raydium_pool,
                complete=complete,
                hidden=hidden,
                website=website,
                show_name=show_name,
                market_cap=market_cap,
                last_reply=last_reply,
                nsfw=nsfw,
                inverted=inverted,
                username=username,
                profile_image=profile_image,
                usd_market_cap=usd_market_cap,
                created_timestamp=timezone.now(),  # Setting the created timestamp
                ai_analysis=ai_analysis
            )
            token.save()
            
            return JsonResponse({'message': 'Token created successfully.'}, status=201)
        except Exception as e:
            print(str(e))
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed.'}, status=405)

def token_detail(request, mint):
    token = get_object_or_404(PumpFunToken, mint=mint)
    
    # Retrieve access_cookie from cookies
    access_cookie = request.COOKIES.get('access_id')
    print(access_cookie)
    
    # Initialize user and public_wallet_address to None
    user = None
    public_wallet_address = None
    
    if access_cookie:
        try:
            # Fetch the Accesstoken based on access_cookie
            access_token = Accesstoken.objects.get(access_cookie=access_cookie)
            public_wallet_address = access_token.public_wallet_address
            print(public_wallet_address)
        except Accesstoken.DoesNotExist:
            access_token = None

    if request.method == 'POST':
        url = request.POST.get('url')
        
        if mint and url:
            # Check if the URL starts with 'https://x.com'
            if url.startswith('https://x.com'):
                # Check if a RaidLink with the same URL and token mint already exists
                existing_link = RaidLink.objects.filter(token_mint=mint, url=url).exists()
                
                if not existing_link:
                    raid_link = RaidLink(
                        token_mint=mint,
                        url=url,
                        click_count=0,  # Initial click count
                        created_by=public_wallet_address  # Set the user who created the link
                    )
                    raid_link.save()
                    return redirect('token_detail', mint=mint)  # Redirect to the same page after saving
                else:
                    # Notify user that the link has already been added
                    messages.error(request, 'This link has already been added for this token.')
            else:
                # Notify user that the URL must start with 'https://x.com'
                messages.error(request, 'URL must start with https://x.com')

            return redirect('token_detail', mint=mint)

    # Retrieve all RaidLinks associated with the token mint
    raid_links = RaidLink.objects.filter(token_mint=mint)
    
    # Extract distinct accounts from raid links
    accounts = set()
    for link in raid_links:
        match = re.search(r'https://x\.com/([^/]+)/status/\d+', link.url)
        if match:
            account = match.group(1)
            accounts.add(account)

    # Prepare data for JSON response
    response_data = {
        'token': {
            'mint': token.mint,
            'name': token.name,
            'symbol': token.symbol,
            'image_uri': token.image_uri,  # Assuming `PumpFunToken` has a `name` field
            'description': token.description,  # Assuming `PumpFunToken` has a `description` field
        },
        'raid_links': [
            {
                'url': link.url,
                'click_count': link.click_count,
                'created_by': link.created_by,
                'created_at': link.created_at.isoformat()
            }
            for link in raid_links
        ],
        'distinct_accounts': list(accounts),
    }

    # Check if the request is for JSON
    if request.headers.get('Accept') == 'application/json' or request.GET.get('format') == 'json':
        return JsonResponse(response_data)

    return render(request, 'token_detail.html', {
        'token': token,
        'raid_links': raid_links,  # Pass the raid links to the template context
        'distinct_accounts': list(accounts)  # Pass distinct accounts to the template context
    })

def delete_tweet_by_content(request):
    content = request.GET.get('content')  # Get the content from the query string
    if not content:
        return redirect('tweet_list')  # Redirect if no content is provided

    # Retrieve all tweets that match the content
    tweets = Tweet.objects.filter(content=content)
    if not tweets.exists():
        return redirect('tweet_list')  # Redirect if no tweets are found

    # Delete all tweets with the matching content
    tweets.delete()
    return redirect('tweet_list')  # Redirect to the list after deletion


# View to delete a tweet without confirmation
def delete_tweet(request, tweet_id):
    tweet = get_object_or_404(Tweet, id=tweet_id)
    tweet.delete()  # Delete the tweet immediately
    return redirect('tweet_list')  # Redirect to the list after deletion

def tweet_list(request):
    tweets = Tweet.objects.all()

    # Check if the request is for JSON format
    if request.GET.get('format') == 'json':
        tweet_data = list(tweets.values())  # Convert the QuerySet to a list of dictionaries
        return JsonResponse(tweet_data, safe=False)

    return render(request, 'tweet_list.html', {'tweets': tweets})


# View to create a new tweet
@admin_required
def create_tweet(request):
    if request.method == 'POST':
        form = TweetForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('tweet_list')  # Redirect to the list after saving
    else:
        form = TweetForm()
    
    return render(request, 'tweet_form.html', {'form': form})

def marketcap_async_search(request): 

    search_name = str(request.GET.get('search_name', ''))
    search_value = request.GET.get('search_value', '')
    context = {'request': request, 'search_name': search_name , 'search_value': search_value  }

    try:
        return render(request, 'marketcap_async_search.html', context)
    except Exception as e:
        print("An error occurred while rendering the template:", e)
        return render(request, 'error.html', {'error_message': 'An error occurred while rendering the template.'})

@csrf_exempt  # For simplicity, disable CSRF validation (for testing)
def save_room_view(request):
    if request.method == 'POST':
        try:
            # Extract data from POST request (you can also use JSON or form data)
            external_id = request.POST.get('external_id')
            external_date_created = request.POST.get('external_date_created')

            # Call the RoomService to save the room
            room = RoomService.save_room(external_id, external_date_created)

            # Return success response
            return JsonResponse({"message": "Room saved successfully", "room_id": room.id})
        
        except Exception as e:
            # Return error response
            return JsonResponse({"error": str(e)}, status=400)

    return JsonResponse({"error": "Only POST requests are allowed."}, status=400)

@api_view(['POST'])
def save_room(request):
    try:
        # Extract data from request
        external_id = request.data.get('external_id')
        external_date_created_str = request.data.get('external_date_created')
        
        if not external_id or not external_date_created_str:
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Convert external_date_created to datetime
        external_date_created = datetime.strptime(external_date_created_str, "%Y-%m-%d %H:%M:%S")
        
        # Save room to the database
        room = Room.objects.create(
            external_id=external_id,
            external_date_created=external_date_created
        )
        
        # Return success response
        return Response({"message": "Room saved successfully", "room_id": room.id}, status=status.HTTP_201_CREATED)
    
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def room_list_view(request):
    # Get all rooms from the database, ordered by created_at (newest first)
    rooms = Room.objects.all().order_by('-created_at')

    # Pass the rooms to the template
    return render(request, 'room_list.html', {'rooms': rooms})

def memory_list(request):
    memories = Memory.objects.all()
    return render(request, 'memory_list.html', {'memories': memories})

class MemoryView(APIView):
    def post(self, request):
        serializer = MemorySerializer(data=request.data)
        if serializer.is_valid():
            memory = MemoryService.create_memory(serializer.validated_data)
            return Response(MemorySerializer(memory).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, memory_id=None):
        if memory_id:
            memory = MemoryService.get_memory_by_id(memory_id)
            if memory:
                return Response(MemorySerializer(memory).data)
            return Response({"detail": "Memory not found."}, status=status.HTTP_404_NOT_FOUND)
        # Return all memories if no ID is provided
        memories = Memory.objects.all()
        return Response(MemorySerializer(memories, many=True).data)

    def put(self, request, memory_id):
        memory = MemoryService.get_memory_by_id(memory_id)
        if not memory:
            return Response({"detail": "Memory not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = MemorySerializer(memory, data=request.data, partial=True)
        if serializer.is_valid():
            updated_memory = MemoryService.update_memory(memory_id, serializer.validated_data)
            return Response(MemorySerializer(updated_memory).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, memory_id):
        if MemoryService.delete_memory(memory_id):
            return Response({"detail": "Memory deleted."}, status=status.HTTP_204_NO_CONTENT)
        return Response({"detail": "Memory not found."}, status=status.HTTP_404_NOT_FOUND)


@csrf_exempt
@admin_required
def tweet_add(request): 

    form = TweetForm()
    
    context = { 
        'form': form,
    }
    response = render(request, 'tweet_form.html', context) 


    return response

 

def pay_with_stripe(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    stripe.api_key = profile.stripe_secret_key

    cart_id = request.COOKIES.get('cartId')
    try:
        cart = Cart.objects.get(external_id=cart_id)
    except Cart.DoesNotExist:
        return redirect('index')

    cart_products = CartProduct.objects.filter(cart=cart)
    subtotal, total_tax, total_with_tax = 0, 0, 0
    products = []

    # Calculate subtotal, total tax, and total with tax for the cart
    for cart_product in cart_products:
        total_price = cart_product.quantity * cart_product.product.price
        product_tax = total_price * cart_product.tax_rate / 100
        total_with_product = total_price + product_tax

        subtotal += total_price
        total_tax += product_tax
        total_with_tax += total_with_product

        products.append({
            'product': cart_product.product,
            'quantity': cart_product.quantity,
            'price': cart_product.product.price,
            'line_item_total': total_price,
            'tax': product_tax,
            'total_with_tax': total_with_product,
            'id': cart_product.id,
        })

    total_in_cents = int(total_with_tax * 100)  # Ensure it's in cents

    if request.method == 'POST':
        card_id = request.POST.get('stripeToken')
        if not card_id:  # Handle missing token
            return redirect('failure')

        try:
            charge = stripe.Charge.create(
                amount=total_in_cents,
                currency="usd",
                source=card_id,
                description="Example charge"
            )
        except stripe.error.CardError as e:
            # Log the error for debugging
            print(f"Card error: {e.user_message}")
            return redirect('failure')

        if charge.paid:
            # Save payment details in the database
            payment = Payment.objects.create(
                customer=cart.customer,
                amount=total_with_tax,
                payment_method='Stripe',
                status='COMPLETED',
            )

            PaymentApplication.objects.create(
                payment=payment,
                cart=cart,
                applied_amount=total_with_tax,
            )

            # Mark cart as paid and save transaction ID
            cart.paid_transaction_id = charge.id
            cart.paid = True
            cart.save()

            return redirect('success')
        else:
            return redirect('failure')

    context = {
        'products': products,
        'subtotal': subtotal,
        'total_tax': total_tax,
        'total_with_tax': total_with_tax,
        'profile': profile,
    }
    response = render(request, 'pay_with_stripe.html', context)
    response.set_cookie('cartId', cart_id, max_age=60*60*24*30, secure=True, httponly=True, samesite='Lax')

    return response

def success(request):
    return render(request, 'success.html')

def failure(request):
    return render(request, 'failure.html')


def select_payment_type(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    tokens = TokenProfile.objects.filter(visible=True)

    if request.method == 'POST':
        payment_type = request.POST.get('payment_type')

        if payment_type == 'solana':
            return redirect('pay_with_solana')
        elif payment_type in [token.address for token in tokens]:
            return redirect('pay_with_token', token_address=payment_type)
        elif payment_type == 'stripe':
            return redirect('pay_with_stripe')
        else:
            return render(request, 'select_payment.html', {
                'tokens': tokens,
                'error': 'Invalid selection'
            })

    return render(request, 'select_payment.html', {'tokens': tokens, 'profile': profile})
 
def pay_with_token(request, token_address):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    cart_id = request.COOKIES.get('cartId')
    try:
        cart = Cart.objects.get(external_id=cart_id)
    except Cart.DoesNotExist:
        return redirect('index')

    cart_products = CartProduct.objects.filter(cart=cart)
    subtotal, total_tax, total_with_tax = 0, 0, 0
    products = []

    for cart_product in cart_products:
        total_price = cart_product.quantity * cart_product.product.price
        product_tax = total_price * cart_product.tax_rate / 100
        total_with_product = total_price + product_tax

        subtotal += total_price
        total_tax += product_tax
        total_with_tax += total_with_product

        products.append({
            'product': cart_product.product,
            'quantity': cart_product.quantity,
            'price': cart_product.product.price,
            'line_item_total': total_price,
            'tax': product_tax,
            'total_with_tax': total_with_product,
            'id': cart_product.id,
        })

    txn = request.GET.get('txn')
    if txn:
        payment = Payment.objects.create(
            customer=cart.customer,
            amount=total_with_tax,
            payment_method='Solana',
            status='COMPLETED',
        )

        PaymentApplication.objects.create(
            payment=payment,
            cart=cart,
            applied_amount=total_with_tax,
        )

        cart.paid_transaction_id = txn
        cart.paid = True
        cart.save()

        return redirect('process_checkout')

    # Fetch token price from the new service
    url = f"https://public-api.birdeye.so/defi/price?address={token_address}"
    headers = {
        'X-API-KEY': profile.bird_eye_api_key,
        'accept': 'application/json',
        'x-chain': 'solana'
    }
    response = requests.get(url, headers=headers)
    data = response.json()

    token_price = data['data']['value']
    token_to_usd_rate = Decimal(token_price)
    total_in_token = Decimal(total_with_tax) / token_to_usd_rate

    recipient = profile.wallet
    return redirect(f'/solana_payment/?amount={total_in_token:.8f}&recipient={recipient}&splToken={token_address}')


def pay_with_solana(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    cart_id = request.COOKIES.get('cartId')
    try:
        cart = Cart.objects.get(external_id=cart_id)
    except Cart.DoesNotExist:
        return redirect('index')

    cart_products = CartProduct.objects.filter(cart=cart)
    subtotal, total_tax, total_with_tax = 0, 0, 0
    products = []

    # Calculate subtotal, total tax, and total with tax for the cart
    for cart_product in cart_products:
        total_price = cart_product.quantity * cart_product.product.price
        product_tax = total_price * cart_product.tax_rate / 100
        total_with_product = total_price + product_tax

        subtotal += total_price
        total_tax += product_tax
        total_with_tax += total_with_product

        products.append({
            'product': cart_product.product,
            'quantity': cart_product.quantity,
            'price': cart_product.product.price,
            'line_item_total': total_price,
            'tax': product_tax,
            'total_with_tax': total_with_product,
            'id': cart_product.id,
        })

    # Handle Solana payment
    txn = request.GET.get('txn')
    if txn:
        # Assume the transaction is successful and apply payment (simulate with a SOL payment)
        # Here, you can save the payment details as you did in the Stripe example

        payment = Payment.objects.create(
            customer=cart.customer,
            amount=total_with_tax,
            payment_method='Solana',
            status='COMPLETED',
        )

        PaymentApplication.objects.create(
            payment=payment,
            cart=cart,
            applied_amount=total_with_tax,
        )

        # Mark cart as paid and save transaction ID (here txn is used as a placeholder)
        cart.paid_transaction_id = txn
        cart.paid = True
        cart.save()

        return redirect('process_checkout')

    # Fetch Solana price in USD (using an external API)
    url = "https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd"
    response = requests.get(url)
    data = response.json()

    solana_price = data['solana']['usd']
    sol_to_usd_rate = float(solana_price)  # 1 SOL = price in USD (based on the current market rate)
    total_in_sol = Decimal(total_with_tax) / Decimal(sol_to_usd_rate)  # Convert total_with_tax (USD) to SOL

    # Redirect to the Solana payment URL with the correct SOL amount
    recipient = profile.wallet
    return redirect(f'/solana_payment/?amount={total_in_sol:.8f}&recipient={recipient}')

     
# List all touchpoint types
@admin_required
def touchpoint_type_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    touchpoint_types = TouchPointType.objects.all()
    return render(request, 'touchpoint_type_list.html', {'touchpoint_types': touchpoint_types, 'profile': profile})

# Add a new touchpoint type
@admin_required
def touchpoint_type_add(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    if request.method == "POST":
        form = TouchPointTypeForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('touchpoint_type_list')
    else:
        form = TouchPointTypeForm()
    return render(request, 'touchpoint_type_form.html', {'form': form, 'profile': profile})

# Edit an existing touchpoint type
@admin_required
def touchpoint_type_edit(request, pk):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    touchpoint_type = get_object_or_404(TouchPointType, pk=pk)
    if request.method == "POST":
        form = TouchPointTypeForm(request.POST, instance=touchpoint_type)
        if form.is_valid():
            form.save()
            return redirect('touchpoint_type_list')
    else:
        form = TouchPointTypeForm(instance=touchpoint_type)
    return render(request, 'touchpoint_type_form.html', {'form': form, 'profile': profile})     

@admin_required
def generate_message(request, customer_id, touchpoint_id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    customer = get_object_or_404(Customer, id=customer_id)
    touchpoint = get_object_or_404(TouchPointType, id=touchpoint_id)

    # Prepare the prompt for DeepSeek API
    prompt = f"""
    Customer Information:
    - Name: {customer.first_name} {customer.last_name}
    - Email: {customer.email}
    - Phone: {customer.phone_number}
    - Address: {customer.address1}, {customer.city}, {customer.state}, {customer.zip_code}, {customer.country}

    TouchPoint Information:
    - Type: {touchpoint.name}
    - Objective: {touchpoint.objective}
    - Instructions: {touchpoint.instructions}
    - Format: {touchpoint.touchpoint_format}

    Generate a personalized message for the customer based on the above information.
    """

    # Call DeepSeek API
    api_key = profile.deepseek_api_key
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "deepseek-v3",  # Replace with the correct model name
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        generated_message = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        return JsonResponse({"message": generated_message})
    else:
        return JsonResponse({"error": "Failed to generate message"}, status=500)

@csrf_exempt
@staff_required
def generate_message_chatgpt(request, customer_id, touchpoint_id):
    # Fetch the latest WebsiteProfile
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)

    # Ensure the ChatGPT API key is available
    if not profile.chatgpt_api_key:
        return JsonResponse({"error": "ChatGPT API key is missing in the website profile."}, status=400)

    print("API Key:", profile.chatgpt_api_key)  # Debugging: Print API key

    # Fetch customer and touchpoint details
    customer = get_object_or_404(Customer, id=customer_id)
    touchpoint = get_object_or_404(TouchPointType, id=touchpoint_id)

    # Prepare the prompt for OpenAI ChatGPT API
    prompt = f"""
    Website Information:
    - Name: {profile.name}
    - About Us: {profile.about_us}
    - Wallet: {profile.wallet}
    - x Handle: {profile.x_handle}
    - Email: {profile.email}
    - Phone: {profile.phone}
    - Address: {profile.address1}, {profile.city}, {profile.state}, {profile.zip_code}, {profile.country}

    Customer Information:
    - Name: {customer.first_name} {customer.last_name}
    - Email: {customer.email}
    - Phone: {customer.phone_number}
    - Address: {customer.address1}, {customer.city}, {customer.state}, {customer.zip_code}, {customer.country}

    TouchPoint Information:
    - Type: {touchpoint.name}
    - Objective: {touchpoint.objective}
    - Instructions: {touchpoint.instructions}
    - Format: {touchpoint.touchpoint_format}

    Generate a personalized message for the customer based on the above information.
    """

    # Initialize the OpenAI client with the API key from the profile
    client = OpenAI(api_key=profile.chatgpt_api_key)

    # Include business context about 'About Us' and ensure a short, concise response
    context = [
        {"role": "system", "content": f"You are a helpful chatbot assistant for a company. Here is some information about the company: {profile.about_us}. Please keep your responses really short and to the point."},
        {"role": "user", "content": prompt}  # Include the prompt
    ]

    # Check fine-tuned model status
    if profile.chatgpt_model_id_current:
        fine_tune_status = client.fine_tuning.jobs.retrieve(profile.chatgpt_model_id_current)
        print("Fine-tune status:", fine_tune_status)

        if fine_tune_status.status == 'succeeded':
            # Use the model ID for the fine-tuned model
            model_id = fine_tune_status.fine_tuned_model
        else:
            # If still processing or failed, use a fallback model
            model_id = "gpt-3.5-turbo"
    else:
        # If no fine-tuned model is specified, use a fallback model
        model_id = "gpt-3.5-turbo"

    print("Using model:", model_id)  # Debugging: Print model ID

    try:
        # Call the OpenAI API
        response = client.chat.completions.create(
            model=model_id,  # Use the fine-tuned model or fallback model
            messages=context
        )

        # Extract the bot's reply
        bot_reply = response.choices[0].message.content

        return JsonResponse({"message": bot_reply})

    except Exception as e:
        # Handle any errors from the OpenAI API
        print("OpenAI API Error:", str(e))  # Debugging: Print API error
        return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

@csrf_exempt
@login_required
def save_generated_message(request):
    if request.method == "POST":
        print(f"Raw POST data: {request.POST}")  # Debugging

        customer_id = request.POST.get("customer_id")
        touchpoint_id = request.POST.get("touchpoint_id")
        message_text = request.POST.get("message")

        print(f"Received customer_id: {customer_id}, touchpoint_id: {touchpoint_id}, message: {message_text}")

        if not customer_id or not touchpoint_id or not message_text:
            return JsonResponse({"status": "error", "message": "Missing required fields"}, status=400)

        try:
            customer = get_object_or_404(Customer, id=customer_id)
            touchpoint = get_object_or_404(TouchPointType, id=touchpoint_id)

            print(f"Found customer: {customer}, touchpoint: {touchpoint}")

            message = GeneratedMessage.objects.create(
                customer=customer,
                touchpoint=touchpoint,
                message=message_text
            )
            
            return JsonResponse({"status": "success", "message_id": message.id})
        
        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)

@login_required
def customer_messages(request, customer_id):
    customer = get_object_or_404(Customer, id=customer_id)
    messages = GeneratedMessage.objects.filter(customer=customer).order_by('-created_at')

    return render(request, 'customer_messages.html', {'customer': customer, 'messages': messages})

@login_required
def customer_messages(request, customer_id):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")
    customer = get_object_or_404(Customer, id=customer_id)
    messages = GeneratedMessage.objects.filter(customer=customer).order_by('-created_at')
    
    context = {
        'profile': profile,
        'customer': customer,
        'messages': messages,
    }
    
    return render(request, 'customer_messages.html', context)

@login_required
def update_generated_message(request, pk):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        profile = WebsiteProfile(name="add name", about_us="some info about us")

    message = get_object_or_404(GeneratedMessage, pk=pk)
    
    if request.method == 'POST':
        form = GeneratedMessageForm(request.POST, instance=message)
        if form.is_valid():
            form.save()
            return redirect('customer_edit', customer_id=message.customer.id)  # Redirect to customer detail page
    else:
        form = GeneratedMessageForm(instance=message)
    
    return render(request, 'generated_message_update.html', {'form': form, 'message': message, 'profile': profile})


# View to upload and display PDFs
@admin_required
def pdf_list(request):
    pdfs = PDFDocument.objects.all()
    return render(request, 'pdf_list.html', {'pdfs': pdfs})

# View to serve a PDF
@admin_required
def view_pdf(request, pk):
    pdf = get_object_or_404(PDFDocument, pk=pk)
    return FileResponse(pdf.file.open('rb'), content_type='application/pdf')

# View to add a new PDF
@admin_required
def add_pdf(request):
    if request.method == 'POST':
        form = PDFDocumentForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('pdf_list')
    else:
        form = PDFDocumentForm()
    return render(request, 'add_pdf.html', {'form': form})

# View to edit an existing PDF
@admin_required
def edit_pdf(request, pk):
    pdf = get_object_or_404(PDFDocument, pk=pk)
    if request.method == 'POST':
        form = PDFDocumentForm(request.POST, request.FILES, instance=pdf)
        if form.is_valid():
            form.save()
            return redirect('pdf_list')
    else:
        form = PDFDocumentForm(instance=pdf)
    return render(request, 'edit_pdf.html', {'form': form, 'pdf': pdf})
  
@login_required
def secure_download(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    # Check if the user has a cart containing this product and if the cart is paid
    try:
        cart = Cart.objects.get(user=request.user, checked_out=True, paid=True)
    except Cart.DoesNotExist:
        logger.error(f"User {request.user} does not have a paid, checked-out cart.")
        return HttpResponseForbidden("You don't have an active, paid cart.")

    # Check if the product exists in the cart
    cart_product = CartProduct.objects.filter(cart=cart, product=product).first()
    if not cart_product:
        logger.error(f"User {request.user} does not have product {product_id} in their cart.")
        return HttpResponseForbidden("You have not purchased this product.")

    # Serve the file securely
    file_path = join(settings.MEDIA_ROOT, product.digital_file.name)
    if not product.digital_file:
        logger.error(f"Product {product_id} does not have a digital file.")
        return HttpResponseForbidden("The product does not have a digital file.")
    
    logger.info(f"Serving digital file for product {product_id}.")
    return FileResponse(open(file_path, 'rb'), as_attachment=True)


@csrf_exempt
def chatbot_response(request):
    # Fetch the latest WebsiteProfile
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)

    # Ensure the ChatGPT API key is available
    if not profile.chatgpt_api_key:
        return JsonResponse({"error": "ChatGPT API key is missing in the website profile."}, status=400)

    print("API Key:", profile.chatgpt_api_key)  # Debugging: Print API key

    if request.method == "POST":
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return JsonResponse({"response": "Please log in to use the chat feature."})

        print("User Authenticated:", request.user.is_authenticated)  # Debugging: Print authentication status

        # Parse the user's message from the request body
        try:
            data = json.loads(request.body)
            user_message = data.get("message", "")
            if not user_message:
                return JsonResponse({"error": "No message provided"}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON in request body"}, status=400)

        print("Request Data:", data)  # Debugging: Print request data

        # Initialize the OpenAI client with the API key from the profile
        client = OpenAI(api_key=profile.chatgpt_api_key)

        # Include business context about 'About Us' and ensure a short, concise response
        messages = [
            {"role": "system", "content": f"You are a helpful chatbot assistant for a company. Here is some information about the company: {profile.about_us}. Please keep your responses really short and to the point."},
            {"role": "user", "content": user_message}  # Include the user's message
        ]

        fine_tune_status = client.fine_tuning.jobs.retrieve(profile.chatgpt_model_id_current)
        print("Fine-tune status:", fine_tune_status)
        print("TEST") 
        print("TEST ", fine_tune_status.status)

        if fine_tune_status.status == 'succeeded':
            # Use the model ID for the fine-tuned model
            model_id = fine_tune_status.fine_tuned_model
        else:
            # If still processing or failed, use a fallback model
            model_id = "gpt-3.5-turbo"

        print(model_id)

        print("TEST ", model_id)

        try:
            # Call the OpenAI API
            response = client.chat.completions.create(
                model=model_id,  # Use the fine-tuned model or fallback model
                messages=messages  # Use the correct message structure
            )

            # Extract the bot's reply
            bot_reply = response.choices[0].message.content

            return JsonResponse({"response": bot_reply})

        except Exception as e:
            # Handle any errors from the OpenAI API
            print("OpenAI API Error:", str(e))  # Debugging: Print API error
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)


def get_latest_profile():
    return WebsiteProfile.objects.order_by('-created_at').first()

def validate_profile(profile):
    if not profile:
        return {"error": "No website profile found. Please create a profile first."}, 400
    if not profile.chatgpt_api_key:
        return {"error": "ChatGPT API key is missing in the website profile."}, 400
    return None

def format_training_entry(system_content, user_content, assistant_content):
    return {"messages": [
        {"role": "system", "content": system_content},
        {"role": "user", "content": user_content},
        {"role": "assistant", "content": assistant_content}
    ]}


def get_general_info(profile):
    training_data = []
    info_entries = [
        ("terms_of_service", "What are the terms of service?"),
        ("privacy_policy", "What is the privacy policy?"),
        ("about_us", "Tell me about your company."),
        ("email", "What is your contact email?"),
        ("phone", "What is your contact phone number?")
    ]
    for attr, question in info_entries:
        content = getattr(profile, attr, None)
        if content:
            training_data.append(format_training_entry(
                "You are a helpful AI assistant that provides website information.",
                question,
                content
            ))
    
    address_fields = [profile.address1, profile.address2, profile.city, profile.state, profile.zip_code, profile.country]
    address_info = ", ".join(filter(None, address_fields)).strip(', ')
    if address_info:
        training_data.append(format_training_entry(
            "You are a helpful AI assistant that provides website address information.",
            "What is your business address?",
            address_info
        ))
    return training_data

def get_conversation_info():
    training_data = []
    conversations = Conversation.objects.prefetch_related("messages").all()

    for convo in conversations:
        messages = convo.messages.order_by("timestamp")
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        training_data.append({"messages": formatted_messages})

    return training_data

def get_product_info():
    training_data = []
    products = Product.objects.all()
    for product in products:
        desc = f"Here are the details for {product.name}:\nDescription: {product.description}\n"
        training_data.append(format_training_entry(
            "You are a knowledgeable assistant that provides details about products.",
            f"What can you tell me about {product.name}?",
            desc
        ))
    return training_data

def get_qa_info():
    training_data = []
    approved_qas = QuestionAnswer.objects.filter(
        is_approved=True, has_sensitive_data=False, is_visible_public=True, is_deleted=False
    )
    for qa in approved_qas:
        training_data.append(format_training_entry(
            "You are a helpful AI assistant providing accurate answers to customer questions.",
            qa.question,
            qa.answer
        ))
    return training_data

def save_training_data(training_data):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl", mode="w", encoding="utf-8") as temp_file:
        jsonl_file_path = temp_file.name
        for entry in training_data:
            temp_file.write(json.dumps(entry) + "\n")
    return jsonl_file_path

def upload_and_finetune(client, jsonl_file_path, profile):
    try:
        with open(jsonl_file_path, "rb") as file:
            file_response = client.files.create(file=file, purpose="fine-tune")
        file_id = file_response.id
        fine_tune_response = client.fine_tuning.jobs.create(training_file=file_id, model="gpt-3.5-turbo")
        profile.chatgpt_model_id = fine_tune_response.id
        profile.save()
        os.remove(jsonl_file_path)
        return file_id, fine_tune_response.id
    except Exception as e:
        return None, str(e)

@csrf_exempt
@admin_required
def train_product_model(request):
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request"}, status=400)
    
    profile = get_latest_profile()
    validation_error = validate_profile(profile)
    if validation_error:
        return JsonResponse(*validation_error)
    
    client = OpenAI(api_key=profile.chatgpt_api_key)
    training_data = get_general_info(profile) + get_product_info() + get_qa_info() + get_conversation_info()
    jsonl_file_path = save_training_data(training_data)
    
    file_id, result = upload_and_finetune(client, jsonl_file_path, profile)
    if not file_id:
        return JsonResponse({"error": f"An error occurred: {result}"}, status=500)
    
    return redirect('admin_panel')

@admin_required
def copy_profile(request):
    # Get the WebsiteProfile object by ID
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)
     
    # Copy the profile's model ID to the current active model ID
    profile.chatgpt_model_id_current = profile.chatgpt_model_id
    profile.save()
    
    # Optionally, you can redirect to another page after performing the action
    return redirect('admin_panel')
 

# List all question answers
@staff_required
def question_answer_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)
    
    question_answers = QuestionAnswer.objects.all()
    return render(request, 'question_answer_list.html', {'question_answers': question_answers, 'profile': profile})

# View a single question answer
@staff_required
def question_answer_detail(request, pk):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)
    question_answer = get_object_or_404(QuestionAnswer, pk=pk)
    return render(request, 'question_answer_detail.html', {'question_answer': question_answer, 'profile': profile})

# Add a new question answer
@staff_required
def question_answer_add(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)
    if request.method == 'POST':
        form = QuestionAnswerForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('question_answer_list')
    else:
        form = QuestionAnswerForm()
    return render(request, 'question_answer_form.html', {'form': form, 'profile': profile})

# Edit a question answer
@staff_required
def question_answer_edit(request, pk):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)
    question_answer = get_object_or_404(QuestionAnswer, pk=pk)
    if request.method == 'POST':
        form = QuestionAnswerForm(request.POST, instance=question_answer)
        if form.is_valid():
            form.save()
            return redirect('question_answer_list')
    else:
        form = QuestionAnswerForm(instance=question_answer)
    return render(request, 'question_answer_form.html', {'form': form, 'profile': profile})

# Delete a question answer
@staff_required
def question_answer_delete(request, pk):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)
    question_answer = get_object_or_404(QuestionAnswer, pk=pk)
    if request.method == 'POST':
        question_answer.delete()
        return redirect('question_answer_list')
    return render(request, 'question_answer_confirm_delete.html', {'question_answer': question_answer, 'profile': profile})

def public_question_answer_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)
    
    # Filter answers that are:
    # - approved (is_approved)
    # - visible to the public (is_visible_public)
    # - not marked as deleted (is_deleted)
    # - do not contain sensitive data (has_sensitive_data=False)
    question_answers = QuestionAnswer.objects.filter(
        is_approved=True,
        is_visible_public=True,
        is_deleted=False,
        has_sensitive_data=False
    )
    
    return render(request, 'question_answer_list.html', {'question_answers': question_answers, 'profile': profile})

# Add a new answer (only answer field)
@login_required
def simple_question_add(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)

    if request.method == 'POST':
        form = SimpleAnswerForm(request.POST)
        if form.is_valid():
            # Create a new QuestionAnswer object but don't save it yet
            question_answer = form.save(commit=False)
            # Set the created_by field to the currently logged-in user
            question_answer.created_by = request.user
            # Now save the object to the database
            question_answer.save()

            if not request.user.is_staff:
                return redirect('public_question_answer_list')
                
            return redirect('question_answer_list')
    else:
        form = SimpleAnswerForm()  # Use the new form with only the 'answer' field

    return render(request, 'question_answer_form.html', {'form': form, 'profile': profile})

@admin_required
def conversation_list(request):
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)
    
    conversations = Conversation.objects.prefetch_related("messages").all()
    
    # Link conversations with customers based on email
    for conversation in conversations:
        try:
            customer = Customer.objects.get(email=conversation.user.email)
            conversation.customer = customer
        except Customer.DoesNotExist:
            conversation.customer = None
    
    return render(request, "conversation_list.html", {"conversations": conversations, 'profile': profile})

@csrf_exempt
@admin_required
@require_POST
def update_message_content(request, message_id):
    try:
        # Log the raw request body for debugging
        print("Raw request body:", request.body)
        print("message id ", message_id )

        # Parse JSON data from the request body
        try:
            data = json.loads(request.body)
            print("Parsed JSON data:", data)
        except json.JSONDecodeError as e:
            print("Failed to parse JSON:", e)
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'})

        # Extract the content_update field
        content_update = data.get('content_update')
        if not content_update:
            print("No content_update provided in the request")
            return JsonResponse({'success': False, 'error': 'content_update is required'})

        # Log the received content_update
        print("Content update received:", content_update)

        # Fetch the message object
        try:
            message = Message.objects.get(id=message_id)
            print("Message found:", message)
        except Message.DoesNotExist:
            print("Message not found for ID:", message_id)
            return JsonResponse({'success': False, 'error': 'Message not found'})

        # Update the message content
        message.content_update = content_update
        message.save()
 
        # Log the updated message for debugging

        return JsonResponse({'success': True})
    except Exception as e:
        print("Unexpected error:", str(e))
        return JsonResponse({'success': False, 'error': str(e)})