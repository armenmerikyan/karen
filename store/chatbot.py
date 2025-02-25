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
from .models import Visitor  
from .forms import SimpleQuestionForm
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

import geoip2.database
from user_agents import parse
import maxminddb
 
from django import forms
from django.apps import apps
import importlib 

def get_django_forms():
    entities = []
    
    for app_config in apps.get_app_configs():
        try:
            forms_module = importlib.import_module(f"{app_config.name}.forms")
            for _, obj in vars(forms_module).items():
                if isinstance(obj, type) and issubclass(obj, forms.BaseForm) and obj is not forms.BaseForm:
                    if hasattr(obj, "usable_for_chatgpt") and getattr(obj, "usable_for_chatgpt") is True:
                        entities.append(obj.__name__)
        except ModuleNotFoundError:
            continue  # Skip apps without a forms module
    
    return entities
 

def chatbot_get_entity_value(message, user, profile):
    print("chatbot_get_entity_value")

    # Step 1: Get the current intent, entity, and field from the message using chatbot_get_intent_and_entity
    # Assuming user.current_intent and user.current_field are set elsewhere
    intent = user.current_intent
    field = user.current_field

    # Step 2: Create messages for ChatGPT to extract the entity value
    messages = [
        {"role": "system", "content": (
            f"You are a helpful assistant. "
            f"The goal is to extract the value of '{field}' for the entity '{intent}' from the following message. "
            "Please respond strictly in JSON format with only the value of the entity. "
            "The response should be in the following format: {\"entity_value\": \"<value>\"}."
        )},
        {"role": "user", "content": message}
    ]

    # Step 3: Set up the API call to ChatGPT with the defined messages
    client = OpenAI(api_key=profile.chatgpt_api_key)
    
    fine_tune_status = client.fine_tuning.jobs.retrieve(profile.chatgpt_model_id_current)
    print("Fine-tune status:", fine_tune_status)

    if fine_tune_status.status == 'succeeded':
        model_id = fine_tune_status.fine_tuned_model
    else:
        model_id = "gpt-3.5-turbo"

    response = client.chat.completions.create(
        model=model_id,
        messages=messages
    )
    
    # Step 4: Parse the response to get the extracted value
    bot_reply = json.loads(response.choices[0].message.content)

    # Step 5: Return the extracted entity value
    return bot_reply.get("entity_value", "No value found")


def chatbot_get_intent_and_entity(message, profile):
    intents = ["Add", "Delete", "Edit", "Search", "View Details", "View Summary", "List"]
    entities = get_django_forms()
    
    client = OpenAI(api_key=profile.chatgpt_api_key)
    print("Entity:", f"{json.dumps(entities)}. ")
    messages = [
        {"role": "system", "content": (
            "You are a helpful chatbot assistant for a company. "
            "Identify the intent of the following user message based on these predefined intents: "
            f"{json.dumps(intents)}. "
            "Also, identify the relevant entity from the following list of known entities: "
            f"{json.dumps(entities)}. "
            "Respond strictly in JSON format with the following structure: {\"intent\": \"<intent>\", \"entity\": \"<entity>\"}. "
            "If the message does not match any intent or entity, respond with {\"intent\": \"Unknown\", \"entity\": \"Unknown\"}."
        )},
        {"role": "user", "content": message}
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
  
    response = client.chat.completions.create(
        model=model_id,  # Use the fine-tuned model or fallback model
        messages=messages  # Use the correct message structure
    )
 
    bot_reply = json.loads(response.choices[0].message.content)
    
    return bot_reply.get("intent", "Unknown"), bot_reply.get("entity", "Unknown")

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

    user = get_object_or_404(User, id=request.user.id)  # Adjust based on how you fetch the user
    
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
        error_occurred = False

        if not user.current_intent and not user.current_entity and not user.current_field:
            user_intent, entity = chatbot_get_intent_and_entity(user_message, profile)
        else:
            try:
                user_intent = user.current_intent
                entity = user.current_entity
                field_value = chatbot_get_entity_value(user_message, user, profile)
                print("USER PROVIDED FIELD:", field_value)
            except Exception as e:
                error_occurred = True
                print("Error occurred:", e)


        print("USER INTENT:", user_intent)
        print("ENTITY:", entity)
        #Unknown 
        if not error_occurred and user_intent is not None and entity is not None:
            try:
                FormClass = globals().get(entity)  # Retrieve form class dynamically
                if FormClass and issubclass(FormClass, forms.ModelForm):  # Ensure it's a ModelForm
                    form_instance = FormClass()
                    model_class = form_instance._meta.model  # Get associated model
                    print("Model representing the object:", model_class)



                    # Convert form fields into a list of tuples (field_name, model_field) for easier iteration
                    fields_list = list(form_instance.fields.items())

                    # Iterate through the fields
                    # Initialize a flag to track if a match was found
                    found_match = False

                    for index, (field_name, field) in enumerate(fields_list):
                        print(f"Field: {field_name}, Type: {type(field)}")
                        model_field = model_class._meta.get_field(field_name)  # Get the model field
                        print(f"Help Text: {model_field.help_text if model_field.help_text else 'No help text available'}")

                        # Check if the current field matches the user's current_field
                        if user.current_field == model_field:
                            found_match = True  # Mark that a match was found
                            
                            # If a match is found, move to the next item in the loop
                            if index + 1 < len(fields_list):  # Check if there is a next item
                                next_field_name, next_field = fields_list[index + 1]
                                next_model_field = model_class._meta.get_field(next_field_name)

                                # Update the user object with the next field
                                user.current_intent = user_intent  # Example intent, replace with actual logic
                                user.current_entity = entity  # 'entity' can be passed in the request
                                user.current_field = next_model_field  # Set the next field as the current field

                                # Save the updated user object
                                user.save()
                                break  # Exit the loop after updating to the next field
                            else:
                                # If it's the last item, stop the loop
                                break

                    # If no match was found, set current_field to the first item in the loop
                    if not found_match:
                        first_field_name, first_field = fields_list[0]
                        first_model_field = model_class._meta.get_field(first_field_name)
                        user.current_field = first_model_field
                        user.save()



                else:
                    print(f"'{entity}' is not a valid ModelForm.")
            except Exception as e:
                print(f"Error: {e}")

        # Initialize the OpenAI client with the API key from the profile
        client = OpenAI(api_key=profile.chatgpt_api_key)

        # Include business context about 'About Us' and ensure a short, concise response
        system_message = f"You are a helpful chatbot assistant for a company. Here is some information about the company: {profile.about_us}. Please keep your responses really short and to the point."
        print(system_message)

        # If there's a current field message, update the system message to include that information
        if user.current_field:
            system_message += f" You are in the process of collecting data and only need the following field from the user: {user.current_field}. Ask the user to provide this information."

        if error_occurred:
            system_message += " An error occurred while collecting the data. Can you please provide it again?"


        print(system_message)

        messages = [
            {"role": "system", "content": system_message},
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

            # Retrieve the most recent conversation for the user or create a new one
            conversation = Conversation.objects.filter(user=request.user).order_by('-created_at').first()
            if not conversation:
                conversation = Conversation.objects.create(user=request.user)

            # Save the user's message
            Message.objects.create(
                conversation=conversation,
                role="user",
                content=user_message
            )

            # Save the bot's reply
            Message.objects.create(
                conversation=conversation,
                role="assistant",
                content=bot_reply
            )

            return JsonResponse({"response": bot_reply})

        except Exception as e:
            # Handle any errors from the OpenAI API
            print("OpenAI API Error:", str(e))  # Debugging: Print API error
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)