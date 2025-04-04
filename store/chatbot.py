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
from .models import Referral
from .models import LandingPage

from .forms import ReferralForm
from .forms import SimpleCustomerForm
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
import maxminddb
 
from django import forms
from django.apps import apps
import importlib 

from django.db import transaction   

from .utils import ( 
    fetch_mcp_data,
    create_business,
    fetch_all_businesses,
    fetch_support_ticket,
    create_support_ticket,
    fetch_all_support_tickets
)

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

    entity_value = bot_reply.get("entity_value", None)

    if entity_value:
        # Check if user.current_entity_json is not set or is set to a non-list value (e.g., string)
        if not hasattr(user, 'current_entity_json') or not user.current_entity_json:
            user.current_entity_json = '[]'  # Initialize as empty JSON array (string representation)

        # Convert current_entity_json from string to list
        current_entity_json = json.loads(user.current_entity_json)

        # Append the new data
        current_entity_json.append({"field": field, "value": entity_value})

        # Convert back to string for saving in the database
        user.current_entity_json = json.dumps(current_entity_json)
        user.save()

    # Step 7: Return both value even if it's None
    return field, entity_value


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

def reset_user_fields(user):
    user.current_intent = None
    user.current_entity = None
    user.current_field = None
    user.current_entity_json = None
    user.current_field_help_text = None
    user.current_intent_is_done = False
    user.save()

def populate_and_save_form(user):
    try:
        if not user.current_entity_json:
            return "No data to process"

        data = json.loads(user.current_entity_json)

        if not data or "field" not in data[0]:
            return "Invalid data format"

        # Extract app_label and model_name from the first field entry
        field_parts = data[0]["field"].split(".")
        if len(field_parts) < 2:
            return "Invalid field format in data"

        app_label, model_name = field_parts[0], field_parts[1]
        ModelClass = apps.get_model(app_label, model_name)

        form_data = {}
        for item in data:
            field_name = item["field"].split(".")[-1]  # Extract actual field name
            form_data[field_name] = item["value"]

        # Dynamically create a ModelForm for the extracted model
        FormClass = type(f"{model_name}Form", (forms.ModelForm,), {
            'Meta': type('Meta', (), {'model': ModelClass, 'fields': '__all__'})
        })

        form = FormClass(form_data)
        if form.is_valid():
            with transaction.atomic():
                instance = form.save()
                user.current_entity_json = json.dumps(data)  # Persist JSON state
                user.save()
                return f"Form successfully saved: {instance}"

        return f"Form validation failed: {form.errors}"

    except Exception as e:
        return f"Error in populate_and_save_form: {e}"

def get_landing_page(request):
    try: 
        referer = request.META.get('HTTP_REFERER', '')
        origin = request.META.get('HTTP_ORIGIN', '')

        # Use 'origin' or 'referer' to extract the domain name to match with LandingPage
        domain = origin or referer

        # Extract just the domain without path (e.g., 'https://example.com' -> 'example.com')
        from urllib.parse import urlparse
        parsed_url = urlparse(domain)
        domain_name = parsed_url.hostname or ''

    # Get the matching LandingPage
        landing_page = LandingPage.objects.get(domain_name=domain_name, is_activated=True)
        landing_page.visitor_count += 1
        landing_page.save()
        return landing_page
    except LandingPage.DoesNotExist:
        return None


@csrf_exempt
def chatbot_response_public(request):
    """Handles chatbot responses, including MCP API and Support Ticket integration."""
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile or not profile.chatgpt_api_key:
        return JsonResponse({"error": "Invalid website profile or missing API key."}, status=400)

    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method."}, status=400)

    try:
        data = json.loads(request.body)
        user_message = data.get("message", "").strip()
        client_id = data.get("clientId", "").strip()
        if not user_message or not client_id:
            return JsonResponse({"error": "Message and clientId are required."}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON format."}, status=400)

    client = OpenAI(api_key=profile.chatgpt_api_key)

    landingpage = get_landing_page(request)
    messages = [
        {
            "role": "system",
            "content": (
                "You are a chatbot assistant for a company. If a user reports an issue, determine if a support ticket is needed. "
                "For login problems, system errors, or product malfunctions, create a support ticket using 'CREATE_TICKET'. "
                "Ask for the user's email and issue details if missing. If it's a general inquiry, provide helpful information."
            ),
        },
        {"role": "user", "content": user_message},
    ]

    # ✅ Step 1: Ask OpenAI if an API call is needed
    try:
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=messages,
            tools=[
                # Business API Tools
                {
                    "type": "function",
                    "function": {
                        "name": "GET_BUSINESS",
                        "description": "Retrieve business details by ID.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "integer", "description": "Business ID to fetch"}
                            },
                            "required": ["id"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "CREATE_BUSINESS",
                        "description": "Create a new business entry.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "description": "Business name"},
                                "industry": {"type": "string", "description": "Industry type"},
                                "email": {"type": "string", "description": "Business contact email"},
                                "phone": {"type": "string", "description": "Business contact phone"},
                                "website": {"type": "string", "description": "Business website URL"}
                            },
                            "required": ["name", "industry"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "LIST_BUSINESSES",
                        "description": "Retrieve a list of all businesses.",
                        "parameters": {}
                    }
                },
                # ✅ Support Ticket API Tools
                {
                    "type": "function",
                    "function": {
                        "name": "GET_TICKET",
                        "description": "Retrieve support ticket details by ID.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "integer", "description": "Support Ticket ID to fetch"}
                            },
                            "required": ["id"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "CREATE_TICKET",
                        "description": "Create a new support ticket.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string", "description": "Short summary of the issue"},
                                "description": {"type": "string", "description": "Detailed description of the issue"},
                                "priority": {"type": "string", "description": "Priority level (low, medium, high, urgent)"},
                                "contact_email": {"type": "string", "description": "Contact email for follow-up"}
                            },
                            "required": ["title", "description", "priority", "contact_email"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "LIST_TICKETS",
                        "description": "Retrieve a list of all support tickets.",
                        "parameters": {}
                    }
                }
            ],
            tool_choice="auto"
        )

        if not response.choices:
            return JsonResponse({"error": "No response from OpenAI."}, status=500)

        tool_calls = response.choices[0].message.tool_calls if response.choices else []
        
    except Exception as e:
        return JsonResponse({"error": f"OpenAI request failed: {str(e)}"}, status=500)

    # ✅ Step 2: Process API Calls
    mcp_data = None
    if tool_calls:
        for tool in tool_calls:
            function_args = json.loads(tool.function.arguments)

            if tool.function.name == "GET_BUSINESS":
                mcp_data = fetch_mcp_data(function_args.get("id"))

            elif tool.function.name == "CREATE_BUSINESS":
                mcp_data = create_business(function_args)

            elif tool.function.name == "LIST_BUSINESSES":
                mcp_data = fetch_all_businesses()

            elif tool.function.name == "GET_TICKET":
                mcp_data = fetch_support_ticket(function_args.get("id"))

            elif tool.function.name == "CREATE_TICKET":
                mcp_data = create_support_ticket(function_args)

            elif tool.function.name == "LIST_TICKETS":
                mcp_data = fetch_all_support_tickets()

    # ✅ Step 3: Fallback to Auto-Create Ticket if OpenAI Fails
    if not tool_calls and ("login" in user_message.lower() or "error" in user_message.lower() or "crash" in user_message.lower()):
        ticket_data = {
            "title": "System Issue Detected",
            "description": user_message,
            "priority": "high",
            "contact_email": data.get("contact_email", "unknown@example.com")
        }
        mcp_data = create_support_ticket(ticket_data)

    # ✅ Step 4: Generate Final Response
    followup_messages = messages.copy()
    if tool_calls and mcp_data:
        followup_messages.append({
            "role": "assistant",
            "tool_calls": tool_calls
        })
        followup_messages.append({
            "role": "tool",
            "name": tool_calls[0].function.name,
            "tool_call_id": tool_calls[0].id,
            "content": json.dumps(mcp_data)
        })
    elif mcp_data:
        followup_messages.append(
            {"role": "assistant", "content": f"Support Ticket Info: {json.dumps(mcp_data)}"}
        )

    try:
        final_response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=followup_messages
        )
        bot_reply = final_response.choices[0].message.content if final_response.choices else "I'm sorry, I couldn't process your request."
    except Exception as e:
        return JsonResponse({"error": f"Final OpenAI request failed: {str(e)}"}, status=500)

    # ✅ Step 5: Save Conversation and Return Response
    conversation, _ = Conversation.objects.get_or_create(client_id=client_id)
    Message.objects.create(conversation=conversation, role="user", content=user_message)
    Message.objects.create(conversation=conversation, role="assistant", content=bot_reply)

    return JsonResponse({"response": bot_reply})


@csrf_exempt
def chatbot_response_private(request):
    if not request.user.is_authenticated:
        return JsonResponse({"response": "Please log in to use the chat feature."})

    # Fetch the latest WebsiteProfile
    profile = WebsiteProfile.objects.order_by('-created_at').first()
    if not profile:
        return JsonResponse({"error": "No website profile found. Please create a profile first."}, status=400)

    # Ensure the ChatGPT API key is available
    if not profile.chatgpt_api_key:
        return JsonResponse({"error": "ChatGPT API key is missing in the website profile."}, status=400)

    print("API Key:", profile.chatgpt_api_key)  # Debugging: Print API key

    user = get_object_or_404(User, id=request.user.id)  # Adjust based on how you fetch the user
    user_message = ''
    if request.method == "POST":
        # Check if the user is authenticated

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

        print("Before assignment - Intent:", user.current_intent, "Entity:", user.current_entity, "Field:", user.current_field)
        print("USER INTENT:", user_intent)
        print("ENTITY:", entity)
        #Unknown 
        if not error_occurred and user_intent not in [None, "Unknown"] and entity not in [None, "Unknown"]:
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
                    if user.current_field:
                        for index, (field_name, field) in enumerate(fields_list):
                            print(f"Field: {field_name}, Type: {type(field)}")
                            model_field = model_class._meta.get_field(field_name)  # Get the model field
                            print(f"Help Text: {model_field.help_text if model_field.help_text else 'No help text available'}")

                            print(f"Comparing user.current_field: {user.current_field} with field_name: {field_name}")

                            # Check if the current field matches the user's current_field
                            current_field_name = user.current_field.split('.')[-1]
                            print(f"Comparing user.current_field: {current_field_name} with field_name: {field_name}")

                            if current_field_name == field_name:    
                                found_match = True  # Mark that a match was found
                                
                                # If a match is found, move to the next item in the loop
                                if index + 1 < len(fields_list):  # Check if there is a next item
                                    next_field_name, next_field = fields_list[index + 1]
                                    next_model_field = model_class._meta.get_field(next_field_name)

                                    # Update the user object with the next field
                                    user.current_intent = user_intent  # Example intent, replace with actual logic
                                    user.current_entity = entity  # 'entity' can be passed in the request
                                    user.current_field = next_model_field  # Set the next field as the current field
                                    user.current_field_help_text = next_model_field.help_text                                  
                                    # Save the updated user object
                                    user.save()
                                    break  # Exit the loop after updating to the next field
                                else:
                                    # If it's the last item, stop the loop
                                    user.current_intent_is_done = True
                                    user.save()
                                    break
                     

                    # If no match was found, set current_field to the first item in the loop
                    if not found_match:
                        first_field_name, first_field = fields_list[0]
                        first_model_field = model_class._meta.get_field(first_field_name)
                        user.current_intent = user_intent  # Example intent, replace with actual logic
                        user.current_entity = entity  # 'entity' can be passed in the request
                        user.current_field = first_model_field
                        user.current_field_help_text = first_model_field.help_text
                        user.save()



                else:
                    print(f"'{entity}' is not a valid ModelForm.")
            except Exception as e:
                print(f"Error: {e}")

        # Initialize the OpenAI client with the API key from the profile
        client = OpenAI(api_key=profile.chatgpt_api_key)

        

        # Include business context about 'About Us' and ensure a short, concise response
        system_message = f"You are a helpful chatbot assistant for a company. Here is some information about the company: {profile.about_us}. Please keep your responses really short and to the point."

        # If the user is in the middle of providing information for a specific field, update the message
        if user.current_field and not user.current_intent_is_done: 
            system_message += f" You are in the process of collecting data and only need the following field from the user: {user.current_field}. this is the help text for the field '{user.current_field_help_text}', use the help text and field name to construct a human readable message to ask the user to provide {user.current_field} information, the current content provided by role user may be a response to a previous question or request that is already processed, ignore it if necessary."

        # If an error occurred, ask the user to try again
        if error_occurred:
            system_message += " An error occurred while collecting the data. Can you please provide it again?"

        if user.current_intent_is_done: 
            instance = populate_and_save_form(user)            
            if instance:
                reset_user_fields(user)
                print(f"Form successfully saved: {instance}")
            else:
                print("Form validation failed or no data to process.")

            system_message += f" tell user thank you for the information, the current content provided by role user may be a response to a previous question or request that is already processed, ignore it if necessary."
            print("SAVING THE INTAKE INFORMATION")

        print("System Message: ", system_message)
        try:
            messages = [{"role": "system", "content": system_message}]

            # Retrieve the latest conversation for the user
            conversation = Conversation.objects.filter(user=request.user).order_by('-created_at').first()

            if not conversation:
                conversation = Conversation.objects.create(user=request.user)

            # Fetch the last 10 messages from the conversation history using the correct field 'timestamp'
            recent_messages = Message.objects.filter(conversation=conversation).order_by('-timestamp')[:10]

            # Format them properly for OpenAI's API
            for msg in reversed(recent_messages):  # Reverse to maintain chronological order
                messages.append({"role": msg.role, "content": msg.content})

            # Append the new user message
            messages.append({"role": "user", "content": user_message})

            fine_tune_status = client.fine_tuning.jobs.retrieve(profile.chatgpt_model_id_current)
            model_id = fine_tune_status.fine_tuned_model if fine_tune_status.status == 'succeeded' else "gpt-3.5-turbo"

            # Call the OpenAI API
            response = client.chat.completions.create(
                model=model_id,  # Use the fine-tuned model or fallback model
                messages=messages  # Use the correct message structure
            )

            # Extract the bot's reply
            bot_reply = response.choices[0].message.content

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