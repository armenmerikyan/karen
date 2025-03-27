from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

from store.models import User
from store.models import Brand
from store.models import Category
from store.models import Product
from store.models import Cart
from store.models import WebsiteProfile
from store.models import TokenProfile
from store.models import LifecycleStage
from store.models import Customer
from store.models import ProductLifecycleStage
from .models import TokenMarketingContent
from store.models import Tweet 
from .models import TouchPointType 
from .models import GeneratedMessage
from .models import PDFDocument 
from .models import QuestionAnswer
from .models import Referral
from .models import LandingPage

from .models import UserCharacter
from .models import CharacterMemory

class CharacterMemoryForm(forms.ModelForm):
    class Meta:
        model = CharacterMemory
        fields = ['content', 'importance', 'memory_type']  # removed 'character'
        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'importance': forms.NumberInput(attrs={'class': 'form-control', 'step': 0.1, 'min': 0, 'max': 1}),
            'memory_type': forms.Select(attrs={'class': 'form-control'}),
        }
        labels = {
            'content': 'Memory',
            'importance': 'Importance (0.0 - 1.0)',
            'memory_type': 'Type of Memory',
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class UserCharacterForm(forms.ModelForm):
    class Meta:
        model = UserCharacter
        fields = ['name', 'persona', 'chatgpt_model_id', 'chatgpt_model_id_current', 'is_public', 'allow_memory_update', 'character_image', 'allow_free_sample_usage_anyone', 'allow_free_sample_usage_users', 'sample_usage_call_limit', 'x_handle']

class ReferralForm(forms.ModelForm):
    usable_for_chatgpt = True  # Move this to class level
    class Meta:
        model = Referral
        fields = ['name', 'email', 'phone', 'referred_by']  # No changes needed here


class SimpleQuestionForm(forms.ModelForm):
    usable_for_chatgpt = True  # Move this to class level
    class Meta:
        model = QuestionAnswer
        fields = ['question']  # Only the 'answer' field
 

class QuestionAnswerForm(forms.ModelForm):
    class Meta:
        model = QuestionAnswer
        fields = ['question', 'answer', 'is_approved', 'product', 'customer', 'is_visible_user', 'is_visible_public', 'has_sensitive_data', 'is_chatgpt_answer']

class CustomerPDFForm(forms.Form):
    customer = forms.ModelChoiceField(queryset=Customer.objects.all(), label="Select Customer")
    pdf_document = forms.ModelChoiceField(queryset=PDFDocument.objects.all(), label="Select PDF")
    
class PDFDocumentForm(forms.ModelForm):
    class Meta:
        model = PDFDocument
        fields = ['title', 'description', 'file', 'lifecycle_stage', 'is_visible']

class GeneratedMessageForm(forms.ModelForm):
    class Meta:
        model = GeneratedMessage
        fields = ['message', 'sent_social_media', 'sent_email', 'sent_text', 'sent_linkedin', 'sent_x', 'sent_instagram']

class TouchPointTypeForm(forms.ModelForm):
    class Meta:
        model = TouchPointType
        fields = ['name', 'instructions', 'lifecycle_stage', 'objective', 'touchpoint_format', 'integration', 'outcome', 'is_visible']

class ShippingBillingForm(forms.ModelForm):
    class Meta:
        model = Cart
        fields = [
            'billing_address_line1', 'billing_address_line2', 'billing_city', 'billing_state', 'billing_zipcode', 'billing_country',
            'shipping_address_line1', 'shipping_address_line2', 'shipping_city', 'shipping_state', 'shipping_zipcode', 'shipping_country'
        ]

class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['name', 'description', 'price', 'wholesale_price', 'your_price', 'source_upload', 'product_image', 'display_priority', 'quantity', 'lifecycle_stage', 'is_labor', 'digital_file']


class ProductLifecycleStageForm(forms.ModelForm):
    class Meta:
        model = ProductLifecycleStage
        fields = ['name', 'rank', 'description', 'is_visible', 'is_sellable']


class SimpleCustomerForm(forms.ModelForm):
    usable_for_chatgpt = True  # Move this to class level
     
    class Meta:
        model = Customer
        fields = [
            'first_name', 'last_name', 'email', 'phone_number', 
            'address1', 'address2', 'city', 'state', 'zip_code', 'notes'
        ]

class CustomerForm(forms.ModelForm): 
    
    lifecycle_stage = forms.ModelChoiceField(
        queryset=LifecycleStage.objects.filter(is_visible=True),
        empty_label="Select Lifecycle Stage",
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Customer
        fields = [
            'first_name', 'last_name', 'business_name', 'email', 'phone_number', 
            'address1', 'address2', 'city', 'state', 'zip_code', 'country', 
            'linkedin_url', 'twitter_handle', 'facebook_url', 'instagram_url',  # Added Instagram
            'photo',  # Added photo
            'lifecycle_stage', 'notes'
        ]

        
class LifecycleStageForm(forms.ModelForm):
    class Meta:
        model = LifecycleStage
        fields = ['name', 'rank', 'description', 'is_visible']

class TokenMarketingContentForm(forms.ModelForm):
    class Meta:
        model = TokenMarketingContent
        fields = ['marketing_content', 'contract_address']

class UserProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'openai_api_key']
        
class UserCreationForm(UserCreationForm): 
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
 

class TweetForm(forms.ModelForm):
    class Meta:
        model = Tweet
        fields = ['content']  # Only show the content field in the form
    
    def __init__(self, *args, **kwargs):
        super(TweetForm, self).__init__(*args, **kwargs)
        self.fields['content'].widget.attrs.update({
            'class': 'form-control',  # Adds Bootstrap class to the input
            'placeholder': 'Write your tweet here...'
        })


class EditProfileForm(forms.ModelForm):
    company_name = forms.CharField(max_length=255, required=False)
    company_phone = forms.CharField(max_length=255, required=False)
    company_email_address = forms.CharField(max_length=255, required=False)
    billing_address_line1 = forms.CharField(max_length=255, required=False)
    billing_address_line2 = forms.CharField(max_length=255, required=False)
    billing_city = forms.CharField(max_length=255, required=False)
    billing_state = forms.CharField(max_length=255, required=False)
    billing_zipcode = forms.CharField(max_length=255, required=False)
    billing_country = forms.CharField(max_length=255, required=False)
    shipping_address_line1 = forms.CharField(max_length=255, required=False)
    shipping_address_line2 = forms.CharField(max_length=255, required=False)
    shipping_city = forms.CharField(max_length=255, required=False)
    shipping_state = forms.CharField(max_length=255, required=False)
    shipping_zipcode = forms.CharField(max_length=255, required=False)
    shipping_country = forms.CharField(max_length=255, required=False)

    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'username', 'company_name', 'company_phone', 'company_email_address',
            'billing_address_line1', 'billing_address_line2', 'billing_city', 'billing_state', 'billing_zipcode', 'billing_country',
            'shipping_address_line1', 'shipping_address_line2', 'shipping_city', 'shipping_state', 'shipping_zipcode', 'shipping_country'
        ]

class BrandForm(forms.ModelForm):
    class Meta:
        model = Brand
        fields = ['name', 'description', 'image']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['image'].required = False

class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'description', 'image']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['image'].required = False

 

class CartForm(forms.ModelForm):
    class Meta:
        model = Cart
        fields = [
            "customer",  # Add customer to the fields
            "billing_address_line1",
            "billing_address_line2",
            "billing_city",
            "billing_state",
            "billing_zipcode",
            "billing_country",
            "shipping_address_line1",
            "shipping_address_line2",
            "shipping_city",
            "shipping_state",
            "shipping_zipcode",
            "shipping_country",
            "is_processed",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Customize the customer field
        self.fields['customer'].queryset = Customer.objects.all()
        self.fields['customer'].label = "Select Customer"
        self.fields['customer'].empty_label = "Choose a customer"
        # Override the label for each customer in the queryset
        self.fields['customer'].choices = [
            (customer.id, f"{customer.first_name} {customer.last_name} (ID: {customer.id})")
            for customer in Customer.objects.all()
        ]

class WebsiteProfileForm(forms.ModelForm):
    class Meta:
        model = WebsiteProfile
        fields = [
            'name', 'about_us', 'wallet', 'x_handle', 'email', 'phone', 
            'address1', 'address2', 'city', 'state', 'zip_code', 'country',
            'tax_rate', 'terms_of_service', 'privacy_policy', 
            'stripe_publishable_key', 'stripe_secret_key', 
            'bird_eye_api_key', 'deepseek_api_key', 'chatgpt_api_key', 'chatgpt_model_id', 'chatgpt_model_id_current', 'dockerhub_username', 'dockerhub_password',
            'sendgrid_email', 'sendgrid_key', 'google_analytics_key'
        ]

class TokenProfileForm(forms.ModelForm):
    class Meta:
        model = TokenProfile
        fields = ['name', 'description', 'image_uri', 'address', 'visible']

class LandingPageForm(forms.ModelForm):
    class Meta:
        model = LandingPage
        fields = ['name', 'description', 'goal', 'domain_name', 'is_activated', 'is_docker', 'docker_name', 'content', 'port', 'github']