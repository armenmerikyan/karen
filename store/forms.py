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
from store.models import Product 
from .models import TokenMarketingContent
from store.models import Tweet 
from .models import TouchPointType 
from .models import GeneratedMessage

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
        fields = ['name', 'description', 'price', 'wholesale_price', 'your_price', 'source_upload', 'product_image', 'display_priority', 'quantity', 'lifecycle_stage', 'is_labor']


class ProductLifecycleStageForm(forms.ModelForm):
    class Meta:
        model = ProductLifecycleStage
        fields = ['name', 'rank', 'description', 'is_visible', 'is_sellable']


class CustomerForm(forms.ModelForm):
    lifecycle_stage = forms.ModelChoiceField(
        queryset=LifecycleStage.objects.filter(is_visible=True),
        empty_label="Select Lifecycle Stage",
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Customer
        fields = [
            'first_name', 'last_name', 'email', 'phone_number', 
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
        fields = ['first_name', 'last_name' ]
        
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
            'bird_eye_api_key', 'deepseek_api_key', 'chatgpt_api_key'
        ]

class TokenProfileForm(forms.ModelForm):
    class Meta:
        model = TokenProfile
        fields = ['name', 'description', 'image_uri', 'address', 'visible']