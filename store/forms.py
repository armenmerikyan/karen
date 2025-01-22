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
from .models import TokenMarketingContent
from store.models import Tweet

class CustomerForm(forms.ModelForm):
    class Meta:
        model = Customer
        fields = ['first_name', 'last_name', 'email', 'phone_number', 
                  'address1', 'address2', 'city', 'state', 'zip_code', 'country']
        
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
        fields = ['first_name', 'last_name', 'email']
        
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


class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['name', 'display_priority', 'price', 'wholesale_price', 'your_price', 'description', 'product_image', 'quantity', 'category', 'brand']
        widgets = {
            'product_image': forms.ClearableFileInput(attrs={'multiple': False}),
        }
    def __init__(self, *args, **kwargs):
        super(ProductForm, self).__init__(*args, **kwargs)
        self.fields['brand'].queryset = Brand.objects.all()
        self.fields['category'].queryset = Category.objects.all()

class CartForm(forms.ModelForm):
    class Meta:
        model = Cart
        fields = [
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
            "shipping_country"
        ]

class WebsiteProfileForm(forms.ModelForm):
    class Meta:
        model = WebsiteProfile
        fields = ['name', 'about_us', 'wallet', 'x_handle']

class TokenProfileForm(forms.ModelForm):
    class Meta:
        model = TokenProfile
        fields = ['name', 'description', 'image_uri', 'address', 'visible']