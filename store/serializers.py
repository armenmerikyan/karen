# serializers.py
from rest_framework import serializers
from .models import TwitterStatus
from .models import UserQuery
from .models import ConvoLog
from .models import ConversationTopic
from .models import Memory
from .models import Business
from .models import SupportTicket
from .models import Review
from .models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class RegisterResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "company_name", "company_phone", "sol_wallet_address", "created_at"]

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims here if needed
        token['username'] = user.username
        return token

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True)
    message = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name',
            'password', 'password2', 'company_name', 'company_phone', 'sol_wallet_address', 'message'
        )
        extra_kwargs = {'password': {'write_only': True}}

    def get_message(self, obj):
        return "User registered successfully."

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords must match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        
        # Extract additional fields before creating user
        company_name = validated_data.pop('company_name', None)
        company_phone = validated_data.pop('company_phone', None)
        sol_wallet_address = validated_data.pop('sol_wallet_address', None)

        # Create the user
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )

        # Store additional fields in user profile (assuming you extend the User model)
        user.profile.company_name = company_name
        user.profile.company_phone = company_phone
        user.profile.sol_wallet_address = sol_wallet_address
        user.profile.save()

        return user


# Serializer
class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = '__all__'

class SupportTicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupportTicket
        fields = "__all__"

class BusinessSerializer(serializers.ModelSerializer):
    class Meta:
        model = Business
        fields = '__all__'
        
class ConversationTopicSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConversationTopic
        fields = '__all__' # Include 'id' for easier reference

class ConvoLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConvoLog
        fields = '__all__'  # This will include all fields in the model

class TwitterStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = TwitterStatus
        fields = ['url', 'created_by_user']

class UserQuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserQuery
        fields = ['id', 'created_date', 'username', 'question', 'reasoning', 'response', 'connanicall_action_text']


class MemorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Memory
        fields = '__all__'
        
class EmptySerializer(serializers.Serializer):
    pass