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