"""los URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from store import views
from store import chatbot
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls.static import static
from django.conf import settings
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LoginView 
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import PasswordResetConfirmView 
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from store.serializers import CustomTokenObtainPairSerializer 
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.routers import DefaultRouter
from store.views import MemoryViewSet, CharacterViewSet


memory_character_router = DefaultRouter()
memory_character_router.register(r'memories', MemoryViewSet, basename='memory')
memory_character_router.register(r'characters', CharacterViewSet, basename='character')

urlpatterns = [   

    path('admin/', admin.site.urls),  
    
    path('', views.index, name='index'), 

    path('api/memory-character/', include(memory_character_router.urls)),  # Use a unique prefix
    path('api/memory-character/memories/<int:pk>/characters/', MemoryViewSet.as_view({'get': 'characters'}), name='memory-characters'),
    path('api/memory-character/characters/<int:pk>/add_memory/', CharacterViewSet.as_view({'post': 'add_memory'}), name='character-add-memory'),
    path('api/memory-character/characters/<int:pk>/remove_memory/', CharacterViewSet.as_view({'post': 'remove_memory'}), name='character-remove-memory'),
    path('api/memory-character/characters/<int:pk>/shared_memories/', CharacterViewSet.as_view({'get': 'shared_memories'}), name='character-shared-memories'),

    path('verify_signature/', views.verify_signature, name='verify_signature'),    
    path('api/add-handle/', views.add_social_media_handle, name='api_add_handle'),
    path('toggle_handle/<int:handle_id>/', views.toggle_handle_status, name='toggle_handle_status'),
    path('add-token-marketing/', views.TokenMarketingContentCreateView.as_view(), name='add_token_marketing'),
    path('login/', views.login_view, name='login'),
    path('forward-to-x/', views.forward_to_x, name='forward_to_x'),
    path('tweets/', views.tweet_list, name='tweet_list'),  # URL for listing tweets
    path('add/', views.create_tweet, name='tweet_add'),  # URL for creating a new tweet
    path('delete_tweet/', views.delete_tweet_by_content, name='delete_tweet_by_content'),
    path('delete/<int:tweet_id>/', views.delete_tweet, name='tweet_delete'),  # URL for deleting a tweet
    path('api/create-tweet/', views.create_tweet_api, name='create_tweet_api'),
    path('api/twitter-status/', views.save_twitter_status, name='save_twitter_status'),
    path('api/twitter-status/view/', views.list_twitter_status, name='list_twitter_status'),  # API view
    path('twitter-status/', views.view_twitter_status, name='view_twitter_status'),  # HTML view
    path('delete-status/<int:status_id>/', views.delete_status, name='delete_status'), 
    path('status/<str:status_id>/', views.twitter_status_detail, name='twitter_status_detail'),
    path('status/<str:status_id>/process/', views.processed_status, name='toggle_processed_status'),
    path('api/user-query/', views.create_user_query, name='create_user_query'), 
    path('api/user-query/<int:query_id>/', views.get_user_query, name='get_user_query'),
    path('user-queries/', views.user_queries_view, name='user_queries_view'),
    path('accounts/login/', views.login_view, name='login'),
    path('api/convo-log/', views.create_convo_log, name='create_convo_log'),
    path('convo_log/<int:pk>/', views.convo_log_detail, name='convo_log_detail'),
    path('api/conversation-topics/', views.create_conversation_topic, name='create_conversation_topic'),
    path('topics/', views.conversation_topics, name='conversation_topics'),  # URL to view topics
    path('topics/<int:pk>/delete/', views.delete_conversation_topic, name='conversation_topic_delete'),
    path('convo_log/delete/<int:id>/', views.delete_convo_log, name='delete_convo_log'),
    path('about-us/', views.about_us, name='about_us'),
    path('upvote/<int:log_id>/', views.upvote_convo_log, name='upvote_convo_log'),
    
    path('verify_signature_game/', views.verify_signature_game, name='verify_signature_game'),
    path('verify_signature/', views.verify_signature, name='verify_signature'),
    path('terms_of_service/', views.terms_of_service, name='terms_of_service'),
    path('privacy_policy/', views.privacy_policy, name='privacy_policy'),
    
    path('marketcap_async/', views.marketcap_async, name='marketcap_async'),
    path('marketcap_json/', views.marketcap_json, name='marketcap_json'),
    path('create_token/', views.create_token, name='create_token'),
    path('get_count/', views.get_count, name='get_count'),  
    
    path('token/<str:mint>/', views.token_detail, name='token_detail'),  
    path('tweets/', views.tweet_list, name='tweet_list'),  # URL for listing tweets
    path('add/', views.create_tweet, name='tweet_add'),  # URL for creating a new tweet
    path('toggle-scam-filter/', views.toggle_scam_filter, name='toggle_scam_filter'),
    path('marketcap_async_search/', views.marketcap_async_search, name='marketcap_async_search'), 


    path('save_room/', views.save_room_view, name='save_room'),
    path('rooms/', views.room_list_view, name='room_list'),  # URL for listing rooms
    path('api/save_room/', views.save_room, name='save_room'),

    path('memories/', views.memory_list, name='memory-list'),  # This will render the HTML page

    path('memory/', views.MemoryView.as_view(), name='create_memory'),
    path('memory/<int:memory_id>/', views.MemoryView.as_view(), name='memory_detail'),
    path('website_profiles/', views.list_and_add_website_profiles, name='list_and_add_website_profiles'),
    path('admin_panel/', views.admin_panel, name='admin_panel'),
    path('logout/', views.custom_logout_view, name='logout'),
    path('token_list', views.token_list, name='token_list'),
    path('add_token/', views.add_token, name='add_token'),
    path('toggle-visibility/<int:token_id>/', views.toggle_visibility, name='toggle_visibility'),
    path('register/', views.register, name='register'), # create account
    path('update_profile/', views.update_profile, name='update_profile'),
    path('accounts/profile/', views.update_profile, name='update_profile'),

    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),

    path('verify-email/<uidb64>/<token>/', views.email_verification_confirm, name='email_verification_confirm'),
    
    path("accounts/", include("allauth.urls")),
    path('email-verification-sent/', views.email_verification_sent, name='email_verification_sent'),
    path('resend-verification-email/', views.resend_verification_email, name='resend_verification_email'),

    path('lifecycle-stages/', views.lifecycle_stage_list, name='lifecycle_stage_list'),
    path('lifecycle-stages/create/', views.lifecycle_stage_create, name='lifecycle_stage_create'),
    path('lifecycle-stages/<int:pk>/update/', views.lifecycle_stage_update, name='lifecycle_stage_update'),


    path('customer_list', views.customer_list, name='customer_list'),
    path('add_customer/', views.customer_add, name='customer_add'),
    path('edit/<int:customer_id>/', views.customer_edit, name='customer_edit'),
    path('customer/<int:customer_id>/cart/create/', views.cart_create, name='cart_create'),

    path('product_lifecycle_stages_list', views.product_lifecycle_stages_list, name='product_lifecycle_stages_list'),
    path('product_lifecycle_stages_create/', views.product_lifecycle_stages_create, name='product_lifecycle_stages_create'),
    path('product_lifecycle_stages_edit/<int:pk>/', views.product_lifecycle_stages_edit, name='product_lifecycle_stages_edit'),


    path('product_list', views.product_list, name='product_list'),
    path('product_add/', views.product_add, name='product_add'),
    path('product_edit/<int:pk>/', views.product_edit, name='product_edit'),
    path('shop/<int:cart_id>/', views.product_list_shop, name='product_list_shop'),
    path('add_to_cart/<int:cart_id>/<int:product_id>/', views.add_to_cart, name='add_to_cart'),


    path('create/', views.create_cart, name='create_cart'),
    path('cart_list/', views.cart_list, name='cart_list'),  # URL pattern for viewing the list of carts
    path('cart/<int:id>/', views.cart_detail, name='cart_detail'),
    path('cart/<int:id>/edit/', views.cart_edit, name='cart_edit'),

    path('cart/<int:cart_id>/payment/', views.payment_form, name='payment_form'),

    path('shop_products/', views.shop_product_list, name='shop_product_list'),
    # URL for viewing a specific product's details
    path('shop_products/<int:product_id>/', views.shop_product_detail, name='shop_product_detail'),


    path('add-to-cart/', views.shop_add_to_cart, name='shop_add_to_cart'),

    path('cart/<int:cart_id>/', views.view_cart_detail_shop, name='view_cart_detail_shop'),
    path('current_cart/', views.view_cart_detail_shop_current, name='view_cart_detail_shop_current'),
    
    path('checkout/', views.checkout_view, name='checkout'),
    path('process_checkout/', views.process_checkout, name='process_checkout'),


    path('pay_with_stripe/', views.pay_with_stripe, name='pay_with_stripe'),
    # Add additional URLs for success and failure views
    path('success/', views.success, name='success'),
    path('failure/', views.failure, name='failure'),
    
    path('delete-product/<int:product_id>/', views.delete_product, name='delete_product'),


    path('select-payment/', views.select_payment_type, name='select_payment'),


    path('pay-with-solana/', views.pay_with_solana, name='pay_with_solana'),
    path('pay-with-token/<str:token_address>/', views.pay_with_token, name='pay_with_token'),

    path('touchpoint-types/', views.touchpoint_type_list, name='touchpoint_type_list'),
    path('touchpoint-types/add/', views.touchpoint_type_add, name='touchpoint_type_add'),
    path('touchpoint-types/edit/<int:pk>/', views.touchpoint_type_edit, name='touchpoint_type_edit'),

    path('generate-message/<int:customer_id>/<int:touchpoint_id>/', views.generate_message, name='generate_message'),   
    path('generate-message-chatgpt/<int:customer_id>/<int:touchpoint_id>/', views.generate_message_chatgpt, name='generate_message_chatgpt'),      


    path('save-message/', views.save_generated_message, name='save_generated_message'),

    path('customer/<int:customer_id>/messages/', views.customer_messages, name='customer_messages'),
    path('generated-message/<int:pk>/edit/', views.update_generated_message, name='generated_message_update'),


    path('pdf_list/', views.pdf_list, name='pdf_list'),
    path('pdf/<int:pk>/', views.view_pdf, name='view_pdf'),
    path('pdf/add/', views.add_pdf, name='add_pdf'),
    path('pdf/edit/<int:pk>/', views.edit_pdf, name='edit_pdf'),    
 
    path('download/<int:product_id>/', views.secure_download, name='secure_download'),

    path('chatbot-response/', chatbot.chatbot_response_private, name='chatbot_response'),

    path('chatbot-response-public/', chatbot.chatbot_response_public, name='chatbot_response_hosted'),

    path("train-products/", views.train_product_model, name="train-products"),

    path('copy-profile/', views.copy_profile, name='copy_profile'),

    path('question_answer_list/', views.question_answer_list, name='question_answer_list'),
    path('question_answer_add/', views.question_answer_add, name='question_answer_add'),
    path('question_answer_edit/<int:pk>/', views.question_answer_edit, name='question_answer_edit'),
    path('question_answer_delete/<int:pk>/', views.question_answer_delete, name='question_answer_delete'),
    path('question_answer_detail/<int:pk>/', views.question_answer_detail, name='question_answer_detail'),
    path('public_question_answer_list/', views.public_question_answer_list, name='public_question_answer_list'),
    path('simple_question_add/', views.simple_question_add, name='simple_question_add'),

    path("conversations/", views.conversation_list, name="conversation_list"),
    path('update_message_content/<int:message_id>/', views.update_message_content, name='update_message_content'), 
    
    path('visitors/', views.visitor_list, name='visitor_list'),
    path('visitor/delete/<int:id>/', views.visitor_delete, name='visitor_delete'),

    path('users/', views.list_users, name='user_list'),
    path('users/clear/<int:user_id>/', views.clear_user_fields, name='clear_user_fields'),


    path('referrals/', views.referral_list, name='referral_list'),


    path('landing_page_list/', views.landing_page_list, name='landing_page_list'),
    path('landing_page_create/', views.landing_page_create, name='landing_page_create'),
    path('landing_page_edit/<int:pk>/', views.landing_page_edit, name='landing_page_edit'),
    path('landing_page/<int:pk>/activate/', views.set_landing_page_active, name='landing_page_activate'),
    path('landing_page/<int:pk>/deactivate/', views.set_landing_page_inactive, name='landing_page_deactivate'),

    path('contact_us_api/', views.submit_form, name='contact_us_api'),
    path('submissions/', views.submission_list, name='submission_list'),

    path('api/businesses/', views.BusinessListCreateView.as_view(), name='business-list'),
    path('api/businesses/<int:pk>/', views.BusinessDetailView.as_view(), name='business-detail'),
    path('api/businesses/mcp/', views.BusinessMCPView.as_view(), name='business-mcp'),
    path("api/businesses/create/", views.BusinessCreateView.as_view(), name="business-create"),  # ✅ New endpoint for creating a business 
    path('business/<int:pk>/update/', views.BusinessUpdateView.as_view(), name='business-update'),

    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    '''
    path("api/support-tickets/", views.SupportTicketListView.as_view(), name="support-ticket-list"),  # ✅ List all tickets
    path("api/support-tickets/create/", views.SupportTicketCreateView.as_view(), name="support-ticket-create"),  # ✅ Create a new ticket
    path("api/support-tickets/<int:pk>/", views.SupportTicketDetailView.as_view(), name="support-ticket-detail"),  # ✅ Retrieve or update a ticket
    path("api/support-tickets/<int:pk>/update/", views.SupportTicketUpdateView.as_view(), name="support-ticket-update"),  # ✅ Fully update a ticket
    path('businesses/', views.business_list, name='business_list'),
    path('businesses/delete/<int:business_id>/', views.delete_business, name='delete_business'),
    '''
    path('oauth/', include('oauth2_provider.urls', namespace='oauth2_provider')),
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),


    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('generate-token/', views.generate_token, name='generate_token'),

    path('service-request/', views.CleaningRequestCreateView.as_view(), name='create-service-request'),


    path('cleaning-requests/', views.cleaning_request_list, name='cleaning_request_list'),

    path("intake-form/", views.ImmigrationCaseCreateView.as_view(), name="intake-form"),


    #path('letters/create/', views.LetterCreateView.as_view(), name='letter-create'),
    #path('letters/search/', views.LetterSearchView.as_view(), name='letter-search'),    
    path('api/car-finder/', views.CarFinderResponseCreateView.as_view(), name='car-finder-create'),

    #path('api/register/', views.RegisterAPIView.as_view(), name='api_register'),
    #path('api/login/', views.CustomLoginView.as_view(serializer_class=CustomTokenObtainPairSerializer), name='api_login'),
    #path('reviews/', views.ReviewListCreateView.as_view(), name='review-list-create'),
    #path('reviews/<int:pk>/', views.ReviewDetailView.as_view(), name='review-detail'),
    path("api/userinfo/", views.userinfo, name="userinfo"),

] 

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

