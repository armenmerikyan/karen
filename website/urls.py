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
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls.static import static
from django.conf import settings
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LoginView 
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import PasswordResetConfirmView 

urlpatterns = [  
    path('admin/', admin.site.urls),  
    
    path('', views.index, name='index'), 
    path('verify_signature/', views.verify_signature, name='verify_signature'),    
    path('game_create/', views.game_create, name='game_create'),  
    path('game_next/', views.game_next, name='game_next'),  
    path('all_games/', views.all_games, name='all_games'), 
    path('game/<str:game_id>/', views.view_game, name='view_game'), 
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
    path('api/token/', views.ObtainAuthToken.as_view(), name='token_obtain'),
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
] 

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

