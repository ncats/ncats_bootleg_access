from django.urls import path, reverse
from . import views

urlpatterns = [
    path(r'', views.home, name='bootleg-home'),

    # authentication views
    path(r'signin', views.sign_in, name='bootleg-signin'),
    path(r'signout', views.sign_out, name='bootleg-signout'),
    path(r'callback', views.callback, name='bootleg-callback'),
    path(r'auth', views.auth, name='bootleg-auth'),
    path(r'verify', views.verify, name='bootleg-verify'),
    path(r'login', views.bootleg_login, name='bootleg-login'),

    # app content views
    path(r'calendar', views.calendar, name='bootleg-calendar'),
    path(r'messages/new', views.message_new, name='bootleg-message-new'),
    path(r'messages/<id>', views.message, name='bootleg-message'),
    path(r'messages/<id>/body', views.message_body,
         name='bootleg-message-body'),
    path(r'messages/<id>/<type>', views.message_send,
         name='bootleg-message-send'),
    path(r'messages', views.messages, name='bootleg-messages'),
    
    # app content api
    path(r'api/messages/new', views.api_message_new,
         name='bootleg-api-message-new'),
    path(r'api/messages/<id>', views.api_message,
         name='bootleg-api-message'),
    path(r'api/messages/<id>/attachment/<attachment_id>',
         views.api_message_attachment_content,
         name='bootleg-api-message-attachment'),
]
