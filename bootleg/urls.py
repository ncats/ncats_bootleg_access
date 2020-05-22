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
    path(r'messages/<id>', views.message, name='bootleg-message'),
    path(r'messages/<id>/body', views.message_body,
         name='bootleg-message-body'),
    path(r'messages', views.messages, name='bootleg-messages'),
    path(r'reply/<id>', views.reply, name='bootleg-reply'),
    path(r'reply/<id>/send', views.reply_send, name='bootleg-reply-send'),
]
