from django.shortcuts import render
from django.urls import reverse
from django.shortcuts import render
from django.core import serializers
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages as flash_messages
from csp.decorators import csp_exempt

import dateutil.parser, json, logging, traceback, sys, pickle
from dateutil import tz
from datetime import datetime
from PIL import Image
from io import BytesIO
import base64, pyotp, time

from .models import User, Session
from bootleg.graph_helper import *
from bootleg.auth_helper import *

logger = logging.getLogger(__name__)

# default timeout (in seconds) before the user has to enter the passcode
DEFAULT_TIMEOUT = 60*60

def initialize_context(request):
    context = {}
    
    # Check for any errors in the session
    error = request.session.pop('flash_error', None)
    
    if error != None:
        context['errors'] = []
        context['errors'].append(error)
        
    # Check for user in the session
    context['user'] = request.session.get('user', {'id': None})
    return context

def auth(request):
    context = initialize_context(request)
    id = context['user']['id']
    if id:
        return render(request, 'bootleg/auth.html', context)
    return HttpResponseRedirect(reverse('bootleg-home'))

def update_session_user(request, user):
    # update session user from an instance of models.User
    data = json.loads(serializers.serialize('json', [user]))[0]
    request.session['user'] = {
        'id': data['pk'],
        'name': data['fields']['name'],
        'username': data['fields']['username'],
        'email': data['fields']['email'],
        'verified': data['fields']['verified']
    }
    
@csrf_exempt
def verify(request):
    if request.method != 'POST':
        return HttpResponseRedirect(reverse('bootleg-home'))
    
    context = initialize_context(request)
    user = context['user']
    if user['id']:
        code = request.POST['passcode']    
        logger.debug('%s:%s: %s' % (request.path, user['id'], code))
        
        try:
            u = User.objects.get(pk=user['id'])
            totp = pyotp.totp.TOTP(u.secret.decode())
            if totp.verify(code):
                u.verified = time.time()
                u.save()
                
                update_session_user(request, u)
                if request.session['current_path']:
                    return HttpResponseRedirect(
                        request.session['current_path'])
                flash_messages.success(
                    request,
                    'Congratulations, your MFA setup is successful configured!')
            else:
                flash_messages.warning(
                    request, 'Your passcode is not valid!')
                return HttpResponseRedirect(reverse('bootleg-auth'))
        except User.DoesNotExist:
            logger.warning('%s: bogus user id' % id)
        except:
            traceback.print_exc(file=sys.stderr)

    return HttpResponseRedirect(reverse('bootleg-home'))
    
def home(request):
    context = initialize_context(request)
    id = context['user']['id']
    if id:
        try:
            user = User.objects.get(pk=id)
            totp = pyotp.totp.TOTP(user.secret.decode())
            context['qr'] = totp.provisioning_uri(
                    name=user.username, issuer_name='NCATS Bootleg Access')
            #context['otp'] = totp.now()
        except User.DoesNotExist:
            logger.warning('%s: bogus user!' % id)
        except:
            traceback.print_exc(file=sys.stderr)
    return render(request, 'bootleg/home.html', context)

def instrument(request, id):
    try:
        user = User.objects.get(pk=id)
        token = pickle.loads(user.session.token)
        update_session_user(request, user)
        request.session['oauth_token'] = token
    except User.DoesNotExist:
        logger.warning('%s: bogus user!' % id)
    except:
        traceback.print_exc(file=sys.stderr)
    
def user(request, id):
    instrument(request, id)
    context = {}        
    context['user'] = request.session.get('user', {'id': None})
    return render(request, 'bootleg/home.html', context)

def sign_in(request):
    # Get the sign-in URL
    sign_in_url, state = get_sign_in_url()
    # Save the expected state so we can validate in the callback
    request.session['auth_state'] = state
    # Redirect to the Azure sign-in page
    return HttpResponseRedirect(sign_in_url)

def callback(request):
    # Get the state saved in session
    expected_state = request.session.pop('auth_state', '')
    # Make the token request
    token = get_token_from_code(request.get_full_path(), expected_state)
    
    # Get the user's profile
    user = get_user(token)
    # Save token and user
    save_session(request, user, token)
    
    return HttpResponseRedirect(reverse('bootleg-home'))

def sign_out(request):
    # Clear out the user and token
    remove_user_and_token(request)
    return HttpResponseRedirect(reverse('bootleg-home'))

def local_time(time):
    t = dateutil.parser.isoparse(time['dateTime'])
    from_zone = tz.gettz(time['timeZone'])
    t = t.replace(tzinfo=from_zone)
    local_zone = tz.tzlocal()
    local_time = t.astimezone(local_zone)
    return local_time

def validate_request(request, run_if_validated, current_path=True, **kargs):
    context = initialize_context(request)
    if not context['user']['id']:
        return HttpResponseRedirect(reverse('bootleg-home'))

    now = time.time()
    dif = now - context['user']['verified']    
    logger.debug('%s: now=%f verified=%f => %f' % (
        request.path, now, context['user']['verified'], dif))
    if dif > DEFAULT_TIMEOUT:
        if current_path:
            request.session['current_path'] = request.get_full_path()
        return HttpResponseRedirect(reverse('bootleg-auth'))

    token = get_token(request)
    return run_if_validated(request, token, context, **kargs)

def calendar(request):
    def show_calendar(request, token, context):
        events = get_calendar_events(token)
        if events:
            # Convert the ISO 8601 date times to a datetime object
            # This allows the Django template to format the value nicely
            for event in events['value']:
                event['start']['dateTime'] = local_time(event['start'])
                event['end']['dateTime'] = local_time(event['end'])

            context['events'] = events['value']
        return render(request, 'bootleg/calendar.html', context)

    return validate_request(request, show_calendar)

def instrument_messages(context, messages):
    if messages and 'value' in messages:
        index = 1
        for m in messages['value']:
            m['receivedDateTime'] = dateutil.parser.isoparse(
                m['receivedDateTime'])
            if not m['subject'] or m['subject'] == 0:
                m['subject'] = '(no subject)'
            m['message_index'] = index
            index += 1
        context['messages'] = messages['value']
    
def messages(request):
    def show_messages(request, token, context):
        top = 10
        if 'top' in request.GET:
            top = int(request.GET['top'])
        
        if 'search' in request.GET:
            query = context['search_term'] = request.GET['search']
            skip = None
            if 'skip' in request.GET:
                skip = request.GET['skip']

            messages = search_messages(token, query,
                                       top=top, skiptoken = skip)
            if '@odata.nextLink' in messages:
                for s in messages['@odata.nextLink'].split("&"):
                    if s.startswith('$skiptoken='):
                        context['nextpage'] = (
                            reverse('bootleg-messages')
                            +'?search=%s&skip=%s&top=%d' % (
                                query, s[len('$skiptoken='):], top))
            elif 'nextpage' in context:
                del context['nextpage']
            instrument_messages(context, messages)
            return render(request, 'bootleg/search_messages.html', context)
        else:
            skip = 0
            if 'skip' in request.GET:
                skip = int(request.GET['skip'])
            messages = get_messages(token, skip=skip, top=top)
            instrument_messages(context, messages)
            
            if skip - top > 0:
                context['prevpage'] = '%s?skip=%d' % (
                    reverse('bootleg-messages'), skip-top)
            elif skip - top == 0:
                context['prevpage'] = reverse('bootleg-messages')
            context['nextpage'] = '%s?skip=%d' % (
                reverse('bootleg-messages'), skip+top)
            context['count'] = skip+top
            context['skip'] = skip
            
            return render(request, 'bootleg/messages.html', context)

    return validate_request(request, show_messages)


@csp_exempt
def message(request, id):
    def show_message(request, token, context, id):
        mesg = get_message(token, id)
        if mesg:
            mesg['receivedDateTime'] = dateutil.parser.isoparse(
                mesg['receivedDateTime'])
        context['mesg'] = mesg
        if mesg['body']['contentType'] != 'html':
            mesg['body']['content_formatted'] = '<br>'.join(
                mesg['body']['content'].splitlines())
        # now check for attachments
        if 'hasAttachments' in mesg and mesg['hasAttachments']:
            context['attachments'] = get_message_attachments(
                token, id, {'$select': 'id,contentType,name'})['value']
        
        return render(request, 'bootleg/message_detail.html', context)
    return validate_request(request, show_message, id=id)

def message_body(request, id):
    def show_message_body(request, token, context, id):
        mesg = get_message(token, id)
        content_type = ''
        content = ''
        if mesg:
            content_type = mesg['body']['contentType']
            if content_type == 'html':
                content_type = 'text/html'
            else:
                content_type = 'text/plain'
            content = mesg['body']['content']
        return HttpResponse(content, content_type=content_type)
                
    return validate_request(request, show_message_body, id=id)

def api_message_attachment_content(request, id, attachment_id):
    def show_message_attachment_content(request, token,
                                        context, id, attachment_id):
        r = get_message_attachment_content(token, id, attachment_id)
        return HttpResponse(r.content, content_type=r.headers['content-type'],
                            status=r.status_code)
    return validate_request(request, show_message_attachment_content, id=id,
                            attachment_id = attachment_id)
            
@csrf_exempt
def bootleg_login(request):
    if request.method != 'POST':
        return HttpResponseRedirect(reverse('bootleg-home'))

    username = request.POST['username']
    code = request.POST['passcode']
    try:
        user = User.objects.get(username=username)
        totp = pyotp.totp.TOTP(user.secret.decode())
        if totp.verify(code):
            token = pickle.loads(user.session.token)
            request.session['oauth_token'] = token
            user.verified = time.time()
            user.save()
            update_session_user(request, user)
            return HttpResponseRedirect(reverse('bootleg-home'))
        else:
            flash_messages.warning(
                request, 'Either your username or passcode is not valid!')
    except User.DoesNotExist:
        flash_messages.warning(
            request, 'Either your username or passcode is not valid!')
    except:
        traceback.print_exc(file=sys.stderr)
    return HttpResponseRedirect(reverse('bootleg-home'))        

@csrf_exempt
def message_send(request, id, type):
    def show_reply(request, token, context, id, type):
        mesg = get_message(token, id)
        if mesg:
            mesg['receivedDateTime'] = dateutil.parser.isoparse(
                mesg['receivedDateTime'])

            email = mesg['from']['emailAddress']['address']
            recipients = '%s <%s>' % (
                mesg['from']['emailAddress']['name'], email)
            unique = set(email)
            # don't include self in reply
            unique.add(context['user']['email']) 

            cc = ''
            if type == 'replyAll':
                for m in mesg['toRecipients']:
                    email = m['emailAddress']['address']
                    if email not in unique:
                        recipients += '; %s <%s>' % (
                            m['emailAddress']['name'], email)
                        unique.add(email)
                for m in mesg['ccRecipients']:
                    email = m['emailAddress']['address']
                    if email not in unique:
                        if len(cc) > 0:
                            cc += '; '
                        cc += '%s <%s>' % (
                            m['emailAddress']['name'], email)
                        unique.add(email)
            elif type == 'reply':
                pass
            elif type == 'forward':
                recipients = ''
            else:
                logger.warning('Unknown send type: %s' % type)
                type = 'reply'
                        
#            subject = mesg['subject']                    
#            if type == 'forward':
#                if subject.find('Fwd:') >= 0 or subject.find('FW:') >= 0:
#                    pass
#                else:
#                    mesg['subject'] = 'Fwd: '+subject.replace(
#                        'Re:', '').replace('RE:', '')
#            else:
#                if subject.find('Re:') >= 0 or subject.find('RE:') >= 0:
#                    pass
#                else:
#                    mesg['subject'] = 'Re: '+subject

            context['sendtype'] = type                    
            context['torecipients'] = recipients
            context['ccrecipients'] = cc
            context['mesg'] = mesg
        return render(request, 'bootleg/edit.html', context)
    
    return validate_request(request, show_reply, id=id, type=type)

@csrf_exempt
def message_new(request):
    def show_message_new(request, token, context):
        recipients = ''
        if 'to' in request.GET:
            recipients = request.GET['to']
        subject = ''
        if 'subject' in request.GET:
            subject = request.GET['subject']
        context['recipients'] = recipients
        context['subject'] = subject
        return render(request, 'bootleg/new_message.html', context)
    return validate_request(request, show_message_new)
    

def parse_email_addresses(str):
    import re
    addresses = []
    for s in str.split(';'):
        if len(s) > 0:
            m = re.search('([^<\s;]+@[^>\s;]+)', s)
            if m:
                email = m.group(1)
                name = s.replace(email, '').replace('<>', '').strip()
                addresses.append({'emailAddress': {
                    'address': email,
                    'name': name
                }})
            else:
                logger.warning("Can't parse token '%s'" % s)
                
    return addresses

@csrf_exempt
def api_message(request, id):
    context = initialize_context(request)
    if not context['user']['id']:
        return HttpResponseRedirect(reverse('bootleg-home'))

    token = get_token(request)
    if request.method == 'POST': # send
        try:
            # we're not checking the passcode here since we don't want
            # to interrupt the send
            logger.debug('%s: payload... %s' % (request.path, request.body))
            data = json.loads(request.body)
            comment = data['comment']
            #if data['contenttype'] == 'html':
            comment = '<p>' + '<br>'.join(comment.splitlines())

            mesg = {
                'message': {
                    'toRecipients': parse_email_addresses (data['to']),
                    'ccRecipients': parse_email_addresses (data['cc']),
                    #'subject': data['subject']
                },
                'comment': comment
            }
            logger.debug('sending...\n' + json.dumps(mesg, indent=2))
            r = deliver_message(token, id, mesg, data['sendtype'])
            logger.debug('status => %d' % r.status_code)
            return HttpResponse('', status=r.status_code)
        except:
            traceback.print_exc(file=sys.stderr)
            
    elif request.method == 'DELETE':
        try:
            r = delete_message(token, id)
            logger.debug('%s: delete message...%d' % (
                request.path, r.status_code))
            return HttpResponse('', status=r.status_code)
        except:
            traceback.print_exc(file=sys.stderr)

    elif request.method == 'PATCH':
        try:
            isread = False
            if 'isread' in request.GET and (
                    request.GET['isread'] == 'true'
                    or request.GET['isread'] == 'yes'):
                isread = True
            r = mark_message_read(token, id, isread)
            logger.debug('marking message read=%s: %s' % (isread, id))
            return HttpResponse(r.content,
                                content_type=r.headers['content-type'],
                                status=r.status_code)
        except:
            traceback.print_exc(file=sys.stderr)
            
    return HttpResponse('Internal server error!', status=500)

@csrf_exempt
def api_message_new(request):
    # we're also not checking the passcode here either
    context = initialize_context(request)
    if not context['user']['id']:
        return HttpResponseRedirect(reverse('bootleg-home'))

    token = get_token(request)
    try:
        logger.debug('%s: payload... %s' % (request.path, request.body))
        data = json.loads(request.body)
        recipients = parse_email_addresses(data['to'])
        cc = parse_email_addresses(data['cc'])
        if len(recipients) == 0:
            return HttpResponse('No recipients specifed!', status=400)
        mesg = {
            'message': {
                'subject': data['subject'],
                'body': {
                    'contentType': data['contenttype'],
                    'content': data['comment']
                },
                'toRecipients': recipients,
                'ccRecipients': cc
            },
            'saveToSentItems': 'true'
        }
        logger.debug('sending...\n' + json.dumps(mesg, indent=2))        
        r = deliver_message_new(token, mesg)
        logger.debug('status => %d' % r.status_code)
        return HttpResponse('', status=r.status_code)        
        
    except:
        traceback.print_exc(file=sys.stderr)
    return HttpResponse('Internal server error!', status=500)    

def api_people(request):
    def fetch_api_people(request, token, context):
        params = {}
        if 'search' in request.GET:
            params['query'] = request.GET['search']
        if 'skip' in request.GET:
            params['skip'] = request.GET['skip']
        if 'top' in request.GET:
            params['top'] = request.GET['top']
        try:
            data = get_people(token, **params)
            return HttpResponse(json.dumps(data, indent=2),
                                content_type='application/json', status=200)
        except:
            traceback.print_exc(file=sys.stderr)
        return HttpResponse('Internal server error!', status=500)
    return validate_request(request, fetch_api_people, current_path=False)

def api_profile_photo(request):
    def fetch_api_profile_photo(request, token, context):
        r = get_photo(token)
        return HttpResponse(r.content, content_type=r.headers['content-type'],
                            status = r.status_code)
    return validate_request(
        request, fetch_api_profile_photo, current_path=False)
