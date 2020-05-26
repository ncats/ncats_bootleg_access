from requests_oauthlib import OAuth2Session
import json

graph_url = 'https://graph.microsoft.com/v1.0'
TIMEOUT = 60

def get_user(token):
    graph_client = OAuth2Session(token=token)
    # Send GET to /me
    return graph_client.get('{0}/me'.format(graph_url)).json()

def get_photo(token):
    graph_client = OAuth2Session(token=token)
    return graph_client.get('%s/me/photo/$value' % graph_url)

def get_calendar_events(token):
    graph_client = OAuth2Session(token=token)

    # Configure query parameters to
    # modify the results
    query_params = {
        '$select': 'subject,organizer,start,end',
        '$orderby': 'createdDateTime DESC'
    }

    # Send GET to /me/events
    events = graph_client.get('{0}/me/events'.format(graph_url),
                              params=query_params)
    # Return the JSON result
    return events.json()

def get_messages(token, folder='Inbox', skip=0, top=10):
    graph_client = OAuth2Session(token=token)
    query_params = {
        '$skip': skip,
        '$top': top
    }
    messages = graph_client.get('%s/me/mailFolders/%s/messages'
                                % (graph_url, folder), params=query_params)
    return messages.json()

def get_message_count(token):
    graph_client = OAuth2Session(token=token)
    return graph_client.get('%s/me/messages/$count' % graph_url).json()

def get_message(token, id, query_params = None):
    graph_client = OAuth2Session(token=token)
    return graph_client.get('%s/me/messages/%s' % (
        graph_url, id), params=query_params).json()

def deliver_message(token, id, mesg, type='reply'):
    graph_client = OAuth2Session(token=token)
    r = graph_client.post(
        '%s/me/messages/%s/%s' % (graph_url, id, type),
        json=mesg, timeout=TIMEOUT
    )
    return r

def deliver_message_new(token, mesg):
    graph_client = OAuth2Session(token=token)
    r = graph_client.post(
        '%s/me/sendMail' % graph_url, json=mesg, timeout=TIMEOUT)
    return r

def delete_message(token, id):
    graph_client = OAuth2Session(token=token)
    return graph_client.delete('%s/me/messages/%s' % (graph_url, id))

def mark_message_read(token, id, isread):
    graph_client = OAuth2Session(token=token)
    mesg = {
        'isRead': isread
    }
    return graph_client.patch('%s/me/messages/%s' % (graph_url, id),
                              json=mesg, timeout=TIMEOUT)

def search_messages(token, query, folder='Inbox', top=10, skiptoken=None):
    graph_client = OAuth2Session(token=token)
    query_params = {
        '$top': top,
        '$search': '"%s"' % query
    }
    if skiptoken:
        query_params['$skiptoken'] = skiptoken
    messages = graph_client.get('%s/me/mailFolders/%s/messages'
                                % (graph_url, folder), params=query_params)
    return messages.json()
    
def get_people(token, query=None, skip=0, top=10):
    graph_client = OAuth2Session(token=token)
    query_params = {
        '$top': top,
        '$skip': skip
    }
    if query:
        query_params['$search'] = '%s' % query
    return graph_client.get('%s/me/people'
                            % graph_url, params=query_params).json()

def get_message_attachments(token, id, query_params):
    graph_client = OAuth2Session(token=token)
    return graph_client.get('%s/me/messages/%s/attachments'
                            % (graph_url, id), params=query_params).json()

def get_message_attachment_content(token, id, attachment_id):
    graph_client = OAuth2Session(token=token)
    return graph_client.get('%s/me/messages/%s/attachments/%s/$value'
                            % (graph_url, id, attachment_id))
