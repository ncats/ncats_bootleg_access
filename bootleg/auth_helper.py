import yaml, os, time, logging, sys, traceback, pickle, pyotp
from requests_oauthlib import OAuth2Session
from .models import User, Session

logger = logging.getLogger(__name__)

# This is necessary for testing with non-HTTPS localhost
# Remove this if deploying to production
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# This is necessary because Azure does not guarantee
# to return scopes in the same case and order as requested
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
os.environ['OAUTHLIB_IGNORE_SCOPE_CHANGE'] = '1'

# Load the oauth_settings.yml file
stream = open('oauth_settings.yml', 'r')
settings = yaml.load(stream, yaml.SafeLoader)
authorize_url = '{0}{1}'.format(settings['authority'], settings['authorize_endpoint'])
token_url = '{0}{1}'.format(settings['authority'], settings['token_endpoint'])

# Method to generate a sign-in url
def get_sign_in_url():
    # Initialize the OAuth client
    aad_auth = OAuth2Session(settings['app_id'],
                             scope=settings['scopes'],
                             redirect_uri=settings['redirect'])

    sign_in_url, state = aad_auth.authorization_url(
        authorize_url, prompt='login')

    return sign_in_url, state

# Method to exchange auth code for access token
def get_token_from_code(callback_url, expected_state):
    # Initialize the OAuth client
    aad_auth = OAuth2Session(settings['app_id'],
                             state=expected_state,
                             scope=settings['scopes'],
                             redirect_uri=settings['redirect'])

    token = aad_auth.fetch_token(token_url,
                                 client_secret = settings['app_secret'],
                                 authorization_response=callback_url)

    return token

def update_token(request, token):
    id = request.session['user']['id']    
    try:
        session = Session(token=pickle.dumps(token))
        session.save()

        user = User.objects.get(pk=id)
        if not user.secret:
            user.secret = pyotp.random_base32()
        user.session = session
        user.save()
        
        request.session['oauth_token'] = token
    except User.DoesNotExist:
        logger.warning('%s: unknown user' % id)
    except:
        traceback.print_exc(file=sys.stderr)        

def save_session (request, user, token):
    try:
        session = Session(token=pickle.dumps(token))
        session.save()
        u = {
            'name': user['displayName'],
            'email': user['mail'] if (user['mail'] != None)
                  else user['userPrincipalName'],
            'username': user['userPrincipalName'],
            'id': user['id'],
            'verified': time.time()
        }
        secret = pyotp.random_base32().encode('utf8')
        
        uu = u.copy()
        uu['session'] = session
        uu['secret'] = secret
        uu, created = User.objects.get_or_create(
            pk=u['id'], defaults=uu)
        if created:
            # new user
            logger.info('#'*5+' principal %s created!' % uu.username)
        else:
            if not uu.secret:
                uu.secret = secret
            uu.token = session
            uu.save() # update token

        request.session['user'] = u
        request.session['oauth_token'] = token        
    except:
        traceback.print_exc(file=sys.stderr)
        

def get_token(request):
    token = request.session['oauth_token']
    if token:
        # Check expiration
        now = time.time()
        # Subtract 5 minutes from expiration to account for clock skew
        expire_time = token['expires_at'] - 300
        if now >= expire_time:
            # Refresh the token
            aad_auth = OAuth2Session(settings['app_id'],
                                     token = token,
                                     scope=settings['scopes'],
                                     redirect_uri=settings['redirect'])

            refresh_params = {
                'client_id': settings['app_id'],
                'client_secret': settings['app_secret'],
            }
            token = aad_auth.refresh_token(token_url, **refresh_params)

            # Save new token
            update_token(request, token)
    # Token still valid, just return it
    return token  

def remove_user_and_token(request):
    if 'oauth_token' in request.session:
        del request.session['oauth_token']

    if 'user' in request.session:
        del request.session['user']
