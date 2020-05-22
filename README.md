This is a django repository to interact with the Microsoft Graph. The
following packages are required to run this code:

```
python 3+
django 3+
pyotp
pytz
python-dateutil
oauthlib
requests
requests-oauthlib
```

To build

```
python manage.py makemigrations bootleg
python manage.py migrate
```

Make sure to edit the files `oauth_settings_example.yml` as appropriate
and rename it as `oauth_settings.yml` and adjust `settings.py`
accordingly before running the code. Please see documentations on 
(https://developer.microsoft.com/en-us/graph/get-started/python)[Microsoft
Graph] for additional details.

```
python manage.py runserver
```

Then point your browser to
[http://localhost:8000](http://localhost:8000).
