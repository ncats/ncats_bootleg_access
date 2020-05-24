from django import template
import re
register = template.Library()

def url_target_blank(text):
    return re.sub("<a([^>]+)(?<!target=)>",'<a target="_blank"\\1>', text)

url_target_blank = register.filter(url_target_blank, is_safe = True)
