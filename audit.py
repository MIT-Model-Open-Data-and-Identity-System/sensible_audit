from django.http import HttpResponse
from django.shortcuts import render
from django.conf import settings
from authorization_manager import authorization_manager
import bson.json_util as json
import database
import logging

log = logging.getLogger('sensible.' + __name__)


def build_request_dict(request, data=None):
    """
        Builds a dictionary with relevant parameters from an
        HTTP Request.
    """
    req = {}
    req['path'] = request.get_full_path()
    req['method'] = request.method
    req['host'] = request.get_host()
    req['remote_addr'] = request.META.get('REMOTE_ADDR')
    if req['remote_addr'] in getattr(settings, 'INTERNAL_IPS', []):
        req['remote_addr'] = (request.META.get('HTTP_X_FORWARDED_FOR') or
                              req['remote_addr'])
    req['remote_host'] = request.META.get('REMOTE_HOST')
    req['user_agent'] = request.META.get('HTTP_USER_AGENT')
    if request.method == 'GET':
        req['GET'] = request.GET
    elif request.method == 'POST':
        req['POST'] = request.POST
    if hasattr(request, 'user'):
        req['user'] = request.user.username
    if data is not None and isinstance(data, dict):
        req.update(data)
    else:
        req['data'] = data
    return req

def visualization(request):
    """
     Shows information about who has access the user's data.
    """
    return get_data(request)

def accesses(request):
    return get_data(request)

def get_data(request):
    auth = authorization_manager.authenticate_token(request)

    if 'error' in auth:
        response = {'meta': {'status':
                            {'status': 'error', 'code': 401,
                             'desc': auth['error']}}}
        log.error('authentication error', extra=build_request_dict(request))
        return HttpResponse(json.dumps(response),
                            status=401, content_type="application/json")

    log.info('audit data accessed', extra=build_request_dict(request))
    accesses = dataBuild(request, request.user.username)
    return render(request, 'sensible_audit/audit.html', {'accesses': accesses})

def dataBuild(request, user):
    db = database.AuditDB()
    accesses = db.get_accesses(user)
    return accesses

class BadRequestException(Exception):
    def __init__(self, value):
        self.value = value
    
    def __init__(self, status, code, description):
        self.value = {}
        self.value['status'] = status
        self.value['code'] = code
        self.value['desc'] = description
    
    def __str__(self):
        return repr(self.value)