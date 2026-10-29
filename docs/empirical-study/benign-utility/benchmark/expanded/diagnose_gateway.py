"""Read-only endpoint diagnostics without emitting model credentials."""
import json,os,socket,urllib.request,urllib.parse
url=os.environ['LITELLM_BASE_URL'];parts=urllib.parse.urlsplit(url)
result=dict(scheme=parts.scheme,hostname=parts.hostname,port=parts.port)
try:result['addresses']=sorted({r[4][0] for r in socket.getaddrinfo(parts.hostname,parts.port or (443 if parts.scheme=='https' else 80))})
except Exception as error:result['dns_error_type']=type(error).__name__
try:
    request=urllib.request.Request(url.rstrip('/')+'/models',headers={'Authorization':'Bearer '+os.environ['LITELLM_API_KEY']})
    with urllib.request.urlopen(request,timeout=8) as response:result['models_status']=response.status
except Exception as error:
    result.update(http_error_type=type(error).__name__,http_status=getattr(error,'code',None),reason_type=type(getattr(error,'reason',None)).__name__)
print(json.dumps(result,sort_keys=True))
