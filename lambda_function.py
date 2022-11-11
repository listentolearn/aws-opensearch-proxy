import base64
import boto3
import json
import os
import re
import requests

from aws_requests_auth.aws_auth import AWSRequestsAuth
from aws_requests_auth.aws_auth import sign

HOST = os.environ.get('ES_HOST')
STAGE = os.environ.get('API_STAGE')


def get_aws4auth(HOST, path, opts):

    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    service = 'es'
    awsauth = AWSRequestsAuth(
        aws_access_key=creds.access_key,
        aws_secret_access_key=creds.secret_key,
        aws_token=creds.token,
        aws_host=opts['HOST'],
        aws_region=session.region_name,
        aws_service=service
    )   

    req = requests.Request(
        opts['method'],
        opts['url'],
        headers=opts['headers'],
        data=opts['body'],
        params=opts['params']
    )
    prepped = req.prepare()

    auth = awsauth.get_aws_request_headers(prepped,
                                aws_access_key=creds.access_key,
                                aws_secret_access_key=creds.secret_key,
                                aws_token=creds.token)

    return auth


def format_response(response):

    resp_body = []
    headers = {}
    isBase64Encoded = False
    rewrite = {
        '&quot;_dashboards&quot': '&quot;{}/_dashboards&quot'.format(API_STAGE),
        '/_dashboards': '/{}/_dashboards'.format(API_STAGE)
    }

    h = dict(response.headers)
    del h['Connection']
    del h['Content-Length']
    if 'content-encoding' in h:
        del h['content-encoding']
    for k, v in h.items():
        headers[k.lower()] = v

    for content in response.iter_content(1024):
        if content:
            resp_body.append(content)
    resp_body = b''.join(resp_body)

    if any(h in headers['content-type'] for h in ['text', 'javascript']):
        resp_body = str(resp_body, 'utf-8')
    elif 'json' in headers['content-type']:
        resp_body = resp_body.decode('utf8').replace("'", '"')
    else:
        isBase64Encoded = True
        resp_body = str(base64.b64encode(resp_body))

    for k, v in rewrite.items():
        resp_body = resp_body.replace(k, v)

    return (headers, resp_body, isBase64Encoded)


def lambda_handler(event, context):

    path = event.get('path')
    method = event.get('httpMethod')
    body = event.get('body')
    query_params = event.get('queryStringParameters')
    headers = event.get('headers', {})
    req_headers = {}
    for k, v in headers.items():
        if any(h in k for h in ['content-type', 'cookie', 'kbn-', 'osd-']):
            req_headers[k] = v
    opts = {
        'method': method.upper(),
        'HOST': HOST,
        'url': 'https://{}{}'.format(HOST, path),
        'service': 'es',
        'region': 'us-east-1',
        'headers': req_headers,
        'body': body,
        'params': query_params
    }

    auth = get_aws4auth(HOST, path, opts)
    req_headers.update(auth)

    response = requests.request(
        method=method,
        url='https://{}{}'.format(HOST, path),
        headers=req_headers,
        data=body,
        params=query_params,
        stream=True
    )
    (headers, body, isBase64Encoded) = format_response(response)
    
    return {
        'statusCode': response.status_code,
        'body': body,
        'headers': headers,
        'isBase64Encoded': isBase64Encoded
    }
