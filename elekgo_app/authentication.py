import imp
from requests import Response
from rest_framework import exceptions
import jwt, datetime
from django.conf import settings
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from elekgo_app import serializers
from elekgo_app.models import User


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if auth and len(auth) == 2:
            token = auth[1].decode('utf-8')
            id = decode_access_token(token)
            try:
                user = User.objects.get(id=id)
            except:
                raise exceptions.AuthenticationFailed('unauthenticated user')
            return (user, None)

        raise exceptions.AuthenticationFailed('unauthenticated user')

class KYCApprovedAuth(JWTAuthentication):
    def kyc_authenticate(self, request):
        user = self.authenticate(request)
        try:
            if user[0].is_user_kyc_verified == "Approved":
                return user
            else:
                raise exceptions.AuthenticationFailed('unauthenticated user')
        except:
            raise exceptions.AuthenticationFailed('unauthenticated user')
            

def create_access_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=10),
        'iat': datetime.datetime.utcnow(),
    }, 'access_secret', algorithm='HS256')


def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Unauthenticated')


def create_refresh_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow(),
    }, 'refresh_secret', algorithm='HS256')


def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Unauthenticated')
    
def create_verification_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=10),
        'iat': datetime.datetime.utcnow(),
    }, 'access_secret', algorithm='HS256')

def decode_verification_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Unauthenticated')
    
def get_verification_token(user):
    verification_token = create_verification_token(user.id)
    return verification_token