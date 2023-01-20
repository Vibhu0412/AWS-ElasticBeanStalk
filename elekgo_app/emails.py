import os

from django.core.mail import send_mail
import random
from django.conf import settings
from .models import User
from twilio.rest import Client
from decouple import config


def send_otp_via_email(email):
    subject = "Account Verification Email - ElekGo"
    otp = random.randint(1000,9999)
    message = f"Please verify your email - your otp is {otp}"
    email_from = settings.EMAIL_HOST
    user_obj = User.objects.get(email=email)
    user_obj.otp = otp
    user_obj.save()
    send_mail(subject , message , email_from , [email])


def send_otp_via_phone(phone):
    account_sid = config('account_sid')
    auth_token = config('auth_token')
    client = Client(account_sid, auth_token)
    user = User.objects.get(phone=phone)
    if user:
        phone_number = phone
        my_otp = random.randint(1111, 9999)
        message = client.messages.create(
            body=f"Hi,Welcome to ElekGo ,{my_otp} is your one time password to proceed on ElekGo. Do not share your OTP with anyone.",
            from_=config('twilio_no'),
            to=f'{phone_number}'
        )
        User.objects.filter(phone=phone).update(otp=my_otp)


def send_otp_session_via_email(email):
    subject = "Account Verification Email - ElekGo"
    otp = random.randint(1000,9999)
    message = f"Please verify your email - your otp is {otp}"
    email_from = settings.EMAIL_HOST
    send_mail(subject , message , email_from , [email])
    return otp

def send_verification_link(email, link):
    subject = "Account Verification Email - ElekGo"
    message = f"Please verify your email - your verification link is {link}"
    email_from = settings.EMAIL_HOST
    send_mail(subject , message , email_from , [email])