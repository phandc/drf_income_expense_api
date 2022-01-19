from unittest import TextTestRunner
from django.template import exceptions
from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from .utils import Util

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    class Meta:
        model = User
        fields = ['email','username','password']


    def validate(self, attrs):
        email = attrs.get('email','')
        username = attrs.get('username','')

        if not username.isalnum():
            raise serializers.ValidationError("The username should only alphanumeric chracter")
        return attrs
    
    def create(self, validated_data):
        print("Validated Data: ", validated_data)
        return User.objects.create_user(**validated_data) #create an user

class EmailVerificationSerializer(serializers.ModelSerializer):
    token=serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=TextTestRunner)
    username = serializers.CharField(max_length=68, min_length=3, read_only=True)
    tokens = serializers.CharField(max_length=255, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email','')
        password = attrs.get('password','')

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed("Invalid Credentials. Please try again!")
        if not user.is_active:
            raise AuthenticationFailed("Account disabled. Please contact amdin")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified. Please contact amdin")
      

        return {      #serializer send data to the view
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens #tokens need to be appopriate in fileds. 
        }
        return super().validate(attrs)

class ResetPasswordEmailRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        model = User
        fields = ['email']
    
    def validate(self, attrs):
            import pdb
            pdb.set_trace()
            print("Attrs ", attrs)
            email = attrs['data'].get('email', '')
            if User.objects.filter(email=email).exists():
                user=User.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(user.id) 
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(request=attrs['data'].get('request')).domain

                relative_link = reverse('password-reset-confirm', kwargs={'uidb64':uidb64, 'token':token})

                absoluteURL = 'http://' + current_site + relative_link
                email_body = "Hello, " + user.username + "\n" + "Use this link below to reset your password\n" + absoluteURL
                data = {
                   "to_email": user.email,
                   "email_body": email_body,
                   "email_subject": "Reset your password"
                }

                Util.send_email(data)

            return super().validate(attrs)
