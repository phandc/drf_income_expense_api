from dataclasses import field
from turtle import pd
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
    

class SetNewPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        model = User
        fields = ['password','token', 'uidb64']


    def validate(self, attrs):
        try:
            password = attrs.get('password') 
            token = attrs.get('token') 
            uidb64 = attrs.get('uidb64') 

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            # import pdb
            # pdb.set_trace
            if not PasswordResetTokenGenerator().check_token(user, token):
               raise AuthenticationFailed('The reset link 1 is invalid!',401) #in view we return Response, in here we raise the error

            user.set_password(password)
            user.save()

            return (user)

        except:
            raise AuthenticationFailed('The reset link is invalid!',401)
        return super().validate(attrs)