import email
from django.shortcuts import render
from rest_framework import generics, status, views
from .serializers import RegisterSerializer, EmailVerificationSerializer,LoginSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer

from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt 
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer


from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from .utils import Util


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)

        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data
            user = User.objects.get(email=user_data['email'])
            print("User Email", user.email)
            token = RefreshToken.for_user(user).access_token #generate token for user

            current_site = get_current_site(request).domain

            relative_link = reverse('email-verify')

            absoluteURL = 'http://' + current_site + relative_link + "?token="+ str(token)
            email_body = "Hi " + user.username + " Use link below to verify your email\n" + absoluteURL
            data = {
                "to_email": user.email,
                "email_body": email_body,
                'email_subject': "Verify your email"
            }
            
            Util.send_email(data)
            return Response(user_data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmail(views.APIView):

    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256") #Don't forget the algorithms
            print("Payload: ", payload)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated!'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError :
            return Response({'erorr': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError :
            return Response({'erorr': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)
            

class RequestPasswordResetEmail(generics.GenericAPIView):

    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        if User.objects.filter(email=email).exists():
                user=User.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(request).domain

                relative_link = reverse('password-reset-confirm', kwargs={'uidb64':uidb64, 'token':token})

                absoluteURL = 'http://' + current_site + relative_link
                email_body = "Hello, " + user.username + "\n" + "Use this link below to reset your password\n" + absoluteURL
                data = {
                   "to_email": user.email,
                   "email_body": email_body,
                   "email_subject": "Reset your password"
                }

                Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(generics.GenericAPIView):
    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            
            if not PasswordResetTokenGenerator().check_token(user, token): #check if user's token is used
                return Response({'error': 'Token is not valid. Please request a new one!'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'message':'Credentials valid', 'uidb64':uidb64, 'token':token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError:
            return Response({'error': 'Token is not valid. Please request a new one!'}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request): #change a part of the object
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)