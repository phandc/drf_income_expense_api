import email
from django.shortcuts import render
from rest_framework import generics, status, views
from .serializers import RegisterSerializer, EmailVerificationSerializer,LoginSerializer, ResetPasswordEmailRequestSerializer

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
            token = RefreshToken.for_user(user).access_token #encode with user id

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
        data = {'request': request, 'data': request.data}
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        pass
