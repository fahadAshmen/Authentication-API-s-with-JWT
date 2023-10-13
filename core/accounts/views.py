from django.shortcuts import render
from rest_framework.views import  APIView
from rest_framework.response import Response
from rest_framework import status
from . serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfieSerializer, UserPasswordChangeSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from django.contrib.auth import authenticate
from . renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import permissions


#Generate Tokens manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):            
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'Token': token,'message':'User created'},
                            status=status.HTTP_201_CREATED)        
        return Response(serializer.errors,
                        status=status.HTTP_400_BAD_REQUEST)
    
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        print("RUNNING 1", request.data)
        serializer = UserLoginSerializer(data=request.data)
        print("RUN")
        if serializer.is_valid():
            print("RUNNING")
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'Token': token,'message':'Login Success'},status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors': 'Credentials do not match'}}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfieSerializer(request.user)
        return Response(serializer.data)
    
class ChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserPasswordChangeSerializer(data=request.data, 
                                                  context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            # serializer.save()
            return Response({'message':'Password changed'}, 
                            status=status.HTTP_200_OK)    
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'message':'Password reset link send. Please check your Email'}, 
                            status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message':'Password reset Successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        