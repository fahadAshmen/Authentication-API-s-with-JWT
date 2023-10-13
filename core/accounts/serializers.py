from . models import User
from rest_framework import serializers
#EMAIL SENDING
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ValidationError
from . utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 =serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model = User
        fields = ['email','name','tc','password','password2']
        extra_kwargs = {
            'password':{'write_only':True}
        }

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        password2= attrs.get('password2')

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('User with this email exists')
        
        if password != password2:
            raise serializers.ValidationError('Password and confirm password does not match')
        
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    class Meta:
        model = User
        fields = ['email','password']

        
class UserProfieSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class UserPasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type':'password'},write_only=True)
    password2= serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        fields = ['password','password2']
    
    def validate(self, attrs):
        print('===',attrs)
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        print(user)

        if password != password2:
            raise serializers.ValidationError('Password and confirm password does not match')
        user.set_password(password)
        user.save()
        return attrs
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']
    
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('ENCODED UID', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token', token)
            link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            print('Password Reset link ',link)
            #Send Email
            body = 'Clink link to reset password '+link
            data ={
                'subject':'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError("User with email does'nt exist")


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type':'password'},write_only=True)
    password2= serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        fields = ['password','password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError('Password and confirm password does not match')
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError('Token is not valid or expired')
            
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError('Token is not valid or expired')

                                                   
    




