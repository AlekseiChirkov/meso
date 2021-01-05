from django.contrib import auth
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.validators import RegexValidator

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import User
from phone.models import PhoneNumber


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'phonenumber')
        depth = 1


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        style={'input_type': 'password'},
        write_only=True
    )
    password2 = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )
    avatar = serializers.FileField(max_length=20, allow_empty_file=True, required=False)
    token = serializers.CharField(max_length=555, read_only=True)

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'address', 'country',
                  'city', 'company', 'password', 'password2', 'avatar', 'token']

    def validate(self, attrs):
        email = attrs.get('email', '')

        if not email:
            raise serializers.ValidationError(
                'User should have email')

        return attrs

    def create(self, validated_data):
        account = User(
            first_name=self.validated_data['first_name'],
            last_name=self.validated_data['last_name'],
            email=self.validated_data['email'],
            address=self.validated_data['address'],
            country=self.validated_data['country'],
            city=self.validated_data['city'],
            company=self.validated_data['company'],
        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({
                'password': 'Passwords must match.'
            })
        account.set_password(password)
        account.save()
        return account


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    first_name = serializers.CharField(max_length=150, read_only=True)
    last_name = serializers.CharField(max_length=150, read_only=True)

    token = serializers.SerializerMethodField()

    def get_token(self, obj):
        user = User.objects.get(email=obj['email'])

        return {
            'refresh': user.token()['refresh'],
            'access': user.token()['access']
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name', 'token']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        filtered_user_by_email = User.objects.filter(email=email)
        user = auth.authenticate(email=email, password=password)

        if filtered_user_by_email.exists() and filtered_user_by_email[0].auth_provider != 'email':
            raise AuthenticationFailed(
                detail='Please continue your login using ' + filtered_user_by_email[0].auth_provider)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_email_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'token': user.token,
        }


class ProfileSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    company = serializers.CharField(required=False)
    city = serializers.CharField(required=False)
    country = serializers.CharField(required=False)
    address = serializers.CharField(required=False)
    avatar = serializers.FileField(required=False)

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email',
                  'phone', 'avatar', 'address',
                  'country', 'city', 'company']


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()
            return user

        except Exception as e:
            raise AuthenticationFailed('The reset links is invalid', 401)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': 'Token is expired or invalid'
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')
