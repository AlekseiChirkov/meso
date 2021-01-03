from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.validators import RegexValidator


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
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,14}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 14 digits allowed.")
    phone = serializers.CharField(validators=[phone_regex], max_length=17, min_length=10)
    token = serializers.CharField(max_length=555, read_only=True)

    default_error_messages = {
        'phone': phone_regex
    }

    class Meta:
        model = User
        fields = ['id', 'phone', 'first_name', 'last_name', 'email',
                  'address', 'country', 'city', 'company', 'password', 'password2', 'token']

    def validate(self, attrs):
        email = attrs.get('email', '')
        phone = attrs.get('phone', '')

        if not phone:
            raise serializers.ValidationError(
                self.default_error_messages)

        return attrs

    def create(self, validated_data):
        account = User(
            first_name=self.validated_data['first_name'],
            last_name=self.validated_data['last_name'],
            email=self.validated_data['email'],
            phone=self.validated_data['phone'],
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
    phone = serializers.CharField(
        max_length=17, min_length=10)

    token = serializers.SerializerMethodField()

    def get_token(self, obj):
        user = User.objects.get(email=obj['email'])

        return {
            'refresh': user.token()['refresh'],
            'access': user.token()['access']
        }

    class Meta:
        model = User
        fields = ['phone', 'email', 'password', 'token']

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
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'username': user.username,
            'token': user.token
        }

        return super().validate(attrs)


class ProfileSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=256, min_length=3, read_only=True)
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True
    )

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email',
                  'phone', 'avatar', 'address',
                  'country', 'city', 'password']

    def validate(self, data):
        token = data.get('token', None)
        user = authenticate(token=token)

        if token is None:
            raise serializers.ValidationError(
                'Token is required to retrieve user data.'
            )

        if self.token != user.token:
            raise serializers.ValidationError(
                'A token provided is not valid or expired. Please get a new token.'
            )
        return {
            'email': user.email,
            'phone': user.phone,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'address': user.address,
            'country': user.country,
            'city': user.city,
            'avatar': user.avatar,
        }

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)

        for (key, value) in validated_data.items():
            setattr(instance, key, value)

        if password is not None:
            instance.set_password(password)

        instance.save()
        return instance


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False)

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

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')