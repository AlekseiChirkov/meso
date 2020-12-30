import datetime
import logging
from django.utils.translation import ugettext as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers
from django.contrib.auth import authenticate
from dateutil.relativedelta import relativedelta

from .models import User


from .backends import get_sms_backend

logger = logging.getLogger(__name__)


class PhoneSerializer(serializers.Serializer):
    phone_number = PhoneNumberField()


class SMSVerificationSerializer(serializers.Serializer):
    phone_number = PhoneNumberField(required=True)
    session_token = serializers.CharField(required=True)
    security_code = serializers.CharField(required=True)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        phone_number = attrs.get("phone_number", None)
        security_code, session_token = (
            attrs.get("security_code", None),
            attrs.get("session_token", None),
        )
        backend = get_sms_backend(phone_number=phone_number)
        verification, token_validatation = backend.validate_security_code(
            security_code=security_code,
            phone_number=phone_number,
            session_token=session_token,
        )

        if verification is None:
            raise serializers.ValidationError(_("Security code is not valid"))
        elif token_validatation == backend.SESSION_TOKEN_INVALID:
            raise serializers.ValidationError(_("Session Token mis-match"))
        elif token_validatation == backend.SECURITY_CODE_EXPIRED:
            raise serializers.ValidationError(_("Security code has expired"))
        elif token_validatation == backend.SECURITY_CODE_VERIFIED:
            raise serializers.ValidationError(_("Security code is already verified"))

        return attrs


class UserSerializer(serializers.ModelSerializer):
    age = serializers.SerializerMethodField()
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True
    )

    class Meta:
        model = User
        fields = [
            'id', 'first_name', 'last_name', 'age', 'username', 'email', 'birthday',
            'gender', 'phone', 'about_me', 'image', 'address', 'zip_code',
            'country', 'city', 'state', 'points', 'avg_rating', 'rating_count',
            'avg_rating_last_ten', 'canceled_posts', 'created_posts', 'password', 'token']
        read_only_fields = ['token', 'password']

    def get_age(self, instance):
        age = relativedelta(datetime.datetime.now(), instance.birthday).years
        return age

    def points_validation(self, instance):
        if instance.points < 20:
            return "You have no points"

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)

        for (key, value) in validated_data.items():
            setattr(instance, key, value)

        if password is not None:
            instance.set_password(password)

        instance.save()
        return instance


class RegistrationSerializer(serializers.ModelSerializer):
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
    token = serializers.CharField(
        max_length=256,
        read_only=True
    )

    class Meta:
        model = User
        fields = [
            'id', 'first_name', 'last_name', 'username', 'email', 'birthday', 'gender', 'phone', 'about_me',
            'image', 'address', 'zip_code', 'country', 'city', 'state', 'password', 'password2', 'token',
        ]
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        account = User(
            first_name=self.validated_data['first_name'],
            last_name=self.validated_data['last_name'],
            username=self.validated_data['username'],
            email=self.validated_data['email'],
            birthday=self.validated_data['birthday'],
            gender=self.validated_data['gender'],
            phone=self.validated_data['phone'],
            address=self.validated_data['address'],
            zip_code=self.validated_data['zip_code'],
            country=self.validated_data['country'],
            city=self.validated_data['city'],
            state=self.validated_data['state'],
            about_me=self.validated_data['about_me'],
            image=self.validated_data['image']
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


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=256)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=256, read_only=True)

    def validate(self, data):
        email = data.get('email', None)
        password = data.get('password', None)

        if email is None:
            raise serializers.ValidationError(
                'An email address is required to log in.'
            )

        if password is None:
            raise serializers.ValidationError(
                'A password is required to log in.'
            )
        user = authenticate(username=email, password=password)

        if user is None:
            raise serializers.ValidationError(
                'A user with this email and password was not found or has been banned.'
            )

        return user


class RatingSerializer(serializers.ModelSerializer):
    requester = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = Rating
        fields = '__all__'


class RatingReadableSerializer(serializers.ModelSerializer):
    requester = UserSerializer()
    provider = UserSerializer()

    class Meta:
        model = Rating
        fields = '__all__'
