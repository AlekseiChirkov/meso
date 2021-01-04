import pyotp

from decouple import config
from twilio.rest import Client
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

from .serializers import PhoneNumberSerializer
from .models import PhoneNumber


account_sid = config('TWILIO_ACCOUNT_SID')
auth_token = config('TWILIO_AUTH_TOKEN')
twilio_phone = config('TWILIO_PHONE')
client = Client(account_sid, auth_token)


class PhoneViewSet(viewsets.ModelViewSet):
    queryset = PhoneNumber.objects.all()
    serializer_class = PhoneNumberSerializer
    permission_classes = (IsAuthenticated, )

    def perform_create(self, serializer):
        serializer.save()


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def send_sms_code(request, format=None):
    time_otp = pyotp.TOTP(request.user.key, interval=300)
    time_otp = time_otp.now()
    user_phone_number = request.user.phonenumber.number
    client.messages.create(
        body='Your verification code is ' + time_otp,
        from_=twilio_phone,
        to=user_phone_number
    )
    return Response(status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_phone(request, sms_code, format=None):
    code = int(sms_code)
    if request.user.authenticate(code):
        phone = request.user.phonenumber
        phone.verified = True
        phone.save()
        return Response(dict(detail="Phone number verified successfully"), status=status.HTTP_201_CREATED)
    return Response(dict(detail='The provided code did not match or has expired'), status=status.HTTP_200_OK)
