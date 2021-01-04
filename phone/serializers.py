from rest_framework import serializers

from phone.models import PhoneNumber


class PhoneNumberSerializer(serializers.ModelSerializer):

    class Meta:
        model = PhoneNumber
        fields = '__all__'
