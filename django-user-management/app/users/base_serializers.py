from django.core.validators import EmailValidator, ValidationError
from rest_framework import serializers
from utils.exceptions import NotFoundException

from .models import User
from .variables import EMAIL, MOBILE


class BaseAuthSerializer(serializers.Serializer):
    @staticmethod
    def get_user(**kwargs) -> User:
        raise_exception = False
        if "raise_exception" in kwargs:
            raise_exception = kwargs.get("raise_exception", False)
            del kwargs["raise_exception"]
        try:
            return User.objects.get(**kwargs)
        except User.DoesNotExist:
            if raise_exception:
                raise NotFoundException("User does not exists")
            return None

    def get_destination_prop(self, attrs: dict):
        validator = EmailValidator()
        try:
            validator(attrs["destination"])
            return EMAIL
        except ValidationError:
            return MOBILE


class ContactInfoBaseSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    mobile = serializers.CharField(required=False)

    def validate(self, attrs: dict) -> dict:
        """Validates the response"""
        if not any(attrs.values()):
            raise serializers.ValidationError("Either email or mobile must be provided")

        return attrs
