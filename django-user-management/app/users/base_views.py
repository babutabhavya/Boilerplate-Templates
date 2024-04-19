import re
from typing import Dict

from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.utils import datetime_from_epoch
from utils.authentication import get_client_ip, send_otp
from utils.exceptions import BadRequestException

from .models import AuthTransaction, OTPValidation
from .serializers import UserSerializer


class BaseAuthView(APIView):
    def check_user_exists(self, username):
        if username.isdigit():
            if not (
                get_user_model()
                .objects.filter(mobile=username, is_staff=False)
                .exists()
            ):
                raise BadRequestException("Customer not registered with mobile number")

        elif re.match(r"[^@]+@[^@]+\.[^@]+", username):
            if not (
                get_user_model().objects.filter(email=username, is_staff=False).exists()
            ):
                raise BadRequestException("Customer not registered with email")

    def login_user(self, user, request: HttpRequest) -> Dict[str, str]:
        token: RefreshToken = RefreshToken.for_user(user)

        if hasattr(user, "email"):
            token["email"] = user.email

        if hasattr(user, "mobile"):
            token["mobile"] = user.mobile

        if hasattr(user, "name"):
            token["name"] = user.name

        user.last_login = timezone.now()
        user.save()

        AuthTransaction(
            created_by=user,
            ip_address=get_client_ip(request),
            token=str(token.access_token),
            refresh_token=str(token),
            session=user.get_session_auth_hash(),
            expires_at=datetime_from_epoch(token["exp"]),
        ).save()

        return {
            "refresh_token": str(token),
            "token": str(token.access_token),
            "session": user.get_session_auth_hash(),
            "user": UserSerializer(user).data,
        }

    def send_otp(self, destination, otp_obj):
        sent_otp_result = send_otp(destination, otp_obj)
        if sent_otp_result:
            otp_obj.send_counter += 1
            otp_obj.save()
            return Response(
                {"message": f"OTP has been sent successfully to {destination}"},
                status=status.HTTP_201_CREATED,
            )
        raise Exception(f"OTP failed to sent to {destination}")

    def delete_otp(self, otp):
        OTPValidation.objects.filter(otp=otp).delete()
