import datetime
import re
from typing import Dict, Optional, Union

import pytz
from django.http import HttpRequest
from django.utils import timezone
from django.utils.text import gettext_lazy as _
from rest_framework.exceptions import NotFound
from users.models import OTPValidation, User
from users.utils import update_user_settings
from utils.exceptions import NotFoundException
from utils.notifications import sms_client

user_settings: Dict[str, Union[bool, Dict[str, Union[int, str, bool]]]] = (
    update_user_settings()
)
otp_settings: Dict[str, Union[str, int]] = user_settings["OTP"]


def datetime_passed_now(source: datetime.datetime) -> bool:
    if source.tzinfo is not None and source.tzinfo.utcoffset(source) is not None:
        return source <= datetime.datetime.utcnow().replace(tzinfo=pytz.utc)

    return source <= datetime.datetime.now()


def get_client_ip(request: HttpRequest) -> Optional[str]:
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")


def generate_otp_request(prop, destination):
    # Get or Create new instance of Model with value of provided value
    # and set proper counter.
    try:
        otp_object: OTPValidation = OTPValidation.objects.get(destination=destination)
    except OTPValidation.DoesNotExist:
        print("Creating new OTP validation", destination)
        otp_object: OTPValidation = OTPValidation()
        otp_object.destination = destination
    # else:
    #     if (
    #         not datetime_passed_now(otp_object.reactive_at)
    #         and not otp_object.is_validated
    #     ):
    #         raise BadRequestException(
    #             _(
    #                 f"Please request for an OTP after {round((otp_object.reactive_at-timezone.now()).total_seconds())} seconds"
    #             )
    #         )

    otp = generate_otp(destination)

    otp_object.otp = otp
    otp_object.prop = prop

    # Set is_validated to False
    otp_object.is_validated = False

    # Set attempt counter to OTP_VALIDATION_ATTEMPTS, user has to enter
    # correct OTP in 3 chances.
    otp_object.validate_attempt = otp_settings["VALIDATION_ATTEMPTS"]

    otp_object.reactive_at = timezone.now() - datetime.timedelta(seconds=1)
    otp_object.save()
    return otp_object


def generate_otp(destination: str) -> OTPValidation:
    print("Generating OTP", destination)
    # Create a random number
    random_number: str = User.objects.make_random_password(
        length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
    )
    print("Random number generated", random_number)

    # Checks if random number is unique among non-validated OTPs and
    # creates new until it is unique.
    while OTPValidation.objects.filter(otp__exact=random_number).filter(
        is_validated=False
    ):
        random_number: str = User.objects.make_random_password(
            length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
        )
        print("Re-generated random number", random_number)

    return random_number


def send_otp(value: str, otp: OTPValidation) -> Dict:
    print("Sending OTP", value, otp)
    if value.isdigit():
        try:
            sms_client.send(value, f"Your OTP for MaterialLibrary is {otp.otp}")
        except ValueError as error:
            raise Exception(_(f"Server configuration error occurred: {error}"))
    elif re.match(r"[^@]+@[^@]+\.[^@]+", value):
        print("Sending OTP", value, otp)
        # TO Send OTP email using email_client

    otp.reactive_at = timezone.now() + datetime.timedelta(
        minutes=otp_settings["COOLING_PERIOD"]
    )

    otp.save()
    return True


def validate_otp(destination: str, otp: int) -> bool:
    try:
        print("Validating OTP sent", otp, destination)
        # Try to get OTP Object from Model and initialize data dictionary
        otp_object: OTPValidation = OTPValidation.objects.get(
            destination=destination, is_validated=False
        )
    except OTPValidation.DoesNotExist:
        raise NotFoundException(
            _(
                f"No pending OTP validation request found for provided {destination}. Kindly send an OTP first"
            )
        )
    # Decrement validate_attempt
    otp_object.validate_attempt -= 1

    if str(otp_object.otp) == str(otp):
        # match otp
        print("Matching OTP", otp_object.otp, otp)
        otp_object.is_validated = True
        otp_object.save()
        return True

        # if otp_object.validate_attempt <= 0:
        #     # check if attempts exceeded and regenerate otp and raise error
        #     otp_obj = generate_otp(destination)
        #     send_otp(destination, otp_obj)

        # raise AuthenticationFailed(detail=_("Incorrect OTP. A new OTP has been sent."))

    # update attempts and raise error
    otp_object.save()
    raise NotFound(detail=_("OTP Validation failed!"))
