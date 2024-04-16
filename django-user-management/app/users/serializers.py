# pylint: disable=W0223
import re

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.text import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .base_serializers import BaseAuthSerializer, ContactInfoBaseSerializer
from .models import BannerImage, ProfileImage, SelectedBannerImage, SelectedProfileImage
from .utils import user_settings


class UserSerializer(serializers.ModelSerializer):
    profile_images = serializers.SerializerMethodField()
    banner_images = serializers.SerializerMethodField()

    def validate_email(self, value: str) -> str:
        """
        Custom validation for email field.
        Check if the email is unique across email and secondary email.
        """

        if get_user_model().objects.filter(email=value).exists():
            raise serializers.ValidationError("Email address is already in use.")

        if get_user_model().objects.filter(secondary_email=value).exists():
            raise serializers.ValidationError(
                "Email address is already in use as a secondary email."
            )

        return value

    def validate_secondary_email(self, value: str) -> str:
        """
        Custom validation for secondary email field.
        Check if the secondary email is unique across email and secondary email.
        """

        if get_user_model().objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "Secondary email address is already in use as a primary email."
            )

        if get_user_model().objects.filter(secondary_email=value).exists():
            raise serializers.ValidationError(
                "Secondary email address is already in use as a secondary email."
            )

        return value

    def validate_mobile(self, value: str) -> str:
        """
        Custom validation for mobile field.
        Check if the mobile number is unique across mobile and secondary mobile.
        """

        if get_user_model().objects.filter(mobile=value).exists():
            raise serializers.ValidationError("Mobile number is already in use.")

        if get_user_model().objects.filter(secondary_mobile=value).exists():
            raise serializers.ValidationError(
                "Mobile number is already in use as a secondary mobile number."
            )

        return value

    def validate_secondary_mobile(self, value: str) -> str:
        """
        Custom validation for secondary mobile field.
        Check if the secondary mobile number is unique across mobile and secondary mobile.
        """

        if get_user_model().objects.filter(mobile=value).exists():
            raise serializers.ValidationError(
                "Secondary mobile number is already in use as a primary mobile number."
            )

        if get_user_model().objects.filter(secondary_mobile=value).exists():
            raise serializers.ValidationError(
                "Secondary mobile number is already in use as a secondary mobile number."
            )

        return value

    def validate_email(self, value: str) -> str:
        if not user_settings["EMAIL_VALIDATION"]:
            return value
        return value

    def validate_mobile(self, value: str) -> str:
        if not user_settings["MOBILE_VALIDATION"]:
            return value
        return value

    def validate_password(self, value: str) -> str:
        validate_password(value)
        return value

    def get_profile_image_banner_image(self, obj, images_model, selected_image_model):
        user_uploaded_images = images_model.objects.filter(user=obj)
        default_images = images_model.objects.filter(user=None)
        images = user_uploaded_images.union(default_images)

        selected_images = selected_image_model.objects.filter(user=obj).values_list(
            "image_id", flat=True
        )

        profile_images = []
        for image in images:
            profile_image = {
                "id": image.id,
                "image": image.image.url,
                "image_type": image.image_type,
                "is_selected": image.id in selected_images,
                "is_solid": image.is_solid if images_model == BannerImage else False,
            }
            profile_images.append(profile_image)

        return profile_images

    def get_profile_images(self, obj):
        return self.get_profile_image_banner_image(
            obj, ProfileImage, SelectedProfileImage
        )

    def get_banner_images(self, obj):
        return self.get_profile_image_banner_image(
            obj, BannerImage, SelectedBannerImage
        )

    class Meta:
        model = get_user_model()
        fields = (
            "id",
            "name",
            "email",
            "mobile",
            "password",
            "is_email_verified",
            "is_mobile_verified",
            "secondary_email",
            "secondary_mobile",
            "is_secondary_email_verified",
            "is_secondary_mobile_verified",
            "last_active",
            "last_login",
            "slug",
            "banner_images",
            "profile_images",
        )
        read_only_fields = ("is_superuser", "is_staff")
        extra_kwargs = {"password": {"write_only": True}}


class OTPLoginSerializer(BaseAuthSerializer):
    otp = serializers.CharField(
        default=None,
        required=False,
        max_length=6,
        min_length=6,
    )
    destination = serializers.CharField(required=False)

    def validate(self, attrs: dict) -> dict:
        """Validates the response"""
        user = None
        try:
            user = get_user_model().objects.get(mobile=attrs.get("destination"))
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError("User not found")
        attrs["user"] = user
        return attrs


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    default_error_messages = {"no_active_account": _("Invalid credentials.")}

    @classmethod
    def get_token(cls, user):
        """Generate token, then add extra data to the token."""
        token = super().get_token(user)

        # Add custom claims
        if hasattr(user, "email"):
            token["email"] = user.email

        if hasattr(user, "mobile"):
            token["mobile"] = user.mobile

        if hasattr(user, "name"):
            token["name"] = user.name

        return token


class OTPSerializer(BaseAuthSerializer):
    destination = serializers.CharField(required=True)
    check_user = serializers.BooleanField(default=False, required=False)

    def validate(self, attrs: dict) -> dict:
        attrs["prop"] = self.get_destination_prop(attrs)
        destination = attrs["destination"]
        if attrs["check_user"] is True:
            if attrs["prop"] == "E":
                try:
                    self.get_user(email=destination, raise_exception=True)
                except:
                    self.get_user(secondary_email=destination, raise_exception=True)
            else:
                try:
                    self.get_user(mobile=destination, raise_exception=True)
                except:
                    self.get_user(secondary_mobile=destination, raise_exception=True)
        return attrs


class RegisterSerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=20)
    email = serializers.EmailField()
    password = serializers.CharField(max_length=128, write_only=True)
    role = serializers.CharField(required=True)

    @staticmethod
    def get_user_auth_combination(email: str, mobile: str):
        """Fetches user object"""
        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            try:
                user = get_user_model().objects.get(mobile=mobile)
            except get_user_model().DoesNotExist:
                user = None

        if user:
            if user.email != email:
                raise serializers.ValidationError(
                    _(
                        f"Your account is registered with {user.mobile} and does not have {email} as the registered email. Please login directly via OTP with your mobile."
                    )
                )
            if mobile and user.mobile != mobile:
                raise serializers.ValidationError(
                    _(
                        f"Your account is registered with {user.email} and does not have {mobile} as the registered mobile. Please login directly via OTP with your email."
                    )
                )
        return user

    def validate_mobile(self, mobile):
        # Add your mobile validation logic here
        return mobile

    def validate(self, attrs):
        email = attrs.get("email")
        mobile = attrs.get("mobile")
        user = self.get_user_auth_combination(email, mobile)
        if user:
            raise serializers.ValidationError(
                "User with this email or mobile already exists."
            )
        return attrs


class OTPValidationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    mobile = serializers.CharField(max_length=20, required=False)
    secondary_mobile = serializers.CharField(max_length=20, required=False)
    secondary_email = serializers.EmailField(required=False)
    otp = serializers.CharField(max_length=6)
    check_user = serializers.BooleanField(default=False)  # New parameter

    def validate_email(self, email):
        # Check if the email is a valid email address
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise serializers.ValidationError("Invalid email address.")
        return email

    def validate_mobile(self, mobile):
        # Check if the mobile number is a valid Indian phone number
        if not re.match(r"^(?:\+91|0)?[6-9]\d{9}$", mobile):
            raise serializers.ValidationError("Invalid mobile number.")
        return mobile

    def validate_secondary_mobile(self, secondary_mobile):
        # Check if the secondary mobile number is a valid Indian phone number
        if not re.match(r"^(?:\+91|0)?[6-9]\d{9}$", secondary_mobile):
            raise serializers.ValidationError("Invalid secondary mobile number.")
        return secondary_mobile

    def validate_secondary_email(self, secondary_email):
        # Check if the secondary email is a valid email address
        if not re.match(r"[^@]+@[^@]+\.[^@]+", secondary_email):
            raise serializers.ValidationError("Invalid secondary email address.")
        return secondary_email

    def validate(self, attrs):
        email = attrs.get("email")
        mobile = attrs.get("mobile")
        secondary_mobile = attrs.get("secondary_mobile")
        secondary_email = attrs.get("secondary_email")
        otp = attrs.get("otp")
        request = self.context.get("request")
        check_user = attrs.get("check_user", False)

        if not email and not mobile and not secondary_mobile and not secondary_email:
            raise serializers.ValidationError(
                "At least one field (email, mobile, secondary_mobile, secondary_email) is required."
            )

        if not otp:
            raise serializers.ValidationError(_("OTP is required."))

        user = (
            request.user
            if hasattr(request, "user") and request.user.is_authenticated
            else None
        )

        if check_user:
            query = {}
            if email:
                query = {"email": email}
            elif secondary_email:
                query = {"secondary_email": secondary_email}
            elif secondary_mobile:
                query = {"secondary_mobile": secondary_mobile}
            elif mobile:
                query = {"mobile": mobile}
            db_user = get_user_model().objects.filter(**query).first()

            if not db_user:
                raise serializers.ValidationError(_("User does not exist."))
            else:
                attrs["db_user"] = db_user

        if user:
            if email:
                if email != user.email:
                    raise serializers.ValidationError(
                        _("Email does not match the user's email.")
                    )
            if mobile:
                if mobile != user.mobile:
                    raise serializers.ValidationError(
                        _("Mobile does not match the user's mobile.")
                    )

            if secondary_mobile:
                if secondary_mobile != user.secondary_mobile:
                    raise serializers.ValidationError(
                        _(
                            "Secondary mobile does not match the user's secondary mobile."
                        )
                    )

            if secondary_email:
                if secondary_email != user.secondary_email:
                    raise serializers.ValidationError(
                        _("Secondary email does not match the user's secondary email.")
                    )

        return attrs


class PasswordResetSerializer(BaseAuthSerializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ContactInfoUpdateInitSerializer(ContactInfoBaseSerializer):
    pass


class ContactInfoUpdateConfirmSerializer(ContactInfoBaseSerializer):
    otp = serializers.CharField(required=True, max_length=6, min_length=6)

    def validate(self, attrs: dict) -> dict:
        """Validates the response"""
        attrs = super().validate(attrs)

        if len([attr for attr in attrs.values() if attr]) > 1:
            raise serializers.ValidationError(
                "Only email or mobile can be updated, not both"
            )

        return attrs


class ProfileImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfileImage
        fields = ("id", "image", "image_type", "user")


class BannerImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = BannerImage
        fields = ("id", "image", "image_type", "user")


class SelectedProfileImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SelectedProfileImage
        fields = ["id", "image"]

    image = serializers.PrimaryKeyRelatedField(queryset=ProfileImage.objects.all())


class SelectedProfileBannerImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SelectedBannerImage
        fields = ["id", "image"]

    image = serializers.PrimaryKeyRelatedField(queryset=BannerImage.objects.all())
