from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Group, PermissionsMixin
from django.db import models
from django.forms import ValidationError
from django.utils.text import gettext_lazy as _
from django_extensions.db.fields import AutoSlugField

from .managers import UserManager
from .variables import DESTINATION_CHOICES, EMAIL


class User(AbstractBaseUser, PermissionsMixin):
    slug = AutoSlugField(
        populate_from=["name", "id"], overwrite=True, verbose_name="Slug", unique=True
    )
    username = models.CharField(
        verbose_name=_("Username"),
        max_length=150,
        unique=True,
    )
    email = models.EmailField(verbose_name=_("Email Address"), unique=True)
    mobile = models.CharField(
        verbose_name=_("Mobile Number"),
        max_length=15,
        unique=True,
    )
    is_email_verified = models.BooleanField(default=False)
    is_mobile_verified = models.BooleanField(default=False)
    secondary_email = models.EmailField(
        verbose_name=_("Secondary Email Address"), null=True, blank=True, unique=True
    )
    secondary_mobile = models.CharField(
        verbose_name=_("Seconday Mobile Number"),
        max_length=15,
        null=True,
        blank=True,
        unique=True,
    )
    is_secondary_email_verified = models.BooleanField(default=False)
    is_secondary_mobile_verified = models.BooleanField(default=False)
    profile_image = models.ImageField(
        upload_to="user/profile-images/",
    )

    name = models.CharField(
        verbose_name=_("Full Name"), max_length=500, blank=True, null=True
    )
    date_joined = models.DateTimeField(verbose_name=_("Date Joined"), auto_now_add=True)
    update_date = models.DateTimeField(verbose_name=_("Date Modified"), auto_now=True)
    is_active = models.BooleanField(verbose_name=_("Activated"), default=False)
    is_staff = models.BooleanField(verbose_name=_("Staff Status"), default=False)
    last_active = models.DateTimeField(
        verbose_name=_("Last Active Date"), auto_now_add=True
    )
    groups = models.ManyToManyField(
        Group,
        verbose_name=_("Groups"),
        blank=True,
        help_text=_(
            "The groups this user belongs to. A user will get all permissions "
            "granted to each of their groups."
        ),
        related_name="user_set",
        related_query_name="Users",
    )
    ml_verified = models.BooleanField(default=False)
    promoted = models.BooleanField(default=False)
    rating = models.IntegerField(default=0)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "mobile"]

    class Meta:
        """Passing model metadata"""

        verbose_name = _("Users")
        verbose_name_plural = _("Users")

    def clean(self):
        if len(self.mobile) > 10 or len(self.mobile) < 10:
            raise ValidationError("Phone Number is not valid")

    def get_full_name(self) -> str:
        """Method to return user's full name"""

        return str(self.name)

    def __str__(self):
        """String representation of model"""
        return str(self.name)

    def get_short_name(self, user_instance):
        return f"{user_instance.name}"


class AuthTransaction(models.Model):
    ip_address = models.GenericIPAddressField(blank=False, null=False)
    token = models.TextField(verbose_name=_("JWT Access Token"))
    session = models.TextField(verbose_name=_("Session Passed"))
    refresh_token = models.TextField(
        blank=True,
        verbose_name=_("JWT Refresh Token"),
    )
    expires_at = models.DateTimeField(
        blank=True, null=True, verbose_name=_("Expires At")
    )
    create_date = models.DateTimeField(
        verbose_name=_("Create Date/Time"), auto_now_add=True
    )
    update_date = models.DateTimeField(
        verbose_name=_("Date/Time Modified"), auto_now=True
    )
    created_by = models.ForeignKey(to=User, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.created_by.name)

    class Meta:
        verbose_name = _("Authentication Transaction")
        verbose_name_plural = _("Authentication Transactions")


class OTPValidation(models.Model):
    otp = models.CharField(verbose_name=_("OTP Code"), max_length=10)
    destination = models.CharField(
        verbose_name=_("Destination Address (Mobile/EMail)"),
        max_length=254,
        unique=True,
    )
    create_date = models.DateTimeField(verbose_name=_("Create Date"), auto_now_add=True)
    update_date = models.DateTimeField(verbose_name=_("Date Modified"), auto_now=True)
    is_validated = models.BooleanField(verbose_name=_("Is Validated"), default=False)
    validate_attempt = models.IntegerField(
        verbose_name=_("Attempted Validation"), default=10
    )
    prop = models.CharField(
        verbose_name=_("Destination Property"),
        default=EMAIL,
        max_length=3,
        choices=DESTINATION_CHOICES,
    )
    send_counter = models.IntegerField(verbose_name=_("OTP Sent Counter"), default=0)
    sms_id = models.CharField(
        verbose_name=_("SMS ID"), max_length=254, null=True, blank=True
    )
    reactive_at = models.DateTimeField(verbose_name=_("ReActivate Sending OTP"))

    def __str__(self):
        """String representation of model"""

        return self.destination

    class Meta:
        verbose_name = _("OTP Validation")
        verbose_name_plural = _("OTP Validations")


class ProfileImageAndBannerImageBase(models.Model):
    DEFAULT = "default"
    UPLOADED = "uploaded"

    IMAGE_TYPE_CHOICES = (
        (DEFAULT, "Default"),
        (UPLOADED, "Uploaded"),
    )

    image_type = models.CharField(
        max_length=10, choices=IMAGE_TYPE_CHOICES, default=UPLOADED
    )
    user = models.ForeignKey(
        get_user_model(), null=True, blank=True, on_delete=models.CASCADE
    )

    class Meta:
        abstract = True


class ProfileImage(ProfileImageAndBannerImageBase):
    image = models.ImageField(upload_to="profile_images", verbose_name="Profile Image")

    def __str__(self) -> str:
        return f"{self.user.name}__{self.image}"
