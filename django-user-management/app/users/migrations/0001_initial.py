# Generated by Django 5.0.4 on 2024-04-16 11:22

import django.db.models.deletion
import django_extensions.db.fields
import users.managers
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="OTPValidation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("otp", models.CharField(max_length=10, verbose_name="OTP Code")),
                (
                    "destination",
                    models.CharField(
                        max_length=254,
                        unique=True,
                        verbose_name="Destination Address (Mobile/EMail)",
                    ),
                ),
                (
                    "create_date",
                    models.DateTimeField(auto_now_add=True, verbose_name="Create Date"),
                ),
                (
                    "update_date",
                    models.DateTimeField(auto_now=True, verbose_name="Date Modified"),
                ),
                (
                    "is_validated",
                    models.BooleanField(default=False, verbose_name="Is Validated"),
                ),
                (
                    "validate_attempt",
                    models.IntegerField(
                        default=10, verbose_name="Attempted Validation"
                    ),
                ),
                (
                    "prop",
                    models.CharField(
                        choices=[("E", "Email Address")],
                        default="E",
                        max_length=3,
                        verbose_name="Destination Property",
                    ),
                ),
                (
                    "send_counter",
                    models.IntegerField(default=0, verbose_name="OTP Sent Counter"),
                ),
                (
                    "sms_id",
                    models.CharField(
                        blank=True, max_length=254, null=True, verbose_name="SMS ID"
                    ),
                ),
                (
                    "reactive_at",
                    models.DateTimeField(verbose_name="ReActivate Sending OTP"),
                ),
            ],
            options={
                "verbose_name": "OTP Validation",
                "verbose_name_plural": "OTP Validations",
            },
        ),
        migrations.CreateModel(
            name="User",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "is_superuser",
                    models.BooleanField(
                        default=False,
                        help_text="Designates that this user has all permissions without explicitly assigning them.",
                        verbose_name="superuser status",
                    ),
                ),
                (
                    "slug",
                    django_extensions.db.fields.AutoSlugField(
                        blank=True,
                        editable=False,
                        overwrite=True,
                        populate_from=["name", "id"],
                        unique=True,
                        verbose_name="Slug",
                    ),
                ),
                (
                    "username",
                    models.CharField(
                        max_length=150, unique=True, verbose_name="Username"
                    ),
                ),
                (
                    "email",
                    models.EmailField(
                        max_length=254, unique=True, verbose_name="Email Address"
                    ),
                ),
                (
                    "mobile",
                    models.CharField(
                        max_length=15, unique=True, verbose_name="Mobile Number"
                    ),
                ),
                ("is_email_verified", models.BooleanField(default=False)),
                ("is_mobile_verified", models.BooleanField(default=False)),
                (
                    "secondary_email",
                    models.EmailField(
                        blank=True,
                        max_length=254,
                        null=True,
                        unique=True,
                        verbose_name="Secondary Email Address",
                    ),
                ),
                (
                    "secondary_mobile",
                    models.CharField(
                        blank=True,
                        max_length=15,
                        null=True,
                        unique=True,
                        verbose_name="Seconday Mobile Number",
                    ),
                ),
                ("is_secondary_email_verified", models.BooleanField(default=False)),
                ("is_secondary_mobile_verified", models.BooleanField(default=False)),
                ("profile_image", models.ImageField(upload_to="user/profile-images/")),
                (
                    "name",
                    models.CharField(
                        blank=True, max_length=500, null=True, verbose_name="Full Name"
                    ),
                ),
                (
                    "date_joined",
                    models.DateTimeField(auto_now_add=True, verbose_name="Date Joined"),
                ),
                (
                    "update_date",
                    models.DateTimeField(auto_now=True, verbose_name="Date Modified"),
                ),
                (
                    "is_active",
                    models.BooleanField(default=False, verbose_name="Activated"),
                ),
                (
                    "is_staff",
                    models.BooleanField(default=False, verbose_name="Staff Status"),
                ),
                (
                    "last_active",
                    models.DateTimeField(
                        auto_now_add=True, verbose_name="Last Active Date"
                    ),
                ),
                ("ml_verified", models.BooleanField(default=False)),
                ("promoted", models.BooleanField(default=False)),
                ("rating", models.IntegerField(default=0)),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
                        related_name="user_set",
                        related_query_name="Users",
                        to="auth.group",
                        verbose_name="Groups",
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        help_text="Specific permissions for this user.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.permission",
                        verbose_name="user permissions",
                    ),
                ),
            ],
            options={
                "verbose_name": "Users",
                "verbose_name_plural": "Users",
            },
            managers=[
                ("objects", users.managers.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name="AuthTransaction",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("ip_address", models.GenericIPAddressField()),
                ("token", models.TextField(verbose_name="JWT Access Token")),
                ("session", models.TextField(verbose_name="Session Passed")),
                (
                    "refresh_token",
                    models.TextField(blank=True, verbose_name="JWT Refresh Token"),
                ),
                (
                    "expires_at",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="Expires At"
                    ),
                ),
                (
                    "create_date",
                    models.DateTimeField(
                        auto_now_add=True, verbose_name="Create Date/Time"
                    ),
                ),
                (
                    "update_date",
                    models.DateTimeField(
                        auto_now=True, verbose_name="Date/Time Modified"
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Authentication Transaction",
                "verbose_name_plural": "Authentication Transactions",
            },
        ),
        migrations.CreateModel(
            name="ProfileImage",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "image_type",
                    models.CharField(
                        choices=[("default", "Default"), ("uploaded", "Uploaded")],
                        default="uploaded",
                        max_length=10,
                    ),
                ),
                (
                    "image",
                    models.ImageField(
                        upload_to="profile_images", verbose_name="Profile Image"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
