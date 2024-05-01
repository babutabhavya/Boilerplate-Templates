from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.sites.models import Site
from django.utils.text import gettext_lazy as _

from .models import AuthTransaction, OTPValidation, User


class BaseAuthAdmin:  # pylint: disable=R0903
    list_display = 20


class DRFUserAdmin(UserAdmin, BaseAuthAdmin):
    fieldsets = (
        (None, {"fields": ("password",)}),
        (
            _("Personal info"),
            {
                "fields": ("username", "name", "email", "mobile"),
                "classes": (
                    "order-0",
                    "baton-tabs-init",
                    "baton-tab-fs-verification",
                    "baton-tab-fs-permissions",
                    "baton-tab-fs-importantdates",
                ),
            },
        ),
        (
            _("Verification"),
            {
                "fields": (
                    "is_email_verified",
                    "is_secondary_email_verified",
                    "is_mobile_verified",
                    "is_secondary_mobile_verified",
                ),
                "classes": ("tab-fs-verification",),
                "description": "This is another description text",
            },
        ),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
                "classes": ("tab-fs-permissions",),
                "description": "Permissions related information",
            },
        ),
        (
            _("Important dates"),
            {
                "fields": ("last_login", "date_joined", "update_date", "last_active"),
                "classes": ("tab-fs-importantdates",),
                "description": "Important dates related information",
            },
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "name",
                    "email",
                    "mobile",
                    "is_active",
                    "is_staff",
                    "password1",
                    "password2",
                    "groups",
                ),
            },
        ),
    )
    list_display = ("mobile", "name", "email", "username", "is_staff")
    search_fields = ("name", "email", "mobile")
    readonly_fields = ("date_joined", "last_login", "update_date", "last_active")
    ordering = ("date_joined",)


class AuthTransactionAdmin(admin.ModelAdmin, BaseAuthAdmin):
    list_display = ("created_by", "ip_address", "create_date", "created_by")
    search_fields = ("created_by",)
    ordering = ("-create_date",)


class OTPValidationAdmin(admin.ModelAdmin, BaseAuthAdmin):
    list_display = (
        "destination",
        "otp",
        "prop",
        "create_date",
        "reactive_at",
        "is_validated",
        "validate_attempt",
        "send_counter",
    )
    search_fields = ("destination", "otp")
    ordering = ("-create_date",)


admin.site.unregister(Site)
admin.site.register(User, DRFUserAdmin)
admin.site.register(AuthTransaction, AuthTransactionAdmin)
admin.site.register(OTPValidation, OTPValidationAdmin)

# Admin Site Headers

admin.site.site_title = "User Management Boilder Template"
admin.site.site_header = f"{admin.site.site_title} Admin"
admin.site.index_title = ""
admin.site.site_url = None
