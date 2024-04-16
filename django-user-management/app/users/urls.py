from django.urls import include, path
from rest_framework.routers import DefaultRouter
from users import views

app_name = "users"

router = DefaultRouter()
router.register(r"profile-images", views.ProfileImageViewSet)
router.register(r"banner-images", views.ProfileBannerImageViewSet)

urlpatterns = [
    path("login/password/", views.LoginPasswordView.as_view(), name="login"),
    path(
        "login/otp/",
        views.LoginOTPView.as_view(),
        name="otp-login",
    ),
    path("otp/", views.OTPView.as_view(), name="send-otp"),
    path("otp/validate/", views.OTPValidationView.as_view(), name="validate-otp"),
    path(
        "signup/",
        views.UserRegistrationView.as_view(),
        name="user-signup",
    ),
    path(
        "refresh-token/", views.CustomTokenRefreshView.as_view(), name="refresh_token"
    ),
    path("password/reset/", views.PasswordResetView.as_view(), name="Password Reset"),
    path("info/", views.CustomerProfileView.as_view(), name="Customer Profile"),
    path(
        "profile/", views.UserProfileUpdateAPIView.as_view(), name="user-profile-update"
    ),
    path(
        "profile-image/<int:pk>/",
        views.ChangeSelectedProfileImageView.as_view(),
        name="change_selected_image",
    ),
    path(
        "banner-image/<int:pk>/",
        views.ChangeSelectedProfileBannerImageView.as_view(),
        name="change_selected_banner_image",
    ),
    path("", include(router.urls)),
]
