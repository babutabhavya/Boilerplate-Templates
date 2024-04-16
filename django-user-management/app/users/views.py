from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.utils import timezone
from faker import Faker
from rest_framework import status, views, viewsets
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.views import TokenRefreshView
from users.base_views import BaseAuthView
from utils.authentication import generate_otp_request, validate_otp
from utils.exception_handling import api_exception_handling
from utils.exceptions import BadRequestException
from django.contrib.auth.admin import Group

from .models import (
    AuthTransaction,
    BannerImage,
    ProfileImage,
    SelectedBannerImage,
    SelectedProfileImage,
)
from .serializers import *
from .variables import EMAIL, MOBILE


class LoginPasswordView(BaseAuthView):  # pylint:disable=R0903
    permission_classes = (AllowAny,)
    serializer_class = CustomTokenObtainPairSerializer

    @api_exception_handling
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.check_user_exists(request.data.get("email"))
        return Response(
            self.login_user(serializer.user, request), status=status.HTTP_200_OK
        )


class LoginOTPView(BaseAuthView):
    permission_classes = (AllowAny,)
    serializer_class = OTPLoginSerializer

    @api_exception_handling
    def post(self, request):
        print(request.data)
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data.get("otp", None)
        destination = serializer.validated_data.get("destination")
        user = serializer.validated_data.get("user")

        if otp and validate_otp(destination, otp):
            print("OTP is validated")
            self.delete_otp(otp)
            return Response(
                data=self.login_user(user, self.request),
                status=status.HTTP_200_OK,
            )


class OTPView(BaseAuthView):  # pylint:disable=R0903
    """API To Send OTP to a destination [Mobile/Email]"""

    permission_classes = (AllowAny,)
    serializer_class = OTPSerializer

    @api_exception_handling
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        destination = serializer.validated_data.get("destination")
        prop = serializer.validated_data.get("prop")

        otp_obj = generate_otp_request(prop, destination)
        return self.send_otp(destination, otp_obj)


class UserRegistrationView(BaseAuthView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def generate_random_username(self):
        fake = Faker()
        return fake.user_name()

    def attach_user_to_group(self, user, role_name):
        try:
            users_group = Group.objects.get(name=role_name)
            user.groups.add(users_group)
        except Group.DoesNotExist as error:
            user.delete()
            raise BadRequestException("Invalid user role in request") from error

    def create_user(self, serializer):
        mobile = serializer.validated_data.get("mobile")
        email = serializer.validated_data.get("email")
        password = serializer.validated_data.get("password")
        role = serializer.validated_data.get("role")
        username = self.generate_random_username()
        user = get_user_model().objects.create(
            mobile=mobile,
            email=email,
            password=password,
            username=username,
        )
        self.attach_user_to_group(user, role)
        user.set_password(password)
        user.is_active = True
        return user

    @api_exception_handling
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = self.create_user(serializer)
        user.save()

        return Response(
            {"detail": "User created successfully."}, status=status.HTTP_201_CREATED
        )


class OTPValidationView(BaseAuthView):
    serializer_class = OTPValidationSerializer

    def update_user_mobile_verification(self, user, mobile_verified=True):
        user.is_mobile_verified = mobile_verified
        user.save()

    def update_user_email_verification(self, user, email_verified=True):
        user.is_email_verified = email_verified
        user.save()

    def update_user_secondary_mobile_verification(
        self, user, secondary_mobile_verified=True
    ):
        user.is_secondary_mobile_verified = secondary_mobile_verified
        user.save()

    def update_user_secondary_email_verification(
        self, user, secondary_email_verified=True
    ):
        user.is_secondary_email_verified = secondary_email_verified
        user.save()

    def validate_otp_combinations(
        self,
        user,
        otp,
        email=None,
        mobile=None,
        secondary_mobile=None,
        secondary_email=None,
    ):
        if email:
            if not validate_otp(email, otp):
                raise serializers.ValidationError("Invalid OTP for email.")
            if user:
                self.update_user_email_verification(user)
        if mobile:
            if not validate_otp(mobile, otp):
                raise serializers.ValidationError("Invalid OTP for mobile.")
            if user:
                self.update_user_mobile_verification(user)
        if secondary_mobile:
            if not validate_otp(secondary_mobile, otp):
                raise serializers.ValidationError("Invalid OTP for secondary mobile.")
            if user:
                self.update_user_secondary_mobile_verification(user)
        if secondary_email:
            if not validate_otp(secondary_email, otp):
                raise serializers.ValidationError(_("Invalid OTP for secondary email."))
            if user:
                self.update_user_secondary_email_verification(user)
        return user

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        self.validate_otp_combinations(
            serializer.validated_data.get("db_user") or request.user,
            serializer.validated_data.get("otp"),
            email=serializer.validated_data.get("email"),
            mobile=serializer.validated_data.get("mobile"),
            secondary_mobile=serializer.validated_data.get("secondary_mobile"),
            secondary_email=serializer.validated_data.get("secondary_email"),
        )

        return Response(
            {"detail": "OTP verification successful."}, status=status.HTTP_200_OK
        )


class CustomTokenRefreshView(TokenRefreshView):
    @api_exception_handling
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as error:
            raise InvalidToken(error.args[0])

        token = serializer.validated_data.get("access")

        auth_transaction = AuthTransaction.objects.get(
            refresh_token=request.data["refresh"]
        )
        auth_transaction.token = token
        auth_transaction.expires_at = (
            timezone.now() + api_settings.ACCESS_TOKEN_LIFETIME
        )
        auth_transaction.save(update_fields=["token", "expires_at"])

        return Response({"token": str(token)}, status=status.HTTP_200_OK)


class PasswordResetView(BaseAuthView):  # pylint:disable=R0903
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordResetSerializer

    @api_exception_handling
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        serializer.is_valid(raise_exception=True)
        user = get_object_or_404(get_user_model(), id=request.user.id)

        current_password = serializer.validated_data.get("current_password")
        new_password = serializer.validated_data.get("new_password")

        if user.check_password(current_password):
            user.set_password(new_password)
            user.save()
            return Response(
                {"message": "Your password has been updated successfully"},
                status=status.HTTP_200_OK,
            )
        raise BadRequestException("Current user password is incorrect")


class CustomerProfileView(BaseAuthView):  # pylint:disable=R0903
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    @api_exception_handling
    def get(self, request):
        """Fetches user from request"""
        user = get_object_or_404(get_user_model(), id=request.user.id)
        serializer = self.serializer_class(user)

        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateContactInfoInit(BaseAuthView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ContactInfoUpdateInitSerializer

    @api_exception_handling
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get("email")
        mobile = serializer.validated_data.get("mobile")

        if not email and not mobile:
            raise BadRequestException("Either email or mobile must be provided")

        if email:
            otp_obj = generate_otp_request(EMAIL, email)
            return self.send_otp(email, otp_obj)
        else:
            otp_obj = generate_otp_request(MOBILE, mobile)
            return self.send_otp(mobile, otp_obj)


class UpdateContactInfoConfirm(BaseAuthView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ContactInfoUpdateConfirmSerializer

    def update_user_fields(self, user_id, email=None, mobile=None):
        user = get_object_or_404(get_user_model(), id=user_id)
        if email:
            user.email = email
        if mobile:
            user.mobile = mobile
        user.save()

    @api_exception_handling
    def put(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get("email")
        mobile = serializer.validated_data.get("mobile")
        otp = serializer.validated_data["otp"]

        if not email and not mobile:
            raise BadRequestException("Either email or mobile must be provided")

        if email and mobile:
            raise BadRequestException("Only email or mobile can be updated, not both")

        if validate_otp(email or mobile, otp):
            self.update_user_fields(request.user.id, email=email, mobile=mobile)
            return Response(
                {"message": "Contact information updated successfully"},
                status=status.HTTP_200_OK,
            )
        return BadRequestException(
            "OTP failed validation while updating contact information"
        )


class UserProfileUpdateAPIView(views.APIView):
    permission_classes = (IsAuthenticated,)

    def patch(self, request):
        user = request.user

        serializer = UserSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user


class ProfileImageBannerImageBaseViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOwner]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user, image_type=ProfileImage.UPLOADED)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.check_object_permissions(request, instance)
        self.perform_destroy(instance)
        return Response(status=204)

    def list(self, request, *args, **kwargs):
        return Response(status=405)

    def retrieve(self, request, *args, **kwargs):
        return Response(status=405)

    def update(self, request, *args, **kwargs):
        return Response(status=405)

    def partial_update(self, request, *args, **kwargs):
        return Response(status=405)


class ProfileImageViewSet(ProfileImageBannerImageBaseViewSet):
    queryset = ProfileImage.objects.all()
    serializer_class = ProfileImageSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user, image_type=ProfileImage.UPLOADED)


class ProfileBannerImageViewSet(ProfileImageBannerImageBaseViewSet):
    queryset = BannerImage.objects.all()
    serializer_class = BannerImageSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user, image_type=BannerImage.UPLOADED)


class ChangeSelectedProfileImagBannerBaseView(views.APIView):
    def put(self, request, pk):
        user = request.user
        try:
            image = self.images_model.objects.get(pk=pk)
        except self.images_model.DoesNotExist:
            return Response(
                {"error": "Invalid profile image."}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            selected_image = self.model.objects.get(user=user)
            selected_image.image = image
        except self.model.DoesNotExist:
            selected_image = self.model.objects.create(user=user, image=image)

        selected_image.save()

        serializer = self.serializer_class(selected_image)
        return Response(serializer.data)


class ChangeSelectedProfileImageView(ChangeSelectedProfileImagBannerBaseView):
    model = SelectedProfileImage
    images_model = ProfileImage
    serializer_class = SelectedProfileImageSerializer


class ChangeSelectedProfileBannerImageView(ChangeSelectedProfileImagBannerBaseView):
    model = SelectedBannerImage
    images_model = BannerImage
    serializer_class = SelectedProfileBannerImageSerializer
