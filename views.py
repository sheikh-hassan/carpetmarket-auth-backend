from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, Group
from django.http import Http404
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings

from .models import User, VendorProfile, CleanerProfile
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail, EmailMultiAlternatives
from rest_framework import generics, permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# from django.core.cache import cache  # Commented out for now
# from ratelimit.decorators import ratelimit  # Commented out for now
from datetime import datetime, timedelta
from django.utils import timezone
from rest_framework.decorators import action
from django.urls import reverse
from rest_framework.permissions import DjangoModelPermissions
from django.core.cache import cache  # NEW: use cache for token tracking
from rest_framework_simplejwt.authentication import JWTAuthentication

from .serializers import (
    RegisterSerializer,
    VendorSignupSerializer,
    MeSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, VendorProfileSerializer,
    AdminSerializer, GroupSerializer, PermissionSerializer,
    CleanerSignupSerializer, CleanerProfileSerializer, PublicCleanerProfileSerializer,
    ChangePasswordSerializer,  # NEW
    ProfileUpdateSerializer,   # NEW
)
from .tokens import password_reset_token, email_verification_token

# Google OAuth imports
from google_auth_oauthlib.flow import Flow
import requests as http_requests

import logging

User = get_user_model()


# Custom JWT token serializer: attach role/email if desired
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["email"] = user.email
        token["role"] = user.role
        return token


class IsAdminOrSuperAdmin(permissions.BasePermission):
    """
    Custom permission: Only Admins and SuperAdmins can manage Vendor Profiles.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ["admin", "superadmin"]


class IsSuperUser(permissions.BasePermission):
    """
    Allows access only to superusers.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_superuser


class LoginJWTView(APIView):
    permission_classes = [permissions.AllowAny]

    # @ratelimit(key='ip', rate='5/m', block=True)  # Commented out for now
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")
        user = authenticate(email=email, password=password)

        if not user:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        # Vendor login checks
        if user.role == User.ROLE_VENDOR:
            try:
                profile = user.vendor_profile
                if not profile.is_email_approved:
                    return Response({"detail": "Please verify your email first."}, status=status.HTTP_403_FORBIDDEN)
                if not profile.is_approved:
                    return Response({"detail": "Awaiting for admin approval."}, status=status.HTTP_403_FORBIDDEN)
                if not user.is_active:
                    return Response({"detail": "User is inactive"}, status=status.HTTP_403_FORBIDDEN)
            except VendorProfile.DoesNotExist:
                return Response({"detail": "Vendor profile not found."}, status=status.HTTP_403_FORBIDDEN)
        # Cleaner login checks
        if user.role == User.ROLE_CLEANER:
            try:
                profile = user.cleaner_profile
                if not profile.is_email_approved:
                    return Response({"detail": "Please verify your email first."}, status=status.HTTP_403_FORBIDDEN)
                if not profile.is_approved:
                    return Response({"detail": "Awaiting for admin approval."}, status=status.HTTP_403_FORBIDDEN)
                if not user.is_active:
                    return Response({"detail": "User is inactive"}, status=status.HTTP_403_FORBIDDEN)
            except CleanerProfile.DoesNotExist:
                return Response({"detail": "Cleaner profile not found."}, status=status.HTTP_403_FORBIDDEN)
        if not user.is_active:
            return Response({"detail": "User is inactive"}, status=status.HTTP_403_FORBIDDEN)
        access = AccessToken.for_user(user)

        # Get grouped permissions for admin users
        grouped_permissions = []
        if getattr(user, 'role', None) == 'admin':
            grouped_permissions = list(
                user.user_permissions.filter(codename__startswith="can_manage_").values_list("codename", flat=True)
            )

        response_data = {
            "access": str(access),
            "user": MeSerializer(user).data
        }
        if getattr(user, 'role', None) == 'admin' and grouped_permissions:
            response_data["grouped_permissions"] = grouped_permissions
        return Response(response_data, status=status.HTTP_200_OK)


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate JWT token valid for 24 hours
        access = AccessToken.for_user(user)

        headers = self.get_success_headers(serializer.data)
        return Response(
            {
                "user": MeSerializer(user).data,
                "access": str(access),
            },
            status=status.HTTP_201_CREATED,
            headers=headers,
        )


class VendorSignupView(generics.CreateAPIView):
    queryset = VendorProfile.objects.all()
    serializer_class = VendorSignupSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        vendor_profile = user.vendor_profile  # Access the related VendorProfile
        access = AccessToken.for_user(user)

        # Assign can_manage_products permission to vendor
        from django.contrib.auth.models import Permission
        try:
            perm = Permission.objects.get(codename="can_manage_products")
            user.user_permissions.add(perm)
            user.save()  # Ensure the permission is persisted
        except Permission.DoesNotExist:
            pass

        # Send verification email using the helper function
        send_vendor_verification_email(user, request)

        headers = self.get_success_headers(serializer.data)
        return Response(
            {
                "success": True
            },
            status=status.HTTP_201_CREATED,
            headers=headers
        )


class CleanerSignupView(generics.CreateAPIView):
    queryset = CleanerProfile.objects.all()
    serializer_class = CleanerSignupSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        cleaner_profile = serializer.save()

        user = cleaner_profile.user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = email_verification_token.make_token(user)
        verification_path = reverse("verify-email")
        verification_link = f"{request.build_absolute_uri(verification_path)}?uid={uid}&token={token}"

        html_content = render_to_string(
            "emails/email_verification.html",
            {
                "verification_link": verification_link,
                "year": datetime.now().year,
                "user_type": "cleaner"
            }
        )
        text_content = (
            "Welcome to Carpet Market!\n\n"
            f"Please verify your email within 15 minutes by clicking the link below:\n{verification_link}\n\n"
            "If you did not request this, you can ignore this email."
        )
        email_subject = "Verify Your Email"
        email_message = EmailMultiAlternatives(
            subject=email_subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()
        access = AccessToken.for_user(user)

        return Response(
            {
                "success": True,
                "access": str(access)
            },
            status=status.HTTP_201_CREATED
        )


class MeView(generics.RetrieveAPIView):
    serializer_class = MeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        if not email:
            return Response({"detail": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Always return success (don't leak valid emails)
            return Response({"detail": "If the email exists, a reset link has been sent."})

        cache_key = f"pwdreset:{user.pk}"
        existing = cache.get(cache_key)
        # If a token exists and still within 15 minutes, just re-send SAME token to avoid spamming generation
        if existing:
            token = existing.get("token")
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = f"{settings.FRONTEND_BASE_URL}/auth/change-password/{uid}/{token}/"
        else:
            # Generate fresh token + uid and store in cache for 15 minutes (single active token policy)
            token = password_reset_token.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            cache.set(cache_key, {"token": token, "ts": timezone.now().timestamp()}, timeout=900)
            reset_link = f"{settings.FRONTEND_BASE_URL}/auth/change-password/{uid}/{token}/"

        html_content = render_to_string("emails/password_reset.html", {
            "user": user,
            "reset_link": reset_link,
        })
        text_content = (
            f"Hello {user.full_name or 'User'},\n\n"
            f"Click the link below to reset your password (valid for 15 minutes):\n{reset_link}\n\n"
            f"If you didn’t request this, you can ignore this email."
        )
        email_subject = "Password Reset Request"
        email_message = EmailMultiAlternatives(
            subject=email_subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()

        return Response({"detail": "If the email exists, a reset link has been sent."})


class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        uidb64 = request.data.get("uidb64")
        token = request.data.get("token")
        new_password = request.data.get("new_password")

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Invalid user."}, status=status.HTTP_400_BAD_REQUEST)

        cache_key = f"pwdreset:{user.pk}"
        data = cache.get(cache_key)
        if not data:
            return Response({"detail": "Password reset link has expired."}, status=status.HTTP_400_BAD_REQUEST)
        if data.get("token") != token:
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        # Use shared token generator (enforces PASSWORD_RESET_TIMEOUT)
        if not password_reset_token.check_token(user, token):
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        if not new_password:
            return Response({"detail": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        cache.delete(cache_key)
        return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)


class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        uid = request.query_params.get("uid")
        token = request.query_params.get("token")

        try:
            user_id = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            # Render custom HTML error page for invalid UID
            return render(request, "emails/verification_error.html", {"year": datetime.now().year}, status=400)

        if email_verification_token.check_token(user, token):
            updated = False
            try:
                vendor_profile = user.vendor_profile
                vendor_profile.is_email_approved = True
                vendor_profile.save()
                user.is_active = True
                user.save()
                updated = True
            except VendorProfile.DoesNotExist:
                pass
            try:
                cleaner_profile = user.cleaner_profile
                cleaner_profile.is_email_approved = True
                cleaner_profile.save()
                user.is_active = True
                user.save()
                updated = True
            except CleanerProfile.DoesNotExist:
                pass
            if updated:
                return redirect(f"{settings.FRONTEND_BASE_URL}/auth/email-verified-success")
            else:
                # Render custom HTML error page for no profile found
                return render(request, "emails/verification_error.html", {"year": datetime.now().year}, status=400)
        else:
            # Render custom HTML error page for invalid/expired token
            return render(request, "emails/verification_error.html", {"year": datetime.now().year}, status=400)


class HasGroupedPermission(permissions.BasePermission):
    """
    Checks if the user has the required grouped permission for the viewset.
    Usage: permission_classes = [HasGroupedPermission.with_codename('accounts.can_manage_cleaners')]
    """
    codename = None

    @classmethod
    def with_codename(cls, codename):
        # Return a new permission class with the codename set as a class attribute
        return type(f"HasGroupedPermission_{codename}", (cls,), {"codename": codename})

    def has_permission(self, request, view):
        # Always allow superadmins
        if getattr(request.user, "role", None) == "superadmin":
            return True

        # Log user permissions for debugging
        if request.user.is_authenticated:
            user_permissions = request.user.get_all_permissions()
        has_permission = request.user.is_authenticated and request.user.has_perm(self.codename)
        return has_permission


class CleanerProfileViewSet(viewsets.ModelViewSet):
    queryset = CleanerProfile.objects.all()
    serializer_class = CleanerProfileSerializer
    permission_classes = [HasGroupedPermission.with_codename("accounts.can_manage_cleaners")]

    def _is_privileged(self, obj=None):
        user = self.request.user
        if not user.is_authenticated:
            return False
        if getattr(user, 'role', None) in [User.ROLE_ADMIN, User.ROLE_SUPERADMIN]:
            return True
        if user.has_perm("accounts.can_manage_cleaners"):
            return True
        if obj is not None and hasattr(obj, 'user_id') and obj.user_id == user.id:
            return True
        return False

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated and getattr(user, 'role', None) in [User.ROLE_ADMIN, User.ROLE_SUPERADMIN]:
            return CleanerProfile.objects.all()
        return CleanerProfile.objects.filter(is_approved=True)

    def get_permissions(self):
        if self.action in ['list', 'create', 'retrieve']:
            # Public can list and view; create is open per original logic
            return [permissions.AllowAny()]
        return [HasGroupedPermission.with_codename("accounts.can_manage_cleaners")()]

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        if self._is_privileged():
            serializer = CleanerProfileSerializer(queryset, many=True, context={'request': request})
        else:
            serializer = PublicCleanerProfileSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if self._is_privileged(instance):
            serializer = CleanerProfileSerializer(instance, context={'request': request})
        else:
            # Only allow retrieval if approved when not privileged
            if not instance.is_approved:
                return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
            serializer = PublicCleanerProfileSerializer(instance, context={'request': request})
        return Response(serializer.data)

    @action(detail=True, methods=["post"],
            permission_classes=[HasGroupedPermission.with_codename("accounts.can_manage_cleaners")])
    def approve(self, request, pk=None):
        cleaner = self.get_object()
        if cleaner.is_approved:
            return Response({"detail": "Cleaner already approved."}, status=status.HTTP_400_BAD_REQUEST)
        cleaner.is_approved = True
        cleaner.save()
        # Send approval email to cleaner
        html_content = render_to_string(
            "emails/cleaner_approved.html",
            {
                "full_name": getattr(cleaner.user, "full_name", None),
            }
        )
        text_content = (
            f"Dear {getattr(cleaner.user, 'full_name', 'Cleaner')},\n\n"
            "Your cleaner profile has been approved by our team. You can now access all cleaner features on the platform.\n\n"
            "Thank you for joining us!\n\n"
            "Best regards,\nCarpet Market Team"
        )
        email_subject = "Congratulations! Your Cleaner Profile is Approved"
        email_message = EmailMultiAlternatives(
            subject=email_subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[cleaner.user.email],
        )
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()
        return Response({"detail": "Cleaner approved successfully and email sent."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"],
            permission_classes=[HasGroupedPermission.with_codename("accounts.can_manage_cleaners")])
    def reject(self, request, pk=None):
        cleaner = self.get_object()
        if not cleaner.user.is_active:
            return Response({"detail": "Cleaner already rejected."}, status=status.HTTP_400_BAD_REQUEST)
        message = request.data.get("message")
        if not message:
            return Response({"detail": "Message is required."}, status=status.HTTP_400_BAD_REQUEST)
        # Deactivate cleaner and set is_approved to False
        cleaner.user.is_active = False
        cleaner.is_approved = False
        cleaner.user.save()
        cleaner.save()
        # Compose rejection email body
        body = (
            "You are being rejected as a cleaner due to the following reason(s):\n"
            f"{message}"
        )
        # Render HTML rejection email
        html_content = render_to_string(
            "emails/rejection.html",
            {
                "subject": "Rejection Notice from Carpet Market",
                "message": body,
                "user_type": "cleaner",
                "full_name": getattr(cleaner.user, "full_name", None),
                "user_email": cleaner.user.email,
            }
        )
        # Send rejection email
        email_message = EmailMultiAlternatives(
            subject="Rejection Notice from Carpet Market",
            body=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[cleaner.user.email],
        )
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()
        return Response({"detail": "Cleaner rejected and email sent."}, status=status.HTTP_200_OK)


class VendorProfileViewSet(viewsets.ModelViewSet):
    queryset = VendorProfile.objects.all()
    serializer_class = VendorProfileSerializer
    permission_classes = [HasGroupedPermission.with_codename("accounts.can_manage_vendors")]

    def get_object(self):
        pk = self.kwargs.get("pk")
        # Try to get by VendorProfile pk first
        try:
            return VendorProfile.objects.get(pk=pk)
        except VendorProfile.DoesNotExist:
            # Try to get by user id
            try:
                return VendorProfile.objects.get(user__id=pk)
            except VendorProfile.DoesNotExist:
                raise Http404("VendorProfile not found.")

    def get_permissions(self):
        # Only allow GET (retrieve) for the vendor themselves or admins/superadmins with permission
        if self.action == "retrieve":
            vendor_id = self.kwargs.get("pk")
            try:
                vendor_profile = VendorProfile.objects.get(pk=vendor_id)
            except VendorProfile.DoesNotExist:
                return [permissions.AllowAny()]
            user = self.request.user
            # Only allow if user is the vendor themselves
            if user.is_authenticated and user.id == vendor_profile.user.id:
                return [permissions.AllowAny()]
            # Or if user is admin/superadmin or has grouped permission
            if user.is_authenticated and (
                    getattr(user, "role", None) in [User.ROLE_ADMIN, User.ROLE_SUPERADMIN] or user.has_perm(
                    "accounts.can_manage_vendors")):
                return [permissions.AllowAny()]
            # Otherwise, deny
            return [permissions.IsAuthenticated()]
        return [HasGroupedPermission.with_codename("accounts.can_manage_vendors")()]

    def retrieve(self, request, *args, **kwargs):
        vendor_profile = self.get_object()
        user_obj = vendor_profile.user
        user = request.user
        # Security: Only allow if user is the vendor themselves or has permission
        if not (user.is_authenticated and (
                user.id == vendor_profile.user.id or getattr(user, "role", None) in [User.ROLE_ADMIN,
                                                                                     User.ROLE_SUPERADMIN] or user.has_perm(
                "accounts.can_manage_vendors"))):
            return Response({"detail": "You do not have permission to view this vendor profile."},
                            status=status.HTTP_403_FORBIDDEN)
        vendor_data = VendorProfileSerializer(vendor_profile).data
        user_data = MeSerializer(user_obj).data
        return Response({
            "vendor_profile": vendor_data,
            "user": user_data
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"],
            permission_classes=[HasGroupedPermission.with_codename("accounts.can_manage_vendors")])
    def approve(self, request, pk=None):
        vendor = self.get_object()
        if vendor.is_approved:
            return Response({"detail": "Vendor already approved."}, status=status.HTTP_400_BAD_REQUEST)
        vendor.is_approved = True
        vendor.user.is_active = True  # Reactivate user on approval
        vendor.user.save()
        vendor.save()
        # Send congratulations email to vendor (HTML)
        html_content = render_to_string(
            "emails/vendor_approved.html",
            {
                "business_name": vendor.business_name,
                "dashboard_url": f"{settings.FRONTEND_BASE_URL}/vendor/dashboard"
            }
        )
        text_content = (
            f"Dear {vendor.business_name},\n\n"
            "Your vendor profile has been approved by our team. You can now access all vendor features on the platform.\n\n"
            "Thank you for joining us!\n\n"
            "Best regards,\nCarpet Market Team"
        )
        email_subject = "Congratulations! Your Vendor Profile is Approved"
        email_message = EmailMultiAlternatives(
            subject=email_subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[vendor.user.email],
        )
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()
        return Response({"detail": "Vendor approved successfully and email sent."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"],
            permission_classes=[HasGroupedPermission.with_codename("accounts.can_manage_vendors")])
    def reject(self, request, pk=None):
        vendor = self.get_object()
        if not vendor.user.is_active:
            return Response({"detail": "Vendor already rejected."}, status=status.HTTP_400_BAD_REQUEST)
        message = request.data.get("message")
        if not message:
            return Response({"detail": "Message is required."}, status=status.HTTP_400_BAD_REQUEST)
        # Deactivate vendor and set is_approved to False
        vendor.user.is_active = False
        vendor.is_approved = False
        vendor.user.save()
        vendor.save()
        # Compose rejection email body
        body = (
            "You are being rejected as a vendor due to the following reason(s):\n"
            f"{message}"
        )
        # Render HTML rejection email
        html_content = render_to_string(
            "emails/rejection.html",
            {
                "subject": "Rejection Notice from Carpet Market",
                "message": body,
                "user_type": "vendor",
                "business_name": vendor.business_name,
                "user_email": vendor.user.email,
            }
        )
        # Send rejection email
        email_message = EmailMultiAlternatives(
            subject="Rejection Notice from Carpet Market",
            body=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[vendor.user.email],
        )
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()
        return Response({"detail": "Vendor rejected and email sent."}, status=status.HTTP_200_OK)


class SuperAdminAdminViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing admin users (is_staff=True, not superuser).
    Only accessible by superusers.
    """
    queryset = User.objects.filter(is_staff=True, is_superuser=False)
    serializer_class = AdminSerializer
    permission_classes = [IsSuperUser]

    def perform_create(self, serializer):
        # Always create as is_staff=True, is_superuser=False, role="admin"
        user = serializer.save(is_staff=True, is_superuser=False, role="admin")
        # Generate password set token and UID (15 min validity via PASSWORD_RESET_TIMEOUT)
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = password_reset_token.make_token(user)
        set_password_link = f"{settings.FRONTEND_BASE_URL}/auth/change-password/{uidb64}/{token}/?type=new"
        # Render and send invitation email
        html_content = render_to_string(
            "emails/admin_invite.html",
            {
                "full_name": getattr(user, "full_name", None),
                "user_email": user.email,
                "set_password_link": set_password_link,
            }
        )
        text_content = (
            "You are invited to manage Carpet Market as an admin. "
            "Please set your password using the link below (valid for 15 minutes):\n"
            f"{set_password_link}\n\nIf the link expires, request a new invite from a superadmin."
        )
        email_subject = "You're Invited to Manage Carpet Market"
        email_message = EmailMultiAlternatives(
            subject=email_subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()

    def perform_update(self, serializer):
        # Always update as is_staff=True, is_superuser=False
        serializer.save(is_staff=True, is_superuser=False)

    def get_queryset(self):
        return User.objects.filter(is_staff=True, is_superuser=False)

    @action(detail=True, methods=["post"], url_path="assign-groups")
    def assign_groups(self, request, pk=None):
        user = self.get_object()
        groups = request.data.get("groups", [])
        user.groups.clear()
        for group_name in groups:
            group, _ = Group.objects.get_or_create(name=group_name)
            user.groups.add(group)
        return Response({"status": "groups assigned"})

    @action(detail=True, methods=["post"], url_path="assign-permissions")
    def assign_permissions(self, request, pk=None):
        user = self.get_object()
        permissions = request.data.get("permissions", [])
        user.user_permissions.clear()
        # Mapping grouped permissions to CRUD permissions
        grouped_map = {
            "can_manage_products": [
                "add_product", "change_product", "delete_product", "view_product"
            ],
            "can_manage_vendors": [
                "add_vendorprofile", "change_vendorprofile", "delete_vendorprofile", "view_vendorprofile"
            ],
            "can_manage_cleaners": [
                "add_cleanerprofile", "change_cleanerprofile", "delete_cleanerprofile", "view_cleanerprofile"
            ],
            "can_manage_analytics": []  # Add analytics permissions if any
        }
        for perm_codename in permissions:
            try:
                permission = Permission.objects.get(codename=perm_codename)
                user.user_permissions.add(permission)

                # If grouped, also assign all related CRUD permissions
                if perm_codename in grouped_map:
                    for crud_codename in grouped_map[perm_codename]:
                        try:
                            crud_perm = Permission.objects.get(codename=crud_codename)
                            user.user_permissions.add(crud_perm)
                        except Permission.DoesNotExist:
                            continue
            except Permission.DoesNotExist:
                continue

        return Response({"status": "permissions assigned"})

    @action(detail=False, methods=["get"], url_path="groups")
    def list_groups(self, request):
        groups = Group.objects.all()
        serializer = GroupSerializer(groups, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], url_path="permissions")
    def list_permissions(self, request):
        # Only return grouped permissions for Super Admins
        if request.user.is_authenticated and request.user.role == "superadmin":
            permissions = Permission.objects.filter(codename__startswith="can_manage_")
        else:
            permissions = Permission.objects.none()
        serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data)


class SetPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        uidb64 = request.data.get("uidb64")
        token = request.data.get("token")
        new_password = request.data.get("new_password")
        if not uidb64 or not token or not new_password:
            return Response({"detail": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Invalid user."}, status=status.HTTP_400_BAD_REQUEST)
        # Enforce timeout with shared token generator
        if not password_reset_token.check_token(user, token):
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.is_active = True
        user.save()
        return Response({"detail": "Password has been set successfully. You can now log in."},
                        status=status.HTTP_200_OK)


def send_vendor_verification_email(user, request):
    from django.utils.http import urlsafe_base64_encode
    from django.utils.encoding import force_bytes
    from django.urls import reverse
    from datetime import datetime
    from .tokens import email_verification_token
    from django.template.loader import render_to_string
    from django.core.mail import EmailMultiAlternatives
    from django.conf import settings

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = email_verification_token.make_token(user)
    verification_path = reverse("verify-email")
    verification_link = f"{request.build_absolute_uri(verification_path)}?uid={uid}&token={token}"

    html_content = render_to_string(
        "emails/email_verification.html",
        {
            "verification_link": verification_link,
            "year": datetime.now().year,
            "user_type": "vendor"
        }
    )
    text_content = (
        "Welcome to Carpet Market!\n\n"
        f"Please verify your email within 15 minutes by clicking the link below:\n{verification_link}\n\n"
        "If you did not request this, you can ignore this email."
    )
    email_subject = "Verify Your Email"
    email_message = EmailMultiAlternatives(
        subject=email_subject,
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[user.email],
    )
    email_message.attach_alternative(html_content, "text/html")
    email_message.send()


class CanManageOrdersPermission(permissions.BasePermission):
    """
    Allows access only to admin/superadmin users with 'can_manage_orders' permission.
    """
    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False
        if user.role in ["admin", "superadmin"]:
            # Check for custom permission
            return user.user_permissions.filter(codename="can_manage_orders").exists() or user.is_superuser
        return False


class ChangePasswordView(APIView):
    """Authenticated endpoint to change the password using old/new password."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)


class ProfileUpdateView(APIView):
    """Endpoint for updating only the authenticated user's full_name.
    Ignores any other fields provided in the request body.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        data = {'full_name': request.data.get('full_name')}
        serializer = ProfileUpdateSerializer(data=data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            'detail': 'Full name updated successfully.',
            'user': MeSerializer(user).data
        }, status=status.HTTP_200_OK)

    # Allow POST as well (some clients might not support PATCH properly)
    def post(self, request, *args, **kwargs):
        return self.patch(request, *args, **kwargs)


class GoogleLoginView(APIView):
    """
    Initiates Google OAuth flow by redirecting to Google's authorization URL.
    Frontend calls: window.location.href = "https://backenddomain.com/api/auth/login/google"
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        # Capture UTM parameters from query string
        utm_params = {
            'utm_source': request.GET.get('utm_source', ''),
            'utm_campaign': request.GET.get('utm_campaign', ''),
            'utm_medium': request.GET.get('utm_medium', ''),
        }

        # Store UTM params in session for use after callback
        request.session['google_oauth_utm'] = utm_params

        # Create OAuth flow
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
                    "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [settings.GOOGLE_OAUTH_REDIRECT_URI]
                }
            },
            scopes=[
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile"
            ],
            redirect_uri=settings.GOOGLE_OAUTH_REDIRECT_URI
        )

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='select_account'
        )

        # Store state in session for CSRF protection
        request.session['google_oauth_state'] = state

        return redirect(authorization_url)


class GoogleCallbackView(APIView):
    """
    Google OAuth callback endpoint.
    Handles the callback from Google, exchanges code for tokens, and logs in/creates user.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        # Get the authorization code from query params
        code = request.GET.get('code')
        state = request.GET.get('state')
        error = request.GET.get('error')

        # Handle user denial
        if error:
            frontend_url = f"{settings.FRONTEND_BASE_URL}/auth/login?error=google_auth_cancelled"
            return redirect(frontend_url)

        if not code:
            frontend_url = f"{settings.FRONTEND_BASE_URL}/auth/login?error=no_code"
            return redirect(frontend_url)

        # Verify state for CSRF protection
        session_state = request.session.get('google_oauth_state')
        if not session_state or state != session_state:
            frontend_url = f"{settings.FRONTEND_BASE_URL}/auth/login?error=invalid_state"
            return redirect(frontend_url)

        try:
            # Create OAuth flow
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
                        "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [settings.GOOGLE_OAUTH_REDIRECT_URI]
                    }
                },
                scopes=[
                    "openid",
                    "https://www.googleapis.com/auth/userinfo.email",
                    "https://www.googleapis.com/auth/userinfo.profile"
                ],
                redirect_uri=settings.GOOGLE_OAUTH_REDIRECT_URI
            )

            # Exchange authorization code for tokens
            flow.fetch_token(code=code)
            credentials = flow.credentials

            # Get user info from Google
            userinfo_response = http_requests.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {credentials.token}"}
            )

            if userinfo_response.status_code != 200:
                frontend_url = f"{settings.FRONTEND_BASE_URL}/auth/login?error=failed_to_get_user_info"
                return redirect(frontend_url)

            user_info = userinfo_response.json()
            email = user_info.get('email')
            full_name = user_info.get('name', '')
            google_id = user_info.get('sub')

            if not email:
                frontend_url = f"{settings.FRONTEND_BASE_URL}/auth/login?error=no_email"
                return redirect(frontend_url)

            # Check if user exists
            try:
                user = User.objects.get(email=email)
                # User exists - log them in (automatically link accounts)
                created = False
            except User.DoesNotExist:
                # Create new user with customer role
                user = User.objects.create_user(
                    email=email,
                    full_name=full_name,
                    role=User.ROLE_CUSTOMER,
                    is_active=True
                )
                created = True

            # Generate JWT token
            access_token = AccessToken.for_user(user)

            # Get UTM params from session if available
            utm_params = request.session.get('google_oauth_utm', {})

            # Clean up session
            request.session.pop('google_oauth_state', None)
            request.session.pop('google_oauth_utm', None)

            # Redirect to frontend with token
            frontend_url = f"{settings.FRONTEND_BASE_URL}/auth/google/callback?token={str(access_token)}&created={created}"

            # Add UTM params if present
            if utm_params.get('utm_source'):
                frontend_url += f"&utm_source={utm_params['utm_source']}"
            if utm_params.get('utm_campaign'):
                frontend_url += f"&utm_campaign={utm_params['utm_campaign']}"
            if utm_params.get('utm_medium'):
                frontend_url += f"&utm_medium={utm_params['utm_medium']}"

            return redirect(frontend_url)

        except Exception as e:
            # Log the error for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Google OAuth error: {str(e)}")

            frontend_url = f"{settings.FRONTEND_BASE_URL}/auth/login?error=oauth_failed"
            return redirect(frontend_url)

