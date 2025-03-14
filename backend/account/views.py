from rest_framework import viewsets, status
from .models import User, Profile
from .serializers import (
    UserSerializer,
    CustomTokenObtainPairSerializer,
    ProfileSerializer,
    UserListSerializer
)
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import send_mail
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import viewsets, permissions, status
from django.db.models import Q
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class LoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                response_data = serializer.validated_data
                return Response(response_data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)

        except AuthenticationFailed as e:
            return Response({"detail": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response(
                {"detail": "An error occurred during login"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"message": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(
                {"message": "Successfully logged out."}, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        user_serializer = UserSerializer(data=request.data)
        if user_serializer.is_valid():
            user = user_serializer.save()

            # Create corresponding profile based on role
            if user.role == "User":
                User.objects.create(
                    user=user,
                    # Add other required fields from request.data
                )
            elif user.role == "Admin":
                User.objects.create(
                    user=user,
                    # Add other required fields from request.data
                )

            # Generate verification token and send email
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            verification_link = f"http://silvercarbon.co.zw/"

            subject = "Verify Your Email"
            html_message = render_to_string(
            "verify_email.html",
                {
                    "user": user,
                    "verification_link": verification_link,
                },
            )
            plain_message = strip_tags(html_message)  # Create a text/plain version
            email = EmailMultiAlternatives(
                subject, 
                plain_message, 
                "noreply@silvercarbon.com",  # Update this to match your domain
                [user.email]
            )
            email.attach_alternative(html_message, "text/html")
            email.send()

            return Response(
                {
                    "message": "Registration successful. Please verify your email.",
                    "user_id": user.id,
                    "role": user.role,
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                user.email_verified = True
                user.is_active = True
                user.save()

                # Generate authentication tokens
                refresh = RefreshToken.for_user(user)

                return Response(
                    {
                        "access": str(refresh.access_token),
                        "refresh": str(refresh),
                        "user_id": user.id,
                        "role": user.role,
                    },
                    status=status.HTTP_200_OK,
                )

            return Response(
                {"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid verification link"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ProfileView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        try:
            profile = request.user.profile
            serializer = ProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Profile.DoesNotExist:
            return Response(
                {"detail": "Profile not found"}, status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request):
        try:
            profile = request.user.profile
            serializer = ProfileSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Profile.DoesNotExist:
            return Response(
                {"detail": "Profile not found"}, status=status.HTTP_404_NOT_FOUND
            )



class UserManagementViewSet(viewsets.ModelViewSet):
    serializer_class = UserListSerializer
    
    def get_queryset(self):
        # Only admins can access this view
        if not self.request.user.role == 'ADMIN' and not self.request.user.is_superuser:
            return User.objects.none()
        
        queryset = User.objects.all().order_by('-date_joined')
        
        # Apply filters if present
        search_query = self.request.query_params.get('search', None)
        role_filter = self.request.query_params.get('role', None)
        status_filter = self.request.query_params.get('status', None)
        
        if search_query:
            queryset = queryset.filter(
                Q(username__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(profile__first_name__icontains=search_query) |
                Q(profile__last_name__icontains=search_query)
            )
        
        if role_filter:
            queryset = queryset.filter(role=role_filter)
            
        if status_filter:
            is_active = status_filter.lower() == 'active'
            queryset = queryset.filter(is_active=is_active)
            
        return queryset
    
    @action(detail=True, methods=['patch'])
    def toggle_active(self, request, pk=None):
        user = self.get_object()
        
        # Prevent self-deactivation
        if user == request.user:
            return Response(
                {"detail": "You cannot deactivate your own account."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.is_active = not user.is_active
        user.save()
        
        return Response(
            {"status": "success", "is_active": user.is_active},
            status=status.HTTP_200_OK
        )
    
    @action(detail=True, methods=['patch'])
    def change_role(self, request, pk=None):
        user = self.get_object()
        
        # Prevent changing own role
        if user == request.user:
            return Response(
                {"detail": "You cannot change your own role."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        new_role = request.data.get('role')
        if not new_role or new_role not in [role[0] for role in User.ROLE_CHOICES]:
            return Response(
                {"detail": "Invalid role provided."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.role = new_role
        user.save()
        
        return Response(
            {"status": "success", "role": user.role},
            status=status.HTTP_200_OK
        )
