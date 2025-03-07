from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenBlacklistView
from account.views import VerifyEmailView, LoginView, RegisterView, LogoutView, ProfileView, UserManagementViewSet

router = DefaultRouter()
router.register(r'users', UserManagementViewSet, basename='user-management')

urlpatterns = [
    path("admin/", admin.site.urls),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('api/verify-email/<str:uidb64>/<str:token>/', VerifyEmailView.as_view(), name='verify_email'),
    path('api/profile/', ProfileView.as_view(), name='profile'),

    path('api/', include(router.urls)),
]
