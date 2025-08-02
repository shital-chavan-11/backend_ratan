from django.urls import path
from .views import SignAPIView,OTPVerificationAPIview,SigninAPIView,LogoutAPIView,RefreshTokenAPIView,ForgetPasswordAPIView,ResetPasswordWithOTPView,EditProfileView,ResendOTPAPIView
urlpatterns =[
    path('signup/',SignAPIView.as_view(),name='signup'),
    path('verify-otp/',OTPVerificationAPIview.as_view(),name="verify_otp"),
    path('signin/',SigninAPIView.as_view(),name='signin'),
    path('logout/',LogoutAPIView.as_view(),name='logout'),
    path('refresh_token/',RefreshTokenAPIView.as_view(),name='refresh_token'),
    path('forgot-password/',ForgetPasswordAPIView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordWithOTPView.as_view(), name='reset-password'),
    path('resend-otp/',ResendOTPAPIView.as_view(), name='resend-otp'),
    path('user/edit/', EditProfileView.as_view(), name='edit-profile'),
]