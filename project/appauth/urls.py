from django.urls import path
from .views import SignAPIView,OTPVerificationAPIview,SigninAPIView
urlpatterns =[
    path('register/',SignAPIView.as_view(),name='signup'),
    path('verify-otp/',OTPVerificationAPIview.as_view(),name="verify_otp"),
    path('signin/',SigninAPIView.as_view(),name='signin'),
]