from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from appauth.models import CustomUser,OTPRecord
import random 
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import JsonResponse
import json
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
def generate_otp():
    return str(random.randint(100000,999999))
class SignAPIView(APIView):
    def post(self, request):
        try:
            data = request.data
            required_fields = ['first_name', 'last_name', 'birth_date', 'mobile', 'email', 'password', 'confirm_password']
            missing_fields = [field for field in required_fields if not data.get(field)]

            if missing_fields:
                return Response({'error': f"Missing fields: {', '.join(missing_fields)}"}, status=400)

            first_name = data['first_name'].strip()
            last_name = data['last_name'].strip()
            birth_date = data['birth_date']
            mobile = data['mobile']
            email = data['email']
            password = data['password']
            confirm_password = data['confirm_password']

            if password != confirm_password:
                return Response({'error': 'Passwords do not match'}, status=400)

            # Check if email already exists
            if CustomUser.objects.filter(email=email).exists():
                return Response({'error': 'User with this email already exists'}, status=400)

            # Create user
            user = CustomUser.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                birth_date=birth_date,
                mobile=mobile,
                email=email,
                is_active=False,
                password=password
            )

            # Generate and save OTP
            otp = generate_otp()
            OTPRecord.objects.create(user=user, otp=otp)

            # Send OTP to email
            send_mail(
                subject="Verify Your Email - OTP Inside",
                message=f"Your OTP is {otp}. It is valid for 10 minutes.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

            request.session['user_email'] = email
            request.session.modified = True

            return Response({'message': 'User registered. OTP sent to email'}, status=201)

        except Exception as e:
            return Response({'error': f'Server error: {str(e)}'}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class OTPVerificationAPIview(APIView):
    authentication_classes = []
    permission_classes = []

    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        data = request.data
        email = data.get('email')
        input_otp = data.get('otp')

        if not email or not input_otp:
            return Response({'error': 'Email and OTP are required'}, status=400)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)

        otp_record = OTPRecord.objects.filter(user=user, is_used=False).order_by('-created_at').first()

        if not otp_record:
            return Response({'error': "No active OTP. Please request a new one."}, status=400)

        if not otp_record.is_valid():
            new_otp = generate_otp()
            OTPRecord.objects.create(user=user, otp=new_otp)
            send_mail(
                subject="New OTP for Verification",
                message=f"Your OTP is: {new_otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
            )
            return Response({'message': "OTP expired. A new OTP has been sent to your email."}, status=400)

        if otp_record.otp != input_otp:
            return Response({'error': 'Invalid OTP'}, status=400)

        otp_record.is_used = True
        otp_record.save()

        user.is_active = True
        user.is_verified = True
        user.save()

        return Response({'message': 'OTP verified successfully, user is now active'}, status=200)
class SigninAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, email=email, password=password)

        if user is None:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_verified and not user.is_superuser:
            return Response({'error': 'Account not verified. Please verify your email.'}, status=status.HTTP_403_FORBIDDEN)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response = Response({
            'message': 'Login successful',
            'is_superuser': user.is_superuser,
        }, status=status.HTTP_200_OK)

        # Set HttpOnly cookies
        cookie_secure = not settings.DEBUG  # Automatically True in production, False during local dev

        cookie_domain = '.ratanjyoti.in'  # 👈️ Add this

        response.set_cookie(
        key='access',
        value=access_token,
        httponly=True,
        secure=cookie_secure,
        samesite='Lax',
        max_age=300,
        domain=cookie_domain   # 👈️ NEW
        )
        response.set_cookie(
        key='refresh',
        value=str(refresh),
        httponly=True,
        secure=cookie_secure,
        samesite='Lax',
        max_age=7 * 24 * 60 * 60,
        domain=cookie_domain   # 👈️ NEW
        )

        return response


class LogoutAPIView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self,request):
        try:
            refresh_token=request.data.get('refresh_token')
            if not refresh_token:
                return Response({"error":"rfresh token is required"},status=status.HTTP_400_BAD_REQUEST)
            token=RefreshToken(refresh_token)
            token.blacklist()
            return Response({"error":"Logout Successfull"},status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response({"error":"Invalid or Expired token"},status=status.HTTP_400_BAD_REQUEST)
class RefreshTokenAPIView(APIView):
    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({"error": "Refresh Token must be provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            # Create a response object
            response = Response({"message": "Access token refreshed"}, status=status.HTTP_200_OK)

            # Set new access token as HttpOnly cookie
            response.set_cookie(
                key='access',
                value=access_token,
                httponly=True,
                secure=True,       # True in production (HTTPS)
                samesite='Lax',
                max_age=300         # 5 minutes
            )

            return response

        except TokenError:
            return Response({"error": "Invalid or Expired Token"}, status=status.HTTP_401_UNAUTHORIZED)
class ForgetPasswordAPIView(APIView):
    def post(self,request):
        email=request.data.get('email')
        if not email:
            return Response({"error":"Email is Required"},status=status.HTTP_400_BAD_REQUEST)
        try:
            user=CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"error":"User not Found"})
        otp=generate_otp()
        OTPRecord.objects.create(user=user,otp=otp)
        send_mail(
            subject='Your OTP for Password Reset',
            message=f'Your OTP is:{otp}',
            from_email='noreply@gmail.com',
            recipient_list=[email],
            fail_silently=True,
        )
        return Response({'message':'OTP sent to your email'},status=status.HTTP_200_OK)
class ResetPasswordWithOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not all([email, otp, new_password]):
            return Response({'error': 'Email, OTP, and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            otp_record = OTPRecord.objects.filter(user=user, otp=otp, is_used=False).latest('created_at')
        except OTPRecord.DoesNotExist:
            return Response({'error': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_record.is_valid():
            return Response({'error': 'OTP expired or already used.'}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Update password
        user.set_password(new_password)
        user.save()

        # ✅ Mark OTP as used
        otp_record.is_used = True
        otp_record.save()

        return Response({'message': 'Password reset successfully.'}, status=status.HTTP_200_OK)
@method_decorator(csrf_exempt, name='dispatch')
class EditProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        return JsonResponse({
            'first_name': user.first_name,
            'last_name': user.last_name,
            'birth_date': user.birth_date,
            'email': user.email,
            'mobile': user.mobile,
        })

    def patch(self, request):
        try:
            data = json.loads(request.body)
            user = request.user

            if 'email' in data and data['email'] != user.email:
                return JsonResponse({'error': 'Email cannot be changed.'}, status=400)

            user.first_name = data.get('first_name', user.first_name).strip()
            user.last_name = data.get('last_name', user.last_name).strip()
            user.birth_date = data.get('birth_date', user.birth_date)
            user.mobile = data.get('mobile', user.mobile).strip()

            user.save()

            return JsonResponse({
                'message': 'Profile updated successfully.',
                'user': {
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'birth_date': user.birth_date,
                    'email': user.email,
                    'mobile': user.mobile,
                }
            }, status=200)

        except Exception as e:
            return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)
class ResendOTPAPIView(APIView):
    authentication_classes = []  # Optional: No auth required
    permission_classes = []      # Optional: No permission required

    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        if user.is_active and user.is_verified:
            return Response({'error': 'User is already verified.'}, status=status.HTTP_400_BAD_REQUEST)

        # Invalidate previous OTPs
        OTPRecord.objects.filter(user=user, is_used=False).update(is_used=True)

        # Generate and save new OTP
        new_otp = generate_otp()
        OTPRecord.objects.create(user=user, otp=new_otp)

        # Send email
        send_mail(
            subject="Your New OTP - Verify Your Email",
            message=f"Your new OTP is: {new_otp}. It is valid for 10 minutes.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )

        return Response({'message': 'New OTP sent successfully.'}, status=status.HTTP_200_OK)
