from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from appauth.models import CustomUser,OTPRecord
import random 
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.tokens import RefreshToken
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
    def post(self,request):
        data=request.data
        email=data.get('email')
        password=data.get('password')
        if not email or not password:
            return Response({'error':'Email and Password are required'})
        user=authenticate(request,email=email,password=password)
        if user is not None:
            if user.is_verified or user.is_superuser:
                refresh=RefreshToken.for_user(user)
                return Response({
                    'access':str(refresh.access_token),
                    'refresh':str(refresh),
                    'is_superuser':user.is_superuser,
                    'message':"Login successfull",
                },status=201)
            else:
                return Response({'error':'Account not verified.Please verify your email.'},status=403)
        else:
            return Response({'error':'Invalid Credentials.'},status=401)
