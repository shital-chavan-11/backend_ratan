from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models
from appauth.managers import CustomUserManager
from django.core.validators import RegexValidator
from django.utils import timezone
class CustomUser(AbstractUser):
    username = None  # We are removing the default username field
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150, blank=True)  # Typo fixed: 'fist_name' -> 'first_name'
    last_name = models.CharField(max_length=150, blank=True)
    mobile = models.CharField(max_length=15)
    birth_date = models.DateField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'  # Typo fixed: 'USERNAME_FIEDLS' -> 'USERNAME_FIELD'
    REQUIRED_FIELDS = ['first_name', 'last_name']  # Typo fixed

    objects = CustomUserManager()

    def __str__(self):
        return f"{self.email} ({self.first_name} {self.last_name})"
class OTPRecord(models.Model):
    user=models.ForeignKey('CustomUser',on_delete=models.CASCADE)
    otp = models.CharField(
    max_length=6,
    validators=[RegexValidator(r'^\d{6}$', 'OTP must be a 6-digit number')]
)
    created_at=models.DateTimeField(auto_now_add=True)
    is_used=models.BooleanField(default=False)
    OTP_VALIDITY_MINUTES=10
    def is_valid(self):
        expiry_time = self.created_at + timezone.timedelta(minutes=self.OTP_VALIDITY_MINUTES)
        return not self.is_used and timezone.now() <= expiry_time

    def time_left(self):
        expiry_time=self.created_at + timezone.timedelta(minutes=self.OTP_VALIDITY_MINUTES)
        remaining=expiry_time-timezone.now
        return max(0,int(remaining.total_seconds()))
    def __str__(self):
        return f"OTP for{self.user.email}-{self.otp}"
 