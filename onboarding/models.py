import datetime
from django.utils import timezone
from django.db.models import F
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import AbstractUser
from merchantonboardingservice.constants import MAX_LOGIN_ATTEMPTS

class Merchant(AbstractUser):
    # Merchant Signup, Login and Business Verification
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100, blank=True)
    email = models.EmailField(unique=True, null=True, blank=True)
    username = models.CharField(max_length=100, null=True, blank=True)
    phone_number = models.CharField(max_length=15, unique=True, null=True, blank=True)
    country = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_login_user_agent = models.TextField(null=True, blank=True)
    is_locked = models.BooleanField(default=False)
    avatar = models.ImageField(upload_to='profile/', default='profile/avatar.png', null=True, blank=True)
    # Override any methods or add custom methods to the model as needed
    USERNAME_FIELD = "email"  # Use "email" as the unique identifier for authentication
    REQUIRED_FIELDS = ["username"]  # Include "username" in the REQUIRED_FIELDS list
    # Profile Picture
    profile_picture = models.ImageField(upload_to='business/profile_pictures/', null=True, blank=True, verbose_name='Profile Picture', help_text='Upload a profile picture with a maximum size of 500x500 pixels')
    # Business Name
    business_name = models.CharField(max_length=255, null=True, blank=True, verbose_name='Business Name')
    # Business Certificate
    business_certificate = models.FileField(upload_to='business/certificates/', null=True, blank=True, verbose_name='Business Certificate', help_text='Upload the business name certificate')
    # RC Number
    rc_number = models.CharField(max_length=50, null=True, blank=True, verbose_name='RC Number')
    # RC Certificate
    rc_certificate = models.FileField(upload_to='business/rc_certificates/', null=True, blank=True, verbose_name='RC Certificate', help_text='Upload the RC number certificate')
    # Tax ID
    tax_id = models.CharField(max_length=50, null=True, blank=True, verbose_name='Tax ID')
    # Tax Certificate
    tax_certificate = models.FileField(upload_to='business/tax_certificates/', null=True, blank=True, verbose_name='Tax Certificate', help_text='Upload the Tax ID certificate')
    # ID Verification
    id_type = models.CharField(max_length=50, null=True, blank=True, verbose_name='ID Type')
    upload_id = models.FileField(upload_to='verification/upload_ids/', null=True, blank=True, verbose_name='Upload ID')
    # BVN Verification
    bvn = models.CharField(max_length=11, null=True, blank=True, verbose_name='BVN')
    enter_bvn_number = models.CharField(max_length=11, null=True, blank=True, verbose_name='Enter BVN Number')
    BANK_CHOICES = [
        ('bank1', 'Bank 1'),
        ('bank2', 'Bank 2'),
        ('bank3', 'Bank 3'),
        # Add more banks as needed
    ]
    bank_name = models.CharField(max_length=255, null=True, blank=True, choices=BANK_CHOICES, verbose_name='Bank Name')
    account_number = models.CharField(max_length=20, null=True, blank=True, verbose_name='Account Number')   

    class Meta:
        app_label = "onboarding"
    
    def __str__(self):
        return self.first_name
    

class LoginAttempt(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    attempts = models.PositiveIntegerField(default=0)
    last_attempt_time = models.DateTimeField(auto_now=True, null=True, blank=True)
    lockout_duration = models.DurationField(default=timedelta(seconds=900))
    max_login_attempts = models.PositiveIntegerField(default=MAX_LOGIN_ATTEMPTS)

    merchant = models.ForeignKey(Merchant, on_delete=models.CASCADE, related_name='login_attempts', null=True, blank=True)
    
    class Meta:
        app_label = "onboarding"

    @classmethod
    def lock_merchant(cls, ip_address):
       Merchant.objects.filter(last_login_ip=ip_address).update(is_locked=True)
        
 
    @classmethod
    def add_attempt(cls, ip_address):
        """Add a login attempt for the given IP address."""
        merchant = Merchant.objects.filter(last_login_ip=ip_address).first()

        attempt, created = cls.objects.get_or_create(
            ip_address=ip_address, defaults={"merchant": merchant, "attempts": 1, "last_attempt_time": timezone.now()})

        if not created:
            # If a record already exists, update it
            cls.objects.filter(ip_address=ip_address).update(merchant=merchant, attempts=F("attempts") + 1, last_attempt_time=timezone.now())
            attempt.refresh_from_db()
            

    @classmethod
    def get_attempts(cls, ip_address):
        """Get the number of login attempts for the given IP address."""
        try:
            login_attempts = cls.objects.get(ip_address=ip_address)
        except LoginAttempt.DoesNotExist:
            return 0
        if login_attempts.attempts:
            return login_attempts.attempts
        return 0.

    @classmethod
    def reset_attempts(cls, ip_address=None):
        """Reset the login attempts for the given IP address."""
        cls.objects.filter(ip_address=ip_address).update(attempts=0, last_attempt_time=timezone.now())
        Merchant.objects.filter(last_login_ip=ip_address).update(is_locked=False)

    @classmethod
    def is_ip_locked(cls, ip_address=None):
        """
        Check if the IP address is locked due to too many login attempts.
        """
        try:
            login_attempts = cls.objects.get(ip_address=ip_address)
        except LoginAttempt.DoesNotExist:
            # If no record exists for this IP, we can assume it's not locked
            return False

        if login_attempts and login_attempts.attempts >= MAX_LOGIN_ATTEMPTS:
            time_difference = timezone.now() - login_attempts.last_attempt_time
            # result = time_difference <= login_attempts.lockout_duration
            return time_difference <= login_attempts.lockout_duration
        else:
            return False
        

class OTPVerification(models.Model):
    merchant = models.ForeignKey(Merchant, related_name='otp', on_delete=models.CASCADE)
    phone_otp = models.CharField(max_length=6, null=True, blank=True)
    email_otp = models.CharField(max_length=6, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    phone_otp_created_at = models.DateTimeField(auto_now=True, null=True, blank=True)
    email_otp_created_at = models.DateTimeField(auto_now=True, null=True, blank=True)
    attempts = models.IntegerField(default=0)
    
    class Meta:
        app_label = "onboarding"

    def is_expired(self):
        # Set OTP expiry time (e.g., 5 minutes from creation)
        expiry_duration = datetime.timedelta(minutes=5)
        return timezone.now() > self.phone_otp_created_at + expiry_duration or timezone.now() > self.email_otp_created_at + expiry_duration
    
    def set_merchant_is_active(self, id):
        # grab the current user from Uses model user the user instance from OTPVerification model
        current_user = Merchant.objects.get(id=id)
        # set current user status to is_active
        current_user.is_active = True
        # save current user
        current_user.save()

