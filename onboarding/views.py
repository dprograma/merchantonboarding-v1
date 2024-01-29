from django.shortcuts import redirect, render
from rest_framework_simplejwt.exceptions import TokenError
import os, geoip2
from django.contrib.gis.geoip2 import GeoIP2
from django.contrib.auth import authenticate
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from django.utils.encoding import force_str, force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from django.template.loader import render_to_string
import json
from django.conf import settings
import pyotp
import requests
from merchantonboardingservice import constants
from merchantonboardingservice.sendmail import SendMail
from .models import LoginAttempt, Merchant, OTPVerification
from .serializers import (
    BusinessVerificationSerializer,
    LoginViewSerializer,
    OTPVerificationSerializer,
    CreateMerchantSerializer,
    PasswordResetSerializer,
    UpdateSerializer,
    RetrieveMerchantSerializer,
)
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password



@method_decorator(csrf_exempt, name="dispatch")
class CreateMerchantView(generics.CreateAPIView):
    """View class to process merchant signup"""

    authentication_classes = []
    permission_classes = []
    serializer_class = CreateMerchantSerializer

    def post(self, request) -> Response:
        """Create a merchant account and send out an activation email to the user's email"""
        email = request.data.get("email")
        password = request.data.get("password")

        # Check if the user already exists
        try:
            merchant = Merchant.objects.get(email=email)
            return Response(
                {
                    "status": "error",
                    "response": f"This email {email} is already registered.",
                },
                status=status.HTTP_200_OK,
            )
        except Merchant.DoesNotExist:
            merchant = None

        # If the merchant does not exist, create the merchant
        if merchant is None:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save(is_active=False, password=make_password(password))
                return Response(
                    {
                        "status": "success",
                        "response": f"Merchant created successfully. Please verify your account on {email}",
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"status": "error", "response": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {
                    "status": "error",
                    "response": f"This email {email} is already registered.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )



@method_decorator(csrf_exempt, name="dispatch")
class SendEmailOTPView(generics.CreateAPIView):
    authentication_classes = []
    permission_classes = []
    serializer_class = OTPVerificationSerializer

    def post(self, request, *args, **kwargs) -> Response:
        email = request.data.get("email")
        try:
            merchant = Merchant.objects.get(email=email)
        except Merchant.DoesNotExist:
            merchant = None
        # Generate email OTPs
        email_otp = pyotp.TOTP(pyotp.random_base32()).now()

        if merchant is not None:
            # Save or update email otp and attempts to database
            data = {"merchant": merchant.id, "email_otp": email_otp, "email_otp_created_at": timezone.now()}

            # Check if an OTP record already exists for the user
            otp_record = OTPVerification.objects.filter(merchant=merchant).first()
            if otp_record:
                # If record exists, update it
                serializer = self.get_serializer(otp_record, data=data)
            else:
                # If no record, create a new one
                serializer = self.get_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
            # Send OTP to email
            first_name = merchant.first_name
            mail_subject = "Activate your Email Address"
            message = render_to_string(
                "onboarding/email_activation.html",
                {
                    "merchant": first_name,
                    "otp": email_otp,
                },
            )


            SendMail(mail_subject, message, email)

            return Response(
                {"status": "success", "response": f"OTP sent to email {email}."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "error", "response": "Incorrect email address provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )


@method_decorator(csrf_exempt, name="dispatch")
class SendPhoneOTPView(generics.CreateAPIView):
    authentication_classes = []
    permission_classes = []
    serializer_class = OTPVerificationSerializer

    def post(self, request, *args, **kwargs) -> Response:
        phone_number = request.data.get("phone_number")
        try:
            merchant = Merchant.objects.get(phone_number=phone_number)
        except Merchant.DoesNotExist:
            merchant = None
        # generate phone OTP
        phone_otp = pyotp.TOTP(pyotp.random_base32()).now()
        
        if merchant is not None:
            # Save or update email otp and attempts to database
            data = {"merchant": merchant.id, "phone_otp": phone_otp, "phone_otp_created_at":timezone.now()}

            # Check if an OTP record already exists for the user
            otp_record = OTPVerification.objects.filter(merchant=merchant).first()
            if otp_record:
                # If record exists, update it
                serializer = self.get_serializer(otp_record, data=data)
            else:
                # If no record, create a new one
                serializer = self.get_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
            # Send OTP to phone number using Termii
            url = settings.TERMII_PHONE_OTP_URL

            payload = json.dumps(
                {
                    "to": phone_number,
                    "from": "Ojapay",
                    "sms": f"Hi {merchant.first_name} your verification code is {phone_otp}.",
                    "type": "plain",
                    "channel": "generic",
                    "api_key": settings.TERMII_API_KEY,
                }
            )

            headers = {
                "Content-Type": "application/json",
            }

            try:
                response = requests.post(url, data=payload, headers=headers)
                if response.status_code == 200:
                    return Response(
                        {"status": "success", "response": response.json()},
                        status=status.HTTP_200_OK,
                    )
                else:
                    return Response(
                        {"status": "error", "response": "Error retrieving OTP."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except requests.exceptions.RequestException:
                return Response(
                    {"status": "error", "response": "Incorrect Phone number provided."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {"status": "error", "response": "Incorrect Phone number provided222."},
                status=status.HTTP_400_BAD_REQUEST,
            )


@method_decorator(csrf_exempt, name="dispatch")
class VerifyOTPView(generics.CreateAPIView):
    authentication_classes = []
    permission_classes = []
    serializer_class = OTPVerificationSerializer

    def post(self, request, *args, **kwargs) -> Response:
        email = request.data.get("email")
        phone_otp = request.data.get("phone_otp")
        email_otp = request.data.get("email_otp")

        try:
            merchant = Merchant.objects.get(email=email)
        except Merchant.DoesNotExist:
            merchant = None
        if merchant is not None:
            try:
                otp_record = OTPVerification.objects.get(merchant=merchant)
                # Check for expiry
                if otp_record.is_expired():
                    return Response({"status": "error", "response": "OTP expired"})

                # Implement rate limiting
                if otp_record.attempts >= 3:  # Allow up to 3 attempts
                    return Response(
                        {
                            "status": "error",
                            "response": "Maximum attempt limit reached",
                        }
                    )
                
                # Verify OTPs
                if (
                    phone_otp == otp_record.phone_otp
                    and email_otp == otp_record.email_otp
                ):
                    # activate user
                    otp_record.set_merchant_is_active(id=otp_record.merchant_id)
                    return Response(
                        {
                            "status": "success",
                            "response": "Phone and Email verified successfully",
                        },
                        status=status.HTTP_202_ACCEPTED,
                    )
                else:
                    otp_record.attempts += 1
                    otp_record.save()
                    return Response(
                        {"status": "error", "response": "Invalid OTP"},
                    )

            except OTPVerification.DoesNotExist:
                return Response(
                    {"status": "error", "response": "OTP record not found"},
                )
        else:
            return Response({"status": "error", "response": "Merchant not found"}, status=status.HTTP_404_NOT_FOUND)
        
        
@method_decorator(csrf_exempt, name="dispatch")
class MerchantLoginView(generics.CreateAPIView):
    """View class to process merchant login"""

    authentication_classes = []
    permission_classes = []
    serializer_class = RetrieveMerchantSerializer
    max_login_attempts = constants.MAX_LOGIN_ATTEMPTS
    lockout_duration = 900  # 15 minutes in seconds

    def post(self, request) -> Response:
        email = request.data.get("email", "")
        password = request.data.get("password", "")

        try: 
            merchant = authenticate(email=email, password=password)
        except Merchant.DoesNotExist:
            merchant = None
        # Check if the IP is locked
        remote_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if remote_address:
            ip_address = remote_address.split(',')[-1].strip()
        else:
            ip_address = request.META.get("REMOTE_ADDR")
        geopath = os.path.join(settings.BASE_DIR, 'staticfiles/geoip/GeoLite2-Country.mmdb')
        try:
            g = GeoIP2(path=geopath)
            countrycode = g.country_code(ip_address)
        except geoip2.errors.AddressNotFoundError:
            countrycode = 'NG'
        # Get the country name and code
        with open(os.path.join(settings.BASE_DIR,'staticfiles/json/countries.json'), encoding="utf8") as f:
            data = json.load(f)
            for keyval in data:
                if countrycode == keyval['isoAlpha2']:
                    code = keyval['currency']['code']
                    location = keyval['name']
                    
        # Get the merchant agent values
        browser = f'{request.user_agent.browser.family} {request.user_agent.browser.version_string}'
        OS = f'{request.user_agent.os.family} {request.user_agent.os.version_string}'
        
        
        if merchant is not None:
            # Check if the merchant account is locked
            if merchant.is_locked:
                return Response(
                    {
                        "status": "error",
                        "response": "Your account is locked. Please contact support to resolve your account.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                # Create a new token for this merchant
                refresh = RefreshToken.for_user(merchant)
                access_token = str(refresh.access_token)
                serializer = self.get_serializer(merchant, data=request.data)
                if serializer.is_valid():
                    serializer.save()
                LoginAttempt.reset_attempts(ip_address)
                # Check if the user logged in from a new device
                if (
                    merchant.last_login_ip != ip_address
                    or OS != merchant.last_login_user_agent
                ):
                    # Send email notification to the user

                    message = render_to_string(
                        "onboarding/send_new_device_notification.html",
                        {
                            "user": merchant.first_name,
                            "ip_address": ip_address,
                            "location": location,
                            "device": OS,
                            "browser": browser,
                            "datetime": timezone.now(),
                            "site_name": settings.CURRENT_SITE,
                        },
                    )
                    mail_subject = "New Device Login Notification"
                    SendMail(mail_subject, message, email)
                # Update the user ip address and device
                serializer.save(
                    last_login_ip=ip_address, last_login_user_agent=OS
                )

                # Return response to client
                current_user = serializer.data
                return Response(
                    {
                        "status": "success",
                        "response": {
                            "user": current_user,
                            "access_token": access_token,
                            "refresh_token": str(refresh),
                        },
                    },
                    status=status.HTTP_200_OK,
                )

        else:
            # Login failed, increase login attempts
            LoginAttempt.add_attempt(ip_address)
            remaining_attempts = self.max_login_attempts - LoginAttempt.get_attempts(
                ip_address
            )

            if remaining_attempts > 0:
                return Response(
                    {
                        "status": "error",
                        "response": f"Invalid login credentials. You have {remaining_attempts} attempts remaining.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            else:
                # Lock the user's account for 15 minutes
                LoginAttempt.lock_merchant(ip_address)
                return Response(
                    {
                        "status": "error",
                        "response": f"Invalid login credentials. Your IP address has been locked for 15 minutes.",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
                
                
@method_decorator(csrf_exempt, name="dispatch")
class ForgetPasswordView(generics.CreateAPIView):
    permission_classes = []

    def post(self, request):
        email = request.data.get("email", "")
        try:
            merchant = Merchant.objects.get(email=email)
        except Merchant.DoesNotExist:
            merchant = None

        if merchant is not None:
            current_site = settings.CURRENT_SITE
            mail_subject = "Reset your password"
            message = render_to_string(
                "onboarding/password_reset_email.html",
                {
                    "user": merchant.first_name,
                    "domain": current_site,
                    "uid": urlsafe_base64_encode(force_bytes(merchant.id)),
                    "token": default_token_generator.make_token(merchant),
                },
            )
            SendMail(mail_subject, message, email)
            return Response({"status": "success"}, status=status.HTTP_200_OK)
        else:
            return Response(
                {"status": "error", "response": "Incorrect email supplied."},
                status=status.HTTP_400_BAD_REQUEST,
            )
                


class PasswordResetView(generics.RetrieveUpdateAPIView):
    permission_classes = []
    serializer_class = PasswordResetSerializer
    queryset = Merchant.objects.all()

    def post(self, request):
        uidb64 = request.data.get('uid')
        token = request.data.get('token')
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = Merchant.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, Merchant.DoesNotExist):
            user = None

        data = {"password": request.data.get('password')}
        if user is not None and default_token_generator.check_token(user, token):
            serializer = self.get_serializer(user, data=data, partial=True)
            if serializer.is_valid():
                self.perform_update(serializer)
                return Response(
                {
                    "status": "success",
                    "response": "Password reset was successful",
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {
                    "status": "error",
                    "response": "Invalid activation link",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )  
            

@method_decorator(csrf_exempt, name="dispatch")
class UpdateMerchantView(generics.RetrieveUpdateAPIView):
    """View class to update merchant profile"""
    serializer_class = UpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Merchant.objects.filter(id=self.request.user.id)

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs) -> Response:
        merchant = self.get_object()
        serializer = self.get_serializer(merchant, data=request.data, partial=True)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response(
                {"status": "success", "response": serializer.data},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "error", "response": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )
        

class LogoutView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        # Check if the token is blacklisted
        if request.auth and BlacklistedToken.objects.filter(token=request.auth.token).exists():
            return Response(
                {"status": "error", "response": "Invalid token"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Find all refresh tokens for the user
            tokens = OutstandingToken.objects.filter(user_id=request.user.id, token__isnull=False)
            for token in tokens:
                # Blacklist each token
                BlacklistedToken.objects.get_or_create(token=token)
                # Optionally, delete the outstanding token if you want to clean up
                token.delete()

            return Response(
                {"status": "success", "response": "Successfully logged out"},
                status=status.HTTP_200_OK
            )
        except (TokenError, OutstandingToken.DoesNotExist, BlacklistedToken.DoesNotExist):
            return Response(
                {"status": "error", "response": "Invalid token"},
                status=status.HTTP_400_BAD_REQUEST
            )



class DeleteAccountView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        # Check if the token is blacklisted
        if request.auth and BlacklistedToken.objects.filter(token=request.auth.token).exists():
            return Response(
                {"status": "error", "response": "Invalid token"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Delete all outstanding tokens
            tokens = OutstandingToken.objects.filter(user_id=request.user.id)
            for token in tokens:
                # Blacklist each token
                BlacklistedToken.objects.get_or_create(token=token)
                # Optionally, delete the outstanding token if you want to clean up
                token.delete()
        except (TokenError, OutstandingToken.DoesNotExist, BlacklistedToken.DoesNotExist):
            return Response(
                {"status": "error", "response": "Invalid token"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Delete user
        request.user.delete()

        return Response(
            {"status": "success", "response": "User account has been deleted"},
            status=status.HTTP_200_OK,
        )


@method_decorator(csrf_exempt, name="dispatch")
class BusinessVerificationView(generics.RetrieveUpdateAPIView):
    """View class to process user signup"""

    authentication_classes = []
    permission_classes = []
    serializer_class = RetrieveMerchantSerializer

    def update(self, request) -> Response:
        """Create a user account and send out an activation email to user email"""
        email = request.data.get("email")
        # Check if merchant already exist
        try:
            merchant = Merchant.objects.get(email=email)
        except Merchant.DoesNotExist:
            merchant = None
        # If merchant does not exist, create user
        if merchant is None:
            return Response(
                {
                    "status": "error",
                    "response": f"Merchant does not exist.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            serializer = self.get_serializer(merchant, data=request.data, partial=True)
            if serializer.is_valid():
                self.perform_update(serializer)
                return Response(
                    {
                        "status": "success",
                        "response": serializer.data,
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"status": "error", "response": serializer.errors},
                    status=status.HTTP_200_OK,
                )
                

@method_decorator(csrf_exempt, name="dispatch")
class UpdateMerchantBankDetails(generics.RetrieveUpdateAPIView):
    """View class to merchant's bank details"""

    authentication_classes = []
    permission_classes = []
    serializer_class = RetrieveMerchantSerializer

    def update(self, request) -> Response:
        """Update a merchant bank account account details and BVN"""
        email = request.data.get("email")
        # Check if merchant already exist
        try:
            merchant = Merchant.objects.get(email=email)
        except Merchant.DoesNotExist:
            merchant = None
        # If merchant does not exist, create user
        if merchant is None:
            return Response(
                {
                    "status": "error",
                    "response": f"Merchant does not exist.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            serializer = self.get_serializer(merchant, data=request.data, partial=True)
            if serializer.is_valid():
                self.perform_update(serializer)
                return Response(
                    {
                        "status": "success",
                        "response": serializer.data,
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"status": "error", "response": serializer.errors},
                    status=status.HTTP_200_OK,
                )
                
                
@method_decorator(csrf_exempt, name="dispatch")
class RetrieveMerchant(generics.ListAPIView):
    """View class to retrieve merchant profile"""
    serializer_class = RetrieveMerchantSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        try:
            merchant = Merchant.objects.get(id=request.user.id)
        except Merchant.DoesNotExist:
            merchant = None
            
        if merchant is not None:
            serializer = self.get_serializer(merchant)
            return Response(
                {
                    "status": "success",
                    "response": serializer.data
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                    {
                        "status": "error",
                        "response": "Merchant not found"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            

@method_decorator(csrf_exempt, name="dispatch")
class RetrieveAllMerchant(generics.ListAPIView):
    """View class to retrieve all merchants profile"""
    serializer_class = RetrieveMerchantSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        merchants = Merchant.objects.all()  
        if merchants is not None:
            serializer = self.get_serializer(merchants)
            return Response(
                {
                    "status": "success",
                    "response": serializer.data
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                    {
                        "status": "error",
                        "response": "Records not found"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )