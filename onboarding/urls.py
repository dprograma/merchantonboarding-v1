from django.urls import path
from onboarding.views import (
    DeleteAccountView,
    ForgetPasswordView,
    RetrieveAllMerchant,
    RetrieveMerchant,
    SendEmailOTPView,
    SendPhoneOTPView,
    CreateMerchantView,
    BusinessVerificationView,
    MerchantLoginView,
    UpdateMerchantBankDetails,
    UpdateMerchantView,
    VerifyOTPView,
    PasswordResetView,
    LogoutView,
)

urlpatterns = [
    #This is the merchant-creation, merchant-login, email_otp_verification, phone_number_otp_verification and business_verification for JWT
    path('create-merchant/', CreateMerchantView.as_view(), name='create-merchant'),
    # http://127.0.0.1:8000/api/onboarding/create-merchant/
    path('merchant-login/', MerchantLoginView.as_view(), name='merchant_login'),
    # http://127.0.0.1:8000/api/onboarding/merchant-login/
    path('otp-phone-number/', SendPhoneOTPView.as_view(), name='otp-phone-number'),
    # http://127.0.0.1:8000/api/onboarding/otp-phone-number/
    path('otp-email/', SendEmailOTPView.as_view(), name='otp-email'),
    # http://127.0.0.1:8000/api/onboarding/otp-email/
    path('business-verification/', BusinessVerificationView.as_view(), name='business-verification'),
    # http://127.0.0.1:8000/api/onboarding/business-verification/
    path('email-phone-verification/', VerifyOTPView.as_view(), name='email-phone-verification'),
    # http://127.0.0.1:8000/api/onboarding/email-phone-verification/
    # path('reset-password/<str:uidb64>/<str:token>/', PasswordResetView.as_view(), name="reset_password"),
    # # http://127.0.0.1:8000/api/onboarding/reset-password/
    # path("reset/<str:pk>", Reset.as_view(), name="reset"),
    # # http://127.0.0.1:8000/api/onboarding/reset-password/
    # path("reset/", Reset.as_view(), name="reset_pass"),
    path(
        "reset-password/",
        PasswordResetView.as_view(),
        name="reset_password",
    ),
    # http://127.0.0.1:8000/api/onboarding/reset/
    path('logout/', LogoutView.as_view(), name='logout'),
    # http://127.0.0.1:8000/api/onboarding/logout/
    path('forgot-password/', ForgetPasswordView.as_view(), name='forgot_password'),
    # http://127.0.0.1:8000/api/onboarding/forget-password/
    path('delete-account/', DeleteAccountView.as_view(), name='delete_account'),
    # http://127.0.0.1:8000/api/onboarding/delete-account/
    path('update-profile/', UpdateMerchantView.as_view(), name='update_profile'),
    # http://127.0.0.1:8000/api/onboarding/update-profile/   
    path('get-merchant/', RetrieveMerchant.as_view(), name='get_merchant'),
    # http://127.0.0.1:8000/api/onboarding/get-merchant/   
    path('get-all-merchants/', RetrieveAllMerchant.as_view(), name='get_all_merchants'),
    path('update-merchant-bank-details/', UpdateMerchantBankDetails.as_view(), name='update_merchant_bank_details'),
]