from rest_framework import serializers
from .models import Merchant, OTPVerification


class CreateMerchantSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=False)
    country = serializers.CharField(required=False)
    class Meta: 
        model = Merchant
        fields = '__all__'


class LoginViewSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=False)
    username = serializers.CharField(required=False)
    country = serializers.CharField(required=False)
    class Meta: 
        model = Merchant
        fields = '__all__'


class RetrieveMerchantSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=False)
    username = serializers.CharField(required=False)
    country = serializers.CharField(required=False)
    class Meta: 
        model = Merchant
        exclude = ('password',)

# OTPVerification Serializer
class OTPVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTPVerification
        fields = '__all__'


class BusinessVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchant
        fields = '__all__'
#specify the fields i want to submit


class PasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = Merchant
        fields = ['password']


class LogoutSerializer(serializers.Serializer):
    token = serializers.CharField(required=False)


class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class UpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchant
        fields = ['first_name', 'last_name', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}