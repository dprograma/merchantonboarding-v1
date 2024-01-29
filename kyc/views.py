from rest_framework import generics
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from django.utils.decorators import method_decorator
from .models import KYC
from onboarding.models import Merchant
from .serializers import KYCSerializer
        


@method_decorator(csrf_exempt, name="dispatch")
class RetrieveMerchantKyc(generics.ListAPIView):
    """View class to retrieve merchant kyc details"""
    serializer_class = KYCSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs) -> Response:
        try:
            merchant = Merchant.objects.get(id=request.user.id)
        except Merchant.DoesNotExist:
            return Response({"status": "error", "response": "Invalid merchant"}, status=status.HTTP_400_BAD_REQUEST)

        kyc_record = KYC.objects.filter(merchant=merchant).first()

        if kyc_record:
            serializer = self.get_serializer(kyc_record)
            return Response({"status": "success", "response": serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({"status": "error", "response": "KYC record not found"}, status=status.HTTP_404_NOT_FOUND)



@method_decorator(csrf_exempt, name="dispatch")
class UpdateMerchantKyc(generics.RetrieveUpdateAPIView):
    """View class to update merchant kyc details"""

    serializer_class = KYCSerializer
    permission_classes = []

    def update(self, request) -> Response:
        """Update a merchant account with the supplied KYC details"""
        email = request.data.get("email")
        # Check if merchant already exist
        try:
            merchant = Merchant.objects.get(email=email)
        except KYC.DoesNotExist:
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
            request.data['merchant'] = merchant.id
            kyc_record = KYC.objects.filter(merchant=merchant).first()
            serializer = self.get_serializer(kyc_record, data=request.data, partial=True)
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
