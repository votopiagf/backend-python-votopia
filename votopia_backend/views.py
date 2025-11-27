from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView

from services.serializers import LoginSerializer


# Create your views here.
@api_view(['POST'])
def register(request):
    data = request.data
    name = data['name']
    surname = data['surname']
    email = data['email']
    password = data['password']

    return JsonResponse({'status': 'success'})


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)