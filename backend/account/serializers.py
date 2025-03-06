from rest_framework import serializers
from .models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from django.core.exceptions import ObjectDoesNotExist

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        try:
            self.user = User.objects.get(username=attrs[self.username_field])
            
            if not self.user.check_password(attrs['password']):
                raise AuthenticationFailed('Invalid credentials')
                
            if not self.user.is_active:
                raise AuthenticationFailed("Account not activated")
                
        except User.DoesNotExist:
            raise AuthenticationFailed("Invalid credentials")
        
        data = super().validate(attrs)
        data.update({
            'role': self.user.role,
            'user_id': self.user.id,
        })
        
        try:
            if self.user.role == 'PATIENT':
                data['patient_id'] = self.user.patient.id
            elif self.user.role == 'DOCTOR':
                data['doctor_id'] = self.user.doctor.id
        except ObjectDoesNotExist:
            pass

        return data
