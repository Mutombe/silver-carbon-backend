from rest_framework import serializers
from .models import User, Profile
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from django.core.exceptions import ObjectDoesNotExist
from .models import Device

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "role"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        return super().create(validated_data)


class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", required=False)
    email = serializers.EmailField(source="user.email", read_only=True)

    class Meta:
        model = Profile
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "profile_picture",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["email", "created_at", "updated_at"]

    def update(self, instance, validated_data):
        # Handle nested user data
        user_data = validated_data.pop("user", None)
        if user_data and "username" in user_data:
            instance.user.username = user_data["username"]
            instance.user.save()

        # Update profile fields
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.last_name = validated_data.get("last_name", instance.last_name)
        instance.profile_picture = validated_data.get(
            "profile_picture", instance.profile_picture
        )
        instance.save()

        return instance


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        try:
            self.user = User.objects.get(username=attrs[self.username_field])

            if not self.user.check_password(attrs["password"]):
                raise AuthenticationFailed("Invalid credentials")

            if not self.user.is_active:
                raise AuthenticationFailed("Account not activated")

        except User.DoesNotExist:
            raise AuthenticationFailed("Invalid credentials")

        data = super().validate(attrs)
        data.update(
            {
                "role": self.user.role,
                "user_id": self.user.id,
            }
        )

        return data

class UserListSerializer(serializers.ModelSerializer):
    profile_picture = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    date_joined = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 
            'username', 
            'email', 
            'email_verified', 
            'role', 
            'is_active', 
            'full_name', 
            'profile_picture',
            'date_joined',
        ]
    
    def get_profile_picture(self, obj):
        try:
            if obj.profile and obj.profile.profile_picture:
                return obj.profile.profile_picture.url
        except Profile.DoesNotExist:
            pass
        return None
    
    def get_full_name(self, obj):
        try:
            if obj.profile:
                if obj.profile.first_name or obj.profile.last_name:
                    return f"{obj.profile.first_name} {obj.profile.last_name}".strip()
        except Profile.DoesNotExist:
            pass
        return obj.username
    
class DeviceSerializer(serializers.ModelSerializer):
    user_email = serializers.SerializerMethodField()
    
    class Meta:
        model = Device
        fields = [
            'id', 'user', 'user_email', 'device_name', 'default_account_code', 
            'issuer_organisation', 'device_fuel', 'device_technology', 
            'capacity', 'commissioning_date', 'requested_effective_registration_date',  
            'other_labelling_scheme', 'address', 'state_province', 'postcode', 
            'country', 'latitude', 'longitude', 'production_facility_registration',
            'declaration_of_ownership', 'metering_evidence', 'single_line_diagram',
            'project_photos', 'additional_notes', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user', 'user_email', 'created_at', 'updated_at']
    
    def get_user_email(self, obj):
        return obj.user.email
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)