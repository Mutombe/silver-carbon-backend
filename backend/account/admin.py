# account/admin.py
from django.contrib import admin
from .models import User, Profile, Device


class AdminUserOverview(admin.ModelAdmin):
    list_display = (
        "id",
        "role",
        "username",
        "email",
    )
    search_fields = ("username",)

class AdminProfileOverview(admin.ModelAdmin):
    list_display = (
        "id",
        "profile_picture",
        "user",
    )
    search_fields = ("user",)

class AdminDeviceOverview(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "device_name",
        "address",
    )
    search_fields = ("username",)

admin.site.register(User, AdminUserOverview)
admin.site.register(Profile, AdminProfileOverview)
admin.site.register(Device, AdminDeviceOverview)
