# account/admin.py
from django.contrib import admin
from .models import User


class AdminUserOverview(admin.ModelAdmin):
    list_display = (
        "id",
        "role",
        "username",
        "email",
    )
    search_fields = ("username",)


admin.site.register(User, AdminUserOverview)
