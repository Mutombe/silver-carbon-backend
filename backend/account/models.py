from django.db import models
from django.contrib.auth.models import AbstractUser
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.core.validators import MinValueValidator

class User(AbstractUser):
    ROLE_CHOICES = [
        ("USER", "User"),
        ("ADMIN", "Admin"),
    ]
    email_verified = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default="USER")
    # Resolve conflicts by adding custom related_names
    groups = models.ManyToManyField(
        "auth.Group",
        verbose_name="groups",
        blank=True,
        related_name="custom_user_set",
        related_query_name="custom_user",
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        verbose_name="user permissions",
        blank=True,
        related_name="custom_user_set",
        related_query_name="custom_user",
    )

    def __str__(self):
        return f"{self.username} - {self.id}"

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    profile_picture = models.ImageField(
        upload_to="profile_pictures/", null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"


# Create Profile instance automatically when a User is created
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

class Device(models.Model):
    DEVICE_FUEL_CHOICES = [
        ("ES200", "Wind"),
        ("ES201", "Solar"),
        ("ES202", "Hydro"),
        ("ES203", "Geothermal"),
        ("ES204", "Biomass"),
        # Add more fuel types as needed
    ]
    
    DEVICE_TECHNOLOGY_CHOICES = [
        ("TC210", "Onshore"),
        ("TC211", "Offshore"),
        ("TC212", "Photovoltaic"),
        ("TC213", "Concentrated Solar Power"),
        # Add more technology types as needed
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="devices")
    device_name = models.CharField(max_length=255)
    default_account_code = models.CharField(max_length=255, blank=True, null=True)
    issuer_organisation = models.CharField(max_length=255)
    device_fuel = models.CharField(max_length=50, choices=DEVICE_FUEL_CHOICES)
    device_technology = models.CharField(max_length=50, choices=DEVICE_TECHNOLOGY_CHOICES)
    capacity = models.DecimalField(max_digits=10, decimal_places=6, validators=[MinValueValidator(0.000001)])
    commissioning_date = models.DateField()
    requested_effective_registration_date = models.DateField()
    other_labelling_scheme = models.CharField(max_length=255, blank=True, null=True)
    address = models.CharField(max_length=255)
    state_province = models.CharField(max_length=255)
    postcode = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    latitude = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)
    production_facility_registration = models.FileField(upload_to='device_documents/facility_registration/', null=True)
    declaration_of_ownership = models.FileField(upload_to='device_documents/ownership_declaration/', null=True)
    metering_evidence = models.FileField(upload_to='device_documents/metering_evidence/', null=True)
    single_line_diagram = models.FileField(upload_to='device_documents/single_line_diagram/', null=True)
    project_photos = models.FileField(upload_to='device_documents/project_photos/', null=True)
    additional_notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.device_name} - {self.user.username}"