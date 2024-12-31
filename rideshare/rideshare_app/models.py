from django.db import models
from django.contrib.auth.models import AbstractUser
from rideshare_app.managers import CustomUserManager


# Create your models here.
class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True, null=True, db_index=True)
    role_choices = (
        ("admin", "Admin"),
        ("customer", "Customer"),
        ("driver", "Driver"),
    )
    role = models.CharField(max_length=100, choices=role_choices)
    address = models.TextField(max_length=200)
    phone_number = models.CharField(max_length=10)

    REQUIRED_FIELDS = ["role"]
    USERNAME_FIELD = "email"

    objects = CustomUserManager()

    class Meta:
        db_table = "user"

    def __str__(self):
        return self.name


class Driver(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    license_number = models.CharField(max_length=100)
    vehicle_type = models.CharField(max_length=100)
    vehicle_model = models.CharField(max_length=100)
    vehicle_year = models.IntegerField()
    vehicle_capacity = models.IntegerField()
    vehicle_color = models.CharField(max_length=100)

    class Meta:
        db_table = "driver"

    def __str__(self):
        return self.id


class Ride(models.Model):
    pickup_address = models.CharField(max_length=100)
    dropoff_address = models.CharField(max_length=100)
    pickup_time = models.DateTimeField(auto_now_add=True)
    dropoff_time = models.DateTimeField(auto_now_add=True)
    ride_status = [
        ("pending", "Pending"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),

    ]
    ride_status = models.CharField(max_length=100, choices=ride_status)

    class Meta:
        db_table = "ride"

    def __str__(self):
        return self.id


class RideRequest(models.Model):
    rider = models.ForeignKey(User, on_delete=models.CASCADE)
    ride = models.ForeignKey(Ride, on_delete=models.CASCADE)
    request_time = models.DateTimeField(auto_now_add=True)
    ride_request_status = [
        ("pending", "Pending"),
        ("accepted", "Accepted"),
        ("rejected", "Rejected"),
    ]
    status = models.CharField(max_length=100, choices=ride_request_status)

    class Meta:
        db_table = "ride_request"


class Payment(models.Model):
    ride = models.ForeignKey(Ride, on_delete=models.CASCADE)
    payment_amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = [
        ("cash", "Cash"),
        ("card", "Card"),
        ("upi", "UPI"),
        ("wallet", "Wallet"),
        ("other", "Other"),
    ]
    payment_status = [
        ("pending", "Pending"),
        ("paid", "Paid"),
        ("failed", "Failed"),
        ("cancelled", "Cancelled"),
        ("refunded", "Refunded"),
    ]
    payment_method = models.CharField(max_length=100, choices=payment_method)
    payment_status = models.CharField(max_length=100, choices=payment_status)

    class Meta:
        db_table = "payment"


class Review(models.Model):
    ride = models.ForeignKey(Ride, on_delete=models.CASCADE)
    rider = models.ForeignKey(User, on_delete=models.CASCADE)
    driver = models.ForeignKey(Driver, on_delete=models.CASCADE)
    review = models.TextField(max_length=500)
    rating = models.IntegerField()

    class Meta:
        db_table = "review"


class RideDrivers(models.Model):
    ride = models.ForeignKey(Ride, on_delete=models.CASCADE)
    driver = models.ForeignKey(Driver, on_delete=models.CASCADE)

    class Meta:
        db_table = "ride_drivers"


class RideRiders(models.Model):
    ride = models.ForeignKey(Ride, on_delete=models.CASCADE)
    rider = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        db_table = "ride_riders"
