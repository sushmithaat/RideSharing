from rest_framework.serializers import ModelSerializer
from rideshare_app.models import (
    User,
    Driver,
    Ride,
    RideRequest,
    Payment,
    Review,
    RideDrivers,
    RideRiders,
)


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "password",
            "phone_number",
            "address",
            "role",
        ]

    def create(self, validated_data):
        user = User.objects.create_user(
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            email=validated_data["email"],
            password=validated_data["password"],
            phone_number=validated_data["phone_number"],
            address=validated_data["address"],
            role=validated_data["role"],
        )
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        # extra_fields.setdefault('role', 'admin')  # Set the default role for superusers

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        role = extra_fields.pop(
            "role", "admin"
        )  # Pop 'role' from extra_fields and set default value to 'admin'
        return self.create_user(email, password=password, role=role, **extra_fields)


class UserReadSerializer(ModelSerializer):
    class Meta:
        model = User

        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "address",
            "role",
        ]


class DriverSerializer(ModelSerializer):

    class Meta:
        model = Driver
        fields = "__all__"


class DriverReadSerializer(ModelSerializer):
    user = UserReadSerializer(read_only=True)

    class Meta:
        model = Driver
        fields = "__all__"


class RideSerializer(ModelSerializer):
    class Meta:
        model = Ride
        fields = "__all__"


class RideRequestSerializer(ModelSerializer):

    class Meta:
        model = RideRequest
        fields = "__all__"


class RideRequestReadSerializer(ModelSerializer):
    ride = RideSerializer(read_only=True)

    class Meta:
        model = RideRequest
        fields = "__all__"


class PaymentSerializer(ModelSerializer):
    class Meta:
        model = Payment
        fields = "__all__"


class ReviewSerializer(ModelSerializer):
    class Meta:
        model = Review
        fields = "__all__"


class RideDriversSerializer(ModelSerializer):
    ride = RideSerializer(read_only=True)

    class Meta:
        model = RideDrivers
        fields = "__all__"


class RideRidersSerializer(ModelSerializer):
    class Meta:
        model = RideRiders
        fields = "__all__"


class RideRidersReadSerializer(ModelSerializer):
    ride = RideSerializer(read_only=True)
    rider = UserSerializer(read_only=True)

    class Meta:
        model = RideRiders
        fields = "__all__"
