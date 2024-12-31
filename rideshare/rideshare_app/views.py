from django.forms import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

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
from rideshare_app.serializers import (
    UserSerializer,
    DriverSerializer,
    RideSerializer,
    RideRequestSerializer,
    PaymentSerializer,
    ReviewSerializer,
    RideDriversSerializer,
    RideRidersSerializer,
    DriverReadSerializer,
    RideRidersReadSerializer,
    RideRequestReadSerializer,
)


# Create your views here.
class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if user.is_authenticated and user.role == "admin":
            return True
        return False


class IsCustomer(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if user.role == "customer":
            return True
        return False


class IsDriver(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if user.role == "driver":
            return True
        return False


class AdminUserView(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        if pk is not None:
            try:
                user = User.objects.get(pk=pk)
                serializer = UserSerializer(user)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response(
                    {"message": "User not found"}, status=status.HTTP_404_NOT_FOUND
                )
        else:
            users = User.objects.all()
            serializer = UserSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(
                {"message": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk=None):
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return Response(
                {"message": "User deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except User.DoesNotExist:
            return Response(
                {"message": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )


# class AdminDriverView(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsAuthenticated, IsAdminUser]

#     def get(self, request, pk=None):
#         if pk:
#             driver = User.objects.filter(pk=pk, role="driver").all()
#             serializer = UserSerializer(driver)
#         else:
#             drivers = User.objects.filter(role="driver").all()
#             serializer = UserSerializer(drivers, many=True)
#         return Response(serializer.data, status=status.HTTP_200_OK)


class AdminDriverView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        serializer = DriverSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        if pk is not None:
            try:
                driver = Driver.objects.get(pk=pk)
                serializer = DriverReadSerializer(driver)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Driver.DoesNotExist:
                return Response(
                    {"message": "Driver does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            drivers = Driver.objects.all()
            serializer = DriverReadSerializer(drivers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        try:
            driver = Driver.objects.get(pk=pk)
        except Driver.DoesNotExist:
            return Response(
                {"message": "Driver does not exist"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = DriverSerializer(driver, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk=None):
        try:
            driver = Driver.objects.get(pk=pk)
            driver.delete()
            return Response(
                {"message": "Driver deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except Driver.DoesNotExist:
            return Response(
                {"message": "Driver does not exist"}, status=status.HTTP_404_NOT_FOUND
            )


class AdminRideView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        ride_data = request.data
        rider_id = ride_data.pop("rider_id", None)

        if not rider_id:
            return Response(
                {"error": "rider_id is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = RideSerializer(data=ride_data)
        if serializer.is_valid():
            try:
                # Create the ride
                ride = serializer.save()

                # Get the rider
                rider = User.objects.get(id=rider_id)

                # Create the RideRiders entry
                RideRiders.objects.create(ride=ride, rider=rider)

                # Create the RideRequest entry
                RideRequest.objects.create(ride=ride, rider=rider, status="pending")

                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except User.DoesNotExist:
                raise ValidationError("Rider with provided ID does not exist.")

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        if pk is not None:
            try:
                ride = RideRiders.objects.get(pk=pk)
                serializer = RideRidersReadSerializer(ride)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except RideRiders.DoesNotExist:
                return Response(
                    {"message": "Ride does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            rides = RideRiders.objects.all()
            serializer = RideRidersReadSerializer(rides, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        try:
            ride = Ride.objects.get(pk=pk)
        except Ride.DoesNotExist:
            return Response(
                {"message": "Ride does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = RideSerializer(ride, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        try:
            ride_rider = RideRiders.objects.get(pk=pk)
            ride = ride_rider.ride

            ride_rider.delete()
            ride.delete()

            return Response(
                {"message": "Ride and associated Ride Riders deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except RideRiders.DoesNotExist:
            return Response(
                {"message": "Ride does not exist"}, status=status.HTTP_404_NOT_FOUND
            )


class AdminRideRequestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        ride_data = request.data
        driver_id = ride_data.pop("driver_id", None)

        if not driver_id:
            return Response(
                {"error": "driver_id is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = RideRequestSerializer(data=ride_data)
        if serializer.is_valid():
            try:
                driver = Driver.objects.get(id=driver_id)

                ride_request = serializer.save()

                ride = Ride.objects.get(id=ride_request.ride_id)

                RideDrivers.objects.create(ride=ride, driver=driver)

                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Driver.DoesNotExist:
                raise ValidationError("Driver with provided ID does not exist.")

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        if pk is not None:
            try:
                ride_request = RideRequest.objects.get(pk=pk)
                serializer = RideRequestReadSerializer(ride_request)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except RideRequest.DoesNotExist:
                return Response(
                    {"message": "Ride Request does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            ride_requests = RideRequest.objects.all()
            serializer = RideRequestReadSerializer(ride_requests, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        try:
            ride_request = RideRequest.objects.get(pk=pk)
        except RideRequest.DoesNotExist:
            return Response(
                {"message": "Ride Request does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

        ride_request_data = request.data
        driver_id = ride_request_data.pop("driver_id", None)
        serializer = RideRequestSerializer(ride_request, data=ride_request_data)
        if serializer.is_valid():
            if (
                "status" in ride_request_data
                and ride_request_data["status"] == "accepted"
            ):
                # Update the status of the ride request to "accepted"
                ride_request.status = "accepted"
                ride_request.save()

                ride = Ride.objects.get(id=ride_request.ride_id)
                driver = Driver.objects.get(id=driver_id)

                RideDrivers.objects.create(ride=ride, driver=driver)

            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk=None):
        try:
            ride_request = RideRequest.objects.get(pk=pk)
            ride_request.delete()
            return Response(
                {"message": "Ride Request deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except RideRequest.DoesNotExist:
            return Response(
                {"message": "Ride Request does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )


class AdminPaymentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        serializer = PaymentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        if pk is not None:
            try:
                payment = Payment.objects.get(pk=pk)
                serializer = PaymentSerializer(payment)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Payment.DoesNotExist:
                return Response(
                    {"message": "Payment does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            payments = Payment.objects.all()
            serializer = PaymentSerializer(payments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        try:
            payment = Payment.objects.get(pk=pk)
        except Payment.DoesNotExist:
            return Response(
                {"message": "Payment not exist"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = PaymentSerializer(payment, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk=None):
        try:
            payment = Payment.objects.get(pk=pk)
            payment.delete()
            return Response(
                {"message": "Payment deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except Payment.DoesNotExist:
            return Response(
                {"message": "Payment does not exist"}, status=status.HTTP_404_NOT_FOUND
            )


class AdminReviewView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, (IsDriver | IsAdminUser)]

    def post(self, request):
        serializer = ReviewSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        if pk is not None:
            try:
                review = Review.objects.get(pk=pk)
                serializer = ReviewSerializer(review)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Review.DoesNotExist:
                return Response(
                    {"message": "Review does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            reviews = Review.objects.all()
            serializer = ReviewSerializer(reviews, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        try:
            review = Review.objects.get(pk=pk)
        except Review.DoesNotExist:
            return Response(
                {"message": "Review does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ReviewSerializer(review, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, pk=None):
        try:
            review = Review.objects.get(pk=pk)
            review.delete()
            return Response(
                {"message": "Review deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except Review.DoesNotExist:
            return Response(
                {"message": "Review does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )


class DriverProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsDriver]

    def post(self, request):
        serializer = DriverSerializer(data=request.data)
        if serializer.is_valid():
            serializer.validated_data['user'] = request.user
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        driver = Driver.objects.get(user=request.user)
        serializer = DriverReadSerializer(driver)
        return Response(serializer.data)

    def put(self, request):
        driver = Driver.objects.get(user=request.user)
        serializer = DriverSerializer(driver, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        driver = Driver.objects.get(user=request.user)
        user = request.user
        driver.delete()
        user.delete()
        return Response(
            {"message": "Driver profile and user deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


class DriverRideView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsDriver]

    def get(self, request, pk=None):
        if pk is not None:
            try:
                ride = RideDrivers.objects.get(pk=pk, driver__user=request.user)
                serializer = RideDriversSerializer(ride)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Ride.DoesNotExist:
                return Response(
                    {"message": "Driver Ride does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            rides = RideDrivers.objects.filter(driver__user=request.user)
            serializer = RideDriversSerializer(rides, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        try:
            ride_driver = RideDrivers.objects.get(ride_id=pk)
            new_ride_status = request.data.get("ride_status")

            if new_ride_status:
                ride_driver.ride.ride_status = new_ride_status
                ride_driver.ride.save()
                return Response(
                    {"message": "Ride status updated successfully"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"error": "Missing ride_status in payload"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except RideDrivers.DoesNotExist:
            return Response(
                {"error": "Ride driver not found"}, status=status.HTTP_404_NOT_FOUND
            )

    def delete(self, request, pk):
        try:
            ride = Ride.objects.get(id=pk)
            ride_driver = RideDrivers.objects.get(ride=ride)

            ride.delete()
            ride_driver.delete()

            return Response(
                {"message": "Ride canceled successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except Ride.DoesNotExist:
            return Response(
                {"error": "Ride not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except RideDrivers.DoesNotExist:
            return Response(
                {"error": "Ride driver association not found"},
                status=status.HTTP_404_NOT_FOUND,
            )


class DriverRideRequestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsDriver]

    def post(self, request):
        ride_request_id = request.data.get("ride_request_id")
        action = request.data.get("status")  # 'accept' or 'decline'

        try:
            ride_request = RideRequest.objects.get(id=ride_request_id)

            if action == "accept":
                # Update RideDrivers model when the ride request is accepted
                ride_driver = RideDrivers(ride=ride_request.ride, driver=request.user)
                ride_rider = RideRiders(
                    ride=ride_request.ride, rider=ride_request.rider
                )
                ride_driver.save()
                ride_rider.save()
                message = "Ride request accepted successfully"
            elif action == "decline":
                # Perform actions for declining the ride request
                message = "Ride request declined successfully"
            else:
                return Response(
                    {"error": "Invalid action. Choose 'accept' or 'decline'"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Implement other actions based on accepting or declining the ride request
            return Response({"message": message}, status=status.HTTP_200_OK)
        except RideRequest.DoesNotExist:
            return Response(
                {"error": "Ride request not found"}, status=status.HTTP_404_NOT_FOUND
            )

    def get(self, request, pk=None):
        if pk is not None:
            try:
                ride = RideRequest.objects.get(pk=pk)
                if ride.status != "accepted":
                    serializer = RideRequestReadSerializer(ride)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                else:
                    return Response(
                        {"message": "Ride request is accepted and cannot be retrieved"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except RideRequest.DoesNotExist:
                return Response(
                    {"message": "Ride request does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            rides = RideRequest.objects.exclude(status="accepted")
            serializer = RideRequestReadSerializer(rides, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        try:
            ride_request = RideRequest.objects.get(pk=pk)
        except RideRequest.DoesNotExist:
            return Response(
                {"message": "Ride Request does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

        ride_request_status = request.data.get("status")
        driver_id = request.data.get("driver_id")
        if ride_request_status == "accepted":
            ride_request.status = ride_request_status
            ride_request.save()

            ride = Ride.objects.get(id=ride_request.ride_id)
            driver = Driver.objects.get(id=driver_id)

            RideDrivers.objects.create(ride=ride, driver=driver)

            return Response(
                {"message": "Ride request status updated to 'accepted'"},
                status=status.HTTP_200_OK,
            )
        elif ride_request_status == "rejected":
            ride_request.status = ride_request_status
            ride_request.save()
        else:
            return Response(
                {
                    "error": "Please provide 'status as accepted' to update ride request status"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class CustomerProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsCustomer]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        serializer = UserSerializer(request.user)
        request.user.delete()
        return Response(
            {"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )


class CustomerRideView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsCustomer]

    def get(self, request, pk=None):
        if pk is not None:
            try:
                ride = RideRiders.objects.get(pk=pk, rider=request.user)
                serializer = RideRidersReadSerializer(ride)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except RideRiders.DoesNotExist:
                return Response(
                    {"message": "Customer Ride does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            rides = RideRiders.objects.filter(rider=request.user)
            serializer = RideRidersReadSerializer(rides, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)


class CustomerRideRequestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsCustomer]

    def post(self, request):
        ride_data = request.data
        rider_id = request.user.id

        if not rider_id:
            return Response(
                {"error": "rider_id is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = RideSerializer(data=ride_data)
        if serializer.is_valid():
            try:
                # Create the ride
                ride = serializer.save()

                # Get the rider
                rider = User.objects.get(id=rider_id)

                # Create the RideRequest entry
                RideRequest.objects.create(ride=ride, rider=rider, status="pending")

                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except User.DoesNotExist:
                raise ValidationError("Rider with provided ID does not exist.")

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk=None):
        if pk is not None:
            try:
                ride = RideRequest.objects.get(pk=pk)
                serializer = RideRequestReadSerializer(ride)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except RideRequest.DoesNotExist:
                return Response(
                    {"message": "Ride Request does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            rides = RideRequest.objects.filter(rider=request.user)
            serializer = RideRequestReadSerializer(rides, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        try:
            ride_request = RideRequest.objects.get(pk=pk)
        except RideRequest.DoesNotExist:
            return Response(
                {"message": "Ride Request does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )
        ride_id = ride_request.ride_id
        ride_data = request.data
        ride = Ride.objects.get(id=ride_id)
        serializer = RideSerializer(ride, data=ride_data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk=None):
        try:
            ride_request = RideRequest.objects.get(pk=pk)
            ride_request.delete()
            return Response(
                {"message": "Ride Request deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except RideRequest.DoesNotExist:
            return Response(
                {"message": "Ride Request does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )


class CustomerPaymentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsCustomer]

    def post(self, request):
        serializer = PaymentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomerReviewView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsCustomer]

    def post(self, request):
        serializer = ReviewSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
