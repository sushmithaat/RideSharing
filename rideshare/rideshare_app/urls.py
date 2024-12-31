from django.urls import path
from .views import (
    AdminUserView,
    AdminDriverView,
    AdminRideView,
    AdminRideRequestView,
    AdminPaymentView,
    AdminReviewView,
    DriverProfileView,
    DriverRideView,
    DriverRideRequestView,
    CustomerProfileView,
    CustomerRideView,
    CustomerRideRequestView,
    CustomerPaymentView,
    CustomerReviewView,

)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)


urlpatterns = [
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/token/verify/", TokenVerifyView.as_view(), name="token_verify"),


    # Admin APIs
    path("admin/users", AdminUserView.as_view(), name="admin_user_list"),
    path("admin/users/<pk>", AdminUserView.as_view(), name="admin_user_detail"),
    path("admin/drivers", AdminDriverView.as_view(), name="admin_driver_list"),
    path("admin/drivers/<pk>", AdminDriverView.as_view(), name="admin_driver_detail"),
    path("admin/rides", AdminRideView.as_view(), name="ride_list"),
    path("admin/rides/<pk>", AdminRideView.as_view(), name="ride_detail"),
    path("admin/ride_requests", AdminRideRequestView.as_view(), name="ride_request_list"),
    path("admin/ride_requests/<pk>", AdminRideRequestView.as_view(), name="ride_request_detail"),
    path("admin/payments", AdminPaymentView.as_view(), name="payment_list"),
    path("admin/payments/<pk>", AdminPaymentView.as_view(), name="payment_detail"),
    path("admin/reviews", AdminReviewView.as_view(), name="review_list"),
    path("admin/reviews/<pk>", AdminReviewView.as_view(), name="review_detail"),


    # Driver APIs
    path("driver/profile", DriverProfileView.as_view(), name="driver_profile"),
    path("driver/rides", DriverRideView.as_view(), name="driver_rides"),
    path("driver/rides/<pk>", DriverRideView.as_view(), name="driver_ride_detail"),
    path("driver/ride_requests", DriverRideRequestView.as_view(), name="driver_ride_requets"),
    path("driver/ride_requests/<pk>", DriverRideRequestView.as_view(), name="driver_ride_request_detail"),


    # Customer APIs
    path("customer/profile", CustomerProfileView.as_view(), name="customer_profile"),
    path("customer/rides", CustomerRideView.as_view(), name="customer_rides"),
    path("customer/rides/<pk>", CustomerRideView.as_view(), name="customer_ride_detail"),
    path("customer/ride_requests", CustomerRideRequestView.as_view(), name="customer_ride_request"),
    path("customer/ride_requests/<pk>", CustomerRideRequestView.as_view(), name="customer_ride_request_detail"),
    path("customer/payment", CustomerPaymentView.as_view(), name="customer_payment"),
    path("customer/review", CustomerReviewView.as_view(), name="customer_review"),
]
