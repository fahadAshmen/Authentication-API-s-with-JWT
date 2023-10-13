from django.urls import path
from .views import UserRegistrationView, UserLoginView, UserProfileView, ChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView

urlpatterns = [
    path('register/',UserRegistrationView.as_view(),name='register'),
    path('login/',UserLoginView.as_view(),name='login'),
    path('profile/',UserProfileView.as_view(),name='profile'),
    path('changepassword/',ChangePasswordView.as_view(),name='changepassword'),
    path('send-password-reset-email/',SendPasswordResetEmailView.as_view(),name='send-password-reset-email'),
    path('reset-password/<uid>/<token>/',UserPasswordResetView.as_view(),name='reset-password'),

]
