from .views import IndexView,RegistrationView,VerificationView,UsernameValidationView,EmailValidationView,LoginView,LogoutView, edit_user
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    path('delete_user_by_id/<int:user_id>/', views.delete_user_by_id, name='delete_user_by_id'),
    #假設要刪除id=5就按照右方的網頁，如果要刪除=4，把5換4，  http://127.0.0.1:8000/authentication/delete_user_by_id/5/
    path('update_login_history_user_ids/', views.update_login_history_user_ids, name='update_login_history_user_ids'),

    path('update-user-ids/', views.update_user_ids, name='update_user_ids'),
    path('password_lock/', views.password_lock, name='password_lock'),
    path('custom_404/', views.custom_404, name='custom_404'),
    path('index/', IndexView.as_view(), name='index'),  # 添加name参数
    path('search/', views.search, name='search'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('reset_password/<int:user_id>/<str:token>/', views.reset_password, name='reset_password'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),

    path('users/', views.users, name='users'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('edit_user/<int:user_id>/', edit_user, name='edit_user'),
    path('register',RegistrationView.as_view(),name='register'),
    path('login',LoginView.as_view(),name='login'),
    path('logout/',LogoutView.as_view(),name='logout'),
    path('validate-username',csrf_exempt(UsernameValidationView.as_view()),
        name="validate-username"),
    path('validate-email', csrf_exempt(EmailValidationView.as_view()),
        name="validate-email"),

    path('activate/<uidb64>/<token>', VerificationView.as_view(),name="activate")
    
]