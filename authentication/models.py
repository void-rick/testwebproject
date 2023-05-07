from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils import timezone
from datetime import timedelta
from django.db.models.functions import TruncDay
from django.db.models import Count
from django.db.models import F
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.auth.hashers import make_password
from django.core.validators import MinValueValidator

class User_db(AbstractUser):
    id = models.PositiveIntegerField(primary_key=True, validators=[MinValueValidator(0)])
    email = models.CharField(max_length=255)  # 電子信箱欄位
    groups = models.ManyToManyField(
        Group,
        related_name='user_groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
    )

    user_permissions = models.ManyToManyField(
        Permission,
        related_name='user_permissions_set',
        blank=True,
        help_text='Specific permissions for this user.',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # 新增一個 profile_image 欄位
    profile_image = models.ImageField(upload_to='profile_images', blank=True)

    # 新增地址和性別欄位
    address = models.CharField(max_length=255, blank=True)  # 地址欄位
    gender = models.CharField(max_length=10, choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')], blank=True)  # 性別欄位

    def login(self):
        login_history = LoginHistory(user=self)
        login_history.save()

    class Meta:
        db_table = 'user'  # 資料表名稱
        app_label = 'authentication'  # 應用程式名稱



class LoginHistory(models.Model):
    user = models.ForeignKey(User_db, on_delete=models.CASCADE)
    login_time = models.DateTimeField(auto_now_add=True)
    login_method = models.CharField(max_length=50, choices=[('password', 'Password'), ('oauth', 'OAuth'), ('sso', 'Single Sign-On')], default='password')

    class Meta:
        db_table = 'login_history'
        ordering = ['-login_time']

    @staticmethod
    def group_by_user_and_date():
        return LoginHistory.objects.annotate(
            user_id_annotation=F('user__id'),
            date=TruncDay('login_time')
        ).values('user_id', 'date').annotate(count=Count('id'))
    
class PasswordLockLogin(models.Model):
    user = models.ForeignKey(User_db, on_delete=models.CASCADE)
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        
    class Meta:
        db_table = 'password_lock_login'
        app_label = 'authentication'     

class UserSession(models.Model):
    user = models.ForeignKey(User_db, on_delete=models.CASCADE)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)  # IP 地址欄位
    user_agent = models.TextField(null=True, blank=True)  # 使用者代理欄位

    class Meta:
        db_table = 'user_session'
        app_label = 'authentication'