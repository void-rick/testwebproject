# 匯入必要的套件
from django.shortcuts import render, redirect  # Django內建函式庫，用於渲染和重新導向網頁
from django.views import View  # Django的視圖類別，用於處理HTTP請求和響應
import json  # Python的JSON函式庫，用於處理JSON數據

from django.http import JsonResponse  # Django內建函式庫，用於發送JSON格式的HTTP響應
from django.contrib.auth.models import User  # Django的內建用戶模型，用於處理用戶註冊、登入等操作
from validate_email import validate_email  # 用於驗證電子郵件地址格式的Python函式庫
from django.contrib import messages  # Django內建函式庫，用於顯示錯誤訊息
from django.core.mail import EmailMessage  # Django內建函式庫，用於發送電子郵件
from django.urls import reverse  # Django內建函式庫，用於生成URL地址
import django  # Django的主要套件
from django.utils.encoding import force_bytes, force_str,DjangoUnicodeDecodeError  # Django內建函式庫，用於處理字串編碼問題
django.utils.encoding.force_text = force_str  # 設定強制轉換字串編碼的函式
import re  # Python的正則表達式函式庫
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  # Django內建函式庫，用於將二進制數據轉換成URL安全的字串
from django.contrib.sites.shortcuts import get_current_site  # Django內建函式庫，用於獲取當前站點的名稱和域名
from django.template.loader import render_to_string  # Django內建函式庫，用於渲染HTML模板
from .utils import account_activation_token  # 自定義工具函式庫，用於生成帳號激活的令牌
from django.contrib import auth  # Django內建函式庫，用於處理用戶驗證
from django.http import JsonResponse  # Django內建函式庫，用於發送JSON格式的HTTP響應
from .models import User_db  # 註冊用戶模型和管理員模型
from django.contrib.auth import get_user_model
User = get_user_model()
from datetime import datetime, timedelta
from django.views.decorators.csrf import csrf_exempt

from .forms import UserForm
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.forms import SetPasswordForm
from django.core.exceptions import ValidationError

from .forms import UserProfileForm
from django.contrib.auth.password_validation import validate_password
from django.contrib import messages


# 可視圖
# Create your views here.
from django.shortcuts import render
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

from datetime import datetime, timedelta

from datetime import datetime, timedelta
from django.db.models import OuterRef, Subquery

from datetime import datetime, timedelta
from django.db.models import Count
from django.db.models.functions import TruncDay
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView

from django.db.models import Count, F, Func
from datetime import datetime, timedelta
from django.shortcuts import render
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.db.models import Count
from django.db.models.functions import TruncDay
from authentication.models import LoginHistory
import paho.mqtt.client as mqtt

@method_decorator(login_required(login_url='/authentication/login'), name='dispatch')
class IndexView(TemplateView):
    template_name = "authentication/index.html"

    def dispatch(self, *args, **kwargs):
        return super(IndexView, self).dispatch(*args, **kwargs)

    def get_context_data(self, **kwargs):
        user = self.request.user

        # 获取过去7天的日期
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=6)
        date_range = [(end_date - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]

        user_login_history = (
            LoginHistory.objects
            .filter(user=user, login_time__date__range=(start_date, end_date))
            .annotate(date=TruncDay('login_time'))
            .values('date')
            .annotate(count=Count('id'))
            .order_by('date')
        )

        all_login_history = (
            LoginHistory.objects
            .filter(login_time__date__range=(start_date, end_date))
            .annotate(date=TruncDay('login_time'))
            .values('date')
            .annotate(count=Count('id'))
            .order_by('date')
        )

        user_data = {row['date'].strftime('%Y-%m-%d'): row['count'] for row in user_login_history}
        all_data = {row['date'].strftime('%Y-%m-%d'): row['count'] for row in all_login_history}

        # 填充没有登录记录的日期
        user_login_counts = [user_data.get(date, 0) for date in date_range]
        all_counts = [all_data.get(date, 0) for date in date_range]

        # 获取所有用户的登录次数
        users_login_counts = (
            LoginHistory.objects
            .values('user__username')
            .annotate(count=Count('user'))
            .order_by('-count')
        )

        # 将用户名及对应的登录次数分别存储到两个列表中
        usernames = [row['user__username'] for row in users_login_counts]
        user_counts_pie = [row['count'] for row in users_login_counts]

        # 获取当前用户的登录记录
        user_login_history = (
            LoginHistory.objects
            .filter(user=user)
            .order_by('-login_time')
        )

        context = super().get_context_data(**kwargs)
        context['user_labels'] = date_range
        context['user_data'] = user_login_counts
        context['all_labels'] = date_range
        context['all_data'] = all_counts
        context['usernames'] = usernames
        context['user_counts'] = user_counts_pie
        context['user_login_history'] = user_login_history
        return context



#判別登入
#pipenv install validate-email email判別
class EmailValidationView(View):
    # 處理電子郵件驗證的視圖函式
    def post(self,request):
        # 從POST請求中獲取用戶提交的JSON數據，並解析出電子郵件地址
        data=json.loads(request.body)
        email=data['email']
        # 驗證電子郵件地址格式是否正確，如果不正確返回錯誤訊息
        if not validate_email(email):
            return JsonResponse({'email_error':'Email is invalid'}, status=400)
        # 如果電子郵件地址已經被使用，返回錯誤訊息
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error':'sorry email in use,choose another'}, status=409)
        # 如果電子郵件地址可用，返回成功訊息
        return JsonResponse({'email_valid':True})
    
class UsernameValidationView(View):
    # 處理用戶名驗證的視圖函式
    def post(self,request):
        # 從POST請求中獲取用戶提交的JSON數據，並解析出用戶名
        data=json.loads(request.body)
        username=data['username']
        # 驗證用戶名是否只包含字母和數字，如果不是返回錯誤訊息
        if not str(username).isalnum():
            return JsonResponse({'username_error':'username should only contanin alphanmueric characters'}, status=400)
        # 如果用戶名已經被使用，返回錯誤訊息
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error':'sorry username in use,choose another'}, status=409)
        # 如果用戶名可用，返回成功訊息
        return JsonResponse({'username_valid':True})


class RegistrationView(View):
    # 處理用戶註冊的視圖函式
    def get(self,request):
        # 處理GET請求，返回註冊頁面
        return render(request,'authentication/register.html')
    
    def post(self,request):
        # 處理POST請求，從表單中獲取用戶提交的資訊
        username=request.POST['username']
        email=request.POST['email']
        password=request.POST['password']

        context={
            'fieldValues': request.POST
        }

        # 檢查用戶名是否已被使用
        if not User.objects.filter(username=username).exists():
            # 檢查電子郵件地址是否已被使用
            if not User.objects.filter(email=email).exists():
                # 檢查密碼是否符合要求
                if len(password) < 8:
                    messages.error(request, 'Password must be at least 8 characters long')
                    return render(request, 'authentication/register.html',context)
                if not re.search(r'[A-Z]', password):
                    messages.error(request, 'Password must contain at least one uppercase letter')
                    return render(request, 'authentication/register.html')
                if not re.search(r'[a-z]', password):
                    messages.error(request, 'Password must contain at least one lowercase letter')
                    return render(request, 'authentication/register.html')
                
                # 創建用戶
                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.is_active=False
                user.save()

                # 生成帳號激活鏈接，並發送帳號激活郵件
                uidb64=urlsafe_base64_encode(force_bytes(user.pk))
                domain=get_current_site(request).domain
                link=reverse('activate',kwargs={'uidb64':uidb64,'token':account_activation_token.make_token(user)})
                activate_urls="http://"+domain+link
                email_body='Hi'+ user.username + 'Please use this link to verify your account\n' + activate_urls
                email_subject='Activate your account'
                email = EmailMessage(
                    email_subject,
                    email_body,
                    'noreply@semycolon.com',
                    [email],
                )
                email.send(fail_silently=False)
                messages.success(request, 'Your account has been created!')
            else:
                # 電子郵件地址已被使用，返回錯誤訊息
                messages.error(request, 'Email address is already in use')
                return render(request,'authentication/register.html',context)
        else:
            # 用戶名已被使用，返回錯誤訊息
            messages.error(request, 'Username is already in use')
            return render(request,'authentication/register.html',context)

        # 返回註冊頁面
        return render(request,'authentication/register.html')


class VerificationView(View):
    # 處理帳號激活的視圖函式
    def get(self, request, uidb64, token):
        # 解析出URL中的用戶ID和激活token
        try:
            id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=id)

            # 檢查激活token是否正確，如果不正確返回錯誤訊息
            if not account_activation_token.check_token(user, token):
                return redirect('login'+'?message='+'User already activated')

            # 檢查用戶是否已經激活過，如果已經激活過返回錯誤訊息
            if user.is_active:
                return redirect('login')
            # 激活用戶
            user.is_active=True
            user.save()

            messages.success(request, 'Account activated successfully')
            return redirect('login')

        except Exception as ex:
            pass

        # 如果出現異常，重定向到登入頁面
        return redirect('login')


class LoginView(View):
    # 處理用戶登入的視圖函式
    def get(self, request):
        # 處理GET請求，返回登入頁面
        return render(request, 'authentication/login.html')
    
    def post(self, request):
        # 處理POST請求，從表單中獲取用戶名和密碼
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            # 驗證用戶名和密碼是否正確
            user=auth.authenticate(username=username, password=password)

            if user:
                # 檢查用戶是否已經激活，如果已經激活則進行登入，否則返回錯誤訊息
                if user.is_active:
                    auth.login(request, user)

                    messages.success(request, 'Welcome, ' + user.username+' you are now logged in')

                    return redirect('index')

                messages.error(request,'Account is not active, please check your email')
                return render(request, 'authentication/login.html')
            
            messages.error(request,'Invalid credentials,try again')
            return render(request, 'authentication/login.html')
        
        messages.error(request,'Please fill all fields')
        return render(request, 'authentication/login.html')


class LogoutView(View):
    # 處理用戶登出的視圖函式
    def post(self, request):
        # 進行登出操作
        auth.logout(request)
        messages.success(request, 'You have been logged out')
        return redirect('login')



def edit_user(request, user_id):
    user = User_db.objects.get(pk=user_id)
    if request.method == 'POST':
        form = UserForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect('edit_user', user_id=user_id)
    else:
        form = UserForm(instance=user)
    return render(request, 'edit_user.html', {'form': form})



def users(request):
    users = User_db.objects.all()
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('users')
    else:
        form = UserForm()
    return render(request, 'users.html', {'users': users, 'form': form})

def delete_user(request, user_id):
    user = get_object_or_404(User_db, pk=user_id)
    user.delete()
    return redirect('users')

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password, make_password
from .forms import UserProfileForm
from django.contrib.auth.password_validation import validate_password
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import update_session_auth_hash


@login_required
def edit_profile(request):
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            user = form.save(commit=False)

            # 处理上传的图片
            profile_image = request.FILES.get('profile_image')
            if profile_image:
                fs = FileSystemStorage()
                filename = fs.save(profile_image.name, profile_image)
                user.profile_image = filename

            # 检查是否需要更新密码
            old_password = form.cleaned_data.get('old_password')
            new_password = form.cleaned_data.get('new_password')
            confirm_password = form.cleaned_data.get('confirm_password')
            if old_password and new_password and confirm_password:
                # 確認原始密碼是否正確
                if not request.user.check_password(old_password):
                    form.add_error('old_password', '原始密码错误')
                else:
                    # 確認新密碼和確認密碼是否一致
                    if new_password != confirm_password:
                        form.add_error('confirm_password', '新密码和确认密码不匹配')
                    else:
                        # 檢查新密碼是否符合規範
                        try:
                            validate_password(new_password, user)
                        except ValidationError as e:
                            form.add_error('new_password', e)
                        else:
                            user.set_password(new_password)
                            update_session_auth_hash(request, user)
            
            user.save()
            messages.success(request, '個人資料已更新')
            return redirect('edit_profile')
    else:
        form = UserProfileForm(instance=request.user)
    return render(request, 'edit_profile.html', {'form': form})


from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.urls import reverse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login
from .forms import ForgotPasswordForm, ResetPasswordForm
from .models import User_db

def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = User_db.objects.get(email=email)
            token = default_token_generator.make_token(user)
            reset_url = request.build_absolute_uri(reverse('reset_password', args=[user.pk, token]))
            if not send_mail(
                '重置密码',
                f'请点击以下链接重置您的密码：\n\n{reset_url}',
                'YOUR_EMAIL_ADDRESS',  # 请替换为您自己的电子邮件地址
                [email],
                fail_silently=False,
            ):
                messages.error(request, '邮件发送失败')
            else:
                messages.success(request, '邮件已发送')
            return render(request, 'forgot_password.html')
    else:
        form = ForgotPasswordForm()
    return render(request, 'forgot_password.html', {'form': form})

def reset_password(request, user_id, token):
    user = get_object_or_404(User_db, pk=user_id)
    if not default_token_generator.check_token(user, token):
        return render(request, 'reset_password_invalid.html')

    if request.method == 'POST':
        form = ResetPasswordForm(user=user, data=request.POST)
        if form.is_valid():
            user.password = make_password(form.cleaned_data['new_password1'])
            user.save()
            # 让用户自动登录
            user = authenticate(request, username=user.username, password=form.cleaned_data['new_password1'])
            login(request, user)
            return redirect('login')
    else:
        form = ResetPasswordForm(user=user)

    return render(request, 'reset-password.html', {'form': form})

# 修改後的 views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

from .models import User_db as User

def search(request):
    if 'q' in request.GET:
        search_query = request.GET['q']
        users = User.objects.filter(username__icontains=search_query)
        return render(request, 'search.html', {'users': users})
    else:
        return render(request, 'search.html')


from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.utils import timezone
from .models import LoginHistory

@receiver(user_logged_in)
def record_login_time(sender, user, request, **kwargs):
    login_method = 'web'  # 例如：设置登录方式为网络登录
    LoginHistory.objects.create(user=user, login_time=timezone.now(), login_method=login_method)


from django.shortcuts import render

def custom_404(request):
    return render(request, 'custom_404.html', status=404)


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import PasswordLockLogin
from .forms import PasswordLockLoginForm
from django.contrib import messages

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect
import paho.mqtt.client as mqtt

@login_required
def password_lock(request):
    user = request.user
    try:
        password_lock_login = PasswordLockLogin.objects.get(user=user)
        if not password_lock_login.password:
            raise PasswordLockLogin.DoesNotExist
        action = 'update'
    except PasswordLockLogin.DoesNotExist:
        password_lock_login = None
        action = 'create'

    if request.method == 'POST':
        form = PasswordLockLoginForm(request.POST)
        if form.is_valid():
            if action == 'create':
                password_lock_login = PasswordLockLogin(user=user)
                
            password_lock_login.set_password(form.cleaned_data['password1'])
            password_lock_login.save()
            messages.success(request, '密碼已更新')

            # 创建 MQTT 客户端
            client2 = mqtt.Client()
            # 连接到 MQTT Broker
            client2.connect("broker.hivemq.com", 1883, 60)

            # 从表单中获取明文密码
            plain_password = form.cleaned_data["password1"]
            print(plain_password)
            # 将明文密码发送到 MQTT 代理
            client2.publish("keypad", plain_password)

            return redirect('password_lock')
        else:
            messages.error(request, '密碼不匹配')
            print("Form is not valid")
    else:
        form = PasswordLockLoginForm()

    return render(request, 'password_lock.html', {'form': form, 'action': action})



from django.http import HttpResponse

from django.db.models import F

def update_user_ids(request):
    id_mapping = {
        -1: 0,
        #2: 1,
        #3: 2
    }

    for user in User_db.objects.all():
        old_id = user.id
        new_id = id_mapping.get(old_id)
        if new_id:
            # 修改用户名以避免重复
            original_username = user.username
            user.username = f"temp_{user.username}"
            user.save()

            # 更新用户ID
            user.id = new_id

            # 恢复原始用户名并保存
            user.username = original_username
            user.save()

    # 删除原ID为5的用户记录
    #User_db.objects.filter(id=5).delete()

    return HttpResponse("User IDs have been updated.")


def update_login_history_user_ids(request):
    id_mapping = {
        1: 10,
        #2: 2,
        #5: 3
    }

    for login_history in LoginHistory.objects.all():
        old_user_id = login_history.user_id
        new_user_id = id_mapping.get(old_user_id)

        if new_user_id:
            # 更新LoginHistory中的user外键
            login_history.user_id = new_user_id
            login_history.save()

    return HttpResponse("LoginHistory user IDs have been updated.")



from django.http import HttpResponse
from authentication.models import User_db

def delete_user_by_id(request, user_id):
    try:
        user_to_delete = User_db.objects.get(id=user_id)
        user_to_delete.delete()
        return HttpResponse("User deleted successfully.")
    except User_db.DoesNotExist:
        return HttpResponse("User not found.")


#USE webproject;
#INSERT INTO user (id, password, last_login, is_superuser, username, first_name, last_name, email, is_staff, is_active, date_joined, created_at, updated_at, profile_image, address, gender)
#VALUES (0, '', NOW(), 0, 'admin', '', '', '', 0, 0, NOW(), NOW(), NOW(), 'default_profile_image.jpg', 'Taipei', 'F')



