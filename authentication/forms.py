from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, SetPasswordForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, validate_email
from .models import User_db
from django import forms
from .models import PasswordLockLogin

class UserForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User_db
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 为密码字段添加验证器
        validator = RegexValidator(
            regex=r'^(?=.*[A-Z])(?=.*\d).{8,}$',
            message='密碼必須至少包含8個字符和至少一個大小寫字母',
        )
        self.fields['password1'].validators.append(validator)
        self.fields['password2'].validators.append(validator)

class UserProfileForm(forms.ModelForm):
    old_password = forms.CharField(widget=forms.PasswordInput(), label='原始密碼', required=False)
    new_password = forms.CharField(widget=forms.PasswordInput(), label='新密碼', required=False)
    confirm_password = forms.CharField(widget=forms.PasswordInput(), label='確認新密碼', required=False)
    profile_image = forms.ImageField(required=False)

    GENDER_CHOICES = [
        ('', '請選擇性別'),
        ('M', '男'),
        ('F', '女'),
        ('O', '其他'),
    ]

    gender = forms.ChoiceField(
        choices=GENDER_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = User_db
        fields = ['username', 'email', 'first_name', 'last_name', 'profile_image', 'address', 'gender']
        exclude = ['password']
    
    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            validate_email(email)
        except ValidationError:
            raise forms.ValidationError('請輸入有效的電子郵件地址')
        return email

    def clean_new_password(self):
        new_password = self.cleaned_data['new_password']
        if new_password:
            try:
                validate_password(new_password, self.instance)
            except ValidationError as e:
                raise forms.ValidationError(e)
        return new_password


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField()

    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            user = User_db.objects.get(email=email)
        except User_db.DoesNotExist:
            raise forms.ValidationError('無效的電子郵件地址')
        return email

class ResetPasswordForm(forms.Form):
    new_password1 = forms.CharField(label='新密碼', widget=forms.PasswordInput(
        attrs={'class': 'form-control form-control-user', 'placeholder': '新密碼'}))
    new_password2 = forms.CharField(label='確認新密碼', widget=forms.PasswordInput(
        attrs={'class': 'form-control form-control-user', 'placeholder': '確認新密碼'}))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')  # 从 kwargs 中移除 user
        super().__init__(*args, **kwargs)
    
    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get("new_password1")
        new_password2 = cleaned_data.get("new_password2")
        if new_password1 and new_password2 and new_password1 != new_password2:
            raise forms.ValidationError(
                "新密碼和確認密碼不匹配！請重新輸入")
        if len(new_password1) < 8:
            raise forms.ValidationError(
                "新密碼長度應不少於8個字符")
        if not any(char.isdigit() for char in new_password1) or \
            not any(char.isupper() for char in new_password1) or \
            not any(char.islower() for char in new_password1):
            raise forms.ValidationError(
                "新密碼應至少要8個字且要包含數字、大小寫字母")
        return cleaned_data





from django import forms
from .models import PasswordLockLogin
from django.core.exceptions import ValidationError

class PasswordLockLoginForm(forms.ModelForm):
    password1 = forms.CharField(
        label="密码",
        strip=False,
        widget=forms.PasswordInput(attrs={'placeholder': 'Password'}),
    )
    password2 = forms.CharField(
        label="确认密码",
        strip=False,
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}),
    )

    class Meta:
        model = PasswordLockLogin
        fields = ('password1', 'password2')

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise ValidationError("密码不匹配")
        return password2

