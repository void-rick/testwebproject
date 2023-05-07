from django.shortcuts import render
from django.contrib.auth.decorators import login_required
# Create your views here.


@login_required(login_url='/authentication/login')

def index(request):
    return render(request,'project_app/index.html')


def add_project(request):
    return render(request,'project_app/add_project.html')