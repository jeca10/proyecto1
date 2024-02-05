from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.db import IntegrityError
from .forms import TaskForm
from .models import Task
from django.utils import timezone
import re

# Create your views here.
def home(request):
    return render(request, 'home.html',)

def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')

            # Validar contraseña con expresión regular
            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,}$', password):
                return render(request, 'signup.html', {
                    'form': form,
                    'error': 'La contraseña debe tener al menos una mayúscula, una minúscula, un número y un carácter especial.'
                })

            try:
                user = User.objects.create_user(username=username, password=password)
                user.save()
                login(request, user)
                return redirect('tasks')
            except IntegrityError:
                return render(request, 'signup.html', {
                    'form': form,
                    'error': 'El usuario ya existe'
                })
        else:
            return render(request, 'signup.html', {
                'form': form,
                'error': 'La contraseña debe tener al menos una mayúscula, una minúscula, un número y un carácter especial.'
            })
    else:
        return render(request, 'signup.html', {
            'form': UserCreationForm()
        })
       

def tasks(request):
    tasks = Task.objects.filter(user=request.user, datecompleted__isnull=True)
    return render(request, 'tasks.html', {"tasks": tasks})

def create_task(request):
    if request.method == "GET":
        return render(request, 'create_task.html', {
            'form': TaskForm
        })
    else:
        try:
            form=TaskForm(request.POST)
            new_task = form.save(commit=False)
            new_task.user = request.user
            new_task.save()
            return redirect('tasks')
        except ValueError:
            return render(request, 'create_task.html', {
                'form': TaskForm,
                "error": 'Error al crear la tarea'
            })

def desconectar(request):
    logout(request)
    return redirect('home')

def task_detail(request, task_id):
   if request.method == "GET":
        task =get_object_or_404(Task, pk=task_id, user=request.user)
        form = TaskForm(instance=task)
        return render(request, 'task_detail.html', {'task': task, 'form': form})
   else:
      try:
            task =get_object_or_404(Task, pk=task_id, user=request.user)
            form = TaskForm(request.POST, instance=task)
            form.save()
            return redirect('tasks')
      except ValueError:
            return render(request, 'task_detail.html', {'task': task, 'form': form,
            'error': "error al actualizar"    
            })


def complete_task(request, task_id):
    task = get_object_or_404(Task, pk=task_id, user=request.user)
    if request.method == 'POST':
        task.datecompleted = timezone.now()
        task.save()
        return redirect('tasks')

def delete_task(request, task_id):
    task = get_object_or_404(Task, pk=task_id, user=request.user)
    if request.method == 'POST':
        task.delete()
        return redirect('tasks')

def signin(request):
    if request.method == 'GET':
        return render(request, 'signin.html', {
            'form': AuthenticationForm
        })
    else:
        user = authenticate(
            request, usermame=request.POST['username'], password=request.POST
            ['password'])
        if user is None:
            return render(request,'signin.html', {
                'form': AuthenticationForm,
                "error": 'username or password is incorrect'
            })
        else:
            login(request, user)
            return redirect('tasks')
         

        