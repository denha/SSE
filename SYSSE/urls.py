"""SYSSE URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from keygen.views import *
from authapp.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('generate-key-pair', gen_public_private_key, name="publish_public_key"),
    path("view-public-key/<str:alias>", view_public_key),
    path("generate-secret-key/<str:key>/<str:owner>", generate_data_owner_keys),
    path("get-secret-key/<str:key>/<str:owner>", get_secret_key),
    path("check-secret-key/<str:key>/<str:owner>", check_kske),
    path('user-add', user_register, name='user-add'),
    path('user-login', user_login, name='user-login'),
    path('publish-key/<uuid:key>', publish_keypair),
    path('encrypt/<str:owner>', encrypt),
    path('upload/<str:data_owner>', upload),
    path('search/<str:word>/<str:owner>', searches),
    path('download/<str:file>', download),
    path('decrypt/<str:file>/<str:owner>/<str:user_id>', decrypt_download),
    path('view-file/<str:file>/<str:owner>/<str:user_id>', view_file),
    path('data-owner', data_owners),
    path("fetch-key/<str:key>/<str:owner>", fetch_keys),
    path("fetch-files/<str:path>", file_select),
    path('auth/dropbox/<str:dataowner>', auth_index, name='dropbox_auth'),
    path('callback/', callback, name='dropbox_auth_callback'),
    path('webhook', webhook, name='webhook'),
    path('autoscript', AutoScript, name='webhook'),
    path('policy',data_policy,name='policy'),
    path('view-policy/<str:owner>',view_policy,name='view-policy')
]
