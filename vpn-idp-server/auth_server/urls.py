from django.contrib import admin
from django.urls import path
from auth_server.views import *
from auth_server.views.mvt.protected.views import logout_view
from auth_server.views.mvt.public.views import login_idp_view, login_callback_view, login_view
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = [
    path('admin/', admin.site.urls),
    path('logout/', logout_view, name='logout'),
    path('accounts/login/', login_view, name='login'),
    path('accounts/login/<slug:auth_idp>/', login_idp_view, name='login_idp'),
    path('accounts/login_callback/', login_callback_view, name='login_callback'),
] + staticfiles_urlpatterns()
