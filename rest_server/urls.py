"""rest_server URL Configuration

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
from django.conf.urls import include
from django.urls import path
from django.contrib import admin
from rest_framework import routers
from rest_framework_swagger.views import get_swagger_view
from member import views
import member.api


app_name = 'member'

router = routers.DefaultRouter()
router.register('members', member.api.MemberViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/doc', get_swagger_view(title='Rest API Document')),
    path('api-auth/', include('rest_framework.urls')),

    path('api/members/', views.member_list),   # 학생 회원가입
    path('api/password/', views.password),     # 간편 비밀번호 저장 및 찾기 
    path('api/authkey/', views.auth_key),      # params key 검증
    path('api/regeneratedid/', views.regenerate_did),    # DID 재발급
    path('api/getdid/', views.get_did),        # DID 찾기
    path('api/findmyinfo/', views.findmyinfo), # 회원 찾기
    path('api/getentry/', views.get_entry), # Block Chain 상에서 출입 tx GET
    path('api/generateentry/', views.generate_entry),  # 출입 여부 등록 (tx 발생)
    path('api/entry/', views.entry_list),   # 학생용. 개인 출입 list 조회
    path('api/entryadmin/', views.entry_admin), # 관리자용. 특정 강의동 출입 인원 list 조회
    path('api/admincheck/', views.check_adminkey),  # 관리자 임시키 올바른지 검증
]
