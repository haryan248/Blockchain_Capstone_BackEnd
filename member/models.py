from django.db import models

class Member(models.Model):    # 회원가입 학생 정보 저장 테이블 스키마
    email = models.EmailField(max_length=100, primary_key=True)
    user_key = models.CharField(max_length=200, unique=False, null=True)
    wallet_id = models.CharField(max_length=200, unique=False, null=True)
    wallet_key = models.CharField(max_length=30, null=True)
    did = models.CharField(max_length=200, unique=False, null=True)
    did_time_hash =  models.CharField(max_length=200, unique=False, null=True)
    position = models.CharField(max_length=30, null=True, blank=True)
    container_id = models.CharField(max_length=100, null=True, blank=True)

class Entry(models.Model) :    # 건물 출입 트랜잭션 저장 테이블 스키마
    entry_date = models.CharField(max_length=50, null=True)
    building_num = models.CharField(max_length=30, null=True)
    entry_did = models.CharField(max_length=100, null=True)
    entry_time = models.CharField(max_length=20, null=True)

