from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from .models import Member
from .models import Entry
from .serializers import MemberSerializer
from .serializers import EntrySerializer
from subprocess import Popen, PIPE, STDOUT
import subprocess
import hashlib
import json
import os
import random
import base62
import asyncio
import time
from django.core.paginator import Paginator
from asgiref.sync import async_to_sync
from asgiref.sync import sync_to_async

temp_key = "이팔청춘의 U-PASS"  # tmpkey 선언
admin_key = "admin"  # adminkey 선언
master_did = "HHy8vS8zkfbQXwuAZQmBoV"  # 마스터 DID
container_id_list = [None, '4d2c5ca4e19e', 'dfdbb4abf23f', '3312fbe95203', 'bed25d0b5f45', '5d59ba08653d'] # 생성한 컨테이너 id 리스트


# Key가 DB에 존재하는지 확인
def check_db(api_key):
    student_db = Member.objects.all()  # Member테이블의 모든 튜플 GET
    if student_db.filter(user_key=api_key).exists(): # 전달 받은 key가 db에 존재한다면,
        return True    # True 반환
    else:              # 전달 받은 key가 db에 존재하지 않는다면,
        return False   # False 반환


# DID 검증
def check_did(did, time_stamp, hashed_data):
    # hashedData : qr에 담겨진 H(H(did + 간편비번))

    student = Member.objects.get(did=did)  # 전달 받은 did에 해당하는 Member DB의 튜플을 GET
    cmp1 = str(student.did_time_hash) + str(time_stamp)
    cmp1_hash = hashlib.sha256(cmp1.encode('utf-8')).hexdigest()

    if hashed_data == cmp1_hash:  #전달 받은 정보로 해쉬한 결과가 일치한다면,
        return True
    else:
        return False


# TimeStamp 검증( 오차허용범위  ±15sec )
def check_timestamp(qr):
    api_timestamp = time.time()
    api = int(api_timestamp)
    if abs(api - int(qr)) <= 15:  # 시간 차가 15초 이하라면,
        return True
    else:
        return False


# container_id 체크
def check_container_id():
     container_num = 1
     for i in range(1, len(container_id_list), 1):
         member_db_con_count = Member.objects.filter(container_id=container_id_list[i]).count() # 컨테이너별 가입된 회원 수 반환
         if member_db_con_count == 10:  # 해당 container id로 가입된 회원이 10명이라면,
             container_num = container_num + 1   # 다음 container id 인덱스 번호 지정
     return container_num # container 리스트의 인덱스 번호 반환


# 관리자 임시키 검증
@csrf_exempt
def check_adminkey(request):
    if request.method == 'GET':
        if not 'key' in request.GET:
            return JsonResponse({'msg': 'parmas error'}, status=400)

        ad_key = request.GET.get('key', None)     # params로 전달 받은 관리자 임시 키
        compare_key = hashlib.sha256(admin_key.encode()).hexdigest()  # 올바른 관리자 임시 키

        if ad_key == compare_key:
            return JsonResponse({'msg': 'Admin key success'}, status=201)
        elif ad_key != compare_key:
            return JsonResponse({'msg': 'Key is error'}, status=400)


# 올바른 키인지 체크
@csrf_exempt
def auth_key(request):
    if request.method == 'GET':
        key = request.GET.get('key', None)  # params로 받은 key값 추출

        student_db = Member.objects.all()   # Member 테이블의 모든 튜플 추출
        if student_db.filter(user_key=key).exists():  # 추출한 튜플 중 전달 받은 key값이 존재 한다면,
            student = Member.objects.filter(user_key=key)
            position = student[0].position     # 전달 받은 키 값에 해당하는 튜플의 position 컬럼 값 추출

            if position == 'admin':   # position 값이 admin 이라면,
                ad_key = request.GET.get('admin_key', None)  # 전닫 받은 admin_key 추출
                compare_key = hashlib.sha256(admin_key.encode()).hexdigest() # '이팔청춘의 관리자' 해쉬
                if ad_key == compare_key:  # 전달 받은 key와 올바른 해쉬 값을 비교하여 동일하다면,
                    return JsonResponse({'msg': 'Admin key success'}, status=201)
                elif ad_key != compare_key:  # 전달 받은 key와 올바른 key값이 일치하지 않는다면,
                    return JsonResponse({'msg': 'Admin key is error'}, status=400)

            else:  # position이 admin이 아니라면, 
                return JsonResponse({'msg': 'This is the correct key'}, status=201)
                
        else:  # 추출한 튜플 중 전달 받은 key값이 존재 하지 않는다면,
            return JsonResponse({'msg': 'Key is error'}, status=400)


# 회원 키 GET 및 회원 가입 POST
@csrf_exempt
def member_list(request):
    # 키 발급
    if request.method == 'GET':
        if not 'key' in request.GET:  # key를 파라미터로 주지 않는다면,
            return JsonResponse({'msg': 'params error'}, status=400)

        api_key = request.GET.get('key', None)   # key 파라미터 추출
        if api_key != hashlib.sha256(temp_key.encode()).hexdigest(): # key 파라미터가 올바르지 않으면,
            return JsonResponse({'msg': 'key params error'}, status=400)

        student_db = Member.objects.all()   # Member 테이블의 모든 튜플 추출
        std_num = request.GET.get('std_num', None) # 전달 받은 학번 추출
        major = request.GET.get('major', None)  # 전달 받은 전공 추출
        name = request.GET.get('name', None)    # 전달 받은 이름 추출
        email = request.GET.get('email', None)  # 전달 받은 이메일 추출

        if student_db.filter(email=email).exists():  # params로 전달받은 이메일이 DB에 존재하는지 확인
            return JsonResponse({'msg': 'Email is already exists'}, status=400)
       
        # info_dump에 전달 받은 정보 concat
        info_dump = str(std_num) + str(major) + str(email)  # 학번 + 전공 + 이메일
        info_hash = hashlib.sha256(info_dump.encode('utf-8')).hexdigest() # sha256 해쉬

        container_num = check_container_id() # container_id_list 인덱스 번호 추출
        command = ["sh", "../indy/start_docker/sh_check_attrib.sh",
                   container_id_list[container_num], master_did, info_hash, std_num]  # did발급 명령어
        try:
            # 명령어 인자로 하여 Popen 실행
            process = Popen(command, stdout=PIPE, stderr=PIPE)
            process.wait()  
            with open('../../deploy/' + std_num + '_check_attrib.json')as f:  
                json_data = json.load(f)  
                error = json_data['error']
                if error == 'Error':  # 생성된 JSON파일의 error 키 값이 Error이라면,
                    os.remove('/home/deploy/' + std_num + '_check_attrib.json')  # 생성된 파일 삭제
                    return JsonResponse({'msg': 'user info is not exists in blockchain'}, status=400)
                os.remove('/home/deploy/' + std_num + '_check_attrib.json')  # 생성된 파일 삭제
                # user_key 해시 하는 부분
                salt = base62.encodebytes(os.urandom(16)) # salt값 생성
                salt = bytes(salt, encoding="utf-8")

                email_dump = info_dump + str(name) + str(salt) # 학번 + 전공 + 이메일 + 이름 + 솔트
                user_key = hashlib.sha256(email_dump.encode('utf-8')).hexdigest()  # user_key 해쉬
                user_key_json = {'user_key': ''}
                user_key_json['user_key'] = user_key

                return JsonResponse(user_key_json, status=201)   # user_key 값 반환
        except Exception as e:
            return JsonResponse({'msg': 'failed_Exception', 'error': str(e)}, status=400)
            

    # 회원가입  요청 +  did 발급
    if request.method == 'POST':
        email = request.GET.get('email', None)  # 전달 받은 이메일 값 추출
        student_db = Member.objects.all()       # Member 테이블의 모든 튜플 추출

        user_key = request.GET.get('key', None)  # 전달 받은 key 추출
        std_num = request.GET.get('std_num', None) # 전달 받은 학번 추출
        major = request.GET.get('major', None)    # 전달 받은 전공 추출
        time_stamp = int(time.time())  # 타임스탬프

        # wallet_name (이메일 + timestamp) 생성
        wallet_name = hashlib.sha256((email + str(time_stamp)).encode()).hexdigest()
        wallet_key = request.GET.get('simple_password', None)  # 간편 pwd 추출

        container_num = check_container_id() # container_id_list 인덱스 번호 추출
        command = ["sh", "../indy/start_docker/sh_generate_did.sh",
                   container_id_list[container_num], wallet_name, wallet_key, std_num]  # did발급 명령어
        try:
            # 명령어 인자로 하여 Popen 실행
            process = Popen(command, stdout=PIPE, stderr=PIPE)
            process.wait()  # did 재발급까지 대기
            
            with open('../../deploy/' + wallet_name + '_gen_did.json')as f:  # server로 복사된 did 열기
                json_data = json.load(f)  # json_data에 json으로 저장
                error = json_data['error']
                if error == 'Error':  # 생성된 json파일의 error 키 값이 Error 이라면,
                    os.remove('/home/deploy/' + wallet_name + '_gen_did.json')  # 생성된 파일 삭제
                    return JsonResponse({'msg': 'DID generate error'}, status=400)
                os.remove('/home/deploy/' + wallet_name + '_gen_did.json')  # 생성된 파일 삭제
                did = json_data['did']  # Did 저장
                cmp1 = str(did) + str(wallet_key)
                did_time_hash = hashlib.sha256(cmp1.encode('utf-8')).hexdigest()

                position = request.GET.get('position', None)  # 관리자 인지 여부 추출
                if position == 'admin':    # 관리자 회원가입 이라면,
                    data = {'email': '', 'user_key': '', 'wallet_id': '',  'did': '', # json 형태로 저장 
                            'did_time_hash': '', 'position': '', 'container_id': ''}
                    data['email'] = email
                    data['user_key'] = user_key
                    data['wallet_id'] = wallet_name
                    data['did'] = did
                    data['did_time_hash'] = did_time_hash
                    data['position'] = position
                    data['container_id'] = container_id_list[container_num]

                else:                     # 일반 사용자 회원 가입이라면
                    data = {'email': '', 'user_key': '', 'wallet_id': '',  
                            'did': '', 'did_time_hash': '', 'container_id':''}
                    data['email'] = email
                    data['user_key'] = user_key
                    data['wallet_id'] = wallet_name
                    data['did'] = did
                    data['did_time_hash'] = did_time_hash
                    data['container_id'] = container_id_list[container_num]

                serializer = MemberSerializer(data=data)

                if serializer.is_valid():  # 입력 data들 포맷 일치 여부 확인
                    serializer.save()      # 해당 data를 Member 테이블에 저장
                    return JsonResponse({'did': did, 'error': error}, status=201)

        except Exception as e:  # 예외 처리
            return JsonResponse({'msg': 'failed_Exception', 'error': str(e)}, status=400)


# 간편 비밀번호 저장(POST) 및 찾기(GET)
@csrf_exempt
def password(request):
    # 간편 비밀번호 저장
    if request.method == 'POST':
        if not 'key' in request.GET:  # params로 key를 보내지 않았다면
            return JsonResponse({'msg': 'params error'}, status=400)
        if not 'simple_password' in request.GET: # params로 simple_password를 보내지 않았다면
            return JsonResponse({'msg': 'params error'}, status=400)

        api_key = request.GET.get('key', None)  # key 추출
        wallet_key = request.GET.get('simple_password', None)  # 간편 pwd 추출

        # DB에 해당 키가 존재한다면, 해당 튜플에 간편비밀번호 저장
        if check_db(api_key):    # 전달 받은 key 값이 올바른 키인지 검증, 올바르다면,
            student = Member.objects.get(user_key=api_key)  # 전달 받은 key값에 해당하는 Member튜플 추출
            student.wallet_key = wallet_key  # 해당 튜플의 wallet_key 컬럼 값을 전달 받은 simple_password로 저장
            student.save()  # 저장
            return JsonResponse({'msg': "save complete"}, status=201)
        else:
            return JsonResponse({'msg': 'Key is error'}, status=400)

    # 간편 비밀번호 찾기
    elif request.method == 'GET':
        if not 'key' in request.GET: # params로 key를 보내지 않았다면,
            return JsonResponse({'msg': 'parmas error'}, status=400)

        api_key = request.GET.get('key', None)  # key 추출
        if check_db(api_key):   # 해당 키가 DB에 존재 한다면,
            student = Member.objects.get(user_key=api_key)  # 해당 학생 정보 저장
            wallet_key = student.wallet_key
            if wallet_key is None:    # wallet_key 값이 DB에 저장되어 있지 않을때
                return JsonResponse({'msg': 'wallet_key is empty'}, status=400)

            return JsonResponse({'wallet_key': wallet_key}, status=201) # wallet_key값 반환
        else:
            return JsonResponse({'msg': 'Key is error'}, status=400)

# DID 재발급
@csrf_exempt
def regenerate_did(request):
    if request.method == 'POST':
        if not 'key' in request.GET:  # params로 key값을 보내지 않았다면,
            return JsonResponse({'msg': 'parmas error'}, status=400)

        api_key = request.GET.get('key', None)  # key 추출
        if check_db(api_key): # 전달 받은 key값이 올바른 값이라면,
            # DB에서 key 가지고 email, did 가져오기
            student = Member.objects.get(user_key=api_key)
            old_wallet_name = student.wallet_id  # 기존 wallet_id 값 저장
            did = student.did  # did
            email = student.email  # 이메일
            time_stamp = int(time.time())  # 타임스탬프
            # wallet_name (이메일 + timestamp) 생성
            new_wallet_name = hashlib.sha256((email + str(time_stamp)).encode()).hexdigest() #새로운 wallet_name 저장
            wallet_key = request.GET.get('simple_password', None)  # 간편 pwd 추출
            std_num = request.GET.get('std_num', None)  # 학번 params 가져오기

            # DB에 wallet_name 저장 필요
            container_id = student.container_id # container_id_list 인덱스 번호 구하기
            command = ["sh", "../indy/start_docker/sh_regenerate_did.sh", container_id,
                       did, std_num, email, new_wallet_name, wallet_key]  # did 재발급 명령어
            try:
                # 명령어 인자로 하여 Popen 실행
                process = Popen(command, stdout=PIPE, stderr=PIPE)
                process.wait()  # did 발급까지 대기

                # server로 복사된 did 열기
                with open('/home/deploy/' + str(std_num) + 'NewWalletID.json') as f:
                    json_data = json.load(f)  # json_data에 json으로 저장
                    # 에러 추가
                    if json_data['error'] == 'Error': # 생성된 JSON파일의 error키 값이 Error이라면,
                        os.remove('/home/deploy/' + str(std_num) + 'NewWalletID.json')  # 생성된 파일 삭제
                        return JsonResponse({'msg': 'DID regenerate error'}, status=400)
                    new_wallet_name = json_data['new_wallet']
                    student.wallet_id = new_wallet_name  # 새로운 wallet_name 저장
                    cmp1 = str(student.did) + str(wallet_key)
                    student.did_time_hash = hashlib.sha256(cmp1.encode('utf-8')).hexdigest()
                    student.save()
                    os.remove('/home/deploy/' + str(std_num) + 'NewWalletID.json')  # 생성된 파일 삭제
            except Exception as e:     # 예외 처리
                return JsonResponse({'msg': 'failed_Exception', 'error': str(e)}, status=400)
        else: # 전달 받은 key값이 올바른 값이 아니라면,
            return JsonResponse({'msg': 'Key is error'}, status=400)
        return JsonResponse({'did': student.did, 'new_wallet_name': new_wallet_name, 'old_wallet_name': old_wallet_name}, status=201)

# DID 찾기
@csrf_exempt
def get_did(request):
    if request.method == 'GET':
        if not 'key' in request.GET: # params로 key값을 전달하지 않았다면,
            return JsonResponse({'msg': 'parmas error'}, status=400)
        api_key = request.GET.get('key', None)  # key 추출

        if check_db(api_key): # 전달 받은 key값이 올바른 키라면,
            student = Member.objects.get(user_key=api_key)  # 전달 받은 키에 해당하는 Member테이블의 튜플 추출
            wallet_name = student.wallet_id  # wallet_name 디비에서 찾아오기
            wallet_key = request.GET.get('simple_password', None)  # 간편 pwd 추출

            container_id = student.container_id  # container_id_list의 인덱스 값 가져오기
            command = ["sh", "../indy/start_docker/sh_get_did.sh",
                       container_id, wallet_name, wallet_key]
            try:
                # 명령어 인자로 하여 Popen 실행
                process = Popen(command, stdout=PIPE, stderr=PIPE)
                process.wait()  # did 발급까지 대기
                # server로 복사된 did 열기(학생이름으로 필요)
                with open('/home/deploy/' + wallet_name + '_student_did.json')as f:
                    json_data = json.load(f)  # json_data에 json으로 저장
                    os.remove('/home/deploy/' + wallet_name + '_student_did.json')  # 생성된 파일 삭제
                    if json_data['error'] == 'Error': # 생성된 Json파일의 error키 값이 Error이라면,
                        return JsonResponse({'msg': 'DID not found'}, status=400)
            except Exception as e: # 예외 처리
                return JsonResponse({'msg': 'failed_Exception', 'error': str(e)}, status=400)
        else:  # 전달 받은 key값이 올바른 키가 아니라면,
            return JsonResponse({'msg': 'Key is error'}, status=400)
        return JsonResponse(json_data, status=201) # 생성된 json 데이터 반환


# 회원 찾기
@csrf_exempt
def findmyinfo(request):
    if request.method == 'GET':
        if not 'key' in request.GET:  # key를 파라미터로 주지 않는다면,
            return JsonResponse({'msg': 'params error'}, status=400)

        api_key = request.GET.get('key', None)   # key 파라미터 추출
        if api_key != hashlib.sha256(temp_key.encode()).hexdigest(): # key 파라미터가 올바르지 않으면,
            return JsonResponse({'msg': 'key params error'}, status=400)
        
        student_db = Member.objects.all() # Member 테이블의 모든 튜플 추출
        std_num = request.GET.get('std_num', None) # 전달 받은 학번 값 추출
        major = request.GET.get('major', None) # 전달 받은 전공 값 추출
        email = request.GET.get('email', None) # 전달 받은 이메일 값 추출

        if student_db.filter(email=email).exists():  # params로 전달받은 이메일이Member테이블에 존재하는지 확인
            info_dump = str(std_num) + str(major) + str(email)  # 전달 받은 학번,전공,이메일 concat
            info_hash = hashlib.sha256(info_dump.encode('utf-8')).hexdigest()  # 해쉬
            student = Member.objects.get(email=email) # 전달 받은 이메일 값을 가진 Member테이블의 튜플 추출
            container_id = student.container_id    # container_id_list 인덱스 번호 추출
            command = ["sh", "../indy/start_docker/sh_check_attrib.sh",
                   container_id, master_did, info_hash, std_num]  # did발급 명령어
            try:
                # 명령어 인자로 하여 Popen 실행
                process = Popen(command, stdout=PIPE, stderr=PIPE)
                process.wait()  
                with open('../../deploy/' + std_num + '_check_attrib.json')as f:  
                    json_data = json.load(f)  
                    error = json_data['error']
                    if error == 'Error':  # 생성된 Json파일의 error키 값이 Error이라면,
                        os.remove('/home/deploy/' + std_num + '_check_attrib.json')  # 생성된 파일 삭제
                        return JsonResponse({'msg': 'user info is not exists in blockchain'}, status=400)
                    os.remove('/home/deploy/' + std_num + '_check_attrib.json')  # 생성된 파일 삭제
                    std = student_db.get(email=email) # 전달 받은 이메일 값을 가진 Member테이블의 튜플 추출
                    if std.position == 'admin':   # 만약 해당 멤버가 관리자라면,
                        return JsonResponse({'admin_key': hashlib.sha256(admin_key.encode()).hexdigest(),'user_key': std.user_key}, status=201)    # user_key와 admin_key값 반환
                    else:      # 만약 해당 멤버가 관리자가 아니라면,
                        return JsonResponse({'user_key': std.user_key}, status=201)
            except Exception as e:  # 예외 처리
                return JsonResponse({'msg': 'failed_Exception', 'error': str(e)}, status=400)
        else:  # 전달 받은 이메일이 Member 테이블에 존재하지 않는다면,
            return JsonResponse({'msg': 'not join email'}, status=400)
        


# 출입 여부 찾기(Block Chain 상의 tx)
@csrf_exempt
def get_entry(request):
    if request.method == 'GET':
        if not 'key' in request.GET: # params로 key값을 전달하지 않았다면,
            return JsonResponse({'msg': 'parmas error'}, status=400)
        api_key = request.GET.get('key', None)  # key 추출

        if check_db(api_key):  # 전달 받은 key값이 올바른 값이라면,
            user_did = request.GET.get('did', None)  # user did 추출
            admin_did = request.GET.get('admin_did', None) # admin_did 추출
            year = request.GET.get('year', None)  # 연도추출
            month = request.GET.get('month', None)  # 월추출

            student = Member.objects.get(user_key=api_key) # Member테이블에 전달받은 key값에 해당하는 튜플 추출
            container_id = student.container_id  # container_id_list 인덱스 값 추출
            command = ["sh", "../indy/start_docker/sh_get_attrib.sh",
                       container_id, admin_did, user_did, year, month]
            try:
                # 명령어 인자로 하여 Popen 실행
                process = Popen(command, stdout=PIPE, stderr=PIPE)
                process.wait()  # did 발급까지 대기

                with open('/home/deploy/' + user_did + '_attrib.json')as f:  # server로 복사된 did 열기
                    json_data = json.load(f)  # json_data에 json으로 저장
                    os.remove('/home/deploy/' + did + '_attrib.json')  # 생성된 파일 삭제
                    if json_data['error'] == 'Error':  # 생성된 Json파일의 error키 값이 Error이라면,
                        return JsonResponse({'msg': 'not entry'}, status=400)
            except Exception as e: # 예외처리
                return JsonResponse({'msg': 'failed_Exception', 'error': str(e)}, status=400)
        else:  # 전달 받은 key값이 올바른 값이 아니라면,
            return JsonResponse({'msg': 'Key is error'}, status=400)

        return JsonResponse(json_data, status=201) # Json데이터 반환


# 출입 여부 등록
@csrf_exempt
def generate_entry(request):
    if request.method == 'POST':
        if not 'key' in request.GET:   # params로 key값을 전달하지 않았다면,
            return JsonResponse({'msg': 'parmas error'}, status=400)
        api_key = request.GET.get('key', None)  # key 추출

        if check_db(api_key):   # 전달 받은 key값이 올바른 값이라면,
            student = Member.objects.get(user_key=api_key)  # 전달 받은 key에 해당하는 튜플 추출

            wallet_name = student.wallet_id  # wallet_name 생성
            wallet_key = request.GET.get('simple_password', None)  # 간편 pwd 추출
            admin_did = request.GET.get('admin_did', None)  # 간편 pwd 추출
            std_did = request.GET.get('std_did', None)  # user did 추출
            building_num = request.GET.get('building_num', None)  # 출입 건물 추출
            year = request.GET.get('year', None)  # 연도 추출
            month = request.GET.get('month', None)  # 월 추출
            day = request.GET.get('day', None)  # 일 추출
            time_stamp = request.GET.get('time_stamp', None)  # timestamp 추출
            hashed_data = request.GET.get('hashed_data', None)  # hashedData 추출

            if check_timestamp(time_stamp):  # timestamp 유효범위 검증
                if check_did(std_did, time_stamp, hashed_data):  # qr 정보 검증
                    container_id = student.container_id  # container_id_list 인덱스 번호 추출
                    command = ["sh", "../indy/start_docker/sh_generate_attrib.sh",
                               container_id, wallet_name, wallet_key, 
                               admin_did, std_did, building_num, year, month, day]
                    try:
                        # 명령어 인자로 하여 Popen 실행
                        process = Popen(command, stdout=PIPE, stderr=PIPE)
                        process.wait()  # did 발급까지 대기

                        # server로 복사된 did 열기
                        with open('/home/deploy/' + wallet_name + '_gen_attrib.json')as f:
                            json_data = json.load(f)  # json_data에 json으로 저장
                            os.remove('/home/deploy/' + wallet_name + '_gen_attrib.json')  # 생성된 파일 삭제
                            if json_data['error'] == 'Error':  # 생성된 Json파일의 error키 값이 Error이라면,
                                os.remove('/home/deploy/' + wallet_name + '_gen_attrib.json')  # 생성된 파일 삭제
                                return JsonResponse({'msg': 'error'}, status=400)

                            entry_date = json_data['entry_date']  
                            building_num = json_data['building_num']
                            entry_did = json_data['entry_did']
                            entry_time = json_data['entry_time']

                            # 출입 정보 JSON 형태로 저장
                            data = {'entry_date': '', 'building_num': '', 'entry_did': '', 'entry_time': ''}
                            data['entry_date'] = entry_date
                            data['building_num'] = building_num
                            data['entry_did'] = entry_did
                            data['entry_time'] = entry_time

                            serializer = EntrySerializer(data=data)

                            if serializer.is_valid():  # 입력 data들 포맷 일치 여부 확인
                                serializer.save()      # data의 포맷이 일치한다면, DB에 저장

                        return JsonResponse({'msg': 'generate entry complete'}, status=201)
                    except Exception as e:   # 예외 처리
                        return JsonResponse({'msg': 'failed_Exception', 'error': str(e)}, status=400)
                else:  # qr 정보 검증이 실패했다면,
                    temp_admindid = str(student.did_time_hash) + str(time_stamp)
                    return JsonResponse({'msg': 'check_DID error', 'studentDidhash': hashed_data, 'adminDidhash': hashlib.sha256(temp_admindid.encode('utf-8')).hexdigest()}, status=400)
            else:  #timestamp 유효 범위가 아니라면,
                return JsonResponse({'msg': 'timestamp error'}, status=400)
        else:    # 전달 받은 key값이 올바른 값이 아니라면,
            return JsonResponse({'msg': 'Key is error'}, status=400)


# 사용자 기준 출입 기록 GET
@csrf_exempt
def entry_list(request):
    if request.method == 'GET':
        if not 'entry_did' in request.GET:  # params로 entry_did값을 보내지 않았다면,
            return JsonResponse({'msg': 'parmas error'}, status=400)
        if not 'key' in request.GET:        # params로 key값을 보내지 않았다면,
            return JsonResponse({'msg': 'parmas error'}, status=400)

        api_key = request.GET.get('key', None)  # key 추출

        if check_db(api_key):  # 전달 받은 key가 DB에 존재 한다면,
            entry_did = request.GET.get('entry_did', None)   # entry_did값 추출
            entry_db = Entry.objects.filter(entry_did=entry_did)  # Entry테이블에서 전달 받은 entry_did값을 가진 튜플 추출

            if len(entry_db) == 0:  # 전달 받은 출입 did가 출입한 기록이 없다면,
                return JsonResponse({'msg': 'has no entry'}, status=400)

            json_data = {}
            json_data['entry'] = []

            # JSON 형태로 출입 정보 저장
            for i in range(0, len(entry_db), 1):
                entry_data = {}
                entry_data['entry_date'] = entry_db[i].entry_date
                entry_data['building_num'] = entry_db[i].building_num
                entry_data['entry_did'] = entry_db[i].entry_did
                entry_data['entry_time'] = entry_db[i].entry_time

                json_data['entry'].append(entry_data)

            return JsonResponse(json_data, status=201)  # 저장한 출입 정보 반환
        else:  # 전달 받은 key가 DB에 존재 하지 않는다면,
            return JsonResponse({'msg': 'Key is error'}, status=400)


# 관리자 기준 출입 기록 GET(강의동 별)
@csrf_exempt
def entry_admin(request):
    if request.method == 'GET':
        if not 'building_num' in request.GET:   # params로 building_num을 보내지 않았다면,
            return JsonResponse({'msg': 'params error'}, status=400)
        if not 'page_num' in request.GET:       # params로 page_num을 보내지 않았다면,
            return JsonResponse({'msg': 'params error'}, status=400)
        if not 'order' in request.GET:          # params로 order를 보내지 않았다면,
            return JsonResponse({'msg': 'params error'}, status=400)
        if not 'admin_did' in request.GET:      # params로 admin_did를 보내지 않았다면,
            return JsonResponse({'msg': 'params error'}, status=400)

        admin_did = request.GET.get('admin_did', None)   # 전달 받은 admin_did 값 추출
        student_db = Member.objects.all()  # Member 테이블에 저장된 모든 튜플 추출
        if student_db.filter(did=admin_did).exists():  # 전달받은 admin_did가 Member테이블에  존재한다면,
            member_db = Member.objects.filter(did=admin_did)  # 전달 받은 did에 해당하는 튜플 추출
            position = member_db[0].position    # 해당 튜플의 position 추출
        else:  # 전달 받은 admin_did가 Member테이블에 존재하지 않는다면,
            return JsonResponse({'msg': 'did not exists'}, status=400)

        if position == 'admin':    # 해당 Member가 관리자라면,
            order_by = request.GET.get('order', None)  # 오름차순, 내림차순 params GET
            building_num = request.GET.get('building_num', None)  # 강의동 번호 GET

            # 정렬 방식에 따라 DB 튜플 불러오기
            if order_by == 'Asc':  # 오름차순 이라면,
                entry_db = Entry.objects.filter(building_num=building_num).order_by('id')
            elif order_by == 'Desc':  # 내림차순 이라면,
                entry_db = Entry.objects.filter(building_num=building_num).order_by('-id')
            else:  # order_by값이 Asc, Desc 이외의 값이라면,
                return JsonResponse({'msg': 'order param error'}, status=400)

            if len(entry_db) == 0:  # 해당 건물 번호, 해당 페이지에 출입기록이 존재하지 않는다면,
                return JsonResponse({'msg': 'has no entry'}, status=400)

            # 페이지네이션 적용
            page_num = request.GET.get('page_num', None)  # 페이지 번호 추출
            paginator = Paginator(entry_db, 10)   # 튜플 10개 당 페이지네이터 적용
            total_page = paginator.num_pages      # 총 페이지 수 저장
            total_count = paginator.count         # 총 튜플 수 저장
            posts_entry = paginator.get_page(page_num)  # 페이지 번호에 해당하는 정보 추출

            # JSON 형태로 저장
            json_data = {'entry': '', 'total_page': '', 'total_count': total_count}
            json_data['entry'] = []
            json_data['total_page'] = total_page
            json_data['total_count'] = total_count

            # 해당 페이지에 해당하는 정보 JSON형태로 저장
            for i in range(0, len(posts_entry), 1):
                entry_data = {}
                entry_data['entry_date'] = posts_entry[i].entry_date
                entry_data['building_num'] = posts_entry[i].building_num
                entry_data['entry_did'] = posts_entry[i].entry_did
                entry_data['entry_time'] = posts_entry[i].entry_time

                json_data['entry'].append(entry_data)

            return JsonResponse(json_data, status=201)  # 저장한 페이지 정보 반환

        else:    # 해당 Member가 관리자가 아니라면,
            return JsonResponse({'msg': 'Not Admin'}, status=400)
