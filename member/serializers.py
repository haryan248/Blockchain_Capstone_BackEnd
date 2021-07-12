from .models import Member
from .models import Entry
from rest_framework import serializers, viewsets

class MemberSerializer(serializers.ModelSerializer):    #data를 json형태로
    class Meta:
        model = Member
        fields = '__all__'

class MemberViewSet(viewsets.ModelViewSet):        # Member 테이블에 저장된 튜플 모두 불러오기
    queryset = Member.objects.all()
    serializer_class = MemberSerializer

class EntrySerializer(serializers.ModelSerializer):    #data를 json형태로
    class Meta:
        model = Entry
        fields = '__all__'

class EntryViewSet(viewsets.ModelViewSet):        # Entry 테이블에 저장된 튜플 모두 불러오기
    queryset = Entry.objects.all()
    serializer_class = EntrySerializer

