from cgitb import lookup
from django.shortcuts import render
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView

from .serializers import IncomeSerializer
from .models import Income
from .permissions import IsOwner
from rest_framework import permissions

class IncomeListAPIView(ListCreateAPIView):
    serializer_class = IncomeSerializer
    queryset = Income.objects.all()
    permission_classes = (permissions.IsAuthenticated,) #'BasePermissionMetaclass' object is not iterable. Forget ","

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)


class IncomeDetailAPIView(RetrieveUpdateDestroyAPIView):
    serializer_class = IncomeSerializer
    queryset = Income.objects.all()
    permission_classes = (permissions.IsAuthenticated,IsOwner,)
    lookup_field = "id"

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)