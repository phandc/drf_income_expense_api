from django.urls import path
from .views import ExpenseSumaryStats,IncomeSumaryStats

urlpatterns = [
    path('expense-category-data', ExpenseSumaryStats.as_view(), name='expense-category-data'),
    path('income-source-data', IncomeSumaryStats.as_view(), name='income-source-data')

]