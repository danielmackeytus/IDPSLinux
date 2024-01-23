from django.contrib import admin
from .models import AppUser
from django.contrib.auth.admin import UserAdmin

class CustomUserAdmin(UserAdmin):
    
    list_display = ('email', 'username', 'password', 'is_staff',)
    list_filter = ('is_staff',)
    
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Permissions', {'fields': ('is_staff','groups','is_superuser')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1','password2', 'is_staff')}
        ),
    )

    search_fields = ('username',)
    ordering = ('username',)
    
admin.site.register(AppUser, CustomUserAdmin)
