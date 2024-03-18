from django.contrib import admin
from .models import AppUser
from django.contrib.auth.admin import UserAdmin

class CustomUserAdmin(UserAdmin):
    
    list_display = ('email', 'password')
    list_filter = ('email',)
    
    # modifying a user
    fieldsets = (
        (None, {
             'fields': ('email', 'password')}),
             ('Assign Group & Whether Super User', {'fields': ('groups','is_superuser')}),
    )
    
    # adding a user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1','password2', 'is_staff')}
        ),
    )

    search_fields = ('email',)
    ordering = ('email',)
    
admin.site.register(AppUser, CustomUserAdmin)
