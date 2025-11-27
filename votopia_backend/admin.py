from django.contrib import admin
from .models import *

# -----------------------
# Inlines per le relazioni ManyToMany
# -----------------------
class UserRolesInline(admin.TabularInline):
    model = UserRole
    extra = 1
    verbose_name = "Role"
    verbose_name_plural = "Roles"

class UserListsInline(admin.TabularInline):
    model = UserList
    extra = 1
    verbose_name = "List"
    verbose_name_plural = "Lists"

class RolePermissionsInline(admin.TabularInline):
    model = RolePermission
    extra = 1
    verbose_name = "Permission"
    verbose_name_plural = "Permissions"

class PlanModulesInline(admin.TabularInline):
    model = PlanModule
    extra = 1
    verbose_name = "Module"
    verbose_name_plural = "Modules"

class CandidateCampaignsInline(admin.TabularInline):
    model = CandidateCampaign
    extra = 1
    verbose_name = "Campaign"
    verbose_name_plural = "Campaigns"

class CandidatePositionsCampaignInline(admin.TabularInline):
    model = CandidatePositionCampaign
    extra = 1
    verbose_name = "Candidate Campaign Position"
    verbose_name_plural = "Candidate Campaign Positions"

# -----------------------
# Admin principali
# -----------------------
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'surname', 'email', 'org', 'created_at', 'deleted')
    search_fields = ('name', 'surname', 'email')
    inlines = [UserRolesInline, UserListsInline]
    raw_id_fields = ('org',)
    readonly_fields = ('created_at',)

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'org', 'list', 'created_at')
    search_fields = ('name',)
    inlines = [RolePermissionsInline]
    raw_id_fields = ('org', 'list',)
    readonly_fields = ('created_at',)

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'description')

@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'price', 'created_at')
    inlines = [PlanModulesInline]
    readonly_fields = ('created_at',)

@admin.register(Module)
class ModuleAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'description')

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'code', 'plan', 'status', 'max_lists', 'created_at')
    search_fields = ('name', 'code')
    raw_id_fields = ('plan',)
    readonly_fields = ('created_at',)

@admin.register(School)
class SchoolAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'school_code', 'city', 'address_street', 'created_at')
    readonly_fields = ('created_at',)

@admin.register(List)
class ListAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'org', 'school', 'slogan', 'created_at')
    search_fields = ('name',)
    raw_id_fields = ('org', 'school', 'logo_file',)
    readonly_fields = ('created_at',)

@admin.register(FileCategory)
class FileCategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'created_at')
    readonly_fields = ('created_at',)

@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'org', 'list', 'user', 'category', 'file_path', 'mime_type', 'uploaded_at')
    search_fields = ('name',)
    raw_id_fields = ('list', 'user', 'category', 'org')
    readonly_fields = ('uploaded_at',)

@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'school_class', 'created_at')
    inlines = [CandidateCampaignsInline]
    raw_id_fields = ('user', 'photo_file',)
    readonly_fields = ('created_at',)

@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'list', 'start_date', 'end_date', 'created_at')
    raw_id_fields = ('list',)
    readonly_fields = ('created_at',)

@admin.register(Position)
class PositionAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'list', 'org', 'created_at')
    inlines = [CandidatePositionsCampaignInline]
    raw_id_fields = ('list', 'org',)
    readonly_fields = ('created_at',)

@admin.register(LogAction)
class LogActionAdmin(admin.ModelAdmin):
    list_display = ('id', 'code', 'label', 'level')

@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'action', 'description', 'ip_address', 'created_at')
    raw_id_fields = ('user', 'action',)
    readonly_fields = ('created_at',)

@admin.register(SystemEvent)
class SystemEventAdmin(admin.ModelAdmin):
    list_display = ('id', 'org', 'event_type', 'reference_table', 'reference_id', 'run_at', 'executed', 'created_at')
    raw_id_fields = ('org',)
    readonly_fields = ('created_at',)