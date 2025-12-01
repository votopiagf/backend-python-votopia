from django.db import models

# -------------------------
# Basic tables
# -------------------------

class FileCategory(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)

    class Meta:
        db_table = 'file_categories'
        managed = False


class LogAction(models.Model):
    id = models.AutoField(primary_key=True)
    code = models.CharField(max_length=50, unique=True)
    label = models.CharField(max_length=100)
    level = models.CharField(max_length=10, choices=[('INFO','INFO'),('WARNING','WARNING'),('ERROR','ERROR')], default='INFO')

    class Meta:
        db_table = 'log_actions'
        managed = False


class Module(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)
    description = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = 'modules'
        managed = False


class Permission(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=244, null=True)

    class Meta:
        db_table = 'permissions'
        managed = False


class Plan(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50)
    price = models.DecimalField(max_digits=8, decimal_places=2, default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    modules = models.ManyToManyField(Module, through='PlanModule', related_name='plans')

    class Meta:
        db_table = 'plans'
        managed = False


class PlanModule(models.Model):
    id = models.AutoField(primary_key=True)
    plan = models.ForeignKey(Plan, on_delete=models.CASCADE)
    module = models.ForeignKey(Module, on_delete=models.CASCADE)

    class Meta:
        db_table = 'plan_modules'
        managed = False
        unique_together = ('plan', 'module')


class Organization(models.Model):
    id = models.AutoField(primary_key=True)
    code = models.CharField(max_length=7, unique=True)
    name = models.CharField(max_length=100)
    plan = models.ForeignKey(Plan, null=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=10, choices=[('active','active'),('inactive','inactive')], default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    max_lists = models.IntegerField()

    class Meta:
        db_table = 'organizations'
        managed = False


class School(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, null=True)
    address_street = models.CharField(max_length=255, null=True)
    city = models.CharField(max_length=255, null=True)
    school_code = models.CharField(max_length=20, unique=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)

    class Meta:
        db_table = 'schools'
        managed = False


class User(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    surname = models.CharField(max_length=100)
    email = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=255)
    org = models.ForeignKey(Organization, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    deleted = models.BooleanField(default=False)
    must_change_password = models.BooleanField(default=True)

    roles = models.ManyToManyField('Role', through='UserRole', related_name='users')
    lists = models.ManyToManyField('List', through='UserList', related_name='users')

    class Meta:
        db_table = 'users'
        managed = False


class File(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, null=True)
    org = models.ForeignKey(Organization, null=True, on_delete=models.SET_NULL)
    list = models.ForeignKey('List', null=True, on_delete=models.SET_NULL, related_name='files')
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    category = models.ForeignKey(FileCategory, null=True, on_delete=models.SET_NULL)
    file_path = models.CharField(max_length=255, null=True)
    mime_type = models.CharField(max_length=100, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True, null=True)

    class Meta:
        db_table = 'files'
        managed = False


class List(models.Model):
    id = models.AutoField(primary_key=True)
    org = models.ForeignKey(Organization, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    school = models.ForeignKey(School, null=True, on_delete=models.SET_NULL)
    description = models.TextField(null=True)
    slogan = models.CharField(max_length=255, null=True)
    color_primary = models.CharField(max_length=10, null=True)
    color_secondary = models.CharField(max_length=10, null=True)
    logo_file = models.ForeignKey(File, null=True, on_delete=models.SET_NULL, related_name='logo_of_lists')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'lists'
        managed = False


class Role(models.Model):
    id = models.AutoField(primary_key=True)
    org = models.ForeignKey(Organization, null=True, on_delete=models.SET_NULL)
    list = models.ForeignKey(List, null=True, on_delete=models.SET_NULL)
    name = models.CharField(max_length=50)
    color = models.CharField(max_length=7, null=True)
    level = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    permissions = models.ManyToManyField(Permission, through='RolePermission', related_name='roles')

    class Meta:
        db_table = 'roles'
        managed = False


class RolePermission(models.Model):
    id = models.AutoField(primary_key=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        db_table = 'role_permissions'
        managed = False
        unique_together = ('role', 'permission')


class UserRole(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        db_table = 'user_roles'
        managed = False
        unique_together = ('user', 'role')


class UserList(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    list = models.ForeignKey(List, on_delete=models.CASCADE)

    class Meta:
        db_table = 'user_lists'
        managed = False
        unique_together = ('user', 'list')


class Candidate(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    school_class = models.CharField(max_length=10, null=True)
    photo_file = models.ForeignKey(File, null=True, on_delete=models.SET_NULL)
    bio = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    campaigns = models.ManyToManyField('Campaign', through='CandidateCampaign', related_name='candidates')

    class Meta:
        db_table = 'candidates'
        managed = False


class Campaign(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    list = models.ForeignKey(List, on_delete=models.CASCADE)
    description = models.TextField(null=True)
    start_date = models.DateField()
    end_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'campaigns'
        managed = False


class CandidateCampaign(models.Model):
    id = models.AutoField(primary_key=True)
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE)
    campaign = models.ForeignKey(Campaign, on_delete=models.CASCADE)

    class Meta:
        db_table = 'candidates_campaigns'
        managed = False
        unique_together = ('candidate', 'campaign')


class Position(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    list = models.ForeignKey(List, null=True, on_delete=models.SET_NULL)
    org = models.ForeignKey(Organization, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'positions'
        managed = False


class CandidatePositionCampaign(models.Model):
    id = models.AutoField(primary_key=True)
    position = models.ForeignKey(Position, on_delete=models.CASCADE)
    candidate_campaign = models.ForeignKey(CandidateCampaign, on_delete=models.CASCADE)
    position_in_list = models.IntegerField(null=True)

    class Meta:
        db_table = 'candidate_positions_campaign'
        managed = False
        unique_together = ('position', 'candidate_campaign')


class SystemEvent(models.Model):
    id = models.AutoField(primary_key=True)
    org = models.ForeignKey(Organization, null=True, on_delete=models.SET_NULL)
    event_type = models.CharField(max_length=50)
    reference_table = models.CharField(max_length=50, null=True)
    reference_id = models.IntegerField(null=True)
    run_at = models.DateTimeField()
    executed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'system_events'
        managed = False


class Log(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.ForeignKey(LogAction, on_delete=models.CASCADE)
    description = models.TextField(null=True)
    ip_address = models.CharField(max_length=45)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'logs'
        managed = False