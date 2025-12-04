"""
Definition of models.
"""

from django.db import models
from django.contrib.auth.hashers import make_password

class Reports(models.Model):
    id = models.AutoField(primary_key=True)
    regionname = models.CharField(max_length=50, blank=True, null=True)
    crimetype = models.CharField(max_length=50, blank=True, null=True)
    reportdate = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True, null=True)
    assignedpoliceid = models.IntegerField(blank=True, null=True)
    status = models.CharField(max_length=50, blank=True, null=True)
    casedate = models.DateField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Reports'


class EvidentImages(models.Model):
    id = models.AutoField(primary_key=True)
    image = models.ImageField(upload_to='evidence/images/', blank=True, null=True)
    cid = models.ForeignKey(Reports, on_delete=models.CASCADE, db_column='cid', related_name='evident_images')

    class Meta:
        managed = False
        db_table = 'EvidentImages'


class EvidentVideos(models.Model):
    id = models.AutoField(primary_key=True)
    video = models.FileField(upload_to='evidence/videos/', blank=True, null=True)
    cid = models.ForeignKey(Reports, on_delete=models.CASCADE, db_column='cid', related_name='evident_videos')

    class Meta:
        managed = False
        db_table = 'EvidentVideos'


class Users(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=150, blank=True, null=True)
    password = models.CharField(max_length=50, blank=True, null=True)
    policeid = models.IntegerField(blank=True, null=True)
    rank = models.CharField(max_length=20, blank=True, null=True)
    email = models.CharField(max_length=20, blank=True, null=True)
    state = models.CharField(max_length=20, blank=True, null=True)
    city = models.CharField(max_length=20, blank=True, null=True)
    station = models.CharField(max_length=20, blank=True, null=True)
    last_login = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        """
        Automatically hash plaintext passwords using Django's default (PBKDF2).
        Skip hashing if it already looks hashed.
        """
        pw = self.password or ""
        if not pw.startswith('pbkdf2_'):
            self.password = make_password(pw)
        super().save(*args, **kwargs)
    class Meta:
        managed = False
        db_table = 'Users'


class RegionChangeRequests(models.Model):
    id = models.AutoField(primary_key=True)
    userid = models.IntegerField(blank=True, null=True)
    name = models.CharField(max_length=20, blank=True, null=True)
    policeid = models.IntegerField(blank=True, null=True)
    rank = models.CharField(max_length=20, blank=True, null=True)
    currentlocation = models.CharField(max_length=30, blank=True, null=True)
    updatelocation = models.CharField(max_length=30, blank=True, null=True)
    confirmation = models.CharField(max_length=20, blank=True, null=True)
    class Meta:
        managed = False
        db_table = 'RegionChangeRequests'

class RankChangeRequests(models.Model):
    id = models.AutoField(primary_key=True)
    userid = models.IntegerField(blank=True, null=True)
    name = models.CharField(max_length=20, blank=True, null=True)
    policeid = models.IntegerField(blank=True, null=True)
    state = models.CharField(max_length=20, blank=True, null=True)
    city = models.CharField(max_length=20, blank=True, null=True)
    station = models.CharField(max_length=20, blank=True, null=True)
    currentrank = models.CharField(max_length=20, blank=True, null=True)
    updaterank = models.CharField(max_length=20, blank=True, null=True)
    confirmation = models.CharField(max_length=20, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'RankChangeRequests'


class FeedBack(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=20, blank=True, null=True)
    email = models.CharField(max_length=20, blank=True, null=True)
    message = models.CharField(max_length=900, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'FeedBack'


class CaseReports(models.Model):
    id = models.AutoField(primary_key=True)
    reportid = models.IntegerField(blank=True, null=True)
    state = models.CharField(max_length=20, blank=True, null=True)
    city = models.CharField(max_length=20, blank=True, null=True)
    station = models.CharField(max_length=20, blank=True, null=True)
    suspects = models.CharField(max_length=20, blank=True, null=True)
    culprit = models.CharField(max_length=20, blank=True, null=True)
    casedescription = models.CharField(max_length=1000, blank=True, null=True)
    officer = models.CharField(max_length=20, blank=True, null=True)
    chiefofficer = models.CharField(max_length=20, blank=True, null=True)
    reportdate = models.DateTimeField(auto_now_add=True)
    confirm = models.CharField(max_length=20, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'CaseReports'
