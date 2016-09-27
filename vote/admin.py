# -*- coding: utf-8 -*-

from django.contrib import admin

from vote.models import Candidate, VoteAction, FollowInfo


class CandidateAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'pic_name', 'voted')
    list_filter = ('name',)
    ordering = ('voted',)
    search_fields = ('name',)
    fields = ('name', 'description', 'pic_name')

admin.site.register(Candidate, CandidateAdmin)


class FollowInfoAdmin(admin.ModelAdmin):
    actions = None

    list_display = ('name', 'description', 'pic_name', 'voted')
    list_filter = ('name',)
    ordering = ('voted',)
    search_fields = ('name',)
    fields = ('name', 'description', 'pic_name')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    readonly_fields = ('name', 'description', 'pic_name', 'voted')

admin.site.register(FollowInfo, FollowInfoAdmin)


class VoteActionAdmin(admin.ModelAdmin):
    actions = None

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    # def has_change_permission(self, request, obj=None):
    #     if obj is None:
    #         return True
    #     else:
    #         return False

    list_display = ('openid', 'voteid', 'votetime')
    ordering = ('-votetime',)
    readonly_fields = ('openid', 'voteid', 'votetime')


admin.site.register(VoteAction, VoteActionAdmin)

