# -*- coding: utf-8 -*-

from django.contrib import admin

from vote.models import Candidate


class CandidateAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'pic_name', 'voted')
    list_filter = ('name',)
    ordering = ('voted',)
    search_fields = ('name',)
    fields = ('name', 'description', 'pic_name')

admin.site.register(Candidate, CandidateAdmin)
