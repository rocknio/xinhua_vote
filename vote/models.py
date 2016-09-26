# -*- coding: utf-8 -*-

from django.db import models


class Candidate(models.Model):
    name = models.CharField(max_length=32, blank=False, verbose_name='姓名')
    description = models.CharField(max_length=512, verbose_name='简介')
    pic_name = models.CharField(max_length=256, verbose_name='图片名称')
    voted = models.IntegerField(default=0, verbose_name='当前票数')

    def __unicode__(self):
        return self.name

    class Meta:
        verbose_name = '候选人信息'
        verbose_name_plural = '候选人信息'


class VoteAction(models.Model):
    openid = models.CharField(max_length=64, blank=False, verbose_name='微信用户ID')
    voteid = models.IntegerField(blank=False, verbose_name='被投票人ID')
    votetime = models.CharField(max_length=8, blank=False, verbose_name='投票时间, YYYYMMDD')

    class Meta:
        verbose_name = '投票流水表'
        verbose_name_plural = '投票流水表'
