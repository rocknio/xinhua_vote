# -*- coding: utf-8 -*-

from django.db import models
import datetime


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


class WechatInfo(models.Model):
    openid = models.CharField(max_length=32)
    nickname = models.CharField(max_length=32, null=True)
    sex = models.IntegerField(null=True)
    language = models.CharField(max_length=16)
    city = models.CharField(max_length=32)
    country = models.CharField(max_length=32)
    province = models.CharField(max_length=32)
    headimgurl = models.CharField(max_length=512)
    subscribe_time = models.DateTimeField()
    custid = models.IntegerField(blank=True, null=True)


class WechatInfoUnsub(models.Model):
    openid = models.CharField(max_length=32)
    nickname = models.CharField(max_length=32, null=True)
    sex = models.IntegerField(null=True)
    language = models.CharField(max_length=16)
    city = models.CharField(max_length=32)
    country = models.CharField(max_length=32)
    province = models.CharField(max_length=32)
    headimgurl = models.CharField(max_length=512)
    subscribe_time = models.DateTimeField()
    custid = models.IntegerField(blank=True, null=True)
    unsubscribe_time = models.DateTimeField()

    def __unicode__(self):
        return self.nickname + '-' + self.openid

    class Meta:
        ordering = ['-unsubscribe_time']


class WechatConfig(models.Model):
    tag = models.CharField(max_length=32, db_index=True, unique=True)
    value = models.CharField(max_length=256, null=True, default='')
    touch_time = models.DateTimeField(null=True)
    expire_seconds = models.IntegerField(null=True)

    def __unicode__(self):
        return u'%s %s' % (self.tag, self.value)

    class Meta:
        ordering = ['tag']


class FollowInfo(models.Model):
    name = models.CharField(max_length=32, blank=False, verbose_name='标题')
    description = models.CharField(max_length=512, verbose_name='描述')
    pic_name = models.CharField(max_length=256, verbose_name='公众号二维码')
    voted = models.IntegerField(default=0, verbose_name='无用')

    def __unicode__(self):
        return self.name

    class Meta:
        verbose_name = '关注提示信息'
        verbose_name_plural = '关注提示信息'
