# -*- coding: utf-8 -*-
# Generated by Django 1.10.1 on 2016-09-21 08:24
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vote', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='candidate',
            name='description',
            field=models.CharField(max_length=512, verbose_name='简介'),
        ),
        migrations.AlterField(
            model_name='candidate',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='candidate',
            name='name',
            field=models.CharField(max_length=32, verbose_name='姓名'),
        ),
        migrations.AlterField(
            model_name='candidate',
            name='pic_name',
            field=models.CharField(max_length=256, verbose_name='图片名称'),
        ),
        migrations.AlterField(
            model_name='candidate',
            name='voted',
            field=models.IntegerField(default=0, verbose_name='当前票数'),
        ),
    ]
