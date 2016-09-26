# -*- coding: utf-8 -*-

from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect, HttpResponse
from vote.models import Candidate
from django.db.models import Sum, F
from xinhua_vote.settings import WECHAT_VOTE_TOKEN
import logging
import hashlib

# 获取的logger
logger = logging.getLogger(__name__)


def get_rank(userid):
    i = 0
    all_candidates = Candidate.objects.all().order_by('-voted')
    for one_candidate in all_candidates:
        i += 1
        if one_candidate.id == userid:
            break

    ret = str(i)
    if ret.__len__() < 2:
        ret = '0' + ret
    return ret


def is_request_from_wechat(request, http_method):
    """
    :param http_method:
    :param request:
    :return:
    """
    signature = request.GET.get('signature', '')
    timestamp = request.GET.get('timestamp', '')
    nonce = request.GET.get('nonce', '')
    echostr = request.GET.get('echostr', '')

    tmp_list = [WECHAT_VOTE_TOKEN, timestamp, nonce]
    tmp_list.sort()
    tmp_str = ''.join(tmp_list)
    tmp_str = hashlib.sha1(tmp_str).hexdigest()

    if signature == tmp_str:
        if http_method == 'POST':
            echostr = 'OK'
        return echostr
    else:
        return ''


def wechat_check(request):
    # 检查是否是微信服务器发的有效消息
    echostr = is_request_from_wechat(request, request.method)
    if echostr == '':
        logger.warn('receive msg is not from Wechat Services!')
        return HttpResponse('who you are?')


def show_main_list(request):
    try:
        candidate_objects = Candidate.objects.all()
        candidates = []
        for one_candidate in candidate_objects:
            candidates.append({
                "id": one_candidate.id,
                "name": one_candidate.name,
                "pic_name": '/static/candidate_img/' + one_candidate.pic_name,
                "voted": one_candidate.voted
            })
        return render_to_response("vote/list.html", {"candidates": candidates})
    except Exception as err:
        logger.error("err = {}".format(err))
        return render_to_response("vote/list.html", {"candidates": {}})


def show_contents(request, main_id):
    try:
        main_candidate = Candidate.objects.get(id=main_id)
        candidate = {
            "id": main_candidate.id,
            "name": main_candidate.name,
            "pic_name": '/static/candidate_img/' + main_candidate.pic_name,
            "voted": main_candidate.voted,
            "lines": main_candidate.description.split('\n'),
            "rank": get_rank(main_candidate.id)
        }

        return render_to_response("vote/content.html", {"candidate": candidate})
    except Exception as err:
        logger.error("err = {}".format(err))
        return HttpResponseRedirect('/list/')


def show_charts(request):
    try:
        all_vote = Candidate.objects.aggregate(Sum('voted'))

        all_candidates = Candidate.objects.all().order_by('-voted')
        candidate_rank_list = []
        i = 0
        for one_candidate in all_candidates:
            i += 1
            candidate_rank_list.append({
                "id": one_candidate.id,
                "name": one_candidate.name,
                "pic_name": '/static/candidate_img/' + one_candidate.pic_name,
                "voted": one_candidate.voted,
                "bar_style": "\"" + "width: " + str(str(int(one_candidate.voted * 100 / all_vote['voted__sum']))) + "%" + "\"",
                "rank": get_rank(one_candidate.id),
                "percentage": str(str(int(one_candidate.voted * 100 / all_vote['voted__sum']))) + "%",
                "bar_color": "\"" + "progress-inner progress-color" + str((i % 4 + 1)) + "\""
            })

        return render_to_response("vote/charts.html", {"candidates": candidate_rank_list})
    except Exception as err:
        logger.error("err = {}".format(err))
        return HttpResponseRedirect('/list/')


def do_vote(request, source, voted_id):
    try:
        Candidate.objects.filter(id=voted_id).update(voted=F('voted') + 1)
    except Exception as err:
        logger.error("err = {}".format(err))

    if source == "list":
        return HttpResponseRedirect('/list/')
    else:
        return HttpResponseRedirect('/content/' + str(voted_id) + '/')
