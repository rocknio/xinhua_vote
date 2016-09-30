# -*- coding: utf-8 -*-

from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect, HttpResponse
from vote.models import Candidate, WechatConfig, FollowInfo, VoteAction
from django.db.models import Sum, F
from django.views.decorators.csrf import csrf_exempt
from xinhua_vote.settings import WECHAT_VOTE_TOKEN, WECHAT_GET_USER_INFO_URL, WECHAT_TOKEN_URL, \
    WECHAT_APP_ID, WECHAT_APP_SECRET
import logging
import hashlib
import xml.etree.ElementTree as eTree
import datetime
import time
import json
import requests


# 获取的logger
logger = logging.getLogger(__name__)


@csrf_exempt
def authorization(request):
    try:
        code = request.GET.get('code')
        logger.info("Code = {}".format(code))
        access_token_url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid={}&secret={}&code={}&grant_type=authorization_code".format(WECHAT_APP_ID, WECHAT_APP_SECRET, code)
        logger.info("AccesstokenUrl = {}".format(access_token_url))
        resp = requests.get(access_token_url)
        resp_text = resp.text
        resp_dict = json.loads(resp_text)
        logger.info("authorization = {}".format(resp_dict))
        openid = resp_dict.get('openid', '')
        access_token = resp_dict.get('access_token', '')
        logger.info("Openid = {}, access_token = {}".format(openid, access_token))
        if openid == '' or access_token == '':
            notify_entry()
            return

        ret = get_user_info(openid)
        if ret == 'ok':
            request.session['openid'] = openid
            return HttpResponseRedirect('/list/')
        else:
            return HttpResponseRedirect('/follow_helper/')
    except Exception as err:
        logger.error("err = {}".format(err))
        return HttpResponseRedirect('/list/')


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
    tmp_str = hashlib.sha1(tmp_str.encode()).hexdigest()

    if signature == tmp_str:
        if http_method == 'POST':
            echostr = 'OK'
        return echostr
    else:
        return ''


@csrf_exempt
def wechat_check(request):
    # 检查是否是微信服务器发的有效消息
    echostr = is_request_from_wechat(request, request.method)
    if echostr == '':
        logger.warn('receive msg is not from Wechat Services!')
        return HttpResponse('who you are?')

    if request.method == 'GET':
        return HttpResponse(echostr)

    req_buf = ''
    if request.method == 'POST':
        req_buf = request.body

    if not req_buf:
        return HttpResponse('Request Content is NULL')

    logger.info('RECV = {}'.format(req_buf))
    xml_doc = eTree.fromstring(req_buf)
    wc_msgtype = xml_doc.find('MsgType')
    wc_event = xml_doc.find('Event')

    # 上行处理
    if wc_msgtype.text == 'event':
        # 关注
        if wc_event.text == 'subscribe':
            resp = wechat_subscribe(request, xml_doc)
            if resp == '':
                logger.debug('subscribe resp = %s', resp)
                return HttpResponse('')
            else:
                logger.debug('subscribe resp = %s', resp)
                return render_to_response('vote/resp_text.xml', resp)
        # 取消关注
        elif wc_event.text == 'unsubscribe':
            wechat_unsubscribe(request)
            logger.debug('unsubscribe resp = OK')
            return HttpResponse('')


def wechat_userinfo(access_token, openid):
    try:
        # 获取用户信息
        get_wechat_user_info_url = WECHAT_GET_USER_INFO_URL % (access_token, openid)
        resp = requests.get(get_wechat_user_info_url)
        logger.info("Userinfo: Openid = {}, access_token = {}, Info = {}".format(openid, access_token, resp.text))
        return resp.text
    except Exception:
        return ""


def get_user_info(openid):
    # 获取用户基本信息
    # 先调用内部接口获取accesstoken
    access_token = wechat_get_token('internal')
    try:
        resp = wechat_userinfo(access_token, openid)
    except Exception:
        resp = ""

    decoded = json.loads(resp)
    logger.info("Userinfo_DICT: Openid = {}, access_token = {}, Info = {}".format(openid, access_token, decoded))
    if "errcode" in decoded:
        return ""

    if 'subscribe' in decoded:
        if decoded['subscribe'] == 0:
            return ''
        else:
            return 'ok'
    else:
        return 'ok'


def wechat_subscribe(request, xmldoc):
    """

    :param request:
    :param xmldoc:
    :return:
    """
    touser = xmldoc.find('ToUserName')
    fromuser = xmldoc.find('FromUserName')

    http_resp = {'toUser': fromuser.text, 'fromUser': touser.text, 'createTime': str(int(time.time())),
                 'text': str(1),
                 'textContent': "欢迎关注新华小学"}

    return http_resp


def wechat_unsubscribe(request):
    """
    :param request:
    :return:
    """
    return HttpResponse('OK')


def wechat_get_token(reqfrom='internet'):
    """
    内部接口
    供需要操作微信接口的逻辑获取当前有效的access token
    :param reqfrom:
    :return:
    """
    # 判断，不是内部发来的请求，直接返回，不做处理
    if reqfrom != 'internal':
        return ''

    # 从数据库中获取token，判断是否超时，如果未超时，则直接返回，如果超时，重新获取
    token = ''
    token_record = []
    try:
        token_record = WechatConfig.objects.get(tag='token')
    except WechatConfig.DoesNotExist:
        logger.critical('token Does not in DB!')
    except WechatConfig.MultipleObjectsReturned:
        logger.critical('token have multiple records in DB!')
        # 如果有多条记录，返回错误
        return ''
    else:
        try:
            token = token_record.value
        except ValueError:
            token = ''

    # 获取当前时间
    curtime = datetime.datetime.now()

    if token:
        logger.info('tag = %s, value = %s, touch_time = %s, expire_seconds = %d' %
                    (token_record.tag, token_record.value, token_record.touch_time,
                     token_record.expire_seconds))
        # 计算时间差
        cur_timestamp = time.mktime(curtime.timetuple())
        touch_time_timestamp = time.mktime(token_record.touch_time.timetuple())
        pass_seconds = cur_timestamp - touch_time_timestamp

        # token获取超过10分钟，则再次获取
        if pass_seconds <= 600:
            return token

    # 重新获取token
    resp = requests.get(WECHAT_TOKEN_URL)

    # 解析get access token 返回
    logger.info('Wechat token resp = %s' % resp.text)
    decoded = json.loads(resp.text)

    if "errcode" in decoded.keys():
        return ''

    # 保存accesstoken到数据库
    if token_record:
        try:
            token_record.value = decoded['access_token']
            token_record.expire_seconds = decoded['expires_in']
            token_record.touch_time = datetime.datetime.now()
            token = token_record.value
        except ValueError:
            logger.error('decoded json fail!')
            return ''
    else:
        try:
            token_record = WechatConfig()
            token_record.value = decoded['access_token']
            token_record.tag = 'token'
            token_record.expire_seconds = decoded['expires_in']
            token_record.touch_time = datetime.datetime.now()
            token = token_record.value
        except ValueError:
            logger.error('new WechatConfig fail!')
            return ''

    # 更新数据库
    if token_record:
        try:
            token_record.save()
        except ValueError:
            logger.error('save token to db fail!')
            return ''

    # 返回token
    return token


@csrf_exempt
def show_main_list(request):
    openid = get_openid(request)
    if openid == '':
        return notify_entry()

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


@csrf_exempt
def show_contents(request, main_id):
    openid = get_openid(request)
    if openid == '':
        return notify_entry()

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


@csrf_exempt
def show_charts(request):
    openid = get_openid(request)
    if openid == '':
        return notify_entry()

    try:
        all_vote = Candidate.objects.filter().order_by('-voted').first()

        all_candidates = Candidate.objects.all().order_by('-voted')
        candidate_rank_list = []
        i = 0
        for one_candidate in all_candidates:
            i += 1
            if all_vote.voted == 0:
                tmp = "\"" + "width: " + str(0) + "%" + "\"",
            else:
                tmp = "\"" + "width: " + str(str(int(one_candidate.voted * 100 / all_vote.voted))) + "%" + "\""
            candidate_rank_list.append({
                "id": one_candidate.id,
                "name": one_candidate.name,
                "pic_name": '/static/candidate_img/' + one_candidate.pic_name,
                "voted": one_candidate.voted,
                "bar_style": tmp,
                "rank": get_rank(one_candidate.id),
                "bar_color": "\"" + "progress-inner progress-color" + str((i % 4 + 1)) + "\""
            })

        return render_to_response("vote/charts.html", {"candidates": candidate_rank_list})
    except Exception as err:
        logger.error("err = {}".format(err))
        return HttpResponseRedirect('/list/')


def get_openid(request):
    try:
        openid = request.session['openid']
        return openid
    except Exception:
        return ''


def notify_entry():
    return render_to_response('vote/entryinfo.html')


def real_vote(openid, voted_id):
    try:
        Candidate.objects.filter(id=voted_id).update(voted=F('voted') + 1)

        vote_action = VoteAction()
        vote_action.openid = openid
        vote_action.voteid = voted_id
        vote_action.votetime = datetime.datetime.now().strftime('%Y%m%d')

        vote_action.save()
    except Exception as err:
        logger.error("err = {}".format(err))


@csrf_exempt
def do_vote(request, source, voted_id):
    openid = get_openid(request)
    if openid == '':
        return notify_entry()

    try:
        current_date = datetime.datetime.now().strftime('%Y%m%d')
        VoteAction.objects.get(openid=openid, votetime=current_date, voteid=voted_id)

        candidate = {
            "resp": "你今天已经为他投过票了，请明天继续！"
        }
        return render_to_response('vote/voteinfo.html', {"candidate": candidate})
    except VoteAction.DoesNotExist:
        real_vote(openid, voted_id)

        candidate = {
            "resp": "感谢你宝贵的一票！"
        }
        return render_to_response('vote/voteinfo.html', {"candidate": candidate})
    except Exception as err:
        logger.error("err = {}".format(err))


@csrf_exempt
def show_follow_helper(request):
    try:
        main_candidate = FollowInfo.objects.get(id=1)
        candidate = {
            "id": main_candidate.id,
            "name": main_candidate.name,
            "pic_name": '/static/candidate_img/' + main_candidate.pic_name,
            "voted": main_candidate.voted,
            "lines": main_candidate.description.split('\n'),
            "rank": "00"
        }

        return render_to_response("vote/followinfo.html", {"candidate": candidate})
    except Exception as err:
        logger.error("err = {}".format(err))
