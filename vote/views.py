# -*- coding: utf-8 -*-

from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect, HttpResponse
from vote.models import Candidate, WechatConfig, WechatInfo, FollowInfo
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

# https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx3a998e063f25c7c5&redirect_uri=http%3a%2f%2frocknio.gnway.cc%2fauthorization%2f&response_type=code&scope=snsapi_base&state=STATE#wechat_redirect


def authorization(request):
    try:
        code = request.GET.get('code')
        access_token_url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid={}&secret={}&code={}&grant_type=authorization_code".format(WECHAT_APP_ID, WECHAT_APP_SECRET, code)
        resp = requests.get(access_token_url)
        resp_text = resp.text
        resp_dict = json.loads(resp_text)
        openid = resp_dict['openid']

        ret = get_user_info(openid)
        if ret == 'ok':
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
            wechat_unsubscribe(request, xml_doc)
            logger.debug('unsubscribe resp = OK')
            return HttpResponse('')


def get_user_info(openid):
    # 记录用户数据
    try:
        user_record = WechatInfo.objects.get(openid=openid)
        logger.info("user = {} is already follow!".format(user_record.openid))
        return 'ok'
    except WechatInfo.DoesNotExist:
        pass
    except WechatInfo.MultipleObjectsReturned:
        logger.error('has multiple records in WechatInfo! openid = %s' % openid)
        return ''

    # 获取用户基本信息
    # 先调用内部接口获取accesstoken
    token = wechat_get_token('internal')
    logger.info(token)

    # 获取用户信息
    get_wechat_user_info_url = WECHAT_GET_USER_INFO_URL % (token, openid)
    logger.info(get_wechat_user_info_url)
    resp = requests.get(get_wechat_user_info_url)
    logger.info(resp.text)

    decoded = json.loads(resp.text)
    if 'subscribe' in decoded:
        if decoded['subscribe'] == 0:
            return ''

    user_record = WechatInfo()
    user_record.openid = openid
    user_record.subscribe_time = datetime.datetime.now()
    if user_record:
        try:
            if 'nickname' in decoded:
                user_record.nickname = decoded['nickname']
            if 'sex' in decoded:
                user_record.sex = decoded['sex']
            if 'language' in decoded:
                user_record.language = decoded['language']
            if 'city' in decoded:
                user_record.city = decoded['city']
            if 'province' in decoded:
                user_record.province = decoded['province']
            if 'country' in decoded:
                user_record.country = decoded['country']
            if 'headimgurl' in decoded:
                user_record.headimgurl = decoded['headimgurl']
            if 'subscribe_time' in decoded:
                user_record.subscribe_time = datetime.datetime.fromtimestamp(int(decoded['subscribe_time']))

            user_record.gold = 0
            user_record.diamond = 0
        except KeyError:
            logger.error('json decoded user info fail![%s]' % decoded)
            return ''

        try:
            user_record.save()
            return 'ok'
        except ValueError:
            logger.error('save wechat info fail![%s]' % decoded)
            return ''


def wechat_subscribe(request, xmldoc):
    """

    :param request:
    :param xmldoc:
    :return:
    """
    touser = xmldoc.find('ToUserName')
    fromuser = xmldoc.find('FromUserName')

    get_user_info(fromuser.text)
    http_resp = {'toUser': fromuser.text, 'fromUser': touser.text, 'createTime': str(int(time.time())),
                 'text': str(1),
                 'textContent': "欢迎关注新华小学"}

    return http_resp


def wechat_unsubscribe(request, xmldoc):
    """

    :param request:
    :param xmldoc:
    :return:
    """
    # 将用户数据移到取消关注用户表
    fromuser = xmldoc.find('FromUserName')
    try:
        user_record = WechatInfo.objects.get(openid=fromuser.text)
    except WechatInfo.DoesNotExist:
        logger.error('wechatinfo[%s] is not in DB!' % fromuser.text)
    except WechatInfo.MultipleObjectsReturned:
        logger.error('wechatinfo[%s] have multiple records in DB' % fromuser.text)
    else:
        if user_record:
            # 删除user_record表里数据，
            try:
                user_record.delete()
            except ValueError:
                logger.error('delete wechatinfo fail! openid = %s' % user_record.openid)


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
    logger.info('Wechat token resp = %s' % resp)
    decoded = json.loads(resp.text)

    # 保存accesstoken到数据库
    if token_record:
        try:
            token_record.value = decoded['access_token']
            token_record.expire_seconds = decoded['expires_in']
            token_record.touch_time = curtime
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
            token_record.touch_time = curtime
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


def show_main_list(request):
    try:
        candidate_objects = Candidate.objects.all().order_by('-voted')
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
            if all_vote['voted__sum'] == 0:
                tmp = "\"" + "width: " + str(0) + "%" + "\"",
            else:
                tmp = "\"" + "width: " + str(str(int(one_candidate.voted * 100 / all_vote['voted__sum']))) + "%" + "\""
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


def do_vote(request, source, voted_id):
    try:
        Candidate.objects.filter(id=voted_id).update(voted=F('voted') + 1)
    except Exception as err:
        logger.error("err = {}".format(err))

    if source == "list":
        return HttpResponseRedirect('/list/')
    else:
        return HttpResponseRedirect('/content/' + str(voted_id) + '/')


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
