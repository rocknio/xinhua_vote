# -*- coding: utf-8 -*-

from django.http import HttpResponse
from django.shortcuts import render_to_response
from vote.models import Candidate


def hello(request):
    return HttpResponse("Hello world")


def show_main_list(request):
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


def show_contents(request, main_id):
    main_candidate = Candidate.objects.get(id=main_id)
    candidate = {
        "id": main_candidate.id,
        "name": main_candidate.name,
        "pic_name": '/static/candidate_img/' + main_candidate.pic_name,
        "voted": main_candidate.voted,
        "lines": main_candidate.description.split('\n'),
        "rank": 3
    }

    return render_to_response("vote/content.html", {"candidate": candidate})
