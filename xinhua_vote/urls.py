"""xinhua_vote URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from vote.views import show_main_list, show_contents, show_charts, do_vote, wechat_check, authorization, show_follow_helper
from django.views.generic.base import RedirectView

favicon_view = RedirectView.as_view(url='/static/favicon.ico', permanent=True)

urlpatterns = [
    url(r'^favicon\.ico$', favicon_view),

    url(r'^admin/', admin.site.urls),
    url(r'^content/(\d)/$', show_contents),
    url(r'^list/', show_main_list),
    url(r'^charts/', show_charts),
    url(r'^do_vote/(\w+)/(\d+)/$', do_vote),
    url(r'^wechat/', wechat_check),
    url(r'^authorization/', authorization),
    url(r'^follow_helper/', show_follow_helper)
]
