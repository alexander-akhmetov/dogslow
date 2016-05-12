# -*- coding: utf-8 -*-
import logging
import thread
import datetime as dt

from django.conf import settings
from django.core.exceptions import MiddlewareNotUsed
from django.core.mail.message import EmailMessage
from django.core.urlresolvers import resolve, Resolver404

from dogslow.utils import safehasattr
from dogslow.middlewares.base import BaseWatchdogMiddleware


class WatchdogMiddleware(BaseWatchdogMiddleware):
    def __init__(self):
        if not getattr(settings, 'DOGSLOW', True):
            raise MiddlewareNotUsed
        else:
            super(WatchdogMiddleware, self).__init__()

    def _get_config(self):
        return settings

    def _safe_get_setting(self, name, default_value):
        return getattr(settings, name, default_value)

    def _get_path(self, request):
        return request.META.get('PATH_INFO')

    def _get_query_string(self, request):
        return request.META.get('QUERY_STRING')

    @staticmethod
    def _log_to_email(email_to, email_from, output, req_string):
        em = EmailMessage('Slow Request Watchdog: %s' %
                          req_string.encode('utf-8'),
                          output,
                          email_from,
                          (email_to,))
        em.send(fail_silently=True)

    def _is_exempt(self, request):
        """Returns True if this request's URL resolves to a url pattern whose
        name is listed in settings.DOGSLOW_IGNORE_URLS.
        """
        exemptions = getattr(settings, 'DOGSLOW_IGNORE_URLS', ())
        if exemptions:
            try:
                match = resolve(request.META.get('PATH_INFO'))
            except Resolver404:
                return False
            return match and (match.url_name in exemptions)
        else:
            return False

    def process_request(self, request):
        if not self._is_exempt(request):
            request.dogslow = self.timer.run_later(
                WatchdogMiddleware.peek,
                self.interval,
                request,
                thread.get_ident(),
                dt.datetime.utcnow())

    def process_response(self, request, response):
        self._cancel(request)
        return response

    def process_exception(self, request, exception):
        self._cancel(request)

    def _cancel(self, request):
        try:
            if safehasattr(request, 'dogslow'):
                self.timer.cancel(request.dogslow)
                del request.dogslow
        except Exception:
            logging.exception('Failed to cancel Dogslow timer')
