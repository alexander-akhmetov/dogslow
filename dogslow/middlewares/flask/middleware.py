# -*- coding: utf-8 -*-
import datetime as dt
import logging
import thread
from urlparse import urlparse

from flask import (
    request,
    copy_current_request_context,
)

from dogslow.utils import safehasattr
from dogslow.middlewares.base import BaseWatchdogMiddleware


class WatchdogMiddleware(BaseWatchdogMiddleware):
    def __init__(self, app):
        app.before_request(self.process_request)
        app.teardown_request(self._cancel)
        self.app_config = app.config
        super(WatchdogMiddleware, self).__init__()

    def _get_config(self):
        return self.app_config

    def _safe_get_setting(self, name, default_value):
        return self.app_config.get(name, default_value)

    def _get_path(self, request):
        return request.path

    def _get_query_string(self, request):
        return urlparse(request.url).query

    @staticmethod
    def _log_to_email(email_to, email_from, output, req_string):
        pass

    def _is_exempt(self, request):
        return False

    def process_request(self):
        if not self._is_exempt(request):
            @copy_current_request_context
            def run(request, thread_id, started):
                self.peek(request, thread_id, started)

            request.dogslow = self.timer.run_later(
                run,
                self.interval,
                request,
                thread.get_ident(),
                dt.datetime.utcnow(),
            )

    def _cancel(self, exc=None):
        try:
            if safehasattr(request, 'dogslow'):
                self.timer.cancel(request.dogslow)
                del request.dogslow
        except Exception:
            logging.exception('Failed to cancel Dogslow timer')
