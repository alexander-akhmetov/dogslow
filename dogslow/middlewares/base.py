# -*- coding: utf-8 -*-
import os
import sys
import socket
import inspect
import logging
import tempfile
import datetime as dt

from dogslow.timer import Timer
from dogslow.utils import stack


class BaseWatchdogMiddleware(object):
    def __init__(self):
        self._init_timer()

    def _init_timer(self):
        self.interval = int(self._get_config().get('DOGSLOW_TIMER', 25))
        self.timer = Timer()
        self.timer.setDaemon(True)
        self.timer.start()

    def _get_config():
        raise NotImplementedError()

    def _log_to_custom_logger(self, logger_name, frame, output, req_string, request):
        log_level = self._safe_get_setting('DOGSLOW_LOG_LEVEL', 'WARNING')
        log_to_sentry = self._safe_get_setting('DOGSLOW_LOG_TO_SENTRY', False)
        log_level = logging.getLevelName(log_level)
        logger = logging.getLogger(logger_name)

        # we're passing the request object along
        # with the log call in case we're being used with Sentry:
        extra = {'request': request}

        # if this is not going to Sentry, then we'll use the original msg
        if not log_to_sentry:
            msg = 'Slow Request Watchdog: %s, %s - %s' % (
                request.path,
                # resolve(request.META.get('PATH_INFO')).url_name,
                req_string.encode('utf-8'),
                output,
            )
        else:
            # if it is going to Sentry, we instead want to format differently and send more in extra
            msg, extra = self._get_message_for_sentry(frame, request, extra)
        logger.log(log_level, msg, extra=extra)

    def _safe_get_setting(self, name, default_value):
        raise NotImplementedError()

    def _get_message_for_sentry(self, frame, request, extra):
        msg = 'Slow Request Watchdog: %s' % self._get_path(request)
        module = inspect.getmodule(frame.f_code)

        # This is a bizarre construct, `module` in `function`, but
        # this is how all stack traces are formatted.
        extra['culprit'] = '%s in %s' % (module.__name__,
                                         frame.f_code.co_name)

        # We've got to simplify the stack, because raven only accepts
        # a list of 2-tuples of (frame, lineno).
        # This is a list comprehension split over a few lines.
        extra['stack'] = [
            (frame, lineno)
            for frame, filename, lineno, function, code_context, index
            in inspect.getouterframes(frame)
        ]

        # Lastly, we have to reverse the order of the frames
        # because getouterframes() gives it to you backwards.
        extra['stack'].reverse()

        return msg, extra

    def _get_path(self, requst):
        raise NotImplementedError()

    def _compose_output(self, frame, req_string, started, thread_id):
        output = 'Undead request intercepted at: %s\n\n' \
                 '%s\n' \
                 'Hostname:   %s\n' \
                 'Thread ID:  %d\n' \
                 'Process ID: %d\n' \
                 'Started:    %s\n\n' % \
                 (dt.datetime.utcnow().strftime("%d-%m-%Y %H:%M:%S UTC"),
                  req_string,
                  socket.gethostname(),
                  thread_id,
                  os.getpid(),
                  started.strftime("%d-%m-%Y %H:%M:%S UTC"),)
        output += stack(frame, with_locals=False)
        output += '\n\n'
        stack_vars = self._safe_get_setting('DOGSLOW_STACK_VARS', False)
        if not stack_vars:
            # no local stack variables
            output += ('This report does not contain the local stack '
                       'variables.\n'
                       'To enable this (very verbose) information, add '
                       'this to your application settings:\n'
                       '  DOGSLOW_STACK_VARS = True\n')
        else:
            output += 'Full backtrace with local variables:'
            output += '\n\n'
            output += stack(frame, with_locals=True)
        return output.encode('utf-8')

    def peek(self, request, thread_id, started):
        try:
            frame = sys._current_frames()[thread_id]

            req_string = '%s %s://%s%s' % (
                request.method,
                'http',
                request.headers.get('HTTP_HOST'),
                request.path,
            )
            query_string = self._get_query_string(request)
            if query_string:
                req_string = '%s?%s' % (req_string, query_string)

            output = self._compose_output(frame, req_string, started, thread_id)

            # dump to file:
            self._dump_to_file_if_needed(output)
            # and email?
            self._send_email_if_needed(output, req_string)

            # and a custom logger:
            logger_name = self._safe_get_setting('DOGSLOW_LOGGER', None)
            if logger_name is not None:
                self._log_to_custom_logger(logger_name, frame, output, req_string, request)
        except Exception:
            logging.exception('Dogslow failed')

    def _get_query_string(self, request):
        raise NotImplementedError()

    def _dump_to_file_if_needed(self, output):
        log_to_file = self._safe_get_setting('DOGSLOW_LOG_TO_FILE', True)
        if log_to_file:
            self._log_to_file(output)

    def _log_to_file(self, output):
        fd, fn = tempfile.mkstemp(
            prefix='slow_request_',
            suffix='.log',
            dir=self._safe_get_setting('DOGSLOW_OUTPUT', tempfile.gettempdir()),
        )
        try:
            os.write(fd, output)
        finally:
            os.close(fd)

    def _send_email_if_needed(self, output, req_string):
        email_to = self._safe_get_setting('DOGSLOW_EMAIL_TO', None)
        email_from = self._safe_get_setting('DOGSLOW_EMAIL_FROM', None)

        if email_to is not None and email_from is not None:
            BaseWatchdogMiddleware._log_to_email(email_to, email_from, output, req_string)

    @staticmethod
    def _log_to_email(email_to, email_from, output, req_string):
        raise NotImplementedError()

    def _is_exempt(self):
        raise NotImplementedError()

    def process_request(self):
        raise NotImplementedError()

    def _cancel(self, exc=None):
        raise NotImplementedError()
