# -*- coding: utf-8 -*-
import inspect
import pprint
import sys
import linecache


_sentinel = object()


def safehasattr(obj, name):
    return getattr(obj, name, _sentinel) is not _sentinel


class SafePrettyPrinter(pprint.PrettyPrinter, object):
    def format(self, obj, context, maxlevels, level):
        try:
            return super(SafePrettyPrinter, self).format(
                obj, context, maxlevels, level)
        except Exception:
            return object.__repr__(obj)[:-1] + ' (bad repr)>', True, False


def spformat(obj, depth=None):
    return SafePrettyPrinter(indent=1, width=76, depth=depth).pformat(obj)


def formatvalue(v):
    s = spformat(v, depth=1).replace('\n', '')
    if len(s) > 250:
        s = object.__repr__(v)[:-1] + ' (really long repr)>'
    return '=' + s


def stack(f, with_locals=False):
    limit = getattr(sys, 'tracebacklimit', None)

    frames = []
    n = 0
    while f is not None and (limit is None or n < limit):
        lineno, co = f.f_lineno, f.f_code
        name, filename = co.co_name, co.co_filename
        args = inspect.getargvalues(f)

        linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, f.f_globals)
        if line:
            line = line.strip()
        else:
            line = None

        frames.append((filename, lineno, name, line, f.f_locals, args))
        f = f.f_back
        n += 1
    frames.reverse()

    out = []
    for filename, lineno, name, line, localvars, args in frames:
        out.append('  File "%s", line %d, in %s' % (filename, lineno, name))
        if line:
            out.append('    %s' % line.strip())

        if with_locals:
            args = inspect.formatargvalues(formatvalue=formatvalue, *args)
            out.append('\n      Arguments: %s%s' % (name, args))

        if with_locals and localvars:
            out.append('      Local variables:\n')
            try:
                reprs = spformat(localvars)
            except Exception:
                reprs = "failed to format local variables"
            out += ['      ' + l for l in reprs.splitlines()]
            out.append('')
    return '\n'.join(out).decode('utf-8', 'replace')
