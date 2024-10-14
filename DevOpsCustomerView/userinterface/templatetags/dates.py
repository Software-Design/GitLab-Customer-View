from django.template import Library
import datetime
import userinterface.templatetags.numbers as numbers

register = Library()


@register.filter(expects_localtime=True)
def parse_iso(value):
    if type(value) != str or value == "":
        return "?"
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


@register.filter(expects_localtime=True)
def parse_date(value):
    # if already datetime object, return
    if type(value) == datetime.datetime:
        return value
    if type(value) != str or value == "":
        return "?"
    return datetime.datetime.strptime(value, "%Y-%m-%d")


@register.filter(expects_localtime=True)
def dayssince(value):
    try:
        return (value - datetime.datetime.now()).days * -1
    except:
        return "?"


@register.filter
def humanizeTime(value):
    return numbers.humanizeTime(value)


@register.filter
def first_day_of_month(date):
    return date.replace(day=1)


@register.filter
def last_day_of_month(date):
    return (first_day_of_month(date) + datetime.timedelta(days=32)).replace(
        day=1
    ) - datetime.timedelta(days=1)


@register.filter
def first_day_of_previous_month(date):
    return (first_day_of_month(date) - datetime.timedelta(days=1)).replace(day=1)


@register.filter
def last_day_of_previous_month(date):
    return first_day_of_month(date) - datetime.timedelta(days=1)


@register.simple_tag
def getTimeDifferences(issue, kind, start, end):
    return numbers.humanizeTime(issue.getTimeDifference(kind, start, end))
