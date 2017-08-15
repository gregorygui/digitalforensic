from django import template

register = template.Library()

@register.simple_tag(name="sub")
def sub2(arg1, arg2):
	return arg1-arg2